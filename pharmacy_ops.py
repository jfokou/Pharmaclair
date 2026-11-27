"""
PharmaClair — Opérations Privées de l'Officine (/workspace).
Strictement isolé par organisation (pharmacy_id) et succursale (branch_id).
"""
import secrets
import json
import csv
import io
import calendar
import os
import datetime as dt
from schema import DB_LOCK, TZ, now
from security import need_pharmacy, verify_branch_access, audit_pharmacy, hpw, Denied, Conflict
from platform_saas import redact_pii

EXPIRY_MONTH_RULE = os.environ.get("EXPIRY_MONTH_RULE", "end")

def parse_expiry(s):
    s = s.strip()
    if "/" in s:
        parts = s.split("/")
        if len(parts) == 2:
            m, y = int(parts[0]), int(parts[1])
            if y < 100: y += 2000
            s = f"{y:04d}-{m:02d}"
    if len(s) == 7:
        y, m = int(s[:4]), int(s[5:])
        return dt.date(y, m, calendar.monthrange(y, m)[1] if EXPIRY_MONTH_RULE == "end" else 1) - (dt.timedelta(days=0) if EXPIRY_MONTH_RULE == "end" else dt.timedelta(days=1))
    return dt.date.fromisoformat(s)

def format_ts_details(iso_str):
    try:
        parsed = dt.datetime.fromisoformat(iso_str)
        date_str = parsed.strftime("%d/%m/%Y")
        time_str = parsed.strftime("%H:%M:%S")
        full_str = f"{date_str} à {time_str} (Douala GMT+1)"
        return date_str, time_str, full_str
    except Exception:
        return iso_str[:10], iso_str[11:19] if len(iso_str) > 19 else iso_str, iso_str

# --- GESTION UTILISATEURS & RÔLES PERSONNALISÉS ---

def list_users(c, u):
    need_pharmacy(c, u, "users_view")
    with DB_LOCK:
        return [dict(r) for r in c.execute("""
            SELECT id, pharmacy_id, branch_id, username, full_name, email, role, active, can_block, can_cash, fails
            FROM users WHERE pharmacy_id=? ORDER BY id
        """, (u["pharmacy_id"],)).fetchall()]

def create_user(c, u, username, pw, role, branch_id=None, full_name="", email="", **flags):
    need_pharmacy(c, u, "pharmacy_all")
    if role in ("superadmin", "sales_rep", "support"):
        raise Denied("Impossible de créer un compte plateforme depuis une officine.")
    bid = verify_branch_access(c, u, branch_id)
    salt = secrets.token_hex(8)
    with DB_LOCK:
        try:
            c.execute("""
                INSERT INTO users(pharmacy_id, branch_id, username, full_name, email, salt, pw, role, can_block, can_cash)
                VALUES(?,?,?,?,?,?,?,?,?,?)
            """, (u["pharmacy_id"], bid, username, full_name, email, salt, hpw(pw, salt), role,
                  int(flags.get("can_block", 0)), int(flags.get("can_cash", 0))))
        except Exception:
            raise Conflict("Ce nom d'utilisateur est déjà utilisé.")
    audit_pharmacy(c, u, "user_create", {"username": username, "role": role, "branch_id": bid})

def toggle_user_active(c, u, user_id, active_state):
    need_pharmacy(c, u, "pharmacy_all")
    with DB_LOCK:
        target = c.execute("SELECT id FROM users WHERE id=? AND pharmacy_id=?", (user_id, u["pharmacy_id"])).fetchone()
        if not target:
            raise Denied("Utilisateur introuvable dans votre organisation.")
        c.execute("UPDATE users SET active=? WHERE id=? AND pharmacy_id=?", (int(active_state), user_id, u["pharmacy_id"]))
        if not active_state:
            c.execute("DELETE FROM sessions WHERE user_id=? AND pharmacy_id=?", (user_id, u["pharmacy_id"]))
    audit_pharmacy(c, u, "user_toggle_active", {"target_user_id": user_id, "active": active_state})

def reset_user_fails(c, u, user_id):
    need_pharmacy(c, u, "pharmacy_all")
    with DB_LOCK:
        c.execute("UPDATE users SET fails=0 WHERE id=? AND pharmacy_id=?", (user_id, u["pharmacy_id"]))
    audit_pharmacy(c, u, "user_reset_fails", {"target_user_id": user_id})

# --- SUCCURSALES & TRANSFERTS INTER-SUCCURSALES ---

def list_branches(c, u):
    need_pharmacy(c, u, "stock_view")
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT * FROM branches WHERE pharmacy_id=? ORDER BY is_main DESC, id ASC", (u["pharmacy_id"],)).fetchall()]

def create_branch(c, u, name, city, address="", phone=""):
    need_pharmacy(c, u, "pharmacy_all")
    with DB_LOCK:
        bid = c.execute("INSERT INTO branches(pharmacy_id, name, city, address, phone, is_main) VALUES(?,?,?,?,?,0)",
                        (u["pharmacy_id"], name, city, address, phone)).lastrowid
    audit_pharmacy(c, u, "branch_create", {"branch_id": bid, "name": name, "city": city})
    return bid

# --- CATALOGUE, STOCKS & LOTS (FEFO) ---

def _sellable_lots(c, ph, drug_id, branch_id=None):
    today = dt.datetime.now(TZ).date().isoformat()
    if branch_id:
        return c.execute("""
            SELECT * FROM lots
            WHERE pharmacy_id=? AND (branch_id=? OR branch_id IS NULL) AND drug_id=? AND status='ok' AND qty>0 AND expiry_date>=?
            ORDER BY expiry_date ASC, id ASC
        """, (ph, branch_id, drug_id, today)).fetchall()
    return c.execute("""
        SELECT * FROM lots
        WHERE pharmacy_id=? AND drug_id=? AND status='ok' AND qty>0 AND expiry_date>=?
        ORDER BY expiry_date ASC, id ASC
    """, (ph, drug_id, today)).fetchall()

def list_drugs_with_stock(c, u):
    need_pharmacy(c, u, "stock_view")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        drugs = c.execute("SELECT * FROM drugs WHERE pharmacy_id=? ORDER BY name", (ph,)).fetchall()
        result = []
        for d in drugs:
            phys = c.execute("SELECT COALESCE(SUM(qty),0) FROM lots WHERE pharmacy_id=? AND drug_id=?", (ph, d["id"])).fetchone()[0]
            sellable_lots = _sellable_lots(c, ph, d["id"], u.get("branch_id"))
            sellable = sum(l["qty"] for l in sellable_lots)
            next_lot = sellable_lots[0] if sellable_lots else None
            result.append({
                "id": d["id"], "pharmacy_id": ph, "name": d["name"], "generic_name": d["generic_name"] or "",
                "dosage": d["dosage"] or "", "form": d["form"] or "", "category": d["category"] or "Général",
                "pack": d["pack"], "price": d["price"], "ref": d["ref"], "barcode": d["barcode"],
                "min_stock": d["min_stock"] or 10, "physical": phys, "sellable": sellable,
                "next_expiry": next_lot["expiry"] if next_lot else None,
                "next_expiry_date": next_lot["expiry_date"] if next_lot else None,
                "next_lot_no": next_lot["lot_no"] if next_lot else None
            })
        return result

def stock(c, u, drug_id):
    need_pharmacy(c, u, "stock_view")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        d = c.execute("SELECT id FROM drugs WHERE id=? AND pharmacy_id=?", (drug_id, ph)).fetchone()
        if not d:
            raise Denied("Médicament introuvable dans votre organisation.")
        phys = c.execute("SELECT COALESCE(SUM(qty),0) FROM lots WHERE pharmacy_id=? AND drug_id=?", (ph, drug_id)).fetchone()[0]
        sellable_lots = _sellable_lots(c, ph, drug_id, u.get("branch_id"))
        all_lots = c.execute("SELECT * FROM lots WHERE pharmacy_id=? AND drug_id=? ORDER BY expiry_date,id", (ph, drug_id)).fetchall()
        return {
            "physical": phys,
            "sellable": sum(l["qty"] for l in sellable_lots),
            "lots": [dict(l) for l in all_lots]
        }

def receive(c, u, drug_id, lot_no, expiry, qty, purchase_cost=0, supplier="", bl=""):
    need_pharmacy(c, u, "receive")
    if qty <= 0:
        raise Conflict("Quantité invalide (doit être > 0)")
    ph = u["pharmacy_id"]
    bid = u.get("branch_id")
    with DB_LOCK:
        if not c.execute("SELECT 1 FROM drugs WHERE id=? AND pharmacy_id=?", (drug_id, ph)).fetchone():
            raise Denied("Médicament introuvable dans votre organisation.")
        ed = parse_expiry(expiry).isoformat()
        c.execute("BEGIN IMMEDIATE")
        try:
            l = c.execute("SELECT * FROM lots WHERE pharmacy_id=? AND drug_id=? AND lot_no=?", (ph, drug_id, lot_no)).fetchone()
            if l:
                if l["expiry_date"] != ed:
                    raise Conflict("Lot existant avec une autre péremption : vérification titulaire requise.")
                c.execute("UPDATE lots SET qty=qty+?, purchase_cost=CASE WHEN ?>0 THEN ? ELSE purchase_cost END WHERE id=?",
                          (qty, purchase_cost, purchase_cost, l["id"]))
                lid = l["id"]
            else:
                lid = c.execute("""
                    INSERT INTO lots(pharmacy_id, branch_id, drug_id, lot_no, expiry, expiry_date, qty, purchase_cost)
                    VALUES(?,?,?,?,?,?,?,?)
                """, (ph, bid, drug_id, lot_no, expiry, ed, qty, purchase_cost)).lastrowid
            c.execute("INSERT INTO movements(pharmacy_id, branch_id, lot_id, type, qty, ref, user_id, ts) VALUES(?,?,?,?,?,?,?,?)",
                      (ph, bid, lid, "in", qty, f"BL:{bl} Fournisseur:{supplier}", u["id"], now()))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    audit_pharmacy(c, u, "receive", {"drug_id": drug_id, "lot_id": lid, "qty": qty, "cost": purchase_cost, "bl": bl})
    return lid

def block_lot(c, u, lot_id, status="blocked"):
    need_pharmacy(c, u, "block")
    if status not in ("ok", "blocked", "recalled", "damaged"):
        raise Conflict("Statut de lot invalide")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        l = c.execute("SELECT status FROM lots WHERE id=? AND pharmacy_id=?", (lot_id, ph)).fetchone()
        if not l:
            raise Denied("Lot introuvable dans votre organisation.")
        prev = l["status"]
        c.execute("UPDATE lots SET status=? WHERE id=? AND pharmacy_id=?", (status, lot_id, ph))
    audit_pharmacy(c, u, "lot_status_change", {"lot_id": lot_id}, prev_val=prev, new_val=status)

# --- FOURNISSEURS & COMMANDES D'ACHAT ---

def list_suppliers(c, u):
    need_pharmacy(c, u, "suppliers_view")
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT * FROM suppliers WHERE pharmacy_id=? ORDER BY name", (u["pharmacy_id"],)).fetchall()]

def create_supplier(c, u, name, contact="", phone="", email="", payment_terms="30 jours"):
    need_pharmacy(c, u, "purchase_orders")
    with DB_LOCK:
        sid = c.execute("INSERT INTO suppliers(pharmacy_id, name, contact, phone, email, payment_terms) VALUES(?,?,?,?,?,?)",
                        (u["pharmacy_id"], name, contact, phone, email, payment_terms)).lastrowid
    audit_pharmacy(c, u, "supplier_create", {"supplier_id": sid, "name": name})
    return sid

def create_purchase_order(c, u, supplier_id, items):
    need_pharmacy(c, u, "purchase_orders")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        sup = c.execute("SELECT id FROM suppliers WHERE id=? AND pharmacy_id=?", (supplier_id, ph)).fetchone()
        if not sup:
            raise Denied("Fournisseur introuvable.")
        po_no = f"PO-{dt.datetime.now(TZ).strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
        total_amt = sum(int(it["qty"]) * int(it["unit_cost"]) for it in items)
        po_id = c.execute("""
            INSERT INTO purchase_orders(pharmacy_id, branch_id, supplier_id, po_no, status, total_amount, created_by, ts)
            VALUES(?,?,?,?, 'approved', ?,?,?)
        """, (ph, u.get("branch_id"), supplier_id, po_no, total_amt, u["id"], now())).lastrowid
        for it in items:
            c.execute("""
                INSERT INTO purchase_order_lines(po_id, pharmacy_id, drug_id, qty_ordered, unit_cost)
                VALUES(?,?,?,?,?)
            """, (po_id, ph, int(it["drug_id"]), int(it["qty"]), int(it["unit_cost"])))
    audit_pharmacy(c, u, "po_create", {"po_id": po_id, "po_no": po_no, "total": total_amt})
    return po_id

# --- POINT DE VENTE (POS), COGS & REÇUS ---

def sell(c, u, idem, items, method, paid=None, customer_id=None, prescription_id=None, discount=0, is_offline=0, payment_status=None):
    need_pharmacy(c, u, "sell")
    ph = u["pharmacy_id"]
    bid = u.get("branch_id")
    if discount > 0 and u.get("role") == "cashier":
        # Seuls les rôles supérieurs peuvent accorder une remise importante (> 5%)
        pass

    with DB_LOCK:
        c.execute("BEGIN IMMEDIATE")
        try:
            old = c.execute("SELECT id FROM sales WHERE pharmacy_id=? AND idem=?", (ph, idem)).fetchone()
            if old:
                c.execute("COMMIT")
                return old["id"]

            lines, total, total_cost = [], 0, 0
            for drug_id, qty in items:
                if qty <= 0:
                    raise Conflict("Quantité invalide")
                d = c.execute("SELECT name, price FROM drugs WHERE id=? AND pharmacy_id=?", (drug_id, ph)).fetchone()
                if not d:
                    raise Conflict(f"Médicament introuvable dans votre officine (ID: {drug_id})")
                needed = qty
                for l in _sellable_lots(c, ph, drug_id, bid):
                    take = min(needed, l["qty"])
                    if take > 0:
                        ucost = l["purchase_cost"] or int(d["price"] * 0.72)
                        lines.append((drug_id, l["id"], take, d["price"], ucost, f"{d['name']} (Lot {l['lot_no']} - Exp {l['expiry']})"))
                        total_cost += ucost * take
                        needed -= take
                        if needed == 0:
                            break
                if needed > 0:
                    raise Conflict(f"Stock insuffisant ou lots périmés pour : {d['name']} (manque {needed} boîte(s))")
                total += d["price"] * qty

            total_after_discount = max(0, total - int(discount))
            paid_amt = total_after_discount if paid is None else int(paid)
            if paid_amt < total_after_discount:
                raise Conflict(f"Montant payé insuffisant ({paid_amt} < {total_after_discount})")
            change = paid_amt - total_after_discount

            if not payment_status:
                if is_offline and method in ("om", "mtn_momo", "orange_money"):
                    payment_status = "manually_recorded"
                else:
                    payment_status = "provider_confirmed"

            prefix = "OFF-" if is_offline else "CL-"
            seq = c.execute("SELECT COUNT(*) FROM sales WHERE pharmacy_id=?", (ph,)).fetchone()[0] + 1
            rcpt_no = f"{prefix}{dt.datetime.now(TZ).strftime('%Y%m%d')}-{seq:04d}"

            sid = c.execute("""
                INSERT INTO sales(pharmacy_id, branch_id, user_id, customer_id, idem, receipt_no, total, total_cost, discount, method, paid, change, payment_status, is_offline, ts)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (ph, bid, u["id"], customer_id, idem, rcpt_no, total_after_discount, total_cost, int(discount), method, paid_amt, change, payment_status, is_offline, now())).lastrowid

            for did, lid, q, pr, uc, lbl in lines:
                c.execute("INSERT INTO sale_lines(sale_id, pharmacy_id, drug_id, lot_id, qty, price, unit_cost, label) VALUES(?,?,?,?,?,?,?,?)",
                          (sid, ph, did, lid, q, pr, uc, lbl))
                c.execute("UPDATE lots SET qty=qty-? WHERE id=? AND pharmacy_id=?", (q, lid, ph))
                c.execute("INSERT INTO movements(pharmacy_id, branch_id, lot_id, type, qty, ref, user_id, ts) VALUES(?,?,?,?,?,?,?,?)",
                          (ph, bid, lid, "out", q, f"Vente #{rcpt_no}", u["id"], now()))

            if prescription_id:
                presc = c.execute("SELECT refills_left FROM prescriptions WHERE id=? AND pharmacy_id=?", (prescription_id, ph)).fetchone()
                if presc and presc["refills_left"] > 0:
                    new_refills = presc["refills_left"] - 1
                    new_status = "completed" if new_refills == 0 else "active"
                    c.execute("UPDATE prescriptions SET refills_left=?, status=? WHERE id=? AND pharmacy_id=?", (new_refills, new_status, prescription_id, ph))

            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise

    audit_pharmacy(c, u, "sale", {"sale_id": sid, "receipt_no": rcpt_no, "total": total_after_discount, "method": method, "is_offline": is_offline})
    return sid

def receipt(c, u, sale_id, reprint=False):
    need_pharmacy(c, u, "own_sales")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        s = c.execute("""
            SELECT s.*, u.username as cashier_name
            FROM sales s JOIN users u ON u.id=s.user_id
            WHERE s.id=? AND s.pharmacy_id=?
        """, (sale_id, ph)).fetchone()
        if not s:
            raise Denied("Reçu introuvable ou accès non autorisé.")
        p = c.execute("SELECT * FROM pharmacies WHERE id=?", (ph,)).fetchone()
        lines = c.execute("SELECT * FROM sale_lines WHERE sale_id=? AND pharmacy_id=?", (sale_id, ph)).fetchall()
        customer = None
        if s["customer_id"]:
            cust = c.execute("SELECT name, phone FROM customers WHERE id=? AND pharmacy_id=?", (s["customer_id"], ph)).fetchone()
            if cust:
                customer = dict(cust)

        if reprint:
            audit_pharmacy(c, u, "receipt_reprint", {"sale_id": sale_id, "receipt_no": s["receipt_no"]})

        d_str, t_str, full_ts = format_ts_details(s["ts"])
        return {
            "pharmacy": {
                "name": p["name"], "address": p["address"], "tax_id": p["tax_id"], "rccm": p["rccm"] or "",
                "phone": p["phone"] or "", "footer": p["footer"], "currency": p["currency"] or "FCFA",
                "format": p["receipt_format"] or "80mm"
            },
            "receipt_no": s["receipt_no"],
            "date": d_str,
            "time": t_str,
            "full_timestamp": full_ts,
            "cashier": s["cashier_name"],
            "customer": customer,
            "is_offline": bool(s["is_offline"]),
            "payment_status": s["payment_status"],
            "reprint": reprint,
            "total": s["total"],
            "discount": s["discount"],
            "method": s["method"],
            "paid": s["paid"],
            "change": s["change"],
            "lines": [dict(l) for l in lines]
        }

def sales_list(c, u):
    need_pharmacy(c, u, "own_sales")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        if u["role"] in ("owner", "branch_manager", "accountant", "auditor"):
            rows = c.execute("""
                SELECT s.*, u.username as cashier_name
                FROM sales s JOIN users u ON u.id=s.user_id
                WHERE s.pharmacy_id=? ORDER BY s.id DESC LIMIT 100
            """, (ph,)).fetchall()
        else:
            rows = c.execute("""
                SELECT s.*, u.username as cashier_name
                FROM sales s JOIN users u ON u.id=s.user_id
                WHERE s.pharmacy_id=? AND s.user_id=? ORDER BY s.id DESC LIMIT 50
            """, (ph, u["id"])).fetchall()
        results = []
        for r in rows:
            d_str, t_str, full_ts = format_ts_details(r["ts"])
            item = dict(r)
            if u["role"] == "cashier":
                item.pop("total_cost", None)  # Confidentialité des marges
            item["date_str"] = d_str
            item["time_str"] = t_str
            item["full_ts"] = full_ts
            results.append(item)
        return results

# --- FINANCES, CLÔTURE DE CAISSE & DÉPENSES ---

def perform_cash_closing(c, u, initial_cash, counted_cash):
    need_pharmacy(c, u, "cash_count")
    ph = u["pharmacy_id"]
    bid = u.get("branch_id")
    with DB_LOCK:
        today_date = dt.datetime.now(TZ).date().isoformat()
        sales_today = c.execute("SELECT method, total FROM sales WHERE pharmacy_id=? AND ts LIKE ?", (ph, f"{today_date}%")).fetchall()
        cash_sales = sum(s["total"] for s in sales_today if s["method"] == "cash")
        total_om = sum(s["total"] for s in sales_today if s["method"] in ("om", "mtn_momo", "orange_money"))
        total_card = sum(s["total"] for s in sales_today if s["method"] == "card")
        total_day = sum(s["total"] for s in sales_today)
        expenses_today = c.execute("SELECT COALESCE(SUM(amount),0) FROM expenses WHERE pharmacy_id=? AND ts LIKE ?", (ph, f"{today_date}%")).fetchone()[0]
        theoretical_cash = initial_cash + cash_sales - expenses_today
        diff_cash = counted_cash - theoretical_cash
        cid = c.execute("""
            INSERT INTO cash_closings(pharmacy_id, branch_id, user_id, date_str, initial_cash, counted_cash, theoretical_cash, diff_cash, total_om, total_card, total_day, ts)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        """, (ph, bid, u["id"], today_date, initial_cash, counted_cash, theoretical_cash, diff_cash, total_om, total_card, total_day, now())).lastrowid
    audit_pharmacy(c, u, "cash_closing", {"closing_id": cid, "diff_cash": diff_cash, "total_day": total_day})
    return {
        "closing_id": cid, "date": today_date, "initial_cash": initial_cash, "cash_sales": cash_sales,
        "expenses_today": expenses_today, "counted_cash": counted_cash, "theoretical_cash": theoretical_cash,
        "diff_cash": diff_cash, "total_om": total_om, "total_card": total_card, "total_day": total_day,
        "status": "balanced" if diff_cash == 0 else ("surplus" if diff_cash > 0 else "shortage")
    }

def record_expense(c, u, amount, category, description):
    need_pharmacy(c, u, "expenses")
    if amount <= 0:
        raise Conflict("Montant invalide")
    with DB_LOCK:
        eid = c.execute("INSERT INTO expenses(pharmacy_id, branch_id, user_id, amount, category, description, ts) VALUES(?,?,?,?,?,?,?)",
                        (u["pharmacy_id"], u.get("branch_id"), u["id"], int(amount), category, description, now())).lastrowid
    audit_pharmacy(c, u, "expense_create", {"amount": amount, "category": category, "desc": description})
    return eid

def list_expenses(c, u):
    need_pharmacy(c, u, "finance_view")
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT * FROM expenses WHERE pharmacy_id=? ORDER BY id DESC LIMIT 100", (u["pharmacy_id"],)).fetchall()]

def get_finance_pnl(c, u):
    """Compte de résultat réel basé sur le coût d'achat des lots (COGS)."""
    need_pharmacy(c, u, "finance_view")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        sales = c.execute("SELECT COALESCE(SUM(total),0), COALESCE(SUM(total_cost),0) FROM sales WHERE pharmacy_id=?", (ph,)).fetchone()
        revenue, cogs = sales[0], sales[1]
        gross_profit = revenue - cogs
        margin_pct = round((gross_profit / revenue) * 100, 1) if revenue > 0 else 0.0
        expenses = c.execute("SELECT COALESCE(SUM(amount),0) FROM expenses WHERE pharmacy_id=?", (ph,)).fetchone()[0]
        net_profit = gross_profit - expenses
        inv_val = c.execute("SELECT COALESCE(SUM(qty * purchase_cost), 0) FROM lots WHERE pharmacy_id=? AND qty>0 AND status='ok'", (ph,)).fetchone()[0]
        return {
            "total_revenue": revenue,
            "cogs": cogs,
            "gross_profit": gross_profit,
            "gross_margin_pct": margin_pct,
            "operating_expenses": expenses,
            "net_profit": net_profit,
            "inventory_valuation": inv_val
        }

# --- TABLEAU DE BORD PROPRIÉTAIRE OFFICINE ---

def owner_dashboard_stats(c, u):
    need_pharmacy(c, u, "reports")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        today = dt.datetime.now(TZ).date()
        today_date = today.isoformat()
        yesterday_date = (today - dt.timedelta(days=1)).isoformat()

        sales_today = c.execute("SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.pharmacy_id=? AND s.ts LIKE ? ORDER BY s.id DESC", (ph, f"{today_date}%")).fetchall()
        sales_yesterday = c.execute("SELECT total FROM sales WHERE pharmacy_id=? AND ts LIKE ?", (ph, f"{yesterday_date}%")).fetchall()

        total_revenue_today = sum(s["total"] for s in sales_today)
        total_cost_today = sum(s["total_cost"] for s in sales_today)
        gross_profit_today = total_revenue_today - total_cost_today
        total_revenue_yesterday = sum(s["total"] for s in sales_yesterday)

        trend_pct = int(((total_revenue_today - total_revenue_yesterday) / total_revenue_yesterday) * 100) if total_revenue_yesterday > 0 else 0
        count_sales_today = len(sales_today)
        avg_basket_today = int(total_revenue_today / count_sales_today) if count_sales_today > 0 else 0

        pay_methods = {"cash": 0, "om": 0, "card": 0}
        for s in sales_today:
            m = "om" if s["method"] in ("om", "mtn_momo", "orange_money") else s["method"]
            pay_methods[m] = pay_methods.get(m, 0) + s["total"]

        users = c.execute("SELECT id, username, role, active, fails FROM users WHERE pharmacy_id=?", (ph,)).fetchall()
        logins_today = c.execute("SELECT DISTINCT user_id FROM user_logins WHERE pharmacy_id=? AND ts LIKE ? AND action='login'", (ph, f"{today_date}%")).fetchall()
        active_users_today = len(set(r[0] for r in logins_today)) or 1

        closings_today = c.execute("SELECT * FROM cash_closings WHERE pharmacy_id=? AND date_str=? ORDER BY id DESC LIMIT 1", (ph, today_date)).fetchone()
        cash_discrepancy = closings_today["diff_cash"] if closings_today else 0

        low_stock_drugs = c.execute("""
            SELECT d.id, d.name, d.min_stock, COALESCE(SUM(l.qty),0) as current_stock
            FROM drugs d
            LEFT JOIN lots l ON l.drug_id=d.id AND l.pharmacy_id=? AND l.status='ok' AND l.qty>0 AND l.expiry_date>=?
            WHERE d.pharmacy_id=?
            GROUP BY d.id
            HAVING current_stock <= d.min_stock
        """, (ph, today_date, ph)).fetchall()

        three_months_date = (today + dt.timedelta(days=90)).isoformat()
        expiring = c.execute("""
            SELECT l.*, d.name as drug_name, d.pack as drug_pack
            FROM lots l JOIN drugs d ON d.id=l.drug_id
            WHERE l.pharmacy_id=? AND l.qty>0 AND l.status='ok' AND l.expiry_date<=?
            ORDER BY l.expiry_date ASC
        """, (ph, three_months_date)).fetchall()

        recent_sales = []
        for s in sales_today[:15]:
            d_str, t_str, f_str = format_ts_details(s["ts"])
            recent_sales.append({
                "id": s["id"], "receipt_no": s["receipt_no"], "cashier": s["cashier_name"],
                "total": s["total"], "method": s["method"], "time": t_str, "date": d_str, "full_time": f_str
            })

        p_info = c.execute("SELECT * FROM pharmacies WHERE id=?", (ph,)).fetchone()
        return {
            "today_date": today.strftime("%d/%m/%Y"),
            "total_revenue_today": total_revenue_today,
            "estimated_profit": gross_profit_today,
            "trend_pct": trend_pct,
            "count_sales_today": count_sales_today,
            "avg_basket_today": avg_basket_today,
            "payment_methods": pay_methods,
            "active_employees_ratio": f"{active_users_today} / {len(users)}",
            "cash_discrepancy": cash_discrepancy,
            "low_stock_count": len(low_stock_drugs),
            "expiring_count": len(expiring),
            "expiring_lots": [dict(r) for r in expiring],
            "recent_sales": recent_sales,
            "pharmacy": dict(p_info) if p_info else {}
        }

# --- PATIENTS, ORDONNANCES & CONFIDENTIALITÉ ---

def list_customers(c, u):
    need_pharmacy(c, u, "customers")
    with DB_LOCK:
        rows = [dict(r) for r in c.execute("SELECT * FROM customers WHERE pharmacy_id=? ORDER BY name", (u["pharmacy_id"],)).fetchall()]
    audit_pharmacy(c, u, "patient_list_access", {"count": len(rows)})
    return rows

def create_customer(c, u, name, phone, allergies="", insurance_info="", consent_sms=1):
    need_pharmacy(c, u, "customers")
    with DB_LOCK:
        cid = c.execute("INSERT INTO customers(pharmacy_id, name, phone, allergies, insurance_info, consent_sms, ts) VALUES(?,?,?,?,?,?,?)",
                        (u["pharmacy_id"], name, phone, allergies, insurance_info, int(consent_sms), now())).lastrowid
    audit_pharmacy(c, u, "customer_create", {"customer_id": cid})
    return cid

def list_prescriptions(c, u, customer_id=None):
    need_pharmacy(c, u, "prescriptions")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        sql = """
            SELECT p.*, c.name as customer_name, c.phone as customer_phone, d.name as drug_name
            FROM prescriptions p
            JOIN customers c ON c.id=p.customer_id AND c.pharmacy_id=p.pharmacy_id
            JOIN drugs d ON d.id=p.drug_id AND d.pharmacy_id=p.pharmacy_id
            WHERE p.pharmacy_id=?
        """
        params = [ph]
        if customer_id:
            sql += " AND p.customer_id=?"
            params.append(customer_id)
        sql += " ORDER BY p.id DESC"
        rows = [dict(r) for r in c.execute(sql, tuple(params)).fetchall()]
    audit_pharmacy(c, u, "prescription_access", {"count": len(rows)})
    return rows

def create_prescription(c, u, customer_id, doctor, drug_id, posology, refills_total, expiry_date):
    need_pharmacy(c, u, "prescriptions")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        if not c.execute("SELECT 1 FROM customers WHERE id=? AND pharmacy_id=?", (customer_id, ph)).fetchone():
            raise Denied("Patient introuvable dans votre organisation.")
        if not c.execute("SELECT 1 FROM drugs WHERE id=? AND pharmacy_id=?", (drug_id, ph)).fetchone():
            raise Denied("Médicament introuvable dans votre organisation.")
        pid = c.execute("""
            INSERT INTO prescriptions(pharmacy_id, customer_id, doctor, drug_id, posology, refills_total, refills_left, expiry_date, ts)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, (ph, customer_id, doctor, drug_id, posology, refills_total, refills_total, expiry_date, now())).lastrowid
    audit_pharmacy(c, u, "prescription_create", {"prescription_id": pid})
    return pid

def send_automated_reminders(c, u):
    need_pharmacy(c, u, "notifs")
    sent = 0
    ph = u["pharmacy_id"]
    with DB_LOCK:
        prescs = c.execute("""
            SELECT p.*, c.name as customer_name, c.phone as customer_phone, d.name as drug_name
            FROM prescriptions p
            JOIN customers c ON c.id=p.customer_id AND c.pharmacy_id=p.pharmacy_id
            JOIN drugs d ON d.id=p.drug_id AND d.pharmacy_id=p.pharmacy_id
            WHERE p.pharmacy_id=? AND p.status='active' AND p.refills_left > 0 AND c.consent_sms=1
        """, (ph,)).fetchall()
        for p in prescs:
            msg = f"Bonjour {p['customer_name']}, votre traitement de {p['drug_name']} arrive à renouvellement. Il reste {p['refills_left']} renouvellement(s)."
            c.execute("INSERT INTO sms_notifs(pharmacy_id, customer_id, phone, message, status, ts) VALUES(?,?,?,?,?,?)",
                      (ph, p["customer_id"], p["customer_phone"], msg, "sent", now()))
            sent += 1
    audit_pharmacy(c, u, "reminders_sent", {"count": sent})
    return {"status": "ok", "reminders_sent": sent}

# --- AUDIT INTERNE & DÉTECTION D'ANOMALIES ANTIFRAUDE ---

def get_audit_logs_and_anomalies(c, u):
    need_pharmacy(c, u, "audit_view")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        logs = [dict(r) for r in c.execute("""
            SELECT a.*, u.username
            FROM audit a LEFT JOIN users u ON u.id=a.user_id
            WHERE a.pharmacy_id=? ORDER BY a.id DESC LIMIT 100
        """, (ph,)).fetchall()]
        anomalies = []
        reprints = c.execute("SELECT COUNT(*) FROM audit WHERE pharmacy_id=? AND action='receipt_reprint'", (ph,)).fetchone()[0]
        if reprints >= 5:
            anomalies.append({"type": "Reprints fréquents", "severity": "medium", "detail": f"{reprints} réimpressions de tickets détectées."})
        discrepancies = c.execute("SELECT COUNT(*) FROM cash_closings WHERE pharmacy_id=? AND diff_cash != 0", (ph,)).fetchone()[0]
        if discrepancies > 0:
            anomalies.append({"type": "Écarts de caisse", "severity": "high", "detail": f"{discrepancies} clôture(s) avec écart de caisse."})
        return {"logs": logs, "anomalies": anomalies}

def list_employee_logins(c, u):
    need_pharmacy(c, u, "users_view")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        rows = c.execute("""
            SELECT ul.*, u.username, u.role
            FROM user_logins ul JOIN users u ON u.id=ul.user_id
            WHERE ul.pharmacy_id=? ORDER BY ul.id DESC LIMIT 40
        """, (ph,)).fetchall()
        results = []
        for r in rows:
            d_str, t_str, full_ts = format_ts_details(r["ts"])
            results.append({"id": r["id"], "username": r["username"], "role": r["role"], "action": r["action"], "date": d_str, "time": t_str})
        return results

# --- PARAMÈTRES, ABONNEMENT SASPAY & SUPPORT CLIENT ---

def get_pharmacy_settings(c, u):
    need_pharmacy(c, u, "stock_view")
    with DB_LOCK:
        p = c.execute("SELECT * FROM pharmacies WHERE id=?", (u["pharmacy_id"],)).fetchone()
        res = dict(p) if p else {}
        if u["role"] != "owner":
            res.pop("saspay_secret", None)
        return res

def update_pharmacy_settings(c, u, data):
    need_pharmacy(c, u, "pharmacy_all")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        fields = ["name", "address", "tax_id", "footer", "phone", "email", "city", "rccm", "currency", "receipt_format", "saspay_client_id", "saspay_secret", "saspay_mode"]
        updates, vals = [], []
        for f in fields:
            if f in data:
                updates.append(f"{f}=?")
                vals.append(str(data[f]))
        if updates:
            vals.append(ph)
            c.execute(f"UPDATE pharmacies SET {', '.join(updates)} WHERE id=?", tuple(vals))
    audit_pharmacy(c, u, "settings_update", {"fields": list(data.keys())})
    return get_pharmacy_settings(c, u)

def pay_subscription_saspay(c, u, months, method, phone="", payment_ref=None):
    need_pharmacy(c, u, "pharmacy_all")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        pay_ref = payment_ref or f"SAS-{secrets.token_hex(4).upper()}-{now()[:10].replace('-','')}"
        # Idempotence contre les doubles callbacks de paiement
        existing = c.execute("SELECT id, amount, created_at FROM subscription_payments WHERE payment_ref=?", (pay_ref,)).fetchone()
        if existing:
            p = c.execute("SELECT subscription_expires_at FROM pharmacies WHERE id=?", (ph,)).fetchone()
            return {"status": "already_processed", "payment_ref": pay_ref, "amount": existing["amount"], "new_expiry": p["subscription_expires_at"]}

        p = c.execute("SELECT * FROM pharmacies WHERE id=?", (ph,)).fetchone()
        plan = c.execute("SELECT * FROM subscription_plans WHERE id=?", (p["subscription_plan_id"] or 1,)).fetchone()
        base_monthly = plan["monthly_price"] if plan else 35000
        amount = months * base_monthly
        if months == 3 and plan: amount = plan["quarterly_price"]
        elif months == 12 and plan: amount = plan["annual_price"]

        base_date = dt.datetime.now(TZ).date()
        if p and p["subscription_expires_at"]:
            try:
                parsed = dt.date.fromisoformat(p["subscription_expires_at"][:10])
                if parsed > base_date:
                    base_date = parsed
            except Exception:
                pass

        new_exp = (base_date + dt.timedelta(days=months * 30)).isoformat()
        inv_no = f"INV-{ph}-{now()[:10].replace('-','')}-{secrets.token_hex(2).upper()}"
        inv_id = c.execute("""
            INSERT INTO saas_invoices(pharmacy_id, invoice_no, plan_id, amount, status, period_start, period_end, created_at)
            VALUES(?,?,?,?,'paid',?,?,?)
        """, (ph, inv_no, p["subscription_plan_id"] or 1, amount, base_date.isoformat(), new_exp, now())).lastrowid

        c.execute("""
            INSERT INTO subscription_payments(pharmacy_id, invoice_id, amount, months, payment_method, payment_ref, provider, status, created_at)
            VALUES(?,?,?,?,?,?,'saspay','completed',?)
        """, (ph, inv_id, amount, months, method, pay_ref, now()))

        c.execute("UPDATE pharmacies SET subscription_status='active', subscription_expires_at=? WHERE id=?", (new_exp, ph))
    audit_pharmacy(c, u, "subscription_renew", {"months": months, "amount": amount, "ref": pay_ref})
    return {"status": "ok", "payment_ref": pay_ref, "invoice_no": inv_no, "amount": amount, "new_expiry": new_exp}

def submit_support_ticket(c, u, category, priority, subject, description):
    need_pharmacy(c, u, "stock_view")
    # Masquage automatique des éventuels numéros/emails patients avant transmission au support
    redacted = redact_pii(description)
    with DB_LOCK:
        tid = c.execute("""
            INSERT INTO support_tickets(pharmacy_id, created_by_user_id, category, priority, subject, description_redacted, status, created_at)
            VALUES(?,?,?,?,?,?, 'open', ?)
        """, (u["pharmacy_id"], u["id"], category, priority, subject, redacted, now())).lastrowid
    audit_pharmacy(c, u, "support_ticket_create", {"ticket_id": tid})
    return tid

# --- SYNCHRONISATION HORS-LIGNE (Isolation Stricte par Tenant) ---

def sync_push_events(c, u, device_uuid, events):
    need_pharmacy(c, u, "sell")
    ph = u["pharmacy_id"]
    processed_ids, conflicts = [], []
    with DB_LOCK:
        for ev in events:
            # Rejet strict si l'événement tente d'usurper un autre tenant
            ev_ph = ev.get("pharmacy_id")
            if ev_ph is not None and int(ev_ph) != ph:
                raise Denied("Violation d'isolation multi-tenant : tentative de synchronisation vers une autre pharmacie.")

            event_id = ev.get("event_id")
            event_type = ev.get("event_type", "sale")
            payload = ev.get("payload", {})

            existing = c.execute("SELECT id FROM sync_outbox_log WHERE pharmacy_id=? AND event_id=?", (ph, event_id)).fetchone()
            if existing:
                processed_ids.append(event_id)
                continue

            try:
                if event_type == "sale":
                    sell(c, u, payload["idem"], payload["items"], payload["method"],
                         paid=payload.get("paid"), customer_id=payload.get("customer_id"),
                         prescription_id=payload.get("prescription_id"), is_offline=1)
                elif event_type == "cash_closing":
                    perform_cash_closing(c, u, payload.get("initial_cash", 0), payload["counted_cash"])
                c.execute("""
                    INSERT INTO sync_outbox_log(pharmacy_id, device_uuid, event_id, event_type, payload, server_status, processed_at)
                    VALUES(?,?,?,?,?,'processed',?)
                """, (ph, device_uuid, event_id, event_type, json.dumps(payload), now()))
                processed_ids.append(event_id)
            except Exception as e:
                c.execute("""
                    INSERT INTO sync_outbox_log(pharmacy_id, device_uuid, event_id, event_type, payload, server_status, conflict_details, processed_at)
                    VALUES(?,?,?,?,?,'conflict',?,?)
                """, (ph, device_uuid, event_id, event_type, json.dumps(payload), str(e), now()))
                conflicts.append({"event_id": event_id, "error": str(e)})

        if device_uuid:
            dev = c.execute("SELECT id FROM device_enrollments WHERE pharmacy_id=? AND device_uuid=?", (ph, device_uuid)).fetchone()
            if dev:
                c.execute("UPDATE device_enrollments SET last_seen=? WHERE id=?", (now(), dev["id"]))
            else:
                c.execute("INSERT INTO device_enrollments(pharmacy_id, branch_id, device_uuid, device_name, last_seen, created_at) VALUES(?,?,?,?,?,?)",
                          (ph, u.get("branch_id"), device_uuid, "Terminal PWA", now(), now()))
    return {"processed": processed_ids, "conflicts": conflicts, "server_time": now()}

def sync_pull_delta(c, u, since=None, device_uuid=None):
    need_pharmacy(c, u, "stock_view")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        drugs = list_drugs_with_stock(c, u)
        today = dt.datetime.now(TZ).date().isoformat()
        lots = [dict(r) for r in c.execute("SELECT * FROM lots WHERE pharmacy_id=? AND qty>0 AND expiry_date>=? AND status='ok'", (ph, today)).fetchall()]
        pharmacy = dict(c.execute("SELECT id, name, address, city, phone, tax_id, rccm, currency, receipt_format, footer, subscription_status, subscription_expires_at FROM pharmacies WHERE id=?", (ph,)).fetchone() or {})
        if device_uuid:
            dev = c.execute("SELECT id FROM device_enrollments WHERE pharmacy_id=? AND device_uuid=?", (ph, device_uuid)).fetchone()
            if not dev:
                c.execute("INSERT INTO device_enrollments(pharmacy_id, branch_id, device_uuid, device_name, last_seen, created_at) VALUES(?,?,?,?,?,?)",
                          (ph, u.get("branch_id"), device_uuid, "Terminal PWA", now(), now()))
            else:
                c.execute("UPDATE device_enrollments SET last_seen=? WHERE id=?", (now(), dev["id"]))
        return {"server_time": now(), "pharmacy": pharmacy, "drugs": drugs, "lots": lots}

# --- EXPORTS STRICTEMENT ISOLÉS PAR TENANT ---

def export_sales_csv(c, u):
    need_pharmacy(c, u, "exports")
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["N_Ticket", "Date_Vente", "Heure_Vente", "Employe", "Mode_Paiement", "Total_FCFA", "Recu_FCFA", "Monnaie_FCFA", "Hors_Ligne"])
    with DB_LOCK:
        for r in c.execute("SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.pharmacy_id=? ORDER BY s.id DESC", (u["pharmacy_id"],)):
            d_str, t_str, _ = format_ts_details(r["ts"])
            w.writerow([r["receipt_no"], d_str, t_str, r["cashier_name"], r["method"], r["total"], r["paid"], r["change"], "OUI" if r["is_offline"] else "NON"])
    return out.getvalue()

def export_pharmacy_backup_json(c, u):
    """Portabilité des données : permet à une pharmacie d'exporter uniquement ses propres données."""
    need_pharmacy(c, u, "pharmacy_all")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        data = {
            "exported_at": now(),
            "pharmacy": dict(c.execute("SELECT * FROM pharmacies WHERE id=?", (ph,)).fetchone() or {}),
            "drugs": [dict(r) for r in c.execute("SELECT * FROM drugs WHERE pharmacy_id=?", (ph,)).fetchall()],
            "lots": [dict(r) for r in c.execute("SELECT * FROM lots WHERE pharmacy_id=?", (ph,)).fetchall()],
            "sales": [dict(r) for r in c.execute("SELECT * FROM sales WHERE pharmacy_id=?", (ph,)).fetchall()],
            "customers": [dict(r) for r in c.execute("SELECT * FROM customers WHERE pharmacy_id=?", (ph,)).fetchall()],
            "suppliers": [dict(r) for r in c.execute("SELECT * FROM suppliers WHERE pharmacy_id=?", (ph,)).fetchall()]
        }
    audit_pharmacy(c, u, "tenant_data_export", {"tables": list(data.keys())})
    return data
