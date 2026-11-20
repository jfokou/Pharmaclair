"""PharmaClair - noyau serveur & interface officinale complète (stdlib uniquement). Lancer: python pharmaclair.py"""
import sqlite3, hashlib, secrets, json, datetime as dt, calendar, os, csv, io, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("Africa/Douala")
except Exception:
    TZ = dt.timezone(dt.timedelta(hours=1))  # Douala (WAT: UTC+1)

# Règle péremption "MM/AAAA": le lot reste vendable jusqu'au DERNIER jour du mois ("end")
# ou est bloqué dès le 1er du mois ("start"). Configurable via env.
EXPIRY_MONTH_RULE = os.environ.get("EXPIRY_MONTH_RULE", "end")

SCHEMA = """
CREATE TABLE IF NOT EXISTS pharmacies(id INTEGER PRIMARY KEY, name TEXT, address TEXT, tax_id TEXT, footer TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, pharmacy_id INT, username TEXT UNIQUE, salt TEXT, pw TEXT,
  role TEXT, active INT DEFAULT 1, can_block INT DEFAULT 0, can_cash INT DEFAULT 0, fails INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INT);
CREATE TABLE IF NOT EXISTS drugs(id INTEGER PRIMARY KEY, pharmacy_id INT, name TEXT, pack TEXT, price INT, ref TEXT, barcode TEXT);
CREATE TABLE IF NOT EXISTS lots(id INTEGER PRIMARY KEY, pharmacy_id INT, drug_id INT, lot_no TEXT, expiry TEXT, expiry_date TEXT,
  qty INT, status TEXT DEFAULT 'ok', UNIQUE(pharmacy_id,drug_id,lot_no));
CREATE TABLE IF NOT EXISTS movements(id INTEGER PRIMARY KEY, pharmacy_id INT, lot_id INT, type TEXT, qty INT, ref TEXT, user_id INT, ts TEXT);
CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY, pharmacy_id INT, user_id INT, idem TEXT, receipt_no TEXT, total INT,
  method TEXT, paid INT, change INT, snapshot TEXT, ts TEXT, UNIQUE(pharmacy_id,idem));
CREATE TABLE IF NOT EXISTS sale_lines(id INTEGER PRIMARY KEY, sale_id INT, drug_id INT, lot_id INT, qty INT, price INT, label TEXT);
CREATE TABLE IF NOT EXISTS returns(id INTEGER PRIMARY KEY, pharmacy_id INT, sale_id INT, status TEXT, reason TEXT, by_user INT, approved_by INT, ts TEXT);
CREATE TABLE IF NOT EXISTS return_lines(return_id INT, sale_line_id INT, qty INT);
CREATE TABLE IF NOT EXISTS quarantine(lot_id INT PRIMARY KEY, qty INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS cash_closings(id INTEGER PRIMARY KEY, pharmacy_id INT, user_id INT, date_str TEXT, initial_cash INT,
  counted_cash INT, theoretical_cash INT, diff_cash INT, total_om INT, total_card INT, total_day INT, ts TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, pharmacy_id INT, user_id INT, action TEXT, data TEXT, ts TEXT);
"""
PERMS = {"owner": {"*"},
         "cashier": {"sell", "stock_view", "own_sales", "return_request", "cash_count"},
         "stock": {"stock_view", "receive", "count"}}

DB_LOCK = threading.RLock()

class Denied(Exception): pass
class Conflict(Exception): pass

def now(): return dt.datetime.now(TZ).isoformat(timespec="seconds")

def connect(path=":memory:"):
    c = sqlite3.connect(path, isolation_level=None, timeout=15, check_same_thread=False)
    c.row_factory = sqlite3.Row
    with DB_LOCK:
        c.executescript(SCHEMA)
    return c

def hpw(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()

def audit(c, u, action, data):
    with DB_LOCK:
        c.execute("INSERT INTO audit(pharmacy_id,user_id,action,data,ts) VALUES(?,?,?,?,?)",
                  (u["pharmacy_id"], u["id"], action, json.dumps(data), now()))

def perms(u):
    p = set(PERMS.get(u["role"], set()))
    if u["role"] == "stock":
        if u.get("can_cash"): p |= PERMS["cashier"]
        if u.get("can_block"): p.add("block")
    return p

def need(u, p):
    if "*" not in perms(u) and p not in perms(u): raise Denied(p)

def create_user(c, owner, username, pw, role, **flags):
    need(owner, "users")
    salt = secrets.token_hex(8)
    with DB_LOCK:
        try:
            c.execute("INSERT INTO users(pharmacy_id,username,salt,pw,role,can_block,can_cash) VALUES(?,?,?,?,?,?,?)",
                      (owner["pharmacy_id"], username, salt, hpw(pw, salt), role, int(flags.get("can_block", 0)), int(flags.get("can_cash", 0))))
        except sqlite3.IntegrityError:
            raise Conflict("Ce nom d'utilisateur est déjà utilisé.")
    audit(c, owner, "user_create", {"username": username, "role": role})

def login(c, username, pw):
    with DB_LOCK:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not r or not r["active"] or r["fails"] >= 5: raise Denied("identifiants incorrects ou compte verrouillé")
        if not secrets.compare_digest(r["pw"], hpw(pw, r["salt"])):
            c.execute("UPDATE users SET fails=fails+1 WHERE id=?", (r["id"],))
            raise Denied("identifiants incorrects")
        c.execute("UPDATE users SET fails=0 WHERE id=?", (r["id"],))
        t = secrets.token_urlsafe(32)
        c.execute("INSERT INTO sessions VALUES(?,?)", (t, r["id"]))
        return t

def auth(c, token):
    if not token: raise Denied("session manquante")
    with DB_LOCK:
        r = c.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND u.active=1", (token,)).fetchone()
    if not r: raise Denied("session invalide")
    return dict(r)

def list_users(c, owner):
    need(owner, "users")
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT id, username, role, active, can_block, can_cash, fails FROM users WHERE pharmacy_id=? ORDER BY id", (owner["pharmacy_id"],)).fetchall()]

def toggle_user_active(c, owner, user_id, active_state):
    need(owner, "users")
    with DB_LOCK:
        c.execute("UPDATE users SET active=? WHERE id=? AND pharmacy_id=?", (int(active_state), user_id, owner["pharmacy_id"]))
        if not active_state:
            c.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    audit(c, owner, "user_toggle_active", {"id": user_id, "active": active_state})

def reset_user_fails(c, owner, user_id):
    need(owner, "users")
    with DB_LOCK:
        c.execute("UPDATE users SET fails=0 WHERE id=? AND pharmacy_id=?", (user_id, owner["pharmacy_id"]))
    audit(c, owner, "user_reset_fails", {"id": user_id})

def parse_expiry(s):
    s = s.strip()
    if "/" in s:
        parts = s.split("/")
        if len(parts) == 2:
            m, y = int(parts[0]), int(parts[1])
            if y < 100: y += 2000
            s = f"{y:04d}-{m:02d}"
    if len(s) == 7:  # AAAA-MM
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

def add_drug(c, u, name, pack, price, ref=None, barcode=None):
    need(u, "receive")
    with DB_LOCK:
        return c.execute("INSERT INTO drugs(pharmacy_id,name,pack,price,ref,barcode) VALUES(?,?,?,?,?,?)",
                         (u["pharmacy_id"], name, pack, price, ref, barcode)).lastrowid

def receive(c, u, drug_id, lot_no, expiry, qty, supplier="", bl=""):
    need(u, "receive")
    if qty <= 0: raise Conflict("quantité invalide (doit être > 0)")
    with DB_LOCK:
        if not c.execute("SELECT 1 FROM drugs WHERE id=? AND pharmacy_id=?", (drug_id, u["pharmacy_id"])).fetchone():
            raise Denied("médicament introuvable")
        ed = parse_expiry(expiry).isoformat()
        c.execute("BEGIN IMMEDIATE")
        try:
            l = c.execute("SELECT * FROM lots WHERE pharmacy_id=? AND drug_id=? AND lot_no=?", (u["pharmacy_id"], drug_id, lot_no)).fetchone()
            if l:
                if l["expiry_date"] != ed: raise Conflict("Lot existant avec une autre péremption: vérifier l'emballage (validation titulaire)")
                c.execute("UPDATE lots SET qty=qty+? WHERE id=?", (qty, l["id"]))
                lid = l["id"]
            else:
                lid = c.execute("INSERT INTO lots(pharmacy_id,drug_id,lot_no,expiry,expiry_date,qty) VALUES(?,?,?,?,?,?)",
                                (u["pharmacy_id"], drug_id, lot_no, expiry, ed, qty)).lastrowid
            c.execute("INSERT INTO movements(pharmacy_id,lot_id,type,qty,ref,user_id,ts) VALUES(?,?,?,?,?,?,?)",
                      (u["pharmacy_id"], lid, "reception", qty, f"{supplier}|{bl}", u["id"], now()))
            c.execute("COMMIT")
            return lid
        except Exception:
            c.execute("ROLLBACK")
            raise

def block_lot(c, u, lot_id, status="blocked"):
    need(u, "block")
    with DB_LOCK:
        c.execute("UPDATE lots SET status=? WHERE id=? AND pharmacy_id=?", (status, lot_id, u["pharmacy_id"]))
        c.execute("INSERT INTO movements(pharmacy_id,lot_id,type,qty,ref,user_id,ts) VALUES(?,?,?,?,?,?,?)",
                  (u["pharmacy_id"], lot_id, "status:" + status, 0, "", u["id"], now()))
    audit(c, u, "lot_status", {"lot": lot_id, "status": status})

def _sellable_lots(c, ph, drug_id):
    today = dt.datetime.now(TZ).date().isoformat()
    return c.execute("SELECT * FROM lots WHERE pharmacy_id=? AND drug_id=? AND status='ok' AND qty>0 AND expiry_date>=? ORDER BY expiry_date,id",
                     (ph, drug_id, today)).fetchall()

def stock(c, u, drug_id):
    need(u, "stock_view")
    with DB_LOCK:
        phys = c.execute("SELECT COALESCE(SUM(qty),0) FROM lots WHERE pharmacy_id=? AND drug_id=?", (u["pharmacy_id"], drug_id)).fetchone()[0]
        lots = _sellable_lots(c, u["pharmacy_id"], drug_id)
        all_lots = c.execute("SELECT * FROM lots WHERE pharmacy_id=? AND drug_id=? ORDER BY expiry_date,id", (u["pharmacy_id"], drug_id)).fetchall()
        return {
            "physical": phys,
            "sellable": sum(l["qty"] for l in lots),
            "lots": [{"id": l["id"], "lot_no": l["lot_no"], "expiry": l["expiry"], "expiry_date": l["expiry_date"], "qty": l["qty"], "status": l["status"]} for l in all_lots]
        }

def list_drugs_with_stock(c, u):
    need(u, "stock_view")
    with DB_LOCK:
        today = dt.datetime.now(TZ).date().isoformat()
        drugs = c.execute("SELECT * FROM drugs WHERE pharmacy_id=? ORDER BY name", (u["pharmacy_id"],)).fetchall()
        result = []
        for d in drugs:
            phys = c.execute("SELECT COALESCE(SUM(qty),0) FROM lots WHERE pharmacy_id=? AND drug_id=?", (u["pharmacy_id"], d["id"])).fetchone()[0]
            sellable_lots = _sellable_lots(c, u["pharmacy_id"], d["id"])
            sellable = sum(l["qty"] for l in sellable_lots)
            next_lot = sellable_lots[0] if sellable_lots else None
            result.append({
                "id": d["id"], "name": d["name"], "pack": d["pack"], "price": d["price"],
                "ref": d["ref"], "barcode": d["barcode"], "physical": phys, "sellable": sellable,
                "next_expiry": next_lot["expiry"] if next_lot else None,
                "next_expiry_date": next_lot["expiry_date"] if next_lot else None,
                "next_lot_no": next_lot["lot_no"] if next_lot else None
            })
        return result

def sell(c, u, idem, items, method, paid=None):
    need(u, "sell"); ph = u["pharmacy_id"]
    with DB_LOCK:
        c.execute("BEGIN IMMEDIATE")
        try:
            old = c.execute("SELECT id FROM sales WHERE pharmacy_id=? AND idem=?", (ph, idem)).fetchone()
            if old:
                c.execute("COMMIT")
                return old["id"]
            lines, total = [], 0
            for drug_id, qty in items:
                d = c.execute("SELECT * FROM drugs WHERE id=? AND pharmacy_id=?", (drug_id, ph)).fetchone()
                if not d: raise Denied("médicament introuvable")
                left = qty
                for l in _sellable_lots(c, ph, drug_id):
                    take = min(left, l["qty"]); left -= take
                    label = f"{d['name']} {d['pack']} (Lot: {l['lot_no']} - Exp: {l['expiry']})"
                    lines.append((drug_id, l["id"], take, d["price"], label))
                    if not left: break
                if left: raise Conflict(f"Stock insuffisant pour « {d['name']} »: manque {left}")
                total += qty * d["price"]
            if method == "cash":
                if paid is None or paid < total: raise Conflict(f"Montant remis ({paid or 0} FCFA) inférieur au total ({total} FCFA)")
            else:
                paid = total
            p = c.execute("SELECT * FROM pharmacies WHERE id=?", (ph,)).fetchone()
            snap = json.dumps({"pharmacy": dict(p) if p else {"name": "Pharmacie"}, "cashier": u["username"]})
            cur_ts = now()
            sid = c.execute("INSERT INTO sales(pharmacy_id,user_id,idem,total,method,paid,change,snapshot,ts) VALUES(?,?,?,?,?,?,?,?,?)",
                            (ph, u["id"], idem, total, method, paid, paid - total, snap, cur_ts)).lastrowid
            c.execute("UPDATE sales SET receipt_no=? WHERE id=?", (f"R{ph}-{sid:06d}", sid))
            for d_id, lot_id, q, pr, lab in lines:
                c.execute("INSERT INTO sale_lines(sale_id,drug_id,lot_id,qty,price,label) VALUES(?,?,?,?,?,?)", (sid, d_id, lot_id, q, pr, lab))
                c.execute("UPDATE lots SET qty=qty-? WHERE id=?", (q, lot_id))
                c.execute("INSERT INTO movements(pharmacy_id,lot_id,type,qty,ref,user_id,ts) VALUES(?,?,?,?,?,?,?)",
                          (ph, lot_id, "sale", -q, str(sid), u["id"], cur_ts))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    audit(c, u, "sale", {"id": sid, "total": total})
    return sid

def receipt(c, u, sale_id, reprint=False):
    with DB_LOCK:
        s = c.execute("SELECT * FROM sales WHERE id=? AND pharmacy_id=?", (sale_id, u["pharmacy_id"])).fetchone()
        if not s: raise Denied("introuvable")
        if "*" not in perms(u) and s["user_id"] != u["id"]: raise Denied("own_sales")
        if u["role"] != "owner": need(u, "own_sales")
        ls = [dict(r) for r in c.execute("SELECT id,label,qty,price FROM sale_lines WHERE sale_id=?", (sale_id,))]
        snap = json.loads(s["snapshot"])
        date_str, time_str, full_str = format_ts_details(s["ts"])
        return {
            "id": s["id"],
            "no": s["receipt_no"],
            "raw_ts": s["ts"],
            "date": date_str,
            "time": time_str,
            "full_time": full_str,
            "duplicata": bool(reprint),
            "pharmacy": snap["pharmacy"],
            "cashier": snap["cashier"],
            "lines": ls,
            "total": s["total"],
            "method": s["method"],
            "paid": s["paid"],
            "change": s["change"],
            "currency": "FCFA"
        }

def request_return(c, u, sale_id, lines, reason):
    need(u, "return_request")
    with DB_LOCK:
        s = c.execute("SELECT * FROM sales WHERE id=? AND pharmacy_id=?", (sale_id, u["pharmacy_id"])).fetchone()
        if not s: raise Denied("vente introuvable")
        rid = c.execute("INSERT INTO returns(pharmacy_id,sale_id,status,reason,by_user,ts) VALUES(?,?,?,?,?,?)",
                        (u["pharmacy_id"], sale_id, "pending", reason, u["id"], now())).lastrowid
        for sl, q in lines: c.execute("INSERT INTO return_lines VALUES(?,?,?)", (rid, sl, q))
        return rid

def approve_return(c, owner, rid):
    need(owner, "returns_approve")
    with DB_LOCK:
        r = c.execute("SELECT * FROM returns WHERE id=? AND pharmacy_id=? AND status='pending'", (rid, owner["pharmacy_id"])).fetchone()
        if not r: raise Denied("retour introuvable")
        c.execute("BEGIN IMMEDIATE")
        try:
            for rl in c.execute("SELECT * FROM return_lines WHERE return_id=?", (rid,)).fetchall():
                sl = c.execute("SELECT * FROM sale_lines WHERE id=? AND sale_id=?", (rl["sale_line_id"], r["sale_id"])).fetchone()
                done = c.execute("SELECT COALESCE(SUM(rl.qty),0) FROM return_lines rl JOIN returns r ON r.id=rl.return_id WHERE rl.sale_line_id=? AND r.status='approved'", (sl["id"],)).fetchone()[0]
                if done + rl["qty"] > sl["qty"]: raise Conflict("Retour supérieur aux quantités vendues")
                c.execute("INSERT INTO quarantine(lot_id,qty) VALUES(?,?) ON CONFLICT(lot_id) DO UPDATE SET qty=qty+?", (sl["lot_id"], rl["qty"], rl["qty"]))
                c.execute("INSERT INTO movements(pharmacy_id,lot_id,type,qty,ref,user_id,ts) VALUES(?,?,?,?,?,?,?)",
                          (owner["pharmacy_id"], sl["lot_id"], "return_quarantine", rl["qty"], str(rid), owner["id"], now()))
            c.execute("UPDATE returns SET status='approved',approved_by=? WHERE id=?", (owner["id"], rid))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    audit(c, owner, "return_approved", {"id": rid})

def list_returns(c, u):
    with DB_LOCK:
        q = """
            SELECT r.*, s.receipt_no, u.username as requester_name, ap.username as approver_name
            FROM returns r
            JOIN sales s ON s.id=r.sale_id
            JOIN users u ON u.id=r.by_user
            LEFT JOIN users ap ON ap.id=r.approved_by
            WHERE r.pharmacy_id=?
            ORDER BY r.id DESC
        """
        rows = c.execute(q, (u["pharmacy_id"],)).fetchall()
        return [dict(r) for r in rows]

def sales_list(c, u):
    with DB_LOCK:
        if "*" in perms(u):
            q, a = "SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.pharmacy_id=? ORDER BY s.id DESC", (u["pharmacy_id"],)
        else:
            need(u, "own_sales")
            q, a = "SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.pharmacy_id=? AND s.user_id=? ORDER BY s.id DESC", (u["pharmacy_id"], u["id"])
        
        rows = c.execute(q, a).fetchall()
        res = []
        for r in rows:
            d_str, t_str, f_str = format_ts_details(r["ts"])
            res.append({
                "id": r["id"],
                "receipt_no": r["receipt_no"],
                "total": r["total"],
                "method": r["method"],
                "paid": r["paid"],
                "change": r["change"],
                "ts": r["ts"],
                "date": d_str,
                "time": t_str,
                "full_time": f_str,
                "cashier_name": r["cashier_name"]
            })
        return res

def perform_cash_closing(c, u, initial_cash, counted_cash):
    need(u, "cash_count")
    with DB_LOCK:
        ph = u["pharmacy_id"]
        today_date = dt.datetime.now(TZ).date().isoformat()
        
        sales_today = c.execute("""
            SELECT method, total FROM sales WHERE pharmacy_id=? AND ts LIKE ?
        """, (ph, f"{today_date}%")).fetchall()
        
        total_cash = sum(s["total"] for s in sales_today if s["method"] == "cash")
        total_om = sum(s["total"] for s in sales_today if s["method"] == "om")
        total_card = sum(s["total"] for s in sales_today if s["method"] == "card")
        total_day = total_cash + total_om + total_card
        
        theoretical_cash = initial_cash + total_cash
        diff_cash = counted_cash - theoretical_cash
        
        cid = c.execute("""
            INSERT INTO cash_closings(pharmacy_id, user_id, date_str, initial_cash, counted_cash,
              theoretical_cash, diff_cash, total_om, total_card, total_day, ts)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """, (ph, u["id"], today_date, initial_cash, counted_cash, theoretical_cash, diff_cash, total_om, total_card, total_day, now())).lastrowid
        
        audit(c, u, "cash_closing", {"closing_id": cid, "diff": diff_cash, "total_day": total_day})
        return {
            "closing_id": cid,
            "date": dt.datetime.now(TZ).strftime("%d/%m/%Y"),
            "initial_cash": initial_cash,
            "total_cash": total_cash,
            "theoretical_cash": theoretical_cash,
            "counted_cash": counted_cash,
            "diff_cash": diff_cash,
            "total_om": total_om,
            "total_card": total_card,
            "total_day": total_day,
            "cashier": u["username"]
        }

def owner_dashboard_stats(c, u):
    if u["role"] != "owner":
        raise Denied("Accès réservé au Titulaire / Propriétaire")
    with DB_LOCK:
        ph = u["pharmacy_id"]
        today_date = dt.datetime.now(TZ).date().isoformat()
        
        sales_today = c.execute("""
            SELECT s.*, u.username as cashier_name
            FROM sales s
            JOIN users u ON u.id=s.user_id
            WHERE s.pharmacy_id=? AND s.ts LIKE ?
            ORDER BY s.id DESC
        """, (ph, f"{today_date}%")).fetchall()
        
        total_revenue_today = sum(s["total"] for s in sales_today)
        count_sales_today = len(sales_today)
        avg_basket_today = int(total_revenue_today / count_sales_today) if count_sales_today > 0 else 0
        
        pay_methods = {"cash": 0, "om": 0, "card": 0}
        for s in sales_today:
            m = s["method"]
            pay_methods[m] = pay_methods.get(m, 0) + s["total"]
            
        users = c.execute("SELECT id, username, role, active, fails FROM users WHERE pharmacy_id=?", (ph,)).fetchall()
        employee_stats = []
        for emp in users:
            emp_sales_today = [s for s in sales_today if s["user_id"] == emp["id"]]
            emp_sales_all = c.execute("SELECT total FROM sales WHERE pharmacy_id=? AND user_id=?", (ph, emp["id"])).fetchall()
            
            tot_emp_today = sum(s["total"] for s in emp_sales_today)
            cnt_emp_today = len(emp_sales_today)
            tot_emp_all = sum(s["total"] for s in emp_sales_all)
            cnt_emp_all = len(emp_sales_all)
            
            last_sale = c.execute("SELECT ts FROM sales WHERE pharmacy_id=? AND user_id=? ORDER BY id DESC LIMIT 1", (ph, emp["id"])).fetchone()
            last_ts_str = format_ts_details(last_sale["ts"])[2] if last_sale else "Aucune"
            
            employee_stats.append({
                "id": emp["id"],
                "username": emp["username"],
                "role": emp["role"],
                "active": emp["active"],
                "fails": emp["fails"],
                "sales_today_count": cnt_emp_today,
                "sales_today_amount": tot_emp_today,
                "sales_all_count": cnt_emp_all,
                "sales_all_amount": tot_emp_all,
                "last_sale_ts": last_ts_str
            })
            
        recent_sales = []
        for s in sales_today[:15]:
            d_str, t_str, f_str = format_ts_details(s["ts"])
            recent_sales.append({
                "id": s["id"],
                "receipt_no": s["receipt_no"],
                "cashier": s["cashier_name"],
                "total": s["total"],
                "method": s["method"],
                "time": t_str,
                "date": d_str,
                "full_time": f_str
            })
            
        six_months_date = (dt.datetime.now(TZ).date() + dt.timedelta(days=180)).isoformat()
        expiring = c.execute("""
            SELECT l.*, d.name as drug_name, d.pack as drug_pack
            FROM lots l
            JOIN drugs d ON d.id=l.drug_id
            WHERE l.pharmacy_id=? AND l.qty>0 AND l.status='ok' AND l.expiry_date<=?
            ORDER BY l.expiry_date ASC
        """, (ph, six_months_date)).fetchall()
        
        # Quarantaine
        quarantine_items = c.execute("""
            SELECT q.qty, l.lot_no, l.expiry, d.name as drug_name, d.pack as drug_pack
            FROM quarantine q
            JOIN lots l ON l.id=q.lot_id
            JOIN drugs d ON d.id=l.drug_id
            WHERE q.qty>0
        """).fetchall()
        
        return {
            "today_date": dt.datetime.now(TZ).strftime("%d/%m/%Y"),
            "total_revenue_today": total_revenue_today,
            "count_sales_today": count_sales_today,
            "avg_basket_today": avg_basket_today,
            "payment_methods": pay_methods,
            "employees": employee_stats,
            "recent_sales": recent_sales,
            "expiring_count": len(expiring),
            "expiring_lots": [dict(r) for r in expiring],
            "quarantine_items": [dict(r) for r in quarantine_items]
        }

def export_sales_csv(c, u):
    need(u, "exports")
    out = io.StringIO(); w = csv.writer(out); w.writerow(["N_Ticket", "Date_Vente", "Heure_Vente", "Employe", "Mode_Paiement", "Total_FCFA", "Recu_FCFA", "Monnaie_FCFA"])
    with DB_LOCK:
        for r in c.execute("SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.pharmacy_id=? ORDER BY s.id DESC", (u["pharmacy_id"],)):
            d_str, t_str, _ = format_ts_details(r["ts"])
            w.writerow([r["receipt_no"], d_str, t_str, r["cashier_name"], r["method"], r["total"], r["paid"], r["change"]])
    return out.getvalue()

def seed_demo_data(c):
    with DB_LOCK:
        p = c.execute("SELECT id FROM pharmacies LIMIT 1").fetchone()
        if not p:
            pid = c.execute("INSERT INTO pharmacies(name, address, tax_id, footer) VALUES(?,?,?,?)",
                            ("Grande Pharmacie du Centre", "Avenue de la Liberté, Douala", "M051812345678X", "Ouvert 7j/7 - 24h/24 • Tél: +237 233 42 00 00")).lastrowid
        else:
            pid = p["id"]

        u = c.execute("SELECT id FROM users WHERE username='titulaire'").fetchone()
        if not u:
            salt = secrets.token_hex(8)
            c.execute("INSERT INTO users(pharmacy_id,username,salt,pw,role,can_block,can_cash) VALUES(?,?,?,?,?,?,?)",
                      (pid, "titulaire", salt, hpw("admin123", salt), "owner", 1, 1))

        c1 = c.execute("SELECT id FROM users WHERE username='caissier1'").fetchone()
        if not c1:
            salt = secrets.token_hex(8)
            c.execute("INSERT INTO users(pharmacy_id,username,salt,pw,role,can_block,can_cash) VALUES(?,?,?,?,?,?,?)",
                      (pid, "caissier1", salt, hpw("caisse123", salt), "cashier", 0, 1))

        c2 = c.execute("SELECT id FROM users WHERE username='caissier2'").fetchone()
        if not c2:
            salt = secrets.token_hex(8)
            c.execute("INSERT INTO users(pharmacy_id,username,salt,pw,role,can_block,can_cash) VALUES(?,?,?,?,?,?,?)",
                      (pid, "caissier2", salt, hpw("caisse123", salt), "cashier", 0, 1))

        s1 = c.execute("SELECT id FROM users WHERE username='magasinier'").fetchone()
        if not s1:
            salt = secrets.token_hex(8)
            c.execute("INSERT INTO users(pharmacy_id,username,salt,pw,role,can_block,can_cash) VALUES(?,?,?,?,?,?,?)",
                      (pid, "magasinier", salt, hpw("stock123", salt), "stock", 1, 1))

        if c.execute("SELECT COUNT(*) FROM drugs WHERE pharmacy_id=?", (pid,)).fetchone()[0] == 0:
            catalog = [
                ("Paracétamol 500mg", "Boîte 16 comprimés", 650, "PAR-500", "8901001"),
                ("Amoxicilline 500mg", "Boîte 24 gélules", 2500, "AMX-500", "8901002"),
                ("Ibuprofène 400mg", "Boîte 20 comprimés", 1800, "IBU-400", "8901003"),
                ("Sérum Physiologique 0.9%", "Flacon 500ml", 950, "SER-500", "8901004"),
                ("Vitamine C 1000mg", "Tube 20 cp effervescents", 1500, "VIT-1000", "8901005"),
                ("Artéméther/Luméfantrine 20/120mg", "Boîte 24 comprimés", 3200, "ACT-120", "8901006"),
                ("Oméprazole 20mg", "Boîte 28 gélules", 2800, "OME-020", "8901007"),
                ("Azithromycine 500mg", "Boîte 3 comprimés", 3500, "AZI-500", "8901008"),
            ]
            d_ids = []
            for name, pack, price, ref, bc in catalog:
                did = c.execute("INSERT INTO drugs(pharmacy_id,name,pack,price,ref,barcode) VALUES(?,?,?,?,?,?)",
                                (pid, name, pack, price, ref, bc)).lastrowid
                d_ids.append((did, name))

            lots_seed = [
                (d_ids[0][0], "LOT-24A01", "2027-04", 45),
                (d_ids[0][0], "LOT-24B12", "2027-10", 80),
                (d_ids[1][0], "LOT-24C08", "2027-02", 20),
                (d_ids[1][0], "LOT-24H15", "2027-12", 50),
                (d_ids[2][0], "LOT-23K99", "2027-06", 35),
                (d_ids[3][0], "LOT-24S01", "2028-01", 100),
                (d_ids[4][0], "LOT-24V05", "2027-08", 60),
                (d_ids[5][0], "LOT-24M02", "2027-05", 40),
                (d_ids[6][0], "LOT-24O19", "2027-09", 25),
                (d_ids[7][0], "LOT-24Z03", "2027-03", 18),
            ]
            for did, lot_no, exp, q in lots_seed:
                ed = parse_expiry(exp).isoformat()
                c.execute("INSERT INTO lots(pharmacy_id,drug_id,lot_no,expiry,expiry_date,qty) VALUES(?,?,?,?,?,?)",
                          (pid, did, lot_no, exp, ed, q))

        if c.execute("SELECT COUNT(*) FROM sales WHERE pharmacy_id=?", (pid,)).fetchone()[0] == 0:
            c1_user = c.execute("SELECT * FROM users WHERE username='caissier1'").fetchone()
            c2_user = c.execute("SELECT * FROM users WHERE username='caissier2'").fetchone()
            owner_u = c.execute("SELECT * FROM users WHERE username='titulaire'").fetchone()
            drugs = c.execute("SELECT * FROM drugs WHERE pharmacy_id=?", (pid,)).fetchall()
            
            if c1_user and drugs:
                sell(c, dict(c1_user), "seed-sale-1", [(drugs[0]["id"], 2), (drugs[4]["id"], 1)], "cash", 3000)
                sell(c, dict(c1_user), "seed-sale-2", [(drugs[1]["id"], 1)], "om", 2500)
            if c2_user and len(drugs) >= 6:
                sell(c, dict(c2_user), "seed-sale-3", [(drugs[2]["id"], 1), (drugs[3]["id"], 1)], "cash", 3000)
            if owner_u and len(drugs) >= 6:
                sell(c, dict(owner_u), "seed-sale-4", [(drugs[5]["id"], 2)], "card", 6400)

HTML_PAGE = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PharmaClair - Système Officinal & Direction</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #059669;
      --primary-dark: #047857;
      --primary-light: #ecfdf5;
      --secondary: #0284c7;
      --secondary-light: #f0f9ff;
      --accent: #d97706;
      --accent-light: #fef3c7;
      --danger: #ef4444;
      --danger-light: #fee2e2;
      --bg: #f8fafc;
      --card: #ffffff;
      --text: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --shadow: 0 4px 6px -1px rgb(0 0 0 / 0.07), 0 2px 4px -2px rgb(0 0 0 / 0.05);
      --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', -apple-system, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
    
    header {
      background: #ffffff;
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .brand { display: flex; align-items: center; gap: 0.75rem; }
    .brand-logo {
      width: 40px; height: 40px;
      background: linear-gradient(135deg, #059669 0%, #047857 100%);
      color: white; border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-weight: 800; font-size: 1.35rem;
      box-shadow: 0 4px 6px rgba(5,150,105,0.25);
    }
    .brand-title { font-weight: 700; font-size: 1.25rem; color: #0f172a; letter-spacing: -0.02em; }
    .brand-sub { font-size: 0.78rem; color: var(--text-muted); }
    .user-pill {
      display: flex; align-items: center; gap: 0.75rem;
      background: var(--primary-light); padding: 0.35rem 0.85rem;
      border-radius: 9999px; font-size: 0.85rem; font-weight: 600;
      color: var(--primary-dark); border: 1px solid rgba(5,150,105,0.2);
    }
    
    .app-container { display: flex; flex: 1; height: calc(100vh - 65px); overflow: hidden; }
    .nav-bar {
      width: 250px; background: #ffffff; border-right: 1px solid var(--border);
      padding: 1.25rem 0.75rem; display: flex; flex-direction: column; gap: 0.4rem;
    }
    .nav-btn {
      display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1rem;
      border: none; background: transparent; border-radius: 8px;
      color: var(--text-muted); font-size: 0.95rem; font-weight: 500;
      cursor: pointer; text-align: left; transition: all 0.15s ease;
    }
    .nav-btn:hover { background: #f1f5f9; color: var(--text); }
    .nav-btn.active { background: var(--primary-light); color: var(--primary-dark); font-weight: 600; }
    .nav-btn.owner-btn { border-left: 3px solid var(--secondary); }
    .nav-btn.owner-btn.active { background: var(--secondary-light); color: var(--secondary); font-weight: 600; }
    
    .content-area { flex: 1; padding: 1.5rem; overflow-y: auto; }

    .card {
      background: var(--card); border: 1px solid var(--border);
      border-radius: 12px; padding: 1.5rem; box-shadow: var(--shadow);
      margin-bottom: 1.5rem;
    }
    .card-title {
      font-size: 1.15rem; font-weight: 700; margin-bottom: 1.2rem;
      display: flex; align-items: center; justify-content: space-between;
      color: #1e293b;
    }

    .kpi-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem; margin-bottom: 1.5rem;
    }
    .kpi-card {
      background: white; border: 1px solid var(--border);
      border-radius: 12px; padding: 1.25rem; box-shadow: var(--shadow);
      position: relative; overflow: hidden;
    }
    .kpi-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: var(--primary); }
    .kpi-card.secondary::before { background: var(--secondary); }
    .kpi-card.accent::before { background: var(--accent); }
    .kpi-card.danger::before { background: var(--danger); }
    .kpi-label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); font-weight: 600; }
    .kpi-val { font-size: 1.65rem; font-weight: 800; color: #0f172a; margin-top: 0.35rem; }
    .kpi-sub { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; }

    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th { background: #f8fafc; text-align: left; padding: 0.75rem 1rem; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); }
    td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:hover td { background: #fbfcfe; }
    
    .badge {
      display: inline-flex; align-items: center; gap: 0.25rem;
      padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600;
    }
    .badge-success { background: #dcfce7; color: #166534; }
    .badge-warning { background: var(--accent-light); color: #92400e; }
    .badge-danger { background: var(--danger-light); color: #991b1b; }
    .badge-info { background: var(--secondary-light); color: #075985; }

    .expiry-tag {
      display: inline-flex; align-items: center; gap: 0.25rem;
      padding: 0.2rem 0.5rem; background: #f1f5f9; border: 1px solid #cbd5e1;
      border-radius: 6px; font-size: 0.75rem; font-weight: 600; color: #334155;
    }

    .pos-grid { display: grid; grid-template-columns: 1fr 390px; gap: 1.5rem; height: 100%; }
    .catalog-search { margin-bottom: 1rem; display: flex; gap: 0.5rem; }
    input, select, button { font-size: 0.9rem; border-radius: 8px; }
    input, select {
      border: 1px solid var(--border); padding: 0.6rem 0.85rem; width: 100%; outline: none; transition: border 0.15s;
    }
    input:focus, select:focus {
      border-color: var(--primary); box-shadow: 0 0 0 3px rgba(5, 150, 105, 0.15);
    }
    .btn {
      border: none; padding: 0.65rem 1.1rem; font-weight: 600; cursor: pointer;
      border-radius: 8px; display: inline-flex; align-items: center; justify-content: center;
      gap: 0.5rem; transition: all 0.15s ease;
    }
    .btn-primary { background: var(--primary); color: white; }
    .btn-primary:hover { background: var(--primary-dark); }
    .btn-secondary { background: #e2e8f0; color: #334155; }
    .btn-secondary:hover { background: #cbd5e1; }
    .btn-danger { background: var(--danger); color: white; }
    .btn-danger:hover { background: #dc2626; }
    .btn-sm { padding: 0.35rem 0.65rem; font-size: 0.8rem; }
    
    .cart-box { display: flex; flex-direction: column; height: 100%; }
    .cart-items {
      flex: 1; overflow-y: auto; border: 1px solid var(--border);
      border-radius: 8px; margin-bottom: 1rem; padding: 0.5rem; min-height: 200px; background: #fafafa;
    }
    .cart-item {
      display: flex; justify-content: space-between; align-items: center;
      padding: 0.6rem 0.75rem; background: white; border: 1px solid var(--border);
      border-radius: 6px; margin-bottom: 0.4rem;
    }
    .cart-summary {
      background: #f8fafc; padding: 1rem; border-radius: 8px;
      border: 1px solid var(--border); display: flex; flex-direction: column; gap: 0.65rem;
    }
    .cart-summary-line { display: flex; justify-content: space-between; font-size: 0.9rem; }
    .cart-summary-line.total {
      font-size: 1.35rem; font-weight: 800; color: var(--primary-dark);
      border-top: 2px dashed var(--border); padding-top: 0.5rem;
    }

    .modal-overlay {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(15, 23, 42, 0.6); display: flex; align-items: center;
      justify-content: center; z-index: 1000; backdrop-filter: blur(2px);
    }
    .receipt-paper {
      background: white; width: 380px; max-width: 92vw; border-radius: 12px;
      padding: 1.75rem; box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.25);
      font-family: 'Courier New', Courier, monospace; font-size: 0.85rem; line-height: 1.4; color: #111;
    }

    .login-container {
      max-width: 440px; margin: 4rem auto; background: white; padding: 2.25rem;
      border-radius: 16px; box-shadow: var(--shadow-lg); border: 1px solid var(--border);
    }
    .demo-accounts {
      margin-top: 1.25rem; background: #f8fafc; padding: 0.85rem; border-radius: 8px; font-size: 0.8rem;
    }
    .demo-pill {
      cursor: pointer; display: inline-block; margin: 0.25rem; padding: 0.35rem 0.6rem;
      background: #e2e8f0; border-radius: 6px; font-weight: 600; transition: all 0.15s;
    }
    .demo-pill:hover { background: #cbd5e1; transform: translateY(-1px); }

    /* Impression format Ticket 80mm Thermique */
    @media print {
      body * { visibility: hidden; }
      .modal-overlay { position: static; background: transparent; backdrop-filter: none; }
      #receipt-modal, #receipt-modal .receipt-paper, #receipt-modal .receipt-paper * { visibility: visible; }
      #receipt-modal .receipt-paper {
        position: absolute; left: 0; top: 0; width: 80mm; max-width: 80mm;
        padding: 4mm; box-shadow: none; border-radius: 0;
      }
      .no-print { display: none !important; }
    }
  </style>
</head>
<body>

  <!-- En-tête -->
  <header>
    <div class="brand">
      <div class="brand-logo">℞</div>
      <div>
        <div class="brand-title">PharmaClair</div>
        <div class="brand-sub" id="pharmacy-name">Grande Pharmacie du Centre • Douala (Cameroun)</div>
      </div>
    </div>
    <div id="header-user" style="display: none;" class="user-pill">
      <span id="user-display">👤 Titulaire (Direction)</span>
      <button class="btn btn-secondary btn-sm" onclick="showCashClosingModal()">💰 Z de Caisse</button>
      <button class="btn btn-secondary btn-sm" onclick="logout()">Déconnexion</button>
    </div>
  </header>

  <!-- Login Screen -->
  <div id="login-view" class="login-container">
    <div style="text-align: center; margin-bottom: 1.5rem;">
      <div class="brand-logo" style="margin: 0 auto 0.75rem auto; width: 50px; height: 50px; font-size: 1.5rem;">℞</div>
      <h2>PharmaClair</h2>
      <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.25rem;">Authentification Officine Sécurisée</p>
    </div>
    <form onsubmit="handleLogin(event)">
      <div style="margin-bottom: 1rem;">
        <label style="display:block; font-size: 0.85rem; font-weight:600; margin-bottom: 0.35rem;">Nom d'utilisateur</label>
        <input type="text" id="login-username" required placeholder="ex: titulaire">
      </div>
      <div style="margin-bottom: 1.25rem;">
        <label style="display:block; font-size: 0.85rem; font-weight:600; margin-bottom: 0.35rem;">Mot de passe</label>
        <input type="password" id="login-password" required placeholder="••••••••">
      </div>
      <button type="submit" class="btn btn-primary" style="width: 100%;">Se connecter</button>
      <div id="login-error" style="color: var(--danger); font-size: 0.85rem; margin-top: 0.75rem; text-align: center; display: none;"></div>
    </form>

    <div class="demo-accounts">
      <strong>Comptes disponibles (cliquer pour remplir) :</strong><br>
      <span class="demo-pill" onclick="fillDemo('titulaire', 'admin123')">👑 Titulaire (Direction)</span>
      <span class="demo-pill" onclick="fillDemo('caissier1', 'caisse123')">💵 Caissier 1</span>
      <span class="demo-pill" onclick="fillDemo('caissier2', 'caisse123')">💵 Caissier 2</span>
      <span class="demo-pill" onclick="fillDemo('magasinier', 'stock123')">📦 Magasinier</span>
    </div>
  </div>

  <!-- Main App Layout -->
  <div id="main-view" class="app-container" style="display: none;">
    <nav class="nav-bar">
      <button id="nav-btn-owner" class="nav-btn owner-btn" onclick="switchTab('owner')">👑 Direction & Stats</button>
      <button id="nav-btn-users" class="nav-btn owner-btn" onclick="switchTab('users')">👥 Gestion Personnel</button>
      <button id="nav-btn-pos" class="nav-btn active" onclick="switchTab('pos')">🛒 Caisse / Vente (POS)</button>
      <button id="nav-btn-stock" class="nav-btn" onclick="switchTab('stock')">📦 Stocks & Péremptions</button>
      <button id="nav-btn-sales" class="nav-btn" onclick="switchTab('sales')">📋 Journal des Ventes</button>
      
      <div style="margin-top: auto; padding: 0.75rem; background: #f8fafc; border-radius: 8px; font-size: 0.75rem; color: var(--text-muted); border: 1px solid var(--border);">
        <strong>Règles Métier Actives :</strong><br>
        • Déstockage : <b>FEFO strict</b><br>
        • Péremption : Fin de mois (end)<br>
        • Fuseau : Douala (GMT+1)<br>
        • Devise : FCFA
      </div>
    </nav>

    <!-- Zone de contenu -->
    <main class="content-area">

      <!-- ============================================== -->
      <!-- TAB OWNER: Tableau de bord du Propriétaire       -->
      <!-- ============================================== -->
      <section id="tab-owner" class="tab-content" style="display: none;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
          <div>
            <h2>📊 Tableau de Bord de la Direction</h2>
            <p style="color: var(--text-muted); font-size: 0.85rem;">Suivi en direct des ventes journalières et performance des employés</p>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="loadOwnerDashboard()">🔄 Actualiser les chiffres</button>
        </div>

        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">Ventes Journalières</div>
            <div class="kpi-val" id="kpi-today-revenue">0 FCFA</div>
            <div class="kpi-sub">Total encaissé aujourd'hui</div>
          </div>
          <div class="kpi-card secondary">
            <div class="kpi-label">Transactions du Jour</div>
            <div class="kpi-val" id="kpi-today-count">0</div>
            <div class="kpi-sub">Tickets émis aujourd'hui</div>
          </div>
          <div class="kpi-card accent">
            <div class="kpi-label">Panier Moyen</div>
            <div class="kpi-val" id="kpi-today-basket">0 FCFA</div>
            <div class="kpi-sub">Montant moyen par vente</div>
          </div>
          <div class="kpi-card danger">
            <div class="kpi-label">Lots à Risque (≤ 6 mois)</div>
            <div class="kpi-val" id="kpi-expiring-count">0</div>
            <div class="kpi-sub">Péremptions à écouler</div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            <span>💳 Répartition des Encaissements du Jour</span>
            <span style="font-size: 0.8rem; font-weight: normal; color: var(--text-muted);" id="owner-today-date"></span>
          </div>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
            <div style="padding: 1rem; background: #ecfdf5; border-radius: 8px; border: 1px solid #a7f3d0;">
              <span style="font-size: 0.8rem; color: #047857; font-weight: 600;">💵 ESPÈCES</span>
              <div style="font-size: 1.3rem; font-weight: 800; color: #065f46;" id="pay-cash">0 FCFA</div>
            </div>
            <div style="padding: 1rem; background: #fff7ed; border-radius: 8px; border: 1px solid #fed7aa;">
              <span style="font-size: 0.8rem; color: #c2410c; font-weight: 600;">📱 ORANGE MONEY / MoMo</span>
              <div style="font-size: 1.3rem; font-weight: 800; color: #9a3412;" id="pay-om">0 FCFA</div>
            </div>
            <div style="padding: 1rem; background: #f0f9ff; border-radius: 8px; border: 1px solid #bae6fd;">
              <span style="font-size: 0.8rem; color: #0369a1; font-weight: 600;">💳 CARTE BANCAIRE</span>
              <div style="font-size: 1.3rem; font-weight: 800; color: #075985;" id="pay-card">0 FCFA</div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            <span>👥 Performance des Employés & Caissiers (Ventes Journalières)</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Employé</th>
                <th>Rôle</th>
                <th>Ventes du Jour (Total)</th>
                <th>Nombre de Ventes (Jour)</th>
                <th>Ventes Cumulées (Historique)</th>
                <th>Dernière Vente</th>
              </tr>
            </thead>
            <tbody id="owner-employee-rows"></tbody>
          </table>
        </div>

        <div class="card">
          <div class="card-title">
            <span>🕒 Fil d'Activité des Ventes du Jour (Temps Réel)</span>
            <button class="btn btn-secondary btn-sm" onclick="exportCSV()">📥 Exporter CSV</button>
          </div>
          <table>
            <thead>
              <tr>
                <th>N° Ticket</th>
                <th>Heure Exacte</th>
                <th>Caissier</th>
                <th>Règlement</th>
                <th>Montant</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="owner-recent-rows"></tbody>
          </table>
        </div>

        <div class="card" id="owner-expiring-box" style="display: none;">
          <div class="card-title" style="color: var(--danger);">
            <span>⚠️ Alerte Péremptions : Lots arrivant à échéance d'ici 6 mois</span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Médicament</th>
                <th>N° Lot</th>
                <th>Date Péremption</th>
                <th>Quantité restante</th>
              </tr>
            </thead>
            <tbody id="owner-expiring-rows"></tbody>
          </table>
        </div>
      </section>

      <!-- ============================================== -->
      <!-- TAB USERS: Gestion du Personnel (Titulaire)    -->
      <!-- ============================================== -->
      <section id="tab-users" class="tab-content" style="display: none;">
        <div class="card">
          <div class="card-title">
            <span>Gestion des Utilisateurs & Accréditations</span>
            <button class="btn btn-primary btn-sm" onclick="showAddUserModal()">+ Nouvel Employé</button>
          </div>
          <table>
            <thead>
              <tr>
                <th>Utilisateur</th>
                <th>Rôle</th>
                <th>Statut</th>
                <th>Échecs de mot de passe</th>
                <th>Autorisations</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="users-table-rows"></tbody>
          </table>
        </div>
      </section>

      <!-- ============================================== -->
      <!-- TAB POS: Caisse & Vente (Interface Employé)     -->
      <!-- ============================================== -->
      <section id="tab-pos" class="tab-content">
        <div class="pos-grid">
          <div>
            <div class="card">
              <div class="card-title">
                <span>Catalogue & Disponibilité (Point de Vente)</span>
                <span id="pos-clock" style="font-size: 0.85rem; font-weight: normal; color: var(--text-muted);"></span>
              </div>
              <div class="catalog-search">
                <input type="text" id="pos-search" placeholder="Rechercher par nom, code ou référence..." oninput="filterCatalog()">
              </div>
              <div style="max-height: 520px; overflow-y: auto;">
                <table>
                  <thead>
                    <tr>
                      <th>Désignation</th>
                      <th>Conditionnement</th>
                      <th>Péremption & Lot (FEFO)</th>
                      <th>Prix</th>
                      <th>Stock Vente</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody id="catalog-rows"></tbody>
                </table>
              </div>
            </div>
          </div>

          <div>
            <div class="card cart-box">
              <div class="card-title">
                <span>Panier de Vente</span>
                <button class="btn btn-secondary btn-sm" onclick="clearCart()">Vider</button>
              </div>
              <div class="cart-items" id="cart-list">
                <div style="text-align: center; color: var(--text-muted); margin-top: 3rem;">Le panier est vide</div>
              </div>

              <div class="cart-summary">
                <div class="cart-summary-line">
                  <span>Sous-total</span>
                  <span id="cart-subtotal">0 FCFA</span>
                </div>
                <div class="cart-summary-line">
                  <span>Mode de paiement</span>
                  <select id="sale-method" style="width: auto; padding: 0.2rem 0.5rem;" onchange="updateChange()">
                    <option value="cash">Espèces</option>
                    <option value="om">Orange Money / MoMo</option>
                    <option value="card">Carte bancaire</option>
                  </select>
                </div>
                <div class="cart-summary-line" id="cash-row">
                  <span>Montant remis</span>
                  <input type="number" id="sale-paid" placeholder="0" style="width: 130px; padding: 0.25rem 0.5rem;" oninput="updateChange()">
                </div>
                <div class="cart-summary-line" id="change-row">
                  <span>Monnaie à rendre</span>
                  <strong id="sale-change" style="color: var(--primary); font-size: 1.1rem;">0 FCFA</strong>
                </div>
                <div class="cart-summary-line total">
                  <span>TOTAL À PAYER</span>
                  <span id="cart-total">0 FCFA</span>
                </div>
                <button class="btn btn-primary" style="margin-top: 0.5rem; padding: 0.85rem;" onclick="processSale()">
                  Valider la Vente & Imprimer le Reçu 🖨️
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- ============================================== -->
      <!-- TAB STOCK: Stocks & Lots (FEFO)                -->
      <!-- ============================================== -->
      <section id="tab-stock" class="tab-content" style="display: none;">
        <div class="card">
          <div class="card-title">
            <span>État des Stocks & Suivi de Péremption par Lot (FEFO)</span>
            <button class="btn btn-primary btn-sm" onclick="showReceiveModal()">+ Réceptionner un Lot</button>
          </div>
          <table>
            <thead>
              <tr>
                <th>Médicament</th>
                <th>Prix Unitaire</th>
                <th>Stock Physique</th>
                <th>Stock Vendable</th>
                <th>Lots, Péremptions & Actions</th>
              </tr>
            </thead>
            <tbody id="stock-rows"></tbody>
          </table>
        </div>
      </section>

      <!-- ============================================== -->
      <!-- TAB SALES: Journal des Ventes                  -->
      <!-- ============================================== -->
      <section id="tab-sales" class="tab-content" style="display: none;">
        <div class="card">
          <div class="card-title">
            <span>Journal Général des Ventes & Encaissements</span>
            <button class="btn btn-secondary btn-sm" onclick="exportCSV()">📥 Exporter en CSV</button>
          </div>
          <table>
            <thead>
              <tr>
                <th>N° Ticket</th>
                <th>Date de Vente</th>
                <th>Heure Exacte</th>
                <th>Caissier</th>
                <th>Mode</th>
                <th>Total</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="sales-history-rows"></tbody>
          </table>
        </div>
      </section>

    </main>
  </div>

  <!-- MODAL TICKET DE CAISSE (FORMAT 80MM) -->
  <div id="receipt-modal" class="modal-overlay" style="display: none;">
    <div class="receipt-paper">
      <div style="text-align: center; border-bottom: 1px dashed #000; padding-bottom: 0.75rem; margin-bottom: 0.75rem;">
        <strong id="r-ph-name" style="font-size: 1.05rem;">GRANDE PHARMACIE DU CENTRE</strong><br>
        <span id="r-ph-addr">Avenue de la Liberté, Douala</span><br>
        <span id="r-ph-tax">Contribuable : M051812345678X</span><br>
        ========================================<br>
        <strong style="font-size: 1rem;">TICKET DE CAISSE OFFICINAL</strong><br>
        <span id="r-duplicata" style="color: #b91c1c; font-weight: bold; display: none;">[ DUPLICATA ]<br></span>
        Ticket N° : <strong id="r-no">R1-000001</strong><br>
        ----------------------------------------<br>
        <div style="margin: 0.35rem 0; text-align: left; background: #f8fafc; padding: 0.35rem 0.5rem; border: 1px dotted #ccc;">
          📅 <strong>Date de vente :</strong> <span id="r-date"></span><br>
          ⏰ <strong>Heure exacte  :</strong> <span id="r-time"></span><br>
          👤 <strong>Caissier     :</strong> <span id="r-cashier"></span>
        </div>
      </div>
      
      <div id="r-lines" style="border-bottom: 1px dashed #000; padding-bottom: 0.5rem; margin-bottom: 0.5rem;"></div>
      
      <div style="font-weight: bold; display: flex; justify-content: space-between; margin-bottom: 0.35rem; font-size: 0.95rem;">
        <span>TOTAL À PAYER :</span>
        <span id="r-total">0 FCFA</span>
      </div>
      <div style="display: flex; justify-content: space-between; font-size: 0.8rem;">
        <span>Mode de règlement :</span>
        <span id="r-method" style="font-weight: 600;">Espèces</span>
      </div>
      <div style="display: flex; justify-content: space-between; font-size: 0.8rem;">
        <span>Montant remis :</span>
        <span id="r-paid">0 FCFA</span>
      </div>
      <div style="display: flex; justify-content: space-between; font-size: 0.8rem; border-bottom: 1px dashed #000; padding-bottom: 0.5rem; margin-bottom: 0.5rem;">
        <span>Monnaie rendue :</span>
        <span id="r-change">0 FCFA</span>
      </div>
      <div style="text-align: center; font-size: 0.75rem; margin-top: 0.5rem;" id="r-footer">
        Merci de votre confiance. Bon rétablissement !<br>
        <em>Horodatage certifié Douala (GMT+1)</em>
      </div>
      <div style="text-align: center; margin-top: 1.25rem;" class="no-print">
        <button class="btn btn-secondary btn-sm" onclick="closeReceiptModal()">Fermer</button>
        <button class="btn btn-primary btn-sm" onclick="window.print()">Imprimer le Reçu 🖨️</button>
      </div>
    </div>
  </div>

  <!-- Modal Réception Lot -->
  <div id="receive-modal" class="modal-overlay" style="display: none;">
    <div class="card" style="width: 440px; max-width: 90vw;">
      <div class="card-title">
        <span>Réceptionner une Livraison (Entrée Stock)</span>
        <button class="btn btn-secondary btn-sm" onclick="closeReceiveModal()">✕</button>
      </div>
      <form onsubmit="handleReceive(event)">
        <div style="margin-bottom: 0.75rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">Médicament</label>
          <select id="rec-drug" required></select>
        </div>
        <div style="margin-bottom: 0.75rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">N° de Lot</label>
          <input type="text" id="rec-lot" required placeholder="ex: LOT-2025-01">
        </div>
        <div style="margin-bottom: 0.75rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">Date de Péremption (AAAA-MM ou MM/AAAA)</label>
          <input type="text" id="rec-expiry" required placeholder="ex: 2027-12 ou 12/2027">
        </div>
        <div style="margin-bottom: 0.75rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">Quantité reçue</label>
          <input type="number" id="rec-qty" min="1" required placeholder="50">
        </div>
        <div style="margin-bottom: 1rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">Fournisseur / N° Bon de Livraison</label>
          <input type="text" id="rec-ref" placeholder="ex: LABOREX | BL-9982">
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">Enregistrer l'Entrée en Stock</button>
      </form>
    </div>
  </div>

  <!-- Modal Nouvel Employé -->
  <div id="adduser-modal" class="modal-overlay" style="display: none;">
    <div class="card" style="width: 420px; max-width: 90vw;">
      <div class="card-title">
        <span>Créer un Compte Employé</span>
        <button class="btn btn-secondary btn-sm" onclick="closeAddUserModal()">✕</button>
      </div>
      <form onsubmit="handleAddUser(event)">
        <div style="margin-bottom: 0.75rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">Nom d'utilisateur</label>
          <input type="text" id="new-user-name" required placeholder="ex: caissier3">
        </div>
        <div style="margin-bottom: 0.75rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">Mot de passe initial</label>
          <input type="password" id="new-user-pw" required placeholder="••••••••">
        </div>
        <div style="margin-bottom: 0.75rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">Rôle</label>
          <select id="new-user-role">
            <option value="cashier">Caissier</option>
            <option value="stock">Magasinier / Gestionnaire Stock</option>
          </select>
        </div>
        <div style="margin-bottom: 1rem;">
          <label style="display:flex; align-items:center; gap:0.5rem; font-size:0.85rem;">
            <input type="checkbox" id="new-user-block" style="width:auto;"> Autoriser le blocage de lots
          </label>
          <label style="display:flex; align-items:center; gap:0.5rem; font-size:0.85rem; margin-top:0.35rem;">
            <input type="checkbox" id="new-user-cash" style="width:auto;" checked> Autoriser l'encaissement (Caisse)
          </label>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">Créer l'employé</button>
      </form>
    </div>
  </div>

  <!-- Modal Z de Caisse (Clôture journalière) -->
  <div id="cashclosing-modal" class="modal-overlay" style="display: none;">
    <div class="card" style="width: 460px; max-width: 90vw;">
      <div class="card-title">
        <span>💰 Clôture de Caisse (Rapport Z)</span>
        <button class="btn btn-secondary btn-sm" onclick="closeCashClosingModal()">✕</button>
      </div>
      <form onsubmit="handleCashClosing(event)">
        <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:1rem;">
          Comptage physique des espèces pour la journée du <strong id="closing-today-label"></strong>.
        </p>
        <div style="margin-bottom: 0.75rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">Fond de caisse initial (FCFA)</label>
          <input type="number" id="closing-initial" value="10000" required>
        </div>
        <div style="margin-bottom: 1rem;">
          <label style="font-size: 0.85rem; font-weight: 600;">Montant physique compté en caisse (FCFA)</label>
          <input type="number" id="closing-counted" placeholder="ex: 15550" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">Valider la Clôture & Calculer l'Écart</button>
      </form>
      <div id="closing-result-box" style="display:none; margin-top:1.25rem; padding:1rem; background:#f8fafc; border-radius:8px; border:1px solid var(--border);">
        <h4 style="margin-bottom:0.5rem;">Résultat de la Clôture :</h4>
        <div style="font-size:0.85rem; line-height:1.6;">
          Total Espèces Théorique : <strong id="cr-theo">0 FCFA</strong><br>
          Espèces Comptées : <strong id="cr-counted">0 FCFA</strong><br>
          Écart de caisse : <strong id="cr-diff" style="font-size:1rem;">0 FCFA</strong><br>
          Total Journée (Toutes méthodes) : <strong id="cr-total">0 FCFA</strong>
        </div>
      </div>
    </div>
  </div>

  <script>
    let TOKEN = localStorage.getItem('ph_token') || '';
    let CURRENT_USER = null;
    let DRUGS = [];
    let CART = {};

    function api(path, options = {}) {
      options.headers = options.headers || {};
      if (TOKEN) options.headers['Authorization'] = 'Bearer ' + TOKEN;
      if (options.body && typeof options.body === 'object') {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(options.body);
      }
      return fetch(path, options).then(async res => {
        const text = await res.text();
        let data;
        try { data = JSON.parse(text); } catch(e) { data = text; }
        if (!res.ok) throw new Error((data && data.error) || 'Erreur serveur');
        return data;
      });
    }

    function fillDemo(u, p) {
      document.getElementById('login-username').value = u;
      document.getElementById('login-password').value = p;
    }

    async function handleLogin(e) {
      e.preventDefault();
      const u = document.getElementById('login-username').value;
      const p = document.getElementById('login-password').value;
      const errBox = document.getElementById('login-error');
      errBox.style.display = 'none';
      try {
        const res = await api('/login', { method: 'POST', body: { username: u, password: p } });
        TOKEN = res.token;
        localStorage.setItem('ph_token', TOKEN);
        await initApp();
      } catch (err) {
        errBox.textContent = err.message;
        errBox.style.display = 'block';
      }
    }

    async function initApp() {
      try {
        CURRENT_USER = await api('/me');
        document.getElementById('login-view').style.display = 'none';
        document.getElementById('main-view').style.display = 'flex';
        document.getElementById('header-user').style.display = 'flex';
        
        const roleLabel = CURRENT_USER.role === 'owner' ? '👑 Titulaire (Propriétaire)' : `👤 ${CURRENT_USER.role}`;
        document.getElementById('user-display').textContent = `${CURRENT_USER.username} (${roleLabel})`;

        const ownerBtn = document.getElementById('nav-btn-owner');
        const usersBtn = document.getElementById('nav-btn-users');
        if (CURRENT_USER.role === 'owner') {
          ownerBtn.style.display = 'flex';
          usersBtn.style.display = 'flex';
          switchTab('owner');
        } else {
          ownerBtn.style.display = 'none';
          usersBtn.style.display = 'none';
          switchTab('pos');
        }

        await loadCatalog();
        
        setInterval(() => {
          const now = new Date();
          const el = document.getElementById('pos-clock');
          if (el) el.textContent = now.toLocaleDateString('fr-FR') + ' ' + now.toLocaleTimeString('fr-FR');
        }, 1000);
      } catch (err) {
        console.error("Init failed:", err);
        logout();
      }
    }

    function logout() {
      TOKEN = '';
      localStorage.removeItem('ph_token');
      document.getElementById('login-view').style.display = 'block';
      document.getElementById('main-view').style.display = 'none';
      document.getElementById('header-user').style.display = 'none';
    }

    async function loadCatalog() {
      try {
        DRUGS = await api('/drugs');
        renderCatalog();
        renderStock();
      } catch(err) {
        console.error(err);
      }
    }

    function renderCatalog() {
      const q = (document.getElementById('pos-search').value || '').toLowerCase();
      const tbody = document.getElementById('catalog-rows');
      tbody.innerHTML = '';
      
      DRUGS.filter(d => d.name.toLowerCase().includes(q) || (d.ref && d.ref.toLowerCase().includes(q)))
        .forEach(d => {
          const tr = document.createElement('tr');
          const isAvailable = d.sellable > 0;
          
          let expiryBadge = `<span style="color:var(--text-muted); font-size:0.75rem;">Épuisé</span>`;
          if (d.next_expiry) {
            expiryBadge = `<span class="expiry-tag">⏳ Exp: <strong>${d.next_expiry}</strong> <span style="color:var(--text-muted);">(Lot ${d.next_lot_no})</span></span>`;
          }

          tr.innerHTML = `
            <td><strong>${d.name}</strong><br><span style="font-size:0.75rem; color:var(--text-muted)">Réf: ${d.ref || '-'}</span></td>
            <td>${d.pack}</td>
            <td>${expiryBadge}</td>
            <td><strong>${d.price.toLocaleString()} FCFA</strong></td>
            <td><span class="badge ${isAvailable ? 'badge-success' : 'badge-danger'}">${d.sellable} en stock</span></td>
            <td>
              <button class="btn btn-primary btn-sm" ${isAvailable ? '' : 'disabled'} onclick="addToCart(${d.id})">
                + Vendre
              </button>
            </td>
          `;
          tbody.appendChild(tr);
        });
    }

    function filterCatalog() { renderCatalog(); }

    function addToCart(drugId) {
      const d = DRUGS.find(x => x.id === drugId);
      if (!d) return;
      const cur = CART[drugId] || 0;
      if (cur + 1 > d.sellable) {
        alert(`Stock vendable insuffisant pour ${d.name} (${d.sellable} max)`);
        return;
      }
      CART[drugId] = cur + 1;
      renderCart();
    }

    function removeFromCart(drugId) {
      delete CART[drugId];
      renderCart();
    }

    function changeCartQty(drugId, delta) {
      const d = DRUGS.find(x => x.id === drugId);
      if (!d) return;
      const cur = CART[drugId] || 0;
      const target = cur + delta;
      if (target <= 0) {
        removeFromCart(drugId);
        return;
      }
      if (target > d.sellable) {
        alert(`Stock vendable insuffisant pour ${d.name} (${d.sellable} max)`);
        return;
      }
      CART[drugId] = target;
      renderCart();
    }

    function clearCart() {
      CART = {};
      renderCart();
    }

    function renderCart() {
      const box = document.getElementById('cart-list');
      box.innerHTML = '';
      let total = 0;
      const keys = Object.keys(CART);
      if (keys.length === 0) {
        box.innerHTML = '<div style="text-align: center; color: var(--text-muted); margin-top: 3rem;">Le panier est vide</div>';
      } else {
        keys.forEach(did => {
          const d = DRUGS.find(x => x.id == did);
          const q = CART[did];
          const st = q * d.price;
          total += st;
          const item = document.createElement('div');
          item.className = 'cart-item';
          item.innerHTML = `
            <div>
              <div style="font-weight: 600;">${d.name}</div>
              <div style="font-size: 0.75rem; color: #047857;">⏳ Exp: ${d.next_expiry || '-'} (Lot ${d.next_lot_no || '-'})</div>
              <div style="font-size: 0.8rem; color: var(--text-muted);">${d.price.toLocaleString()} FCFA × ${q} = <strong>${st.toLocaleString()} FCFA</strong></div>
            </div>
            <div style="display:flex; align-items:center; gap:0.25rem;">
              <button class="btn btn-secondary btn-sm" onclick="changeCartQty(${d.id}, -1)">-</button>
              <span style="min-width: 20px; text-align: center; font-weight:600;">${q}</span>
              <button class="btn btn-secondary btn-sm" onclick="changeCartQty(${d.id}, 1)">+</button>
              <button class="btn btn-danger btn-sm" style="margin-left: 0.35rem;" onclick="removeFromCart(${d.id})">×</button>
            </div>
          `;
          box.appendChild(item);
        });
      }
      document.getElementById('cart-subtotal').textContent = total.toLocaleString() + ' FCFA';
      document.getElementById('cart-total').textContent = total.toLocaleString() + ' FCFA';
      updateChange();
    }

    function updateChange() {
      const method = document.getElementById('sale-method').value;
      const cashRow = document.getElementById('cash-row');
      const changeRow = document.getElementById('change-row');
      let total = 0;
      Object.keys(CART).forEach(did => {
        const d = DRUGS.find(x => x.id == did);
        total += CART[did] * d.price;
      });

      if (method === 'cash') {
        cashRow.style.display = 'flex';
        changeRow.style.display = 'flex';
        const paid = parseFloat(document.getElementById('sale-paid').value || 0);
        const change = Math.max(0, paid - total);
        document.getElementById('sale-change').textContent = change.toLocaleString() + ' FCFA';
      } else {
        cashRow.style.display = 'none';
        changeRow.style.display = 'none';
      }
    }

    async function processSale() {
      const items = Object.entries(CART).map(([did, q]) => [parseInt(did), q]);
      if (items.length === 0) {
        alert("Le panier est vide.");
        return;
      }
      const method = document.getElementById('sale-method').value;
      let total = 0;
      items.forEach(([did, q]) => {
        const d = DRUGS.find(x => x.id === did);
        total += q * d.price;
      });
      let paid = total;
      if (method === 'cash') {
        paid = parseFloat(document.getElementById('sale-paid').value || 0);
        if (paid < total) {
          alert(`Montant remis insuffisant (Total: ${total.toLocaleString()} FCFA).`);
          return;
        }
      }
      const idem = 'sale-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6);
      try {
        const res = await api('/sale', {
          method: 'POST',
          body: { idem, items, method, paid }
        });
        clearCart();
        await loadCatalog();
        await viewReceipt(res.sale_id);
      } catch (err) {
        alert("Erreur vente: " + err.message);
      }
    }

    async function viewReceipt(saleId) {
      try {
        const r = await api(`/receipt/${saleId}`);
        document.getElementById('r-ph-name').textContent = r.pharmacy.name || 'GRANDE PHARMACIE DU CENTRE';
        document.getElementById('r-ph-addr').textContent = r.pharmacy.address || '';
        document.getElementById('r-ph-tax').textContent = 'Contribuable : ' + (r.pharmacy.tax_id || '');
        document.getElementById('r-no').textContent = r.no;
        
        document.getElementById('r-date').textContent = r.date;
        document.getElementById('r-time').textContent = r.time + ' (Douala GMT+1)';
        document.getElementById('r-cashier').textContent = r.cashier;
        
        document.getElementById('r-duplicata').style.display = r.duplicata ? 'block' : 'none';
        document.getElementById('r-total').textContent = r.total.toLocaleString() + ' FCFA';
        document.getElementById('r-method').textContent = r.method === 'cash' ? 'Espèces' : (r.method === 'om' ? 'Orange Money / MoMo' : 'Carte Bancaire');
        document.getElementById('r-paid').textContent = r.paid.toLocaleString() + ' FCFA';
        document.getElementById('r-change').textContent = r.change.toLocaleString() + ' FCFA';

        const linesBox = document.getElementById('r-lines');
        linesBox.innerHTML = '';
        r.lines.forEach(l => {
          const div = document.createElement('div');
          div.style.marginBottom = '0.35rem';
          div.innerHTML = `
            <div style="display:flex; justify-content:space-between; font-weight:600;">
              <span>${l.label.split('(')[0]} (×${l.qty})</span>
              <span>${(l.qty * l.price).toLocaleString()} F</span>
            </div>
            <div style="font-size:0.75rem; color:#475569;">${l.label.includes('(') ? '(' + l.label.split('(')[1] : ''}</div>
          `;
          linesBox.appendChild(div);
        });

        document.getElementById('receipt-modal').style.display = 'flex';
      } catch (err) {
        alert("Erreur reçu: " + err.message);
      }
    }

    function closeReceiptModal() {
      document.getElementById('receipt-modal').style.display = 'none';
    }

    async function loadOwnerDashboard() {
      try {
        const data = await api('/owner/stats');
        document.getElementById('kpi-today-revenue').textContent = data.total_revenue_today.toLocaleString() + ' FCFA';
        document.getElementById('kpi-today-count').textContent = data.count_sales_today;
        document.getElementById('kpi-today-basket').textContent = data.avg_basket_today.toLocaleString() + ' FCFA';
        document.getElementById('kpi-expiring-count').textContent = data.expiring_count;
        document.getElementById('owner-today-date').textContent = 'Journée du ' + data.today_date;

        document.getElementById('pay-cash').textContent = (data.payment_methods.cash || 0).toLocaleString() + ' FCFA';
        document.getElementById('pay-om').textContent = (data.payment_methods.om || 0).toLocaleString() + ' FCFA';
        document.getElementById('pay-card').textContent = (data.payment_methods.card || 0).toLocaleString() + ' FCFA';

        const empTbody = document.getElementById('owner-employee-rows');
        empTbody.innerHTML = '';
        data.employees.forEach(emp => {
          const tr = document.createElement('tr');
          const isSelf = CURRENT_USER && CURRENT_USER.username === emp.username;
          tr.innerHTML = `
            <td><strong>${emp.username}</strong> ${isSelf ? '<span class="badge badge-info">Vous</span>' : ''}</td>
            <td><span class="badge badge-secondary">${emp.role}</span></td>
            <td><strong style="color:var(--primary); font-size:1rem;">${emp.sales_today_amount.toLocaleString()} FCFA</strong></td>
            <td><strong>${emp.sales_today_count}</strong> vente(s)</td>
            <td>${emp.sales_all_amount.toLocaleString()} FCFA (${emp.sales_all_count} ventes)</td>
            <td><span style="font-size:0.8rem; color:var(--text-muted);">${emp.last_sale_ts}</span></td>
          `;
          empTbody.appendChild(tr);
        });

        const recTbody = document.getElementById('owner-recent-rows');
        recTbody.innerHTML = '';
        if (data.recent_sales.length === 0) {
          recTbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Aucune vente enregistrée pour le moment ce jour.</td></tr>';
        } else {
          data.recent_sales.forEach(s => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td><strong>${s.receipt_no}</strong></td>
              <td><span style="color:#0369a1; font-weight:600;">${s.time}</span></td>
              <td><strong>${s.cashier}</strong></td>
              <td><span class="badge badge-success">${s.method}</span></td>
              <td><strong>${s.total.toLocaleString()} FCFA</strong></td>
              <td><button class="btn btn-secondary btn-sm" onclick="viewReceipt(${s.id})">Ticket 📄</button></td>
            `;
            recTbody.appendChild(tr);
          });
        }

        const expBox = document.getElementById('owner-expiring-box');
        const expTbody = document.getElementById('owner-expiring-rows');
        if (data.expiring_count > 0) {
          expBox.style.display = 'block';
          expTbody.innerHTML = '';
          data.expiring_lots.forEach(l => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td><strong>${l.drug_name}</strong> (${l.drug_pack})</td>
              <td><span class="badge badge-warning">${l.lot_no}</span></td>
              <td><strong style="color:var(--danger);">${l.expiry}</strong> (${l.expiry_date})</td>
              <td><strong>${l.qty}</strong> unité(s)</td>
            `;
            expTbody.appendChild(tr);
          });
        } else {
          expBox.style.display = 'none';
        }
      } catch (err) {
        console.error("Dashboard error:", err);
      }
    }

    async function loadUsersManagement() {
      try {
        const users = await api('/users');
        const tbody = document.getElementById('users-table-rows');
        tbody.innerHTML = '';
        users.forEach(u => {
          const tr = document.createElement('tr');
          const isOwner = u.role === 'owner';
          const isLocked = u.fails >= 5;
          tr.innerHTML = `
            <td><strong>${u.username}</strong></td>
            <td><span class="badge ${isOwner ? 'badge-info' : 'badge-secondary'}">${u.role}</span></td>
            <td>
              <span class="badge ${u.active ? 'badge-success' : 'badge-danger'}">${u.active ? 'Actif' : 'Désactivé'}</span>
              ${isLocked ? '<span class="badge badge-danger">🔒 Verrouillé</span>' : ''}
            </td>
            <td>${u.fails} / 5 échec(s)</td>
            <td>
              ${u.can_cash ? '<span class="badge badge-success">Encaissement</span> ' : ''}
              ${u.can_block ? '<span class="badge badge-warning">Blocage lots</span>' : ''}
            </td>
            <td>
              ${!isOwner ? `
                <button class="btn btn-secondary btn-sm" onclick="toggleUser(${u.id}, ${u.active ? 0 : 1})">
                  ${u.active ? 'Désactiver' : 'Activer'}
                </button>
                ${isLocked ? `<button class="btn btn-primary btn-sm" onclick="unlockUser(${u.id})">Déverrouiller 🔓</button>` : ''}
              ` : '<em style="color:var(--text-muted)">Titulaire</em>'}
            </td>
          `;
          tbody.appendChild(tr);
        });
      } catch (err) {
        console.error(err);
      }
    }

    async function toggleUser(id, newState) {
      try {
        await api('/user/toggle_active', { method: 'POST', body: { user_id: id, active: newState } });
        await loadUsersManagement();
      } catch (err) {
        alert("Erreur: " + err.message);
      }
    }

    async function unlockUser(id) {
      try {
        await api('/user/reset_fails', { method: 'POST', body: { user_id: id } });
        await loadUsersManagement();
        alert("Compte déverrouillé avec succès.");
      } catch (err) {
        alert("Erreur: " + err.message);
      }
    }

    function showAddUserModal() {
      document.getElementById('adduser-modal').style.display = 'flex';
    }
    function closeAddUserModal() {
      document.getElementById('adduser-modal').style.display = 'none';
    }

    async function handleAddUser(e) {
      e.preventDefault();
      const u = document.getElementById('new-user-name').value.trim();
      const p = document.getElementById('new-user-pw').value;
      const r = document.getElementById('new-user-role').value;
      const b = document.getElementById('new-user-block').checked;
      const c = document.getElementById('new-user-cash').checked;
      try {
        await api('/user/create', { method: 'POST', body: { username: u, password: p, role: r, can_block: b, can_cash: c } });
        closeAddUserModal();
        await loadUsersManagement();
        alert(`Employé « ${u} » créé avec succès.`);
      } catch (err) {
        alert("Erreur création employé: " + err.message);
      }
    }

    function showCashClosingModal() {
      document.getElementById('closing-today-label').textContent = new Date().toLocaleDateString('fr-FR');
      document.getElementById('closing-result-box').style.display = 'none';
      document.getElementById('cashclosing-modal').style.display = 'flex';
    }
    function closeCashClosingModal() {
      document.getElementById('cashclosing-modal').style.display = 'none';
    }

    async function handleCashClosing(e) {
      e.preventDefault();
      const init = parseInt(document.getElementById('closing-initial').value || 0);
      const counted = parseInt(document.getElementById('closing-counted').value || 0);
      try {
        const res = await api('/cash_closing', { method: 'POST', body: { initial_cash: init, counted_cash: counted } });
        document.getElementById('cr-theo').textContent = res.theoretical_cash.toLocaleString() + ' FCFA';
        document.getElementById('cr-counted').textContent = res.counted_cash.toLocaleString() + ' FCFA';
        const diffEl = document.getElementById('cr-diff');
        diffEl.textContent = (res.diff_cash >= 0 ? '+' : '') + res.diff_cash.toLocaleString() + ' FCFA';
        diffEl.style.color = res.diff_cash === 0 ? 'var(--primary)' : (res.diff_cash > 0 ? 'var(--secondary)' : 'var(--danger)');
        document.getElementById('cr-total').textContent = res.total_day.toLocaleString() + ' FCFA';
        document.getElementById('closing-result-box').style.display = 'block';
      } catch (err) {
        alert("Erreur clôture: " + err.message);
      }
    }

    async function renderStock() {
      const tbody = document.getElementById('stock-rows');
      tbody.innerHTML = '';
      for (const d of DRUGS) {
        const stockData = await api(`/stock/${d.id}`);
        const tr = document.createElement('tr');
        const lotsHtml = stockData.lots.map(l => {
          const isBlocked = l.status !== 'ok';
          return `<div style="display:inline-flex; align-items:center; gap:0.35rem; margin:0.2rem; background:#f1f5f9; padding:0.25rem 0.5rem; border-radius:6px; font-size:0.75rem;">
            <strong>${l.lot_no}</strong> (Exp: <strong>${l.expiry}</strong>) : <strong>${l.qty}</strong>
            <span class="badge ${isBlocked ? 'badge-danger' : 'badge-success'}">${l.status}</span>
            ${CURRENT_USER && (CURRENT_USER.role === 'owner' || CURRENT_USER.can_block) ? 
              `<button class="btn btn-secondary btn-sm" style="padding:0 5px; font-size:10px;" onclick="toggleBlockLot(${l.id}, '${isBlocked ? 'ok' : 'blocked'}')">${isBlocked ? 'Débloquer' : 'Bloquer'}</button>` : ''}
          </div>`;
        }).join('') || '<em style="color:var(--text-muted)">Aucun lot en stock</em>';

        tr.innerHTML = `
          <td><strong>${d.name}</strong><br><span style="font-size:0.8rem; color:var(--text-muted);">${d.pack}</span></td>
          <td>${d.price.toLocaleString()} FCFA</td>
          <td><strong>${stockData.physical}</strong></td>
          <td><span class="badge ${stockData.sellable > 0 ? 'badge-success' : 'badge-danger'}">${stockData.sellable} vendable(s)</span></td>
          <td>${lotsHtml}</td>
        `;
        tbody.appendChild(tr);
      }
    }

    async function toggleBlockLot(lotId, newStatus) {
      try {
        await api('/lot/block', { method: 'POST', body: { lot_id: lotId, status: newStatus } });
        await loadCatalog();
      } catch (err) {
        alert("Erreur statut lot: " + err.message);
      }
    }

    function showReceiveModal() {
      const sel = document.getElementById('rec-drug');
      sel.innerHTML = '';
      DRUGS.forEach(d => {
        const opt = document.createElement('option');
        opt.value = d.id;
        opt.textContent = `${d.name} (${d.pack})`;
        sel.appendChild(opt);
      });
      document.getElementById('receive-modal').style.display = 'flex';
    }

    function closeReceiveModal() {
      document.getElementById('receive-modal').style.display = 'none';
    }

    async function handleReceive(e) {
      e.preventDefault();
      const did = parseInt(document.getElementById('rec-drug').value);
      const lot = document.getElementById('rec-lot').value.trim();
      const exp = document.getElementById('rec-expiry').value.trim();
      const qty = parseInt(document.getElementById('rec-qty').value);
      const ref = document.getElementById('rec-ref').value.trim();

      try {
        await api('/receive', {
          method: 'POST',
          body: { drug_id: did, lot_no: lot, expiry: exp, qty, supplier: ref, bl: ref }
        });
        closeReceiveModal();
        await loadCatalog();
        alert("Lot réceptionné avec succès.");
      } catch (err) {
        alert("Erreur réception: " + err.message);
      }
    }

    async function loadSalesHistory() {
      try {
        const sales = await api('/sales');
        const tbody = document.getElementById('sales-history-rows');
        tbody.innerHTML = '';
        sales.forEach(s => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td><strong>${s.receipt_no}</strong></td>
            <td>${s.date}</td>
            <td><span style="color:#0369a1; font-weight:600;">${s.time}</span></td>
            <td>${s.cashier_name || '-'}</td>
            <td><span class="badge badge-success">${s.method}</span></td>
            <td><strong>${s.total.toLocaleString()} FCFA</strong></td>
            <td><button class="btn btn-secondary btn-sm" onclick="viewReceipt(${s.id})">Aperçu 📄</button></td>
          `;
          tbody.appendChild(tr);
        });
      } catch (err) {
        console.error(err);
      }
    }

    function exportCSV() {
      window.open('/export?token=' + encodeURIComponent(TOKEN), '_blank');
    }

    function switchTab(tab) {
      document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
      document.querySelectorAll('.nav-bar .nav-btn').forEach(btn => btn.classList.remove('active'));
      
      const activeTab = document.getElementById('tab-' + tab);
      if (activeTab) activeTab.style.display = 'block';
      
      const navBtn = document.getElementById('nav-btn-' + tab);
      if (navBtn) navBtn.classList.add('active');

      if (tab === 'owner') loadOwnerDashboard();
      if (tab === 'users') loadUsersManagement();
      if (tab === 'pos') renderCatalog();
      if (tab === 'stock') renderStock();
      if (tab === 'sales') loadSalesHistory();
    }

    if (TOKEN) {
      initApp();
    }
  </script>
</body>
</html>
"""

# ---------- API HTTP & UI ----------
def make_handler(c):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, obj, ctype="application/json"):
            b = obj.encode("utf-8") if isinstance(obj, str) else json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _get_auth_user(self):
            token = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
            if not token and "?" in self.path:
                from urllib.parse import parse_qs, urlparse
                qs = parse_qs(urlparse(self.path).query)
                token = qs.get("token", [""])[0]
            return auth(c, token)

        def _run(self, method):
            from urllib.parse import urlparse
            parsed_path = urlparse(self.path).path
            p = parsed_path.split("/")

            if method == "GET" and (parsed_path in ("/", "/index.html", "/app")):
                return self._send(200, HTML_PAGE, "text/html; charset=utf-8")

            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}") if n > 0 else {}

            try:
                if method == "POST" and parsed_path == "/login":
                    return self._send(200, {"token": login(c, body["username"], body["password"])})

                u = self._get_auth_user()

                if method == "GET" and parsed_path == "/me":
                    return self._send(200, {
                        "id": u["id"], "username": u["username"], "role": u["role"],
                        "pharmacy_id": u["pharmacy_id"], "can_block": u["can_block"], "can_cash": u["can_cash"]
                    })

                if method == "GET" and parsed_path == "/owner/stats":
                    return self._send(200, owner_dashboard_stats(c, u))

                if method == "GET" and parsed_path == "/users":
                    return self._send(200, list_users(c, u))

                if method == "POST" and parsed_path == "/user/create":
                    create_user(c, u, body["username"], body["password"], body["role"],
                                can_block=body.get("can_block", 0), can_cash=body.get("can_cash", 1))
                    return self._send(200, {"status": "ok"})

                if method == "POST" and parsed_path == "/user/toggle_active":
                    toggle_user_active(c, u, int(body["user_id"]), body["active"])
                    return self._send(200, {"status": "ok"})

                if method == "POST" and parsed_path == "/user/reset_fails":
                    reset_user_fails(c, u, int(body["user_id"]))
                    return self._send(200, {"status": "ok"})

                if method == "POST" and parsed_path == "/cash_closing":
                    res = perform_cash_closing(c, u, int(body.get("initial_cash", 0)), int(body["counted_cash"]))
                    return self._send(200, res)

                if method == "GET" and parsed_path == "/drugs":
                    return self._send(200, list_drugs_with_stock(c, u))

                if method == "GET" and len(p) >= 3 and p[1] == "stock":
                    return self._send(200, stock(c, u, int(p[2])))

                if method == "POST" and parsed_path == "/receive":
                    lid = receive(c, u, int(body["drug_id"]), body["lot_no"], body["expiry"], int(body["qty"]),
                                  body.get("supplier", ""), body.get("bl", ""))
                    return self._send(200, {"lot_id": lid})

                if method == "POST" and parsed_path == "/lot/block":
                    block_lot(c, u, int(body["lot_id"]), body.get("status", "blocked"))
                    return self._send(200, {"status": "ok"})

                if method == "POST" and parsed_path == "/sale":
                    return self._send(200, {"sale_id": sell(c, u, body["idem"], body["items"], body["method"], body.get("paid"))})

                if method == "GET" and len(p) >= 3 and p[1] == "receipt":
                    return self._send(200, receipt(c, u, int(p[2]), reprint=True))

                if method == "GET" and parsed_path == "/sales":
                    return self._send(200, sales_list(c, u))

                if method == "GET" and parsed_path == "/export":
                    return self._send(200, export_sales_csv(c, u), "text/csv; charset=utf-8")

                return self._send(404, {"error": "inconnu"})
            except Denied as e:
                self._send(403, {"error": f"refusé: {e}"})
            except Conflict as e:
                self._send(409, {"error": str(e)})
            except Exception as e:
                self._send(500, {"error": f"Erreur serveur: {str(e)}"})

        def do_GET(self): self._run("GET")
        def do_POST(self): self._run("POST")

    return H

if __name__ == "__main__":
    db_file = os.environ.get("DB", "pharmaclair.db")
    conn = connect(db_file)
    seed_demo_data(conn)
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 PharmaClair lancé sur http://127.0.0.1:{port}")
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(conn)).serve_forever()
