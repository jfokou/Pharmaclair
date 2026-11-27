"""
PharmaClair — Système Officinal & SaaS Cloud / PWA Offline-First
Production-Ready pour le Cameroun et l'Afrique (Standard Library Python uniquement).
Lancer : python pharmaclair.py
"""
import sqlite3, hashlib, secrets, json, datetime as dt, calendar, os, csv, io, threading, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("Africa/Douala")
except Exception:
    TZ = dt.timezone(dt.timedelta(hours=1))  # Douala / Afrique Centrale (WAT: UTC+1)

EXPIRY_MONTH_RULE = os.environ.get("EXPIRY_MONTH_RULE", "end")

SCHEMA = """
CREATE TABLE IF NOT EXISTS pharmacies(
  id INTEGER PRIMARY KEY,
  name TEXT,
  address TEXT,
  tax_id TEXT,
  footer TEXT,
  phone TEXT DEFAULT '',
  email TEXT DEFAULT '',
  city TEXT DEFAULT 'Douala',
  rccm TEXT DEFAULT '',
  currency TEXT DEFAULT 'FCFA',
  receipt_format TEXT DEFAULT '80mm',
  saspay_client_id TEXT DEFAULT '',
  saspay_secret TEXT DEFAULT '',
  saspay_mode TEXT DEFAULT 'sandbox',
  subscription_status TEXT DEFAULT 'trial',
  subscription_expires_at TEXT DEFAULT '',
  trial_ends_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  username TEXT UNIQUE,
  salt TEXT,
  pw TEXT,
  role TEXT,
  active INT DEFAULT 1,
  can_block INT DEFAULT 0,
  can_cash INT DEFAULT 0,
  fails INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INT
);

CREATE TABLE IF NOT EXISTS drugs(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  name TEXT,
  pack TEXT,
  price INT,
  ref TEXT,
  barcode TEXT,
  min_stock INT DEFAULT 10
);

CREATE TABLE IF NOT EXISTS lots(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  drug_id INT,
  lot_no TEXT,
  expiry TEXT,
  expiry_date TEXT,
  qty INT,
  status TEXT DEFAULT 'ok',
  UNIQUE(pharmacy_id, drug_id, lot_no)
);

CREATE TABLE IF NOT EXISTS movements(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  lot_id INT,
  type TEXT,
  qty INT,
  ref TEXT,
  user_id INT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS sales(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  user_id INT,
  customer_id INT,
  idem TEXT,
  receipt_no TEXT,
  total INT,
  method TEXT,
  paid INT,
  change INT,
  snapshot TEXT,
  is_offline INT DEFAULT 0,
  ts TEXT,
  UNIQUE(pharmacy_id, idem)
);

CREATE TABLE IF NOT EXISTS sale_lines(
  id INTEGER PRIMARY KEY,
  sale_id INT,
  drug_id INT,
  lot_id INT,
  qty INT,
  price INT,
  label TEXT
);

CREATE TABLE IF NOT EXISTS returns(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  sale_id INT,
  status TEXT,
  reason TEXT,
  by_user INT,
  approved_by INT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS return_lines(
  return_id INT,
  sale_line_id INT,
  qty INT
);

CREATE TABLE IF NOT EXISTS quarantine(
  lot_id INT PRIMARY KEY,
  qty INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cash_closings(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  user_id INT,
  date_str TEXT,
  initial_cash INT,
  counted_cash INT,
  theoretical_cash INT,
  diff_cash INT,
  total_om INT,
  total_card INT,
  total_day INT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS customers(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  name TEXT,
  phone TEXT,
  consent_sms INT DEFAULT 1,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS prescriptions(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  customer_id INT,
  doctor TEXT,
  drug_id INT,
  posology TEXT,
  refills_total INT,
  refills_left INT,
  expiry_date TEXT,
  status TEXT DEFAULT 'active',
  ts TEXT
);

CREATE TABLE IF NOT EXISTS sms_notifs(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  customer_id INT,
  phone TEXT,
  message TEXT,
  status TEXT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS user_logins(
  id INTEGER PRIMARY KEY,
  user_id INT,
  action TEXT,
  ip TEXT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS cameras(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  name TEXT,
  location TEXT,
  stream_url TEXT,
  active INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  user_id INT,
  action TEXT,
  data TEXT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS device_enrollments(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  device_uuid TEXT UNIQUE,
  device_name TEXT,
  register_no INT DEFAULT 1,
  device_token TEXT,
  last_seen TEXT,
  is_approved INT DEFAULT 1,
  enrolled_by INT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS sync_outbox_log(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  device_uuid TEXT,
  event_id TEXT UNIQUE,
  event_type TEXT,
  payload TEXT,
  server_status TEXT DEFAULT 'processed',
  conflict_details TEXT,
  processed_at TEXT
);

CREATE TABLE IF NOT EXISTS expenses(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  user_id INT,
  amount INT,
  category TEXT,
  description TEXT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS subscription_payments(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT,
  amount INT,
  months INT,
  payment_method TEXT,
  payment_ref TEXT,
  provider TEXT DEFAULT 'saspay',
  status TEXT DEFAULT 'completed',
  created_at TEXT
);
"""

PERMS = {
    "superadmin": {"*"},
    "owner": {"*"},
    "cashier": {"sell", "stock_view", "own_sales", "return_request", "cash_count", "customers", "notifs"},
    "stock": {"stock_view", "receive", "count"}
}

DB_LOCK = threading.RLock()

class Denied(Exception): pass
class Conflict(Exception): pass

def now(): return dt.datetime.now(TZ).isoformat(timespec="seconds")

def run_migrations(c):
    with DB_LOCK:
        cols = [r["name"] for r in c.execute("PRAGMA table_info(pharmacies)").fetchall()]
        to_add = {
            "phone": "TEXT DEFAULT ''",
            "email": "TEXT DEFAULT ''",
            "city": "TEXT DEFAULT 'Douala'",
            "rccm": "TEXT DEFAULT ''",
            "currency": "TEXT DEFAULT 'FCFA'",
            "receipt_format": "TEXT DEFAULT '80mm'",
            "saspay_client_id": "TEXT DEFAULT ''",
            "saspay_secret": "TEXT DEFAULT ''",
            "saspay_mode": "TEXT DEFAULT 'sandbox'",
            "subscription_status": "TEXT DEFAULT 'trial'",
            "subscription_expires_at": "TEXT DEFAULT ''",
            "trial_ends_at": "TEXT DEFAULT ''"
        }
        for col_name, col_def in to_add.items():
            if col_name not in cols:
                try:
                    c.execute(f"ALTER TABLE pharmacies ADD COLUMN {col_name} {col_def}")
                except Exception:
                    pass

        # Colonne is_offline dans sales
        cols_sales = [r["name"] for r in c.execute("PRAGMA table_info(sales)").fetchall()]
        if "is_offline" not in cols_sales:
            try:
                c.execute("ALTER TABLE sales ADD COLUMN is_offline INT DEFAULT 0")
            except Exception:
                pass

        # Colonne min_stock dans drugs
        cols_drugs = [r["name"] for r in c.execute("PRAGMA table_info(drugs)").fetchall()]
        if "min_stock" not in cols_drugs:
            try:
                c.execute("ALTER TABLE drugs ADD COLUMN min_stock INT DEFAULT 10")
            except Exception:
                pass

def connect(path=":memory:"):
    c = sqlite3.connect(path, isolation_level=None, timeout=15, check_same_thread=False)
    c.row_factory = sqlite3.Row
    with DB_LOCK:
        c.executescript(SCHEMA)
        run_migrations(c)
    return c

def hpw(pw, salt): return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()

def audit(c, u, action, data):
    with DB_LOCK:
        ph = u.get("pharmacy_id", 1) if u else 1
        uid = u.get("id", 0) if u else 0
        c.execute("INSERT INTO audit(pharmacy_id,user_id,action,data,ts) VALUES(?,?,?,?,?)",
                  (ph, uid, action, json.dumps(data), now()))

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

def login(c, username, pw, client_ip="127.0.0.1"):
    with DB_LOCK:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not r or not r["active"] or r["fails"] >= 5:
            if r:
                c.execute("INSERT INTO user_logins(user_id, action, ip, ts) VALUES(?,?,?,?)", (r["id"], "login_failed", client_ip, now()))
            raise Denied("identifiants incorrects ou compte verrouillé")
        if not secrets.compare_digest(r["pw"], hpw(pw, r["salt"])):
            c.execute("UPDATE users SET fails=fails+1 WHERE id=?", (r["id"],))
            c.execute("INSERT INTO user_logins(user_id, action, ip, ts) VALUES(?,?,?,?)", (r["id"], "login_failed", client_ip, now()))
            raise Denied("identifiants incorrects")
        c.execute("UPDATE users SET fails=0 WHERE id=?", (r["id"],))
        t = secrets.token_urlsafe(32)
        c.execute("INSERT INTO sessions VALUES(?,?)", (t, r["id"]))
        c.execute("INSERT INTO user_logins(user_id, action, ip, ts) VALUES(?,?,?,?)", (r["id"], "login", client_ip, now()))
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

def _sellable_lots(c, ph, drug_id):
    today = dt.datetime.now(TZ).date().isoformat()
    return c.execute("SELECT * FROM lots WHERE pharmacy_id=? AND drug_id=? AND status='ok' AND qty>0 AND expiry_date>=? ORDER BY expiry_date,id",
                     (ph, drug_id, today)).fetchall()

def list_drugs_with_stock(c, u):
    need(u, "stock_view")
    with DB_LOCK:
        drugs = c.execute("SELECT * FROM drugs WHERE pharmacy_id=? ORDER BY name", (u["pharmacy_id"],)).fetchall()
        result = []
        for d in drugs:
            phys = c.execute("SELECT COALESCE(SUM(qty),0) FROM lots WHERE pharmacy_id=? AND drug_id=?", (u["pharmacy_id"], d["id"])).fetchone()[0]
            sellable_lots = _sellable_lots(c, u["pharmacy_id"], d["id"])
            sellable = sum(l["qty"] for l in sellable_lots)
            next_lot = sellable_lots[0] if sellable_lots else None
            min_stk = d["min_stock"] if "min_stock" in d.keys() else 10
            result.append({
                "id": d["id"], "name": d["name"], "pack": d["pack"], "price": d["price"],
                "ref": d["ref"], "barcode": d["barcode"], "physical": phys, "sellable": sellable,
                "min_stock": min_stk,
                "next_expiry": next_lot["expiry"] if next_lot else None,
                "next_expiry_date": next_lot["expiry_date"] if next_lot else None,
                "next_lot_no": next_lot["lot_no"] if next_lot else None
            })
        return result

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
                      (u["pharmacy_id"], lid, "in", qty, f"BL:{bl} Fournisseur:{supplier}", u["id"], now()))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    audit(c, u, "receive", {"drug_id": drug_id, "lot_id": lid, "qty": qty, "bl": bl, "supplier": supplier})
    return lid

def block_lot(c, u, lot_id, status="blocked"):
    need(u, "block")
    if status not in ("ok", "blocked"): raise Conflict("statut invalide")
    with DB_LOCK:
        c.execute("UPDATE lots SET status=? WHERE id=? AND pharmacy_id=?", (status, lot_id, u["pharmacy_id"]))
    audit(c, u, "lot_status", {"lot_id": lot_id, "status": status})

def sell(c, u, idem, items, method, paid=None, customer_id=None, prescription_id=None, is_offline=0):
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
                d = c.execute("SELECT name, price FROM drugs WHERE id=? AND pharmacy_id=?", (drug_id, ph)).fetchone()
                if not d: raise Conflict(f"Médicament introuvable (ID: {drug_id})")
                needed = qty
                for l in _sellable_lots(c, ph, drug_id):
                    take = min(needed, l["qty"])
                    if take > 0:
                        lines.append((drug_id, l["id"], take, d["price"], f"{d['name']} (Lot {l['lot_no']} - Exp {l['expiry']})"))
                        needed -= take
                        if needed == 0: break
                if needed > 0:
                    raise Conflict(f"Stock insuffisant ou lots périmés pour: {d['name']} (manque {needed} unité(s))")
                total += d["price"] * qty

            paid = total if paid is None else paid
            if paid < total: raise Conflict(f"Montant payé insuffisant ({paid} < {total})")
            change = paid - total

            receipt_prefix = "OFF-" if is_offline else "CL-"
            seq = c.execute("SELECT COUNT(*) FROM sales WHERE pharmacy_id=?", (ph,)).fetchone()[0] + 1
            rcpt_no = f"{receipt_prefix}{dt.datetime.now(TZ).strftime('%Y%m%d')}-{seq:04d}"

            sid = c.execute("""
                INSERT INTO sales(pharmacy_id,user_id,customer_id,idem,receipt_no,total,method,paid,change,is_offline,ts)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, (ph, u["id"], customer_id, idem, rcpt_no, total, method, paid, change, is_offline, now())).lastrowid

            for did, lid, q, pr, lbl in lines:
                c.execute("INSERT INTO sale_lines(sale_id,drug_id,lot_id,qty,price,label) VALUES(?,?,?,?,?,?)",
                          (sid, did, lid, q, pr, lbl))
                c.execute("UPDATE lots SET qty=qty-? WHERE id=?", (q, lid))
                c.execute("INSERT INTO movements(pharmacy_id,lot_id,type,qty,ref,user_id,ts) VALUES(?,?,?,?,?,?,?)",
                          (ph, lid, "out", q, f"Vente #{rcpt_no}", u["id"], now()))

            if prescription_id:
                presc = c.execute("SELECT refills_left FROM prescriptions WHERE id=? AND pharmacy_id=?", (prescription_id, ph)).fetchone()
                if presc and presc["refills_left"] > 0:
                    new_refills = presc["refills_left"] - 1
                    new_status = "completed" if new_refills == 0 else "active"
                    c.execute("UPDATE prescriptions SET refills_left=?, status=? WHERE id=?", (new_refills, new_status, prescription_id))

            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise

    audit(c, u, "sale", {"sale_id": sid, "receipt_no": rcpt_no, "total": total, "method": method, "is_offline": is_offline})
    return sid

def receipt(c, u, sale_id, reprint=False):
    with DB_LOCK:
        s = c.execute("SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.pharmacy_id=?",
                      (sale_id, u["pharmacy_id"])).fetchone()
        if not s: raise Conflict("Reçu introuvable")
        p = c.execute("SELECT * FROM pharmacies WHERE id=?", (s["pharmacy_id"],)).fetchone()
        lines = c.execute("SELECT * FROM sale_lines WHERE sale_id=?", (sale_id,)).fetchall()
        
        customer = None
        if s["customer_id"]:
            cust = c.execute("SELECT name, phone FROM customers WHERE id=?", (s["customer_id"],)).fetchone()
            if cust: customer = dict(cust)

        if reprint:
            audit(c, u, "receipt_reprint", {"sale_id": sale_id, "receipt_no": s["receipt_no"]})

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
            "is_offline": bool(s.get("is_offline", 0)),
            "reprint": reprint,
            "total": s["total"],
            "method": s["method"],
            "paid": s["paid"],
            "change": s["change"],
            "lines": [dict(l) for l in lines]
        }

def sales_list(c, u):
    need(u, "own_sales")
    with DB_LOCK:
        if u["role"] == "owner" or "*" in perms(u):
            rows = c.execute("SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.pharmacy_id=? ORDER BY s.id DESC LIMIT 100",
                             (u["pharmacy_id"],)).fetchall()
        else:
            rows = c.execute("SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.pharmacy_id=? AND s.user_id=? ORDER BY s.id DESC LIMIT 50",
                             (u["pharmacy_id"], u["id"])).fetchall()
        
        results = []
        for r in rows:
            d_str, t_str, full_ts = format_ts_details(r["ts"])
            item = dict(r)
            item["date_str"] = d_str
            item["time_str"] = t_str
            item["full_ts"] = full_ts
            results.append(item)
        return results

def perform_cash_closing(c, u, initial_cash, counted_cash):
    need(u, "cash_count")
    with DB_LOCK:
        ph = u["pharmacy_id"]
        today_date = dt.datetime.now(TZ).date().isoformat()
        
        sales_today = c.execute("SELECT method, total FROM sales WHERE pharmacy_id=? AND ts LIKE ?", (ph, f"{today_date}%")).fetchall()
        
        cash_sales = sum(s["total"] for s in sales_today if s["method"] == "cash")
        total_om = sum(s["total"] for s in sales_today if s["method"] == "om")
        total_card = sum(s["total"] for s in sales_today if s["method"] == "card")
        total_day = sum(s["total"] for s in sales_today)
        
        expenses_today = c.execute("SELECT COALESCE(SUM(amount),0) FROM expenses WHERE pharmacy_id=? AND ts LIKE ?", (ph, f"{today_date}%")).fetchone()[0]
        
        theoretical_cash = initial_cash + cash_sales - expenses_today
        diff_cash = counted_cash - theoretical_cash
        
        cid = c.execute("""
            INSERT INTO cash_closings(pharmacy_id, user_id, date_str, initial_cash, counted_cash, theoretical_cash, diff_cash, total_om, total_card, total_day, ts)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """, (ph, u["id"], today_date, initial_cash, counted_cash, theoretical_cash, diff_cash, total_om, total_card, total_day, now())).lastrowid
        
        audit(c, u, "cash_closing", {"closing_id": cid, "diff_cash": diff_cash, "total_day": total_day})
        
        return {
            "closing_id": cid,
            "date": today_date,
            "initial_cash": initial_cash,
            "cash_sales": cash_sales,
            "expenses_today": expenses_today,
            "counted_cash": counted_cash,
            "theoretical_cash": theoretical_cash,
            "diff_cash": diff_cash,
            "total_om": total_om,
            "total_card": total_card,
            "total_day": total_day,
            "status": "balanced" if diff_cash == 0 else ("surplus" if diff_cash > 0 else "shortage")
        }

# --- NOUVEAUX MODULES OFFLINE-FIRST, PARAMETRES & SAAS ---

def get_pharmacy_settings(c, u):
    with DB_LOCK:
        p = c.execute("SELECT * FROM pharmacies WHERE id=?", (u["pharmacy_id"],)).fetchone()
        return dict(p) if p else {}

def update_pharmacy_settings(c, u, data):
    need(u, "owner")
    with DB_LOCK:
        ph = u["pharmacy_id"]
        fields = ["name", "address", "tax_id", "footer", "phone", "email", "city", "rccm", "currency", "receipt_format", "saspay_client_id", "saspay_secret", "saspay_mode"]
        updates = []
        vals = []
        for f in fields:
            if f in data:
                updates.append(f"{f}=?")
                vals.append(str(data[f]))
        if updates:
            vals.append(ph)
            c.execute(f"UPDATE pharmacies SET {', '.join(updates)} WHERE id=?", tuple(vals))
        audit(c, u, "settings_update", data)
        return get_pharmacy_settings(c, u)

def sync_push_events(c, u, device_uuid, events):
    need(u, "sell")
    ph = u["pharmacy_id"]
    processed_ids = []
    conflicts = []
    with DB_LOCK:
        for ev in events:
            event_id = ev.get("event_id")
            event_type = ev.get("event_type", "sale")
            payload = ev.get("payload", {})
            
            existing = c.execute("SELECT id, server_status FROM sync_outbox_log WHERE pharmacy_id=? AND event_id=?", (ph, event_id)).fetchone()
            if existing:
                processed_ids.append(event_id)
                continue
                
            try:
                if event_type == "sale":
                    sell(c, u, payload["idem"], payload["items"], payload["method"],
                         paid=payload.get("paid"),
                         customer_id=payload.get("customer_id"),
                         prescription_id=payload.get("prescription_id"),
                         is_offline=1)
                    c.execute("""
                        INSERT INTO sync_outbox_log(pharmacy_id, device_uuid, event_id, event_type, payload, server_status, processed_at)
                        VALUES(?,?,?,?,?,'processed',?)
                    """, (ph, device_uuid, event_id, event_type, json.dumps(payload), now()))
                    processed_ids.append(event_id)
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
                c.execute("INSERT INTO device_enrollments(pharmacy_id, device_uuid, device_name, last_seen, created_at) VALUES(?,?,?,?,?)",
                          (ph, device_uuid, "Terminal PWA", now(), now()))
            
    return {"processed": processed_ids, "conflicts": conflicts, "server_time": now()}

def sync_pull_delta(c, u, since=None, device_uuid=None):
    need(u, "stock_view")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        drugs = list_drugs_with_stock(c, u)
        today = dt.datetime.now(TZ).date().isoformat()
        lots = [dict(r) for r in c.execute("SELECT * FROM lots WHERE pharmacy_id=? AND qty>0 AND expiry_date>=? AND status='ok'", (ph, today)).fetchall()]
        pharmacy = dict(c.execute("SELECT * FROM pharmacies WHERE id=?", (ph,)).fetchone() or {})
        users = [dict(r) for r in c.execute("SELECT id, username, role, active, can_block, can_cash FROM users WHERE pharmacy_id=?", (ph,)).fetchall()]
        
        if device_uuid:
            dev = c.execute("SELECT id FROM device_enrollments WHERE pharmacy_id=? AND device_uuid=?", (ph, device_uuid)).fetchone()
            if not dev:
                c.execute("INSERT INTO device_enrollments(pharmacy_id, device_uuid, device_name, last_seen, created_at) VALUES(?,?,?,?,?)",
                          (ph, device_uuid, "Terminal PWA", now(), now()))
            else:
                c.execute("UPDATE device_enrollments SET last_seen=? WHERE id=?", (now(), dev["id"]))
                
        return {
            "server_time": now(),
            "pharmacy": pharmacy,
            "drugs": drugs,
            "lots": lots,
            "users": users
        }

def record_expense(c, u, amount, category, description):
    need(u, "owner")
    if amount <= 0: raise Conflict("Montant invalide")
    with DB_LOCK:
        eid = c.execute("INSERT INTO expenses(pharmacy_id, user_id, amount, category, description, ts) VALUES(?,?,?,?,?,?)",
                        (u["pharmacy_id"], u["id"], amount, category, description, now())).lastrowid
    audit(c, u, "expense_create", {"amount": amount, "category": category})
    return eid

def list_expenses(c, u):
    need(u, "owner")
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT * FROM expenses WHERE pharmacy_id=? ORDER BY id DESC LIMIT 50", (u["pharmacy_id"],)).fetchall()]

def superadmin_stats(c, u):
    if u["role"] != "superadmin": raise Denied("Super-Admin uniquement")
    with DB_LOCK:
        total_pharmacies = c.execute("SELECT COUNT(*) FROM pharmacies").fetchone()[0]
        pharmacies = [dict(r) for r in c.execute("SELECT * FROM pharmacies ORDER BY id").fetchall()]
        total_sales = c.execute("SELECT COUNT(*), COALESCE(SUM(total),0) FROM sales").fetchone()
        
        today_date = dt.datetime.now(TZ).date().isoformat()
        active_sub = sum(1 for p in pharmacies if p.get("subscription_status") == "active" or (p.get("subscription_expires_at") or "") >= today_date)
        trial_sub = sum(1 for p in pharmacies if p.get("subscription_status") == "trial" and (p.get("subscription_expires_at") or "") >= today_date)
        expired_sub = total_pharmacies - active_sub - trial_sub
        if expired_sub < 0: expired_sub = 0
        
        mrr = active_sub * 35000
        payments = [dict(r) for r in c.execute("SELECT sp.*, p.name as pharmacy_name FROM subscription_payments sp JOIN pharmacies p ON p.id=sp.pharmacy_id ORDER BY sp.id DESC LIMIT 20").fetchall()]
        
        return {
            "total_pharmacies": total_pharmacies,
            "active_subscriptions": active_sub,
            "trial_subscriptions": trial_sub,
            "expired_subscriptions": expired_sub,
            "mrr": mrr,
            "total_sales_count": total_sales[0],
            "total_sales_volume": total_sales[1],
            "pharmacies": pharmacies,
            "payments": payments
        }

def superadmin_extend_subscription(c, u, pharmacy_id, days):
    if u["role"] != "superadmin": raise Denied("Super-Admin uniquement")
    with DB_LOCK:
        p = c.execute("SELECT * FROM pharmacies WHERE id=?", (pharmacy_id,)).fetchone()
        if not p: raise Conflict("Pharmacie introuvable")
        current_exp = p["subscription_expires_at"]
        base_date = dt.datetime.now(TZ).date()
        if current_exp:
            try:
                parsed = dt.date.fromisoformat(current_exp[:10])
                if parsed > base_date: base_date = parsed
            except Exception: pass
        new_exp = (base_date + dt.timedelta(days=days)).isoformat()
        c.execute("UPDATE pharmacies SET subscription_status='active', subscription_expires_at=? WHERE id=?", (new_exp, pharmacy_id))
        audit(c, u, "superadmin_extend_sub", {"pharmacy_id": pharmacy_id, "days": days, "new_expiry": new_exp})
        return {"status": "ok", "new_expiry": new_exp}

def pay_subscription_saspay(c, u, months, method, phone=""):
    if u["role"] not in ("owner", "superadmin"): raise Denied("Titulaire uniquement")
    ph = u["pharmacy_id"]
    with DB_LOCK:
        price_per_month = 35000
        amount = months * price_per_month
        if months == 3: amount = 95000
        elif months == 12: amount = 350000
        
        p = c.execute("SELECT * FROM pharmacies WHERE id=?", (ph,)).fetchone()
        current_exp = p["subscription_expires_at"] if p else ""
        base_date = dt.datetime.now(TZ).date()
        if current_exp:
            try:
                parsed = dt.date.fromisoformat(current_exp[:10])
                if parsed > base_date: base_date = parsed
            except Exception: pass
            
        days_to_add = months * 30
        new_exp = (base_date + dt.timedelta(days=days_to_add)).isoformat()
        pay_ref = f"SAS-{secrets.token_hex(4).upper()}-{now()[:10].replace('-','')}"
        
        c.execute("""
            INSERT INTO subscription_payments(pharmacy_id, amount, months, payment_method, payment_ref, provider, status, created_at)
            VALUES(?,?,?,?,?,'saspay','completed',?)
        """, (ph, amount, months, method, pay_ref, now()))
        
        c.execute("UPDATE pharmacies SET subscription_status='active', subscription_expires_at=? WHERE id=?", (new_exp, ph))
        audit(c, u, "subscription_renew", {"months": months, "amount": amount, "method": method, "ref": pay_ref})
        return {
            "status": "ok",
            "payment_ref": pay_ref,
            "amount": amount,
            "new_expiry": new_exp,
            "receipt": {
                "pharmacy": p["name"] if p else "PharmaClair",
                "date": now(),
                "months": months,
                "amount": amount,
                "ref": pay_ref,
                "method": method
            }
        }

# --- REPERTOIRE CLIENTS, ORDONNANCES, SMS, POINTAGE & CAMERAS ---

def list_customers(c, u):
    need(u, "customers")
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT * FROM customers WHERE pharmacy_id=? ORDER BY name", (u["pharmacy_id"],)).fetchall()]

def create_customer(c, u, name, phone, consent_sms=1):
    need(u, "customers")
    with DB_LOCK:
        cid = c.execute("INSERT INTO customers(pharmacy_id, name, phone, consent_sms, ts) VALUES(?,?,?,?,?)",
                        (u["pharmacy_id"], name, phone, int(consent_sms), now())).lastrowid
    audit(c, u, "customer_create", {"id": cid, "name": name, "phone": phone})
    return cid

def list_prescriptions(c, u, customer_id=None):
    need(u, "customers")
    with DB_LOCK:
        sql = """
            SELECT p.*, c.name as customer_name, c.phone as customer_phone, d.name as drug_name
            FROM prescriptions p
            JOIN customers c ON c.id=p.customer_id
            JOIN drugs d ON d.id=p.drug_id
            WHERE p.pharmacy_id=?
        """
        params = [u["pharmacy_id"]]
        if customer_id:
            sql += " AND p.customer_id=?"
            params.append(customer_id)
        sql += " ORDER BY p.id DESC"
        return [dict(r) for r in c.execute(sql, tuple(params)).fetchall()]

def create_prescription(c, u, customer_id, doctor, drug_id, posology, refills_total, expiry_date):
    need(u, "customers")
    with DB_LOCK:
        pid = c.execute("""
            INSERT INTO prescriptions(pharmacy_id, customer_id, doctor, drug_id, posology, refills_total, refills_left, expiry_date, ts)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, (u["pharmacy_id"], customer_id, doctor, drug_id, posology, refills_total, refills_total, expiry_date, now())).lastrowid
    audit(c, u, "prescription_create", {"id": pid, "customer_id": customer_id, "drug_id": drug_id})
    return pid

def list_sms_notifs(c, u):
    need(u, "notifs")
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT s.*, c.name as customer_name FROM sms_notifs s LEFT JOIN customers c ON c.id=s.customer_id WHERE s.pharmacy_id=? ORDER BY s.id DESC LIMIT 50", (u["pharmacy_id"],)).fetchall()]

def send_automated_reminders(c, u):
    need(u, "notifs")
    sent = 0
    with DB_LOCK:
        ph = u["pharmacy_id"]
        prescs = c.execute("""
            SELECT p.*, c.name as customer_name, c.phone as customer_phone, d.name as drug_name
            FROM prescriptions p
            JOIN customers c ON c.id=p.customer_id
            JOIN drugs d ON d.id=p.drug_id
            WHERE p.pharmacy_id=? AND p.status='active' AND p.refills_left > 0 AND c.consent_sms=1
        """, (ph,)).fetchall()
        for p in prescs:
            msg = f"Bonjour {p['customer_name']}, votre traitement de {p['drug_name']} arrive a renouvellement a la Pharmacie. Il vous reste {p['refills_left']} renouvellement(s). Contactez-nous pour preparer votre commande."
            c.execute("INSERT INTO sms_notifs(pharmacy_id, customer_id, phone, message, status, ts) VALUES(?,?,?,?,?,?)",
                      (ph, p["customer_id"], p["customer_phone"], msg, "sent", now()))
            sent += 1
    audit(c, u, "reminders_sent", {"count": sent})
    return {"status": "ok", "reminders_sent": sent}

def list_employee_logins(c, u):
    need(u, "owner")
    with DB_LOCK:
        rows = c.execute("""
            SELECT ul.*, u.username, u.role
            FROM user_logins ul
            JOIN users u ON u.id=ul.user_id
            WHERE u.pharmacy_id=?
            ORDER BY ul.id DESC LIMIT 40
        """, (u["pharmacy_id"],)).fetchall()
        results = []
        for r in rows:
            d_str, t_str, full_ts = format_ts_details(r["ts"])
            results.append({
                "id": r["id"], "username": r["username"], "role": r["role"], "action": r["action"],
                "ip": r["ip"], "date": d_str, "time": t_str, "full_ts": full_ts
            })
        return results

def list_cameras(c, u):
    need(u, "owner")
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT * FROM cameras WHERE pharmacy_id=? AND active=1", (u["pharmacy_id"],)).fetchall()]

def owner_dashboard_stats(c, u):
    if u["role"] not in ("owner", "superadmin"): raise Denied("Direction uniquement")
    with DB_LOCK:
        ph = u["pharmacy_id"]
        today = dt.datetime.now(TZ).date()
        today_date = today.isoformat()
        yesterday_date = (today - dt.timedelta(days=1)).isoformat()
        
        sales_today = c.execute("SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.pharmacy_id=? AND s.ts LIKE ? ORDER BY s.id DESC", (ph, f"{today_date}%")).fetchall()
        sales_yesterday = c.execute("SELECT total FROM sales WHERE pharmacy_id=? AND ts LIKE ?", (ph, f"{yesterday_date}%")).fetchall()
        
        total_revenue_today = sum(s["total"] for s in sales_today)
        total_revenue_yesterday = sum(s["total"] for s in sales_yesterday)
        
        trend_pct = 0
        if total_revenue_yesterday > 0:
            trend_pct = int(((total_revenue_today - total_revenue_yesterday) / total_revenue_yesterday) * 100)
            
        estimated_profit = int(total_revenue_today * 0.28) # 28% de marge brute moyenne officinale
        count_sales_today = len(sales_today)
        avg_basket_today = int(total_revenue_today / count_sales_today) if count_sales_today > 0 else 0
        
        pay_methods = {"cash": 0, "om": 0, "card": 0}
        for s in sales_today:
            m = s["method"]
            pay_methods[m] = pay_methods.get(m, 0) + s["total"]
            
        users = c.execute("SELECT id, username, role, active, fails FROM users WHERE pharmacy_id=?", (ph,)).fetchall()
        total_users = len(users)
        
        logins_today = c.execute("""
            SELECT DISTINCT user_id FROM user_logins
            WHERE ts LIKE ? AND action='login'
        """, (f"{today_date}%",)).fetchall()
        active_users_today = len(set(r[0] for r in logins_today)) or 1
        
        closings_today = c.execute("SELECT * FROM cash_closings WHERE pharmacy_id=? AND date_str=? ORDER BY id DESC LIMIT 1", (ph, today_date)).fetchone()
        cash_discrepancy = closings_today["diff_cash"] if closings_today else 0
        
        low_stock_drugs = c.execute("""
            SELECT d.id, d.name, d.min_stock, COALESCE(SUM(l.qty),0) as current_stock
            FROM drugs d
            LEFT JOIN lots l ON l.drug_id=d.id AND l.status='ok' AND l.qty>0 AND l.expiry_date>=?
            WHERE d.pharmacy_id=?
            GROUP BY d.id
            HAVING current_stock <= d.min_stock
        """, (today_date, ph)).fetchall()
        
        three_months_date = (today + dt.timedelta(days=90)).isoformat()
        expiring = c.execute("""
            SELECT l.*, d.name as drug_name, d.pack as drug_pack
            FROM lots l
            JOIN drugs d ON d.id=l.drug_id
            WHERE l.pharmacy_id=? AND l.qty>0 AND l.status='ok' AND l.expiry_date<=?
            ORDER BY l.expiry_date ASC
        """, (ph, three_months_date)).fetchall()
        
        employee_stats = []
        for emp in users:
            emp_sales_today = [s for s in sales_today if s["user_id"] == emp["id"]]
            emp_sales_all = c.execute("SELECT total FROM sales WHERE pharmacy_id=? AND user_id=?", (ph, emp["id"])).fetchall()
            last_sale = c.execute("SELECT ts FROM sales WHERE pharmacy_id=? AND user_id=? ORDER BY id DESC LIMIT 1", (ph, emp["id"])).fetchone()
            employee_stats.append({
                "id": emp["id"], "username": emp["username"], "role": emp["role"], "active": emp["active"], "fails": emp["fails"],
                "sales_today_count": len(emp_sales_today), "sales_today_amount": sum(s["total"] for s in emp_sales_today),
                "sales_all_count": len(emp_sales_all), "sales_all_amount": sum(s["total"] for s in emp_sales_all),
                "last_sale_ts": format_ts_details(last_sale["ts"])[2] if last_sale else "Aucune"
            })
            
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
            "total_revenue_yesterday": total_revenue_yesterday,
            "trend_pct": trend_pct,
            "estimated_profit": estimated_profit,
            "count_sales_today": count_sales_today,
            "avg_basket_today": avg_basket_today,
            "payment_methods": pay_methods,
            "active_employees_ratio": f"{active_users_today} / {total_users}",
            "cash_discrepancy": cash_discrepancy,
            "low_stock_count": len(low_stock_drugs),
            "expiring_count": len(expiring),
            "expiring_lots": [dict(r) for r in expiring],
            "employees": employee_stats,
            "recent_sales": recent_sales,
            "pharmacy": dict(p_info) if p_info else {}
        }

def export_sales_csv(c, u):
    need(u, "owner")
    out = io.StringIO(); w = csv.writer(out); w.writerow(["N_Ticket", "Date_Vente", "Heure_Vente", "Employe", "Mode_Paiement", "Total_FCFA", "Recu_FCFA", "Monnaie_FCFA", "Hors_Ligne"])
    with DB_LOCK:
        for r in c.execute("SELECT s.*, u.username as cashier_name FROM sales s JOIN users u ON u.id=s.user_id WHERE s.pharmacy_id=? ORDER BY s.id DESC", (u["pharmacy_id"],)):
            d_str, t_str, _ = format_ts_details(r["ts"])
            w.writerow([r["receipt_no"], d_str, t_str, r["cashier_name"], r["method"], r["total"], r["paid"], r["change"], "OUI" if r.get("is_offline") else "NON"])
    return out.getvalue()

def seed_demo_data(c):
    with DB_LOCK:
        p = c.execute("SELECT id FROM pharmacies LIMIT 1").fetchone()
        exp_date = (dt.datetime.now(TZ).date() + dt.timedelta(days=30)).isoformat()
        if not p:
            pid = c.execute("""
                INSERT INTO pharmacies(name, address, tax_id, footer, phone, email, city, rccm, currency, receipt_format, subscription_status, subscription_expires_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """, ("Grande Pharmacie du Centre", "Avenue de la Liberté, Douala", "M051812345678X", "Ouvert 7j/7 - 24h/24 • Tél: +237 233 42 00 00",
                  "+237 233 42 00 00", "contact@pharmaclair.cm", "Douala", "RC/DLA/2018/B/142", "FCFA", "80mm", "active", exp_date)).lastrowid
        else:
            pid = p["id"]
            c.execute("UPDATE pharmacies SET subscription_status='active', subscription_expires_at=? WHERE id=? AND (subscription_expires_at IS NULL OR subscription_expires_at='')", (exp_date, pid))

        users = [
            ("superadmin", "admin123", "superadmin", 1, 1),
            ("titulaire", "admin123", "owner", 1, 1),
            ("caissier1", "caisse123", "cashier", 0, 1),
            ("caissier2", "caisse123", "cashier", 0, 1),
            ("magasinier", "stock123", "stock", 1, 1)
        ]
        for uname, pw, role, cb, cc in users:
            if not c.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone():
                salt = secrets.token_hex(8)
                c.execute("INSERT INTO users(pharmacy_id,username,salt,pw,role,can_block,can_cash) VALUES(?,?,?,?,?,?,?)",
                          (pid, uname, salt, hpw(pw, salt), role, cb, cc))

        # Seed catalogue si vide
        if not c.execute("SELECT id FROM drugs WHERE pharmacy_id=?", (pid,)).fetchone():
            demo_drugs = [
                ("Paracétamol 500mg", "Boîte de 16 comprimés", 500, "PAR-500", "6941234567890", 20),
                ("Amoxicilline 500mg", "Boîte de 12 gélules", 2500, "AMO-500", "6941234567891", 15),
                ("Ibuprofène 400mg", "Boîte de 20 comprimés", 1800, "IBU-400", "6941234567892", 10),
                ("Artéméther + Luméfantrine (Coartem)", "Plaquette 24 comprimés", 3500, "COA-ACT", "6941234567893", 10),
                ("Sérum Physiologique 0.9%", "Flacon 500ml", 1200, "PHY-500", "6941234567894", 25),
                ("Oméprazole 20mg", "Boîte de 14 gélules", 2200, "OME-020", "6941234567895", 8),
                ("Vitamine C 1000mg Effervescente", "Tube de 20 comprimés", 1500, "VIT-C01", "6941234567896", 30),
                ("Ciprofloxacine 500mg", "Boîte de 10 comprimés", 3800, "CIP-500", "6941234567897", 5)
            ]
            for name, pack, price, ref, bc, min_stk in demo_drugs:
                c.execute("INSERT INTO drugs(pharmacy_id, name, pack, price, ref, barcode, min_stock) VALUES(?,?,?,?,?,?,?)",
                          (pid, name, pack, price, ref, bc, min_stk))

            today = dt.datetime.now(TZ).date()
            drugs_map = {d["ref"]: d["id"] for d in c.execute("SELECT id, ref FROM drugs WHERE pharmacy_id=?", (pid,)).fetchall()}
            
            lots_seed = [
                (drugs_map["PAR-500"], "LT-PAR-2401", "2027-08", (today + dt.timedelta(days=600)).isoformat(), 150),
                (drugs_map["PAR-500"], "LT-PAR-2309", "2026-12", (today + dt.timedelta(days=380)).isoformat(), 80),
                (drugs_map["AMO-500"], "LT-AMO-2402", "2027-04", (today + dt.timedelta(days=480)).isoformat(), 65),
                (drugs_map["IBU-400"], "LT-IBU-2311", "2027-02", (today + dt.timedelta(days=420)).isoformat(), 45),
                (drugs_map["COA-ACT"], "LT-COA-2403", "2026-11", (today + dt.timedelta(days=350)).isoformat(), 90),
                (drugs_map["PHY-500"], "LT-PHY-2308", "2026-05", (today + dt.timedelta(days=160)).isoformat(), 40),
                (drugs_map["OME-020"], "LT-OME-2405", "2027-09", (today + dt.timedelta(days=630)).isoformat(), 30),
                (drugs_map["VIT-C01"], "LT-VIT-2312", "2026-03", (today + dt.timedelta(days=100)).isoformat(), 25),
                (drugs_map["CIP-500"], "LT-CIP-2406", "2026-02", (today + dt.timedelta(days=70)).isoformat(), 15)
            ]
            for did, lno, exp, exp_d, qty in lots_seed:
                c.execute("INSERT INTO lots(pharmacy_id, drug_id, lot_no, expiry, expiry_date, qty) VALUES(?,?,?,?,?,?)",
                          (pid, did, lno, exp, exp_d, qty))

            # Clients et ordonnances démo
            cid1 = c.execute("INSERT INTO customers(pharmacy_id, name, phone, consent_sms, ts) VALUES(?,?,?,?,?)",
                             (pid, "Mme Marie Eyenga", "+237 699 12 34 56", 1, now())).lastrowid
            cid2 = c.execute("INSERT INTO customers(pharmacy_id, name, phone, consent_sms, ts) VALUES(?,?,?,?,?)",
                             (pid, "M. Paul Atangana", "+237 677 98 76 54", 1, now())).lastrowid
            
            c.execute("""
                INSERT INTO prescriptions(pharmacy_id, customer_id, doctor, drug_id, posology, refills_total, refills_left, expiry_date, ts)
                VALUES(?,?,?,?,?,?,?,?,?)
            """, (pid, cid1, "Dr. Mbarga (Hôpital Général)", drugs_map["AMO-500"], "1 gélule matin et soir pendant 6 jours", 3, 2, (today + dt.timedelta(days=90)).isoformat(), now()))

            # Caméras démo
            c.execute("INSERT INTO cameras(pharmacy_id, name, location, stream_url) VALUES(?,?,?,?)",
                      (pid, "Caméra Caisse Principale", "Comptoir Vente Caisse 1", "stream://caisse1"))
            c.execute("INSERT INTO cameras(pharmacy_id, name, location, stream_url) VALUES(?,?,?,?)",
                      (pid, "Caméra Allée Médicaments", "Rayonnage Central Officine", "stream://allee1"))
            c.execute("INSERT INTO cameras(pharmacy_id, name, location, stream_url) VALUES(?,?,?,?)",
                      (pid, "Caméra Réserve & Frigo", "Zone Stockage Sécurisée", "stream://reserve"))

# --- ASSETS PWA, SERVICE WORKER & MANIFEST ---

PWA_MANIFEST = json.dumps({
    "name": "PharmaClair - Système Officinal",
    "short_name": "PharmaClair",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0f172a",
    "theme_color": "#059669",
    "orientation": "any",
    "description": "Système de Gestion d'Officine & Point de Vente Offline-First",
    "icons": [
        {"src": "/icons/icon-192.svg", "sizes": "192x192", "type": "image/svg+xml"},
        {"src": "/icons/icon-512.svg", "sizes": "512x512", "type": "image/svg+xml"}
    ]
}, indent=2)

PWA_ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <rect width="512" height="512" rx="100" fill="#059669"/>
  <circle cx="256" cy="256" r="190" fill="#047857"/>
  <rect x="216" y="116" width="80" height="280" rx="20" fill="#ffffff"/>
  <rect x="116" y="216" width="280" height="80" rx="20" fill="#ffffff"/>
  <circle cx="256" cy="256" r="30" fill="#10b981"/>
</svg>"""

SERVICE_WORKER_JS = """// Service Worker PharmaClair - Cache Offline-First & AppShell
const CACHE_NAME = 'pharmaclair-offline-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/icons/icon-192.svg',
  '/icons/icon-512.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS_TO_CACHE))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  
  // AppShell & Navigation : Network-first avec fallback Cache immédiat
  if (event.request.mode === 'navigate' || url.pathname === '/' || url.pathname === '/index.html') {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const resClone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, resClone));
          return response;
        })
        .catch(() => caches.match('/'))
    );
    return;
  }
  
  // Assets statiques et icônes : Cache-first
  if (url.pathname.startsWith('/icons/') || url.pathname.endsWith('.svg') || url.pathname.endsWith('.webmanifest')) {
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request))
    );
    return;
  }
  
  // API endpoints : Network only (intercepté par IndexedDB côté client en cas de coupure)
  event.respondWith(fetch(event.request));
});
"""

HTML_PAGE = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#059669">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="PharmaClair">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" href="/icons/icon-192.svg" type="image/svg+xml">
  <title>PharmaClair — Gestion Officinale & Direction</title>
  <style>
    :root {
      --primary: #059669;
      --primary-dark: #047857;
      --primary-light: #ecfdf5;
      --secondary: #0284c7;
      --secondary-light: #f0f9ff;
      --accent: #d97706;
      --accent-light: #fef3c7;
      --danger: #dc2626;
      --danger-light: #fef2f2;
      --bg: #f8fafc;
      --card: #ffffff;
      --text: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --sidebar-w: 260px;
      --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
      --shadow: 0 4px 6px -1px rgb(0 0 0 / 0.08), 0 2px 4px -2px rgb(0 0 0 / 0.04);
      --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; -webkit-tap-highlight-color: transparent; }
    
    /* Top Header Bar */
    .topbar {
      height: 60px; background: white; border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between; padding: 0 1.25rem;
      position: sticky; top: 0; z-index: 50; box-shadow: var(--shadow-sm);
    }
    .topbar-left { display: flex; align-items: center; gap: 0.85rem; }
    .brand-logo { width: 34px; height: 34px; border-radius: 8px; }
    .brand-title { font-size: 1.15rem; font-weight: 800; color: var(--primary-dark); display: flex; align-items: center; gap: 0.35rem; }
    .brand-pharmacy { font-size: 0.82rem; font-weight: 600; color: var(--text-muted); padding-left: 0.6rem; border-left: 2px solid var(--border); }
    .topbar-right { display: flex; align-items: center; gap: 0.75rem; }
    
    /* Connectivity Status Pill */
    .status-pill {
      display: inline-flex; align-items: center; gap: 0.45rem; padding: 0.3rem 0.75rem;
      border-radius: 9999px; font-size: 0.78rem; font-weight: 600; transition: all 0.2s ease;
    }
    .status-pill.online { background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
    .status-pill.offline { background: #ffedd5; color: #c2410c; border: 1px solid #fed7aa; }
    .status-pill.syncing { background: #e0f2fe; color: #0369a1; border: 1px solid #bae6fd; }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
    
    .sync-btn {
      background: white; border: 1px solid var(--border); padding: 0.35rem 0.75rem;
      border-radius: 8px; font-size: 0.8rem; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 0.35rem; color: var(--text);
    }
    .sync-btn:hover { background: #f1f5f9; }
    .view-switch-btn {
      background: var(--primary-light); color: var(--primary-dark); border: 1px solid #a7f3d0;
      padding: 0.35rem 0.75rem; border-radius: 8px; font-size: 0.8rem; font-weight: 600; cursor: pointer;
    }
    
    /* Layout */
    .app-layout { display: flex; flex: 1; height: calc(100vh - 60px); overflow: hidden; }
    
    /* Sidebar */
    .sidebar {
      width: var(--sidebar-w); background: white; border-right: 1px solid var(--border);
      display: flex; flex-direction: column; overflow-y: auto; padding: 1rem 0.75rem; flex-shrink: 0;
    }
    .nav-section-title {
      font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
      color: #94a3b8; margin: 1.1rem 0.5rem 0.35rem;
    }
    .nav-section-title:first-child { margin-top: 0.2rem; }
    .nav-btn {
      display: flex; align-items: center; gap: 0.7rem; padding: 0.6rem 0.75rem;
      border: none; background: transparent; border-radius: 8px; color: #475569;
      font-size: 0.88rem; font-weight: 500; cursor: pointer; text-align: left; width: 100%; transition: all 0.15s ease;
    }
    .nav-btn svg { width: 18px; height: 18px; stroke-width: 2; flex-shrink: 0; }
    .nav-btn:hover { background: #f8fafc; color: var(--text); }
    .nav-btn.active { background: var(--primary-light); color: var(--primary-dark); font-weight: 600; }
    .nav-badge { margin-left: auto; font-size: 0.72rem; padding: 0.15rem 0.45rem; border-radius: 9999px; background: #e2e8f0; color: #334155; }
    
    /* Content Area */
    .content-area { flex: 1; padding: 1.5rem; overflow-y: auto; background: var(--bg); }
    .content-container { max-width: 1400px; margin: 0 auto; }
    
    /* Cards & Components */
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; box-shadow: var(--shadow-sm); margin-bottom: 1.5rem; }
    .card-title { font-size: 1.15rem; font-weight: 700; margin-bottom: 1.2rem; display: flex; align-items: center; justify-content: space-between; color: #1e293b; }
    
    /* KPI Grid */
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .kpi-card { background: white; border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; box-shadow: var(--shadow-sm); position: relative; }
    .kpi-card.primary { border-top: 4px solid var(--primary); }
    .kpi-card.secondary { border-top: 4px solid var(--secondary); }
    .kpi-card.accent { border-top: 4px solid var(--accent); }
    .kpi-card.danger { border-top: 4px solid var(--danger); }
    .kpi-label { font-size: 0.78rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
    .kpi-val { font-size: 1.7rem; font-weight: 800; color: #0f172a; margin-top: 0.35rem; }
    .kpi-sub { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; display: flex; align-items: center; gap: 0.25rem; }
    .kpi-trend { color: #16a34a; font-weight: 700; }
    
    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th { background: #f8fafc; text-align: left; padding: 0.75rem 1rem; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); }
    td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
    tr:hover td { background: #fbfcfe; }
    
    .badge { display: inline-flex; align-items: center; gap: 0.25rem; padding: 0.2rem 0.55rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .badge-success { background: #dcfce7; color: #166534; }
    .badge-warning { background: var(--accent-light); color: #92400e; }
    .badge-danger { background: var(--danger-light); color: #991b1b; }
    .badge-info { background: var(--secondary-light); color: #075985; }
    
    /* POS Grid */
    .pos-grid { display: grid; grid-template-columns: 1fr 390px; gap: 1.5rem; height: 100%; }
    .cart-box { display: flex; flex-direction: column; height: 100%; }
    .cart-items { flex: 1; overflow-y: auto; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; padding: 0.5rem; min-height: 200px; background: #fafafa; }
    .cart-item { display: flex; justify-content: space-between; align-items: center; padding: 0.55rem 0.7rem; background: white; border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.4rem; }
    .cart-summary { background: #f8fafc; padding: 1rem; border-radius: 8px; border: 1px solid var(--border); display: flex; flex-direction: column; gap: 0.6rem; }
    .cart-summary-line { display: flex; justify-content: space-between; font-size: 0.88rem; }
    .cart-summary-line.total { font-size: 1.35rem; font-weight: 800; color: var(--primary-dark); border-top: 2px dashed var(--border); padding-top: 0.5rem; }
    
    /* Buttons & Form controls */
    input, select, button, textarea { font-size: 0.9rem; border-radius: 8px; }
    input, select, textarea { border: 1px solid var(--border); padding: 0.6rem 0.85rem; width: 100%; outline: none; background: white; }
    input:focus, select:focus, textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(5, 150, 105, 0.15); }
    .btn { border: none; padding: 0.65rem 1.1rem; font-weight: 600; cursor: pointer; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem; transition: background 0.15s ease; }
    .btn-primary { background: var(--primary); color: white; }
    .btn-primary:hover { background: var(--primary-dark); }
    .btn-secondary { background: #e2e8f0; color: #334155; }
    .btn-secondary:hover { background: #cbd5e1; }
    .btn-danger { background: var(--danger); color: white; }
    .btn-sm { padding: 0.35rem 0.65rem; font-size: 0.8rem; }
    
    /* VUE MOBILE PROPRIÉTAIRE (Image 4) */
    .mobile-owner-app {
      display: none; max-width: 480px; margin: 0 auto; min-height: 100vh;
      background: #f8fafc; padding-bottom: 75px; flex-direction: column;
    }
    .mobile-owner-header {
      padding: 1.25rem 1.25rem 0.75rem; display: flex; justify-content: space-between; align-items: flex-start;
    }
    .mobile-greeting-sub { font-size: 0.88rem; color: #64748b; }
    .mobile-pharmacy-title { font-size: 1.35rem; font-weight: 800; color: #0f172a; margin-top: 0.2rem; }
    .mobile-bell-btn { width: 40px; height: 40px; border-radius: 50%; background: white; border: 1px solid var(--border); display: flex; align-items: center; justify-content: center; color: #334155; }
    
    .mobile-hero-card {
      background: linear-gradient(135deg, #059669 0%, #047857 100%);
      color: white; border-radius: 16px; margin: 0 1.25rem 1rem; padding: 1.5rem; box-shadow: var(--shadow);
    }
    .mobile-hero-label { font-size: 0.88rem; opacity: 0.9; font-weight: 500; }
    .mobile-hero-val { font-size: 2.2rem; font-weight: 900; margin: 0.4rem 0 0.5rem; letter-spacing: -0.02em; }
    .mobile-hero-trend { display: inline-flex; align-items: center; gap: 0.3rem; font-size: 0.85rem; font-weight: 600; opacity: 0.95; }
    
    .mobile-metric-grid {
      display: grid; grid-template-columns: 1fr 1fr; gap: 0.85rem; margin: 0 1.25rem 1.25rem;
    }
    .mobile-metric-card {
      background: white; border-radius: 12px; padding: 1.1rem; border: 1px solid var(--border);
    }
    .mobile-metric-lbl { font-size: 0.82rem; color: #64748b; font-weight: 500; }
    .mobile-metric-val { font-size: 1.35rem; font-weight: 800; color: #0f172a; margin-top: 0.35rem; }
    
    .mobile-alerts-section { margin: 0 1.25rem 1.5rem; }
    .mobile-alerts-title { font-size: 1.05rem; font-weight: 700; margin-bottom: 0.85rem; color: #0f172a; }
    .mobile-alert-item {
      background: white; border: 1px solid var(--border); border-radius: 12px;
      padding: 0.9rem 1rem; margin-bottom: 0.65rem; display: flex; align-items: flex-start; gap: 0.75rem;
    }
    .mobile-alert-icon { font-size: 1.1rem; flex-shrink: 0; margin-top: 0.1rem; }
    .mobile-alert-text { font-size: 0.88rem; font-weight: 600; color: #0f172a; }
    .mobile-alert-sub { font-size: 0.78rem; color: #64748b; margin-top: 0.15rem; }
    
    /* Bottom Navigation Bar Mobile */
    .mobile-bottom-nav {
      position: fixed; bottom: 0; left: 0; right: 0; height: 65px; background: white;
      border-top: 1px solid var(--border); display: flex; justify-content: space-around; align-items: center;
      z-index: 100; max-width: 480px; margin: 0 auto; box-shadow: 0 -4px 6px -1px rgb(0 0 0 / 0.04);
    }
    .mobile-nav-item {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      gap: 0.25rem; color: #64748b; text-decoration: none; font-size: 0.72rem; font-weight: 600;
      background: transparent; border: none; cursor: pointer; flex: 1; padding: 0.35rem 0;
    }
    .mobile-nav-item.active { color: var(--primary); }
    .mobile-nav-item svg { width: 20px; height: 20px; stroke-width: 2; }
    
    /* Modal & Thermal Receipt */
    .modal-overlay {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.65);
      display: flex; align-items: center; justify-content: center; z-index: 1000; backdrop-filter: blur(2px);
    }
    .receipt-paper {
      background: white; width: 380px; max-width: 94vw; border-radius: 12px; padding: 1.75rem;
      box-shadow: var(--shadow-lg); font-family: 'Courier New', Courier, monospace; font-size: 0.85rem; line-height: 1.4; color: #111;
    }
    .receipt-paper.format-58mm { width: 280px; font-size: 0.75rem; padding: 1.1rem; }
    
    @media print {
      body * { visibility: hidden; }
      .receipt-paper, .receipt-paper * { visibility: visible; }
      .receipt-paper { position: absolute; left: 0; top: 0; width: 100%; box-shadow: none; border: none; padding: 0; }
      .no-print { display: none !important; }
    }
    
    /* Login Box */
    .login-container {
      max-width: 440px; margin: 4rem auto; background: white; padding: 2.25rem;
      border-radius: 16px; box-shadow: var(--shadow-lg); border: 1px solid var(--border);
    }
    .demo-pill { cursor: pointer; display: inline-block; margin: 0.25rem; padding: 0.35rem 0.6rem; background: #e2e8f0; border-radius: 6px; font-weight: 600; font-size: 0.8rem; }
    .demo-pill:hover { background: #cbd5e1; }
  </style>
</head>
<body>

  <!-- TOP BAR -->
  <header class="topbar" id="app-topbar">
    <div class="topbar-left">
      <svg class="brand-logo" viewBox="0 0 512 512">
        <rect width="512" height="512" rx="100" fill="#059669"/>
        <rect x="216" y="116" width="80" height="280" rx="20" fill="#ffffff"/>
        <rect x="116" y="216" width="280" height="80" rx="20" fill="#ffffff"/>
      </svg>
      <div>
        <div class="brand-title">PharmaClair</div>
      </div>
      <div class="brand-pharmacy" id="topbar-ph-name">Grande Pharmacie du Centre</div>
    </div>
    
    <div class="topbar-right">
      <!-- Status Pill -->
      <div class="status-pill online" id="sync-status-pill" title="Moteur de synchronisation hors-ligne">
        <div class="status-dot"></div>
        <span id="sync-status-text">En ligne</span>
      </div>
      
      <!-- Bouton Sync Manuel -->
      <button class="sync-btn" id="btn-manual-sync" onclick="PharmaSync.forceSync()" title="Forcer la synchronisation avec le cloud">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
        <span id="sync-btn-label">Sync</span>
      </button>
      
      <!-- Basculeur Vue Mobile Propriétaire (Owner uniquement) -->
      <button class="view-switch-btn" id="btn-toggle-owner-mobile" onclick="toggleOwnerMobileView()" style="display:none;">
        📱 Vue Mobile
      </button>
      
      <!-- User info & Logout -->
      <div id="topbar-user-badge" style="font-size:0.85rem; font-weight:600; color:#334155;"></div>
      <button class="btn btn-secondary btn-sm" onclick="logout()" title="Déconnexion">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
      </button>
    </div>
  </header>

  <!-- VUE BUREAU & TABLETTE -->
  <div class="app-layout" id="desktop-app-layout">
    <!-- SIDEBAR HIERARCHIQUE PRO (Images 2 & 3) -->
    <aside class="sidebar" id="app-sidebar">
      
      <div class="nav-section-title">PRINCIPAL</div>
      <button class="nav-btn active" id="nav-owner" onclick="showTab('owner')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        <span>Tableau de bord</span>
      </button>
      <button class="nav-btn" id="nav-pos" onclick="showTab('pos')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/></svg>
        <span>Point de vente</span>
      </button>
      <button class="nav-btn" id="nav-sales" onclick="showTab('sales')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
        <span>Ventes et tickets</span>
      </button>

      <div class="nav-section-title">GESTION PHARMACEUTIQUE</div>
      <button class="nav-btn" id="nav-drugs" onclick="showTab('drugs')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="m10.5 20.5 10-10a4.95 4.95 0 1 0-7-7l-10 10a4.95 4.95 0 1 0 7 7Z"/><path d="m8.5 8.5 7 7"/></svg>
        <span>Catalogue médicaments</span>
      </button>
      <button class="nav-btn" id="nav-stock" onclick="showTab('stock')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
        <span>Stocks et inventaires</span>
      </button>
      <button class="nav-btn" id="nav-lots" onclick="showTab('lots')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
        <span>Lots et péremptions</span>
        <span class="nav-badge" id="lots-badge-count">0</span>
      </button>
      <button class="nav-btn" id="nav-receive" onclick="showTab('receive')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="1" y="3" width="15" height="13"/><polygon points="16 8 20 8 23 11 23 16 16 16 16 8"/><circle cx="5.5" cy="18.5" r="2.5"/><circle cx="18.5" cy="18.5" r="2.5"/></svg>
        <span>Achats et livraisons</span>
      </button>
      <button class="nav-btn" id="nav-customers" onclick="showTab('customers')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        <span>Patients et ordonnances</span>
      </button>

      <div class="nav-section-title">GESTION D'ENTREPRISE</div>
      <button class="nav-btn" id="nav-closing" onclick="showTab('closing')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="4" width="20" height="16" rx="2"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
        <span>Clôture Z et Caisse</span>
      </button>
      <button class="nav-btn" id="nav-users" onclick="showTab('users')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>
        <span>Personnel et pointage</span>
      </button>
      <button class="nav-btn" id="nav-cameras" onclick="showTab('cameras')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>
        <span>Vidéosurveillance</span>
      </button>

      <div class="nav-section-title">ADMINISTRATION</div>
      <button class="nav-btn" id="nav-settings" onclick="showTab('settings')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
        <span>Paramètres officine</span>
      </button>
      <button class="nav-btn" id="nav-subscription" onclick="showTab('subscription')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
        <span>Mon Abonnement (SasPay)</span>
      </button>
      <button class="nav-btn" id="nav-superadmin" onclick="showTab('superadmin')" style="display:none;">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
        <span>Mes pharmacies (SaaS)</span>
      </button>
    </aside>

    <!-- CONTENT WRAPPER -->
    <main class="content-area">
      <div class="content-container">

        <!-- TAB: OWNER DASHBOARD -->
        <section id="tab-owner" class="tab-pane">
          <div class="card-title">
            <div>
              <h2>Tableau de bord de Direction</h2>
              <p style="font-size:0.85rem; color:var(--text-muted); margin-top:0.2rem;" id="dash-date-str">Aujourd'hui</p>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="exportCSV()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Exporter les ventes (CSV)
            </button>
          </div>

          <div class="kpi-grid">
            <div class="kpi-card primary">
              <div class="kpi-label">Chiffre d'Affaires du Jour</div>
              <div class="kpi-val" id="kpi-rev">0 F</div>
              <div class="kpi-sub"><span class="kpi-trend" id="kpi-trend">+0%</span> par rapport à hier</div>
            </div>
            <div class="kpi-card secondary">
              <div class="kpi-label">Bénéfice Brut Estimé</div>
              <div class="kpi-val" id="kpi-profit">0 F</div>
              <div class="kpi-sub">Marge officinale brute ~28%</div>
            </div>
            <div class="kpi-card accent">
              <div class="kpi-label">Transactions & Panier Moyen</div>
              <div class="kpi-val" id="kpi-sales">0 ventes</div>
              <div class="kpi-sub" id="kpi-basket">Panier: 0 F</div>
            </div>
            <div class="kpi-card danger">
              <div class="kpi-label">Lots à Risque (≤ 3 mois)</div>
              <div class="kpi-val" id="kpi-exp">0 lots</div>
              <div class="kpi-sub" style="color:var(--danger)">Surveillance FEFO requise</div>
            </div>
          </div>

          <div style="display:grid; grid-template-columns: 2fr 1fr; gap:1.5rem; margin-bottom:1.5rem;">
            <div class="card" style="margin-bottom:0;">
              <div class="card-title">Dernières Ventes Réalisées</div>
              <table>
                <thead>
                  <tr><th>Ticket</th><th>Heure</th><th>Caissier</th><th>Mode</th><th>Montant</th><th>Action</th></tr>
                </thead>
                <tbody id="dash-recent-sales"></tbody>
              </table>
            </div>

            <div class="card" style="margin-bottom:0;">
              <div class="card-title">Règlements du Jour</div>
              <div style="display:flex; flex-direction:column; gap:0.85rem; margin-top:0.5rem;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <span>💵 Espèces (Cash)</span><b id="pm-cash">0 F</b>
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <span>📱 Mobile Money (OM / MoMo)</span><b id="pm-om">0 F</b>
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <span>💳 Carte Bancaire</span><b id="pm-card">0 F</b>
                </div>
              </div>
            </div>
          </div>
        </section>

        <!-- TAB: POINT DE VENTE (POS) -->
        <section id="tab-pos" class="tab-pane" style="display:none;">
          <div class="pos-grid">
            <div class="card" style="display:flex; flex-direction:column; margin-bottom:0;">
              <div class="card-title">
                <span>Catalogue & Recherche Médicaments</span>
                <span class="badge badge-info" id="pos-terminal-badge">Terminal Caisse</span>
              </div>
              
              <div style="display:flex; gap:0.5rem; margin-bottom:1rem;">
                <input type="text" id="pos-search" placeholder="Rechercher par nom, référence ou code-barres..." oninput="filterPOSCatalog()">
                <button class="btn btn-secondary" onclick="scanBarcodeModal()">📷 Scan</button>
              </div>

              <div style="flex:1; overflow-y:auto; border:1px solid var(--border); border-radius:8px;">
                <table>
                  <thead>
                    <tr><th>Médicament</th><th>Prix</th><th>Stock Disp.</th><th>Prochain Lot (FEFO)</th><th>Action</th></tr>
                  </thead>
                  <tbody id="pos-catalog-body"></tbody>
                </table>
              </div>
            </div>

            <!-- Panier -->
            <div class="card cart-box" style="margin-bottom:0;">
              <div class="card-title">
                <span>Panier Client</span>
                <button class="btn btn-danger btn-sm" onclick="clearCart()">Vider</button>
              </div>

              <div style="margin-bottom:0.75rem;">
                <label style="font-size:0.78rem; font-weight:600; color:var(--text-muted);">Client / Patient (Optionnel)</label>
                <select id="pos-customer-select" style="margin-top:0.25rem;">
                  <option value="">-- Client Comptoir (Anonyme) --</option>
                </select>
              </div>

              <div class="cart-items" id="cart-items-container">
                <div style="text-align:center; padding:2rem; color:var(--text-muted); font-size:0.85rem;">
                  Panier vide. Cliquez sur "+ Ajouter" dans le catalogue.
                </div>
              </div>

              <div class="cart-summary">
                <div class="cart-summary-line">
                  <span>Sous-total</span><b id="cart-subtotal">0 F</b>
                </div>
                <div class="cart-summary-line total">
                  <span>TOTAL À PAYER</span><b id="cart-total">0 F</b>
                </div>
                
                <div style="margin-top:0.5rem;">
                  <label style="font-size:0.78rem; font-weight:600; color:var(--text-muted);">Mode de Règlement</label>
                  <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.35rem; margin-top:0.25rem;">
                    <button class="btn btn-sm btn-secondary" id="pm-btn-cash" onclick="setPayMethod('cash')">💵 Espèces</button>
                    <button class="btn btn-sm btn-secondary" id="pm-btn-om" onclick="setPayMethod('om')">📱 MoMo/OM</button>
                    <button class="btn btn-sm btn-secondary" id="pm-btn-card" onclick="setPayMethod('card')">💳 Carte</button>
                  </div>
                </div>

                <div id="cash-paid-box" style="margin-top:0.4rem;">
                  <label style="font-size:0.78rem; font-weight:600; color:var(--text-muted);">Montant Reçu (Espèces)</label>
                  <input type="number" id="pos-paid-amount" placeholder="Ex: 5000" oninput="calcChange()">
                  <div style="display:flex; justify-content:space-between; font-size:0.85rem; margin-top:0.35rem;">
                    <span>Monnaie à rendre :</span><b id="pos-change-val" style="color:var(--primary-dark)">0 F</b>
                  </div>
                </div>

                <button class="btn btn-primary" style="margin-top:0.75rem; width:100%; padding:0.85rem;" onclick="processCheckout()">
                  ✅ Valider l'Encaissement & Imprimer
                </button>
              </div>
            </div>
          </div>
        </section>

        <!-- TAB: VENTES & TICKETS -->
        <section id="tab-sales" class="tab-pane" style="display:none;">
          <div class="card">
            <div class="card-title">
              <span>Journal des Ventes & Reçus Officinaux</span>
              <button class="btn btn-secondary btn-sm" onclick="loadSales()">🔄 Actualiser</button>
            </div>
            <table>
              <thead>
                <tr><th>N° Ticket</th><th>Date & Heure</th><th>Caissier</th><th>Mode</th><th>Total</th><th>Statut</th><th>Action</th></tr>
              </thead>
              <tbody id="sales-table-body"></tbody>
            </table>
          </div>
        </section>

        <!-- TAB: CATALOGUE MEDICAMENTS -->
        <section id="tab-drugs" class="tab-pane" style="display:none;">
          <div class="card">
            <div class="card-title">
              <span>Catalogue des Médicaments & Spécialités</span>
              <input type="text" id="drug-filter" placeholder="Filtrer..." style="max-width:250px;" oninput="renderDrugsTable()">
            </div>
            <table>
              <thead>
                <tr><th>Réf</th><th>Nom Commercial</th><th>Conditionnement</th><th>Prix Public</th><th>Stock Total</th><th>Seuil Alerte</th></tr>
              </thead>
              <tbody id="drugs-table-body"></tbody>
            </table>
          </div>
        </section>

        <!-- TAB: STOCKS & LOTS -->
        <section id="tab-stock" class="tab-pane" style="display:none;">
          <div class="card">
            <div class="card-title">
              <span>Niveaux de Stocks & Traçabilité</span>
              <button class="btn btn-secondary btn-sm" onclick="loadStockView()">🔄 Actualiser</button>
            </div>
            <table>
              <thead>
                <tr><th>Médicament</th><th>Stock Physique</th><th>Stock Vendable</th><th>Prochaine Péremption</th><th>Lot FEFO</th></tr>
              </thead>
              <tbody id="stock-view-body"></tbody>
            </table>
          </div>
        </section>

        <!-- TAB: LOTS ET PEREMPTIONS -->
        <section id="tab-lots" class="tab-pane" style="display:none;">
          <div class="card">
            <div class="card-title">
              <span>Surveillance des Lots & Péremptions Imminentes (≤ 3 mois)</span>
              <span class="badge badge-warning" id="lots-exp-badge">Alerte FEFO</span>
            </div>
            <table>
              <thead>
                <tr><th>Médicament</th><th>N° Lot</th><th>Date Péremption</th><th>Quantité Restante</th><th>Statut</th><th>Action</th></tr>
              </thead>
              <tbody id="expiring-lots-body"></tbody>
            </table>
          </div>
        </section>

        <!-- TAB: RECEPTION / ACHATS -->
        <section id="tab-receive" class="tab-pane" style="display:none;">
          <div class="card" style="max-width:680px; margin:0 auto;">
            <div class="card-title">Réception de Livraison Fournisseur & Entrée en Stock</div>
            <form onsubmit="handleReceive(event)">
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem;">
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Médicament</label>
                  <select id="rec-drug" required></select>
                </div>
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">N° de Lot Fabricant</label>
                  <input type="text" id="rec-lot" placeholder="Ex: LT-2026-99" required>
                </div>
              </div>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem;">
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Péremption (AAAA-MM ou AAAA-MM-JJ)</label>
                  <input type="text" id="rec-exp" placeholder="Ex: 2027-12" required>
                </div>
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Quantité Reçue (Boîtes)</label>
                  <input type="number" id="rec-qty" min="1" required>
                </div>
              </div>
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1.5rem;">
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Fournisseur / Grossiste</label>
                  <input type="text" id="rec-supplier" placeholder="Ex: Laborex, Cename, Eurapharma">
                </div>
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">N° Bon de Livraison (BL)</label>
                  <input type="text" id="rec-bl" placeholder="Ex: BL-2026-0845">
                </div>
              </div>
              <button type="submit" class="btn btn-primary" style="width:100%;">Valider la Réception & Mettre en Stock</button>
            </form>
          </div>
        </section>

        <!-- TAB: PATIENTS & ORDONNANCES -->
        <section id="tab-customers" class="tab-pane" style="display:none;">
          <div class="card">
            <div class="card-title">
              <span>Répertoire Patients & Ordonnances Chroniques</span>
              <button class="btn btn-primary btn-sm" onclick="sendSmsReminders()">📱 Déclencher Rappels SMS</button>
            </div>
            <table>
              <thead>
                <tr><th>Patient</th><th>Téléphone</th><th>Médecin</th><th>Médicament</th><th>Posologie</th><th>Renouvellements Restants</th></tr>
              </thead>
              <tbody id="prescriptions-table-body"></tbody>
            </table>
          </div>
        </section>

        <!-- TAB: CLOTURE Z DE CAISSE & DEPENSES -->
        <section id="tab-closing" class="tab-pane" style="display:none;">
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:1.5rem;">
            <div class="card">
              <div class="card-title">Clôture de Caisse Journalière (Z de Caisse)</div>
              <form onsubmit="handleClosing(event)">
                <div style="margin-bottom:1rem;">
                  <label style="font-size:0.8rem; font-weight:600;">Fond de Caisse Initial (FCFA)</label>
                  <input type="number" id="close-initial" value="50000" required>
                </div>
                <div style="margin-bottom:1.5rem;">
                  <label style="font-size:0.8rem; font-weight:600;">Espèces Comptées Physiquement (FCFA)</label>
                  <input type="number" id="close-counted" placeholder="Saisir le comptage physique" required>
                </div>
                <button type="submit" class="btn btn-primary" style="width:100%;">Générer le Z de Caisse</button>
              </form>

              <div id="closing-result-box" style="margin-top:1.25rem; display:none; background:#f8fafc; border:1px solid var(--border); border-radius:8px; padding:1rem;"></div>
            </div>

            <div class="card">
              <div class="card-title">Enregistrement d'une Dépense de Caisse</div>
              <form onsubmit="handleExpense(event)">
                <div style="margin-bottom:1rem;">
                  <label style="font-size:0.8rem; font-weight:600;">Montant Décaissé (FCFA)</label>
                  <input type="number" id="exp-amount" min="100" required>
                </div>
                <div style="margin-bottom:1rem;">
                  <label style="font-size:0.8rem; font-weight:600;">Catégorie</label>
                  <select id="exp-category">
                    <option value="fournitures">Fournitures d'officine (sachets, rouleaux)</option>
                    <option value="transport">Frais de transport / livraison</option>
                    <option value="repas">Collation / Garde de nuit</option>
                    <option value="autre">Autre dépense</option>
                  </select>
                </div>
                <div style="margin-bottom:1.5rem;">
                  <label style="font-size:0.8rem; font-weight:600;">Motif / Description</label>
                  <input type="text" id="exp-desc" placeholder="Ex: Rouleaux thermiques 80mm" required>
                </div>
                <button type="submit" class="btn btn-secondary" style="width:100%;">Enregistrer le Décaissement</button>
              </form>
            </div>
          </div>
        </section>

        <!-- TAB: PERSONNEL & POINTAGE -->
        <section id="tab-users" class="tab-pane" style="display:none;">
          <div class="card">
            <div class="card-title">
              <span>Équipe de l'Officine & Registre de Pointage des Arrivées</span>
            </div>
            <table>
              <thead>
                <tr><th>Date</th><th>Heure d'Arrivée</th><th>Employé</th><th>Rôle</th><th>Action</th><th>Statut</th></tr>
              </thead>
              <tbody id="logins-table-body"></tbody>
            </table>
          </div>
        </section>

        <!-- TAB: VIDEOSURVEILLANCE -->
        <section id="tab-cameras" class="tab-pane" style="display:none;">
          <div class="card">
            <div class="card-title">Grille de Vidéosurveillance de l'Officine (Direct)</div>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(280px, 1fr)); gap:1rem;">
              <div style="background:#0f172a; border-radius:12px; padding:1.25rem; color:#e2e8f0; min-height:180px; display:flex; flex-direction:column; justify-content:space-between;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <b>📹 Caisse Principale</b>
                  <span class="badge badge-success">DIRECT</span>
                </div>
                <div style="text-align:center; color:#94a3b8; font-size:0.82rem;">Flux vidéo sécurisé H.264 / RTSP</div>
                <div style="font-size:0.75rem; color:#64748b;">Comptoir Vente Caisse 1 • Douala GMT+1</div>
              </div>
              <div style="background:#0f172a; border-radius:12px; padding:1.25rem; color:#e2e8f0; min-height:180px; display:flex; flex-direction:column; justify-content:space-between;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <b>📹 Allée Médicaments</b>
                  <span class="badge badge-success">DIRECT</span>
                </div>
                <div style="text-align:center; color:#94a3b8; font-size:0.82rem;">Flux vidéo sécurisé H.264 / RTSP</div>
                <div style="font-size:0.75rem; color:#64748b;">Rayonnage Central Officine</div>
              </div>
              <div style="background:#0f172a; border-radius:12px; padding:1.25rem; color:#e2e8f0; min-height:180px; display:flex; flex-direction:column; justify-content:space-between;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <b>📹 Réserve & Frigo Stock</b>
                  <span class="badge badge-success">DIRECT</span>
                </div>
                <div style="text-align:center; color:#94a3b8; font-size:0.82rem;">Flux vidéo sécurisé H.264 / RTSP</div>
                <div style="font-size:0.75rem; color:#64748b;">Zone Chaîne du Froid 2°C - 8°C</div>
              </div>
            </div>
          </div>
        </section>

        <!-- TAB: PARAMETRES OFFICINE (Pour le Titulaire) -->
        <section id="tab-settings" class="tab-pane" style="display:none;">
          <div class="card" style="max-width:760px; margin:0 auto;">
            <div class="card-title">
              <span>Paramètres de l'Officine & Facturation</span>
              <span class="badge badge-info">Titulaire</span>
            </div>
            <form onsubmit="handleSaveSettings(event)">
              <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem;">
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Nom de l'Officine / Pharmacie</label>
                  <input type="text" id="set-name" required>
                </div>
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Ville / Pays</label>
                  <input type="text" id="set-city" placeholder="Douala, Cameroun" required>
                </div>
              </div>

              <div style="margin-bottom:1rem;">
                <label style="font-size:0.8rem; font-weight:600;">Adresse Complète</label>
                <input type="text" id="set-address" placeholder="Ex: Avenue de la Liberté, Akwa" required>
              </div>

              <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem;">
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">N° Téléphone Officine</label>
                  <input type="text" id="set-phone" placeholder="+237 233 42 00 00">
                </div>
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Email de Contact</label>
                  <input type="email" id="set-email" placeholder="contact@pharmacie.cm">
                </div>
              </div>

              <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem;">
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Numéro d'Identification Fiscale (NIF)</label>
                  <input type="text" id="set-tax-id" placeholder="M051812345678X">
                </div>
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Registre du Commerce (RCCM)</label>
                  <input type="text" id="set-rccm" placeholder="RC/DLA/2018/B/142">
                </div>
              </div>

              <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem;">
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Devise Principale</label>
                  <select id="set-currency">
                    <option value="FCFA">FCFA (XAF / Franc CFA)</option>
                    <option value="EUR">EUR (€)</option>
                    <option value="USD">USD ($)</option>
                  </select>
                </div>
                <div>
                  <label style="font-size:0.8rem; font-weight:600;">Format Imprimante Thermique Ticket</label>
                  <select id="set-receipt-format">
                    <option value="80mm">Standard 80 mm (Recommandé)</option>
                    <option value="58mm">Compact 58 mm</option>
                  </select>
                </div>
              </div>

              <div style="margin-bottom:1.5rem;">
                <label style="font-size:0.8rem; font-weight:600;">Message de Bas de Ticket (Footer)</label>
                <textarea id="set-footer" rows="2" placeholder="Ouvert 7j/7 - 24h/24 • Les médicaments ne sont ni repris ni échangés"></textarea>
              </div>

              <button type="submit" class="btn btn-primary" style="width:100%;">Enregistrer les Paramètres</button>
            </form>
          </div>
        </section>

        <!-- TAB: MON ABONNEMENT (SasPay) -->
        <section id="tab-subscription" class="tab-pane" style="display:none;">
          <div class="card" style="max-width:800px; margin:0 auto;">
            <div class="card-title">
              <span>Mon Abonnement PharmaClair (Plateforme SaaS)</span>
              <span class="badge badge-success" id="sub-status-badge">Actif</span>
            </div>

            <div style="background:var(--primary-light); border:1px solid #a7f3d0; border-radius:12px; padding:1.25rem; margin-bottom:1.5rem; display:flex; justify-content:space-between; align-items:center;">
              <div>
                <div style="font-size:0.85rem; color:#065f46; font-weight:600;">Validité de votre accès officine :</div>
                <div style="font-size:1.4rem; font-weight:800; color:#064e3b; margin-top:0.25rem;" id="sub-expiry-date">Valide jusqu'au 27/12/2026</div>
                <div style="font-size:0.8rem; color:#047857; margin-top:0.15rem;" id="sub-days-left">30 jours restants</div>
              </div>
              <div style="text-align:right;">
                <span class="badge badge-info">Paiements sécurisés SasPay</span>
              </div>
            </div>

            <h3 style="font-size:1rem; font-weight:700; margin-bottom:1rem;">Prolonger ou Renouveler votre Abonnement :</h3>
            
            <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:1rem; margin-bottom:1.5rem;">
              <div style="border:2px solid var(--border); border-radius:12px; padding:1.25rem; text-align:center; cursor:pointer;" class="plan-card" onclick="selectSubPlan(1, 35000, this)">
                <div style="font-weight:700; font-size:1.05rem;">1 Mois</div>
                <div style="font-size:1.5rem; font-weight:900; color:var(--primary-dark); margin:0.5rem 0;">35 000 F</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">Sans engagement</div>
              </div>

              <div style="border:2px solid var(--primary); background:#f0fdf4; border-radius:12px; padding:1.25rem; text-align:center; cursor:pointer;" class="plan-card active-plan" onclick="selectSubPlan(3, 95000, this)">
                <span class="badge badge-warning" style="margin-bottom:0.35rem;">POPULAIRE (-10 000 F)</span>
                <div style="font-weight:700; font-size:1.05rem;">3 Mois</div>
                <div style="font-size:1.5rem; font-weight:900; color:var(--primary-dark); margin:0.3rem 0;">95 000 F</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">Soit 31 600 F / mois</div>
              </div>

              <div style="border:2px solid var(--border); border-radius:12px; padding:1.25rem; text-align:center; cursor:pointer;" class="plan-card" onclick="selectSubPlan(12, 350000, this)">
                <span class="badge badge-success" style="margin-bottom:0.35rem;">2 MOIS OFFERTS</span>
                <div style="font-weight:700; font-size:1.05rem;">1 An (12 Mois)</div>
                <div style="font-size:1.5rem; font-weight:900; color:var(--primary-dark); margin:0.3rem 0;">350 000 F</div>
                <div style="font-size:0.75rem; color:var(--text-muted);">Tranquillité totale</div>
              </div>
            </div>

            <div style="background:#f8fafc; border:1px solid var(--border); border-radius:12px; padding:1.25rem; margin-bottom:1.5rem;">
              <h4 style="font-size:0.9rem; font-weight:700; margin-bottom:0.75rem;">Moyen de Paiement SasPay :</h4>
              <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:0.5rem; margin-bottom:1rem;">
                <button type="button" class="btn btn-secondary btn-sm" id="sub-pay-om" onclick="setSubPayMethod('orange_money')">🟠 Orange Money</button>
                <button type="button" class="btn btn-secondary btn-sm" id="sub-pay-momo" onclick="setSubPayMethod('mtn_momo')">🟡 MTN MoMo</button>
                <button type="button" class="btn btn-secondary btn-sm" id="sub-pay-card" onclick="setSubPayMethod('card')">💳 Carte Bancaire</button>
              </div>

              <div id="sub-phone-box" style="margin-bottom:1rem;">
                <label style="font-size:0.8rem; font-weight:600;">Numéro de Téléphone pour la notification USSD :</label>
                <input type="text" id="sub-phone-input" placeholder="+237 6XX XX XX XX" value="+237 699 00 11 22">
              </div>

              <button class="btn btn-primary" style="width:100%; padding:0.85rem;" onclick="processSaspaySubscription()">
                🚀 Déclencher le Paiement SasPay & Activer
              </button>
            </div>
          </div>
        </section>

        <!-- TAB: SUPER-ADMIN (Mes Pharmacies SaaS) -->
        <section id="tab-superadmin" class="tab-pane" style="display:none;">
          <div class="card">
            <div class="card-title">
              <span>Plateforme SaaS PharmaClair — Gestionnaire Multi-Pharmacies</span>
              <span class="badge badge-danger">Super-Admin</span>
            </div>

            <div class="kpi-grid">
              <div class="kpi-card primary">
                <div class="kpi-label">Pharmacies Clientes</div>
                <div class="kpi-val" id="sa-total-ph">0</div>
                <div class="kpi-sub">Officines inscrites</div>
              </div>
              <div class="kpi-card secondary">
                <div class="kpi-label">Revenu Récurrent (MRR)</div>
                <div class="kpi-val" id="sa-mrr">0 F</div>
                <div class="kpi-sub">Abonnements mensuels actifs</div>
              </div>
              <div class="kpi-card accent">
                <div class="kpi-label">Abonnements Actifs / Essai</div>
                <div class="kpi-val" id="sa-active-subs">0 / 0</div>
                <div class="kpi-sub">Statut temps réel</div>
              </div>
              <div class="kpi-card danger">
                <div class="kpi-label">Volume Ventes Plateforme</div>
                <div class="kpi-val" id="sa-total-sales">0 F</div>
                <div class="kpi-sub">Transactions cumulées</div>
              </div>
            </div>

            <h3 style="font-size:1.05rem; font-weight:700; margin:1.5rem 0 0.75rem;">Liste des Officines & Gestion des Abonnements</h3>
            <table>
              <thead>
                <tr><th>ID</th><th>Nom Pharmacie</th><th>Ville</th><th>Contact</th><th>Abonnement</th><th>Expiration</th><th>Action Rapide</th></tr>
              </thead>
              <tbody id="sa-pharmacies-table"></tbody>
            </table>
          </div>
        </section>

      </div>
    </main>
  </div>

  <!-- VUE MOBILE DÉDIÉE PROPRIÉTAIRE ("Bonjour, Docteur" - Image 4) -->
  <div class="mobile-owner-app" id="mobile-owner-view">
    <div class="mobile-owner-header">
      <div>
        <div class="mobile-greeting-sub">Bonjour, Docteur</div>
        <div class="mobile-pharmacy-title" id="mob-ph-name">Votre pharmacie</div>
      </div>
      <button class="mobile-bell-btn" onclick="showTab('customers')">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
      </button>
    </div>

    <!-- Hero Card Ventes -->
    <div class="mobile-hero-card">
      <div class="mobile-hero-label">Ventes aujourd'hui</div>
      <div class="mobile-hero-val" id="mob-sales-val">0 F</div>
      <div class="mobile-hero-trend">
        <span>↗</span> <span id="mob-sales-trend">+0% par rapport à hier</span>
      </div>
    </div>

    <!-- 4 Metric Cards -->
    <div class="mobile-metric-grid">
      <div class="mobile-metric-card">
        <div class="mobile-metric-lbl">Bénéfice brut</div>
        <div class="mobile-metric-val" id="mob-profit-val">0 F</div>
      </div>
      <div class="mobile-metric-card">
        <div class="mobile-metric-lbl">Transactions</div>
        <div class="mobile-metric-val" id="mob-tx-val">0</div>
      </div>
      <div class="mobile-metric-card">
        <div class="mobile-metric-lbl">Employés actifs</div>
        <div class="mobile-metric-val" id="mob-emp-val">0 / 0</div>
      </div>
      <div class="mobile-metric-card">
        <div class="mobile-metric-lbl">Écarts de caisse</div>
        <div class="mobile-metric-val" id="mob-diff-val">0 F</div>
      </div>
    </div>

    <!-- Section Alertes -->
    <div class="mobile-alerts-section">
      <div class="mobile-alerts-title">Alertes en direct</div>
      
      <div class="mobile-alert-item" id="mob-alert-stock">
        <div class="mobile-alert-icon">⚠️</div>
        <div>
          <div class="mobile-alert-text" id="mob-low-stock-text">0 produits en stock faible</div>
          <div class="mobile-alert-sub">Une commande fournisseur est recommandée</div>
        </div>
      </div>

      <div class="mobile-alert-item" id="mob-alert-closing">
        <div class="mobile-alert-icon">🕒</div>
        <div>
          <div class="mobile-alert-text">Clôture de caisse Z</div>
          <div class="mobile-alert-sub" id="mob-closing-sub">Aucune clôture aujourd'hui</div>
        </div>
      </div>

      <div class="mobile-alert-item" id="mob-alert-exp">
        <div class="mobile-alert-icon">⏳</div>
        <div>
          <div class="mobile-alert-text" id="mob-exp-text">0 lots à péremption imminente</div>
          <div class="mobile-alert-sub">Priorité de déstockage FEFO</div>
        </div>
      </div>
    </div>

    <!-- Bottom Navigation Bar Mobile -->
    <nav class="mobile-bottom-nav">
      <button class="mobile-nav-item active" onclick="switchMobileTab('home')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
        <span>Accueil</span>
      </button>
      <button class="mobile-nav-item" onclick="switchMobileTab('stocks')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
        <span>Stocks</span>
      </button>
      <button class="mobile-nav-item" onclick="switchMobileTab('alerts')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
        <span>Alertes</span>
      </button>
      <button class="mobile-nav-item" onclick="switchMobileTab('account')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        <span>Compte</span>
      </button>
    </nav>
  </div>

  <!-- MODAL DE CONNEXION -->
  <div id="login-modal" class="modal-overlay" style="display:none;">
    <div class="login-container">
      <div style="text-align:center; margin-bottom:1.5rem;">
        <svg style="width:48px; height:48px;" viewBox="0 0 512 512">
          <rect width="512" height="512" rx="100" fill="#059669"/>
          <rect x="216" y="116" width="80" height="280" rx="20" fill="#ffffff"/>
          <rect x="116" y="216" width="280" height="80" rx="20" fill="#ffffff"/>
        </svg>
        <h2 style="font-size:1.4rem; font-weight:800; color:var(--text); margin-top:0.5rem;">Connexion PharmaClair</h2>
        <p style="font-size:0.85rem; color:var(--text-muted); margin-top:0.25rem;">Système de Gestion d'Officine & PWA Offline-First</p>
      </div>

      <form onsubmit="handleLogin(event)">
        <div style="margin-bottom:1rem;">
          <label style="font-size:0.8rem; font-weight:600;">Nom d'utilisateur</label>
          <input type="text" id="login-username" required autocomplete="username">
        </div>
        <div style="margin-bottom:1.5rem;">
          <label style="font-size:0.8rem; font-weight:600;">Mot de passe</label>
          <input type="password" id="login-password" required autocomplete="current-password">
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%; padding:0.75rem;">Se Connecter</button>
      </form>

      <div class="demo-accounts">
        <div style="font-weight:700; margin-bottom:0.35rem; color:#475569;">Comptes de test :</div>
        <span class="demo-pill" onclick="fillLogin('titulaire','admin123')">👑 titulaire</span>
        <span class="demo-pill" onclick="fillLogin('caissier1','caisse123')">🛒 caissier1</span>
        <span class="demo-pill" onclick="fillLogin('magasinier','stock123')">📦 magasinier</span>
        <span class="demo-pill" onclick="fillLogin('superadmin','admin123')">⚡ superadmin</span>
      </div>
    </div>
  </div>

  <!-- MODAL REÇU THERMIQUE 58MM / 80MM -->
  <div id="receipt-modal" class="modal-overlay" style="display:none;">
    <div class="receipt-paper" id="receipt-paper-box">
      <div id="receipt-content"></div>
      <div style="display:flex; gap:0.5rem; margin-top:1.5rem;" class="no-print">
        <button class="btn btn-primary" style="flex:1;" onclick="window.print()">🖨️ Imprimer</button>
        <button class="btn btn-secondary" onclick="closeReceiptModal()">Fermer</button>
      </div>
    </div>
  </div>

  <!-- JAVASCRIPT: INDEXEDDB, PWA SERVICE WORKER & APPLICATION CORE -->
  <script>
    // Enregistrement du Service Worker PWA
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').catch(err => console.log('SW fail:', err));
      });
    }

    // Gestionnaire IndexedDB Local pour le fonctionnement 100% Offline-First
    const PharmaLocalDB = {
      db: null,
      init() {
        return new Promise((resolve, reject) => {
          const req = indexedDB.open('PharmaClairLocalDB', 1);
          req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains('drugs')) db.createObjectStore('drugs', { keyPath: 'id' });
            if (!db.objectStoreNames.contains('lots')) db.createObjectStore('lots', { keyPath: 'id' });
            if (!db.objectStoreNames.contains('outbox')) db.createObjectStore('outbox', { keyPath: 'event_id' });
            if (!db.objectStoreNames.contains('sales')) db.createObjectStore('sales', { keyPath: 'id' });
            if (!db.objectStoreNames.contains('offline_sessions')) db.createObjectStore('offline_sessions', { keyPath: 'username' });
            if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta', { keyPath: 'key' });
          };
          req.onsuccess = (e) => {
            this.db = e.target.result;
            resolve(this.db);
          };
          req.onerror = (e) => reject(e);
        });
      },

      async saveCatalog(drugs, lots) {
        if (!this.db) await this.init();
        const tx = this.db.transaction(['drugs', 'lots'], 'readwrite');
        const drugStore = tx.objectStore('drugs');
        const lotStore = tx.objectStore('lots');
        drugStore.clear();
        lotStore.clear();
        drugs.forEach(d => drugStore.put(d));
        lots.forEach(l => lotStore.put(l));
      },

      async getDrugs() {
        if (!this.db) await this.init();
        return new Promise((resolve) => {
          const tx = this.db.transaction('drugs', 'readonly');
          const req = tx.objectStore('drugs').getAll();
          req.onsuccess = () => resolve(req.result || []);
          req.onerror = () => resolve([]);
        });
      },

      async getLotsForDrug(drugId) {
        if (!this.db) await this.init();
        return new Promise((resolve) => {
          const tx = this.db.transaction('lots', 'readonly');
          const req = tx.objectStore('lots').getAll();
          req.onsuccess = () => {
            const all = req.result || [];
            const filtered = all.filter(l => l.drug_id === drugId && l.qty > 0 && l.status === 'ok');
            filtered.sort((a,b) => (a.expiry_date || '').localeCompare(b.expiry_date || ''));
            resolve(filtered);
          };
          req.onerror = () => resolve([]);
        });
      },

      async queueOutbox(event) {
        if (!this.db) await this.init();
        return new Promise((resolve) => {
          const tx = this.db.transaction('outbox', 'readwrite');
          tx.objectStore('outbox').put(event);
          tx.oncomplete = () => resolve();
        });
      },

      async getPendingOutbox() {
        if (!this.db) await this.init();
        return new Promise((resolve) => {
          const tx = this.db.transaction('outbox', 'readonly');
          const req = tx.objectStore('outbox').getAll();
          req.onsuccess = () => resolve(req.result || []);
          req.onerror = () => resolve([]);
        });
      },

      async removeOutboxItems(eventIds) {
        if (!this.db) await this.init();
        const tx = this.db.transaction('outbox', 'readwrite');
        const store = tx.objectStore('outbox');
        eventIds.forEach(id => store.delete(id));
      }
    };

    // Moteur de Synchronisation Durable
    const PharmaSync = {
      isOnline: navigator.onLine,
      isSyncing: false,
      deviceUUID: localStorage.getItem('pharmaclair_device_uuid') || (() => {
        const id = 'DEV-' + Math.random().toString(36).substring(2, 10).toUpperCase();
        localStorage.setItem('pharmaclair_device_uuid', id);
        return id;
      })(),

      async checkNetwork() {
        try {
          const ctl = new AbortController();
          setTimeout(() => ctl.abort(), 2500);
          const res = await fetch('/api/ping', { signal: ctl.signal });
          this.isOnline = res.ok;
        } catch (e) {
          this.isOnline = false;
        }
        this.updateStatusPill();
        if (this.isOnline) {
          this.flushOutbox();
        }
      },

      updateStatusPill() {
        const pill = document.getElementById('sync-status-pill');
        const txt = document.getElementById('sync-status-text');
        if (!pill) return;
        if (this.isSyncing) {
          pill.className = 'status-pill syncing';
          txt.innerText = 'Sync en cours...';
        } else if (this.isOnline) {
          pill.className = 'status-pill online';
          txt.innerText = 'En ligne';
        } else {
          pill.className = 'status-pill offline';
          txt.innerText = 'Hors-ligne (Local)';
        }
      },

      async forceSync() {
        if (this.isSyncing) return;
        this.isSyncing = true;
        this.updateStatusPill();
        try {
          await this.flushOutbox();
          await this.pullDelta();
        } catch (e) {
          console.error('Sync error:', e);
        } finally {
          this.isSyncing = false;
          this.updateStatusPill();
        }
      },

      async flushOutbox() {
        const events = await PharmaLocalDB.getPendingOutbox();
        if (!events || events.length === 0) return;
        try {
          const res = await api('/api/sync/push', 'POST', {
            device_uuid: this.deviceUUID,
            events: events
          });
          if (res && res.processed) {
            await PharmaLocalDB.removeOutboxItems(res.processed);
          }
        } catch (e) {
          console.warn('Outbox push paused (offline)');
        }
      },

      async pullDelta() {
        try {
          const res = await api(`/api/sync/pull?device_uuid=${this.deviceUUID}`);
          if (res && res.drugs) {
            window.DRUGS_CACHE = res.drugs;
            await PharmaLocalDB.saveCatalog(res.drugs, res.lots || []);
            renderPOSCatalog();
            renderDrugsTable();
            if (res.pharmacy) {
              applyPharmacySettingsUI(res.pharmacy);
            }
          }
        } catch (e) {
          console.warn('Delta pull failed (offline)');
        }
      }
    };

    // État Global Application
    let CURRENT_USER = null;
    let CART = [];
    let CURRENT_PAY_METHOD = 'cash';
    let SUB_PLAN_MONTHS = 3;
    let SUB_PAY_METHOD = 'orange_money';

    // Utilitaires API
    async function api(path, method='GET', body=null) {
      const headers = { 'Content-Type': 'application/json' };
      const token = localStorage.getItem('token');
      if (token) headers['Authorization'] = 'Bearer ' + token;
      
      const opts = { method, headers };
      if (body) opts.body = JSON.stringify(body);
      
      const res = await fetch(path, opts);
      if (res.status === 401 || res.status === 403) {
        const text = await res.text();
        if (text.includes('session')) {
          localStorage.removeItem('token');
          showLogin();
          throw new Error('Non autorisé');
        }
      }
      if (!res.ok) {
        let errData;
        try { errData = await res.json(); } catch(e) { errData = { error: res.statusText }; }
        throw new Error(errData.error || 'Erreur serveur');
      }
      return await res.json();
    }

    // Gestion Onglets & Navigation
    function showTab(tabName) {
      document.querySelectorAll('.tab-pane').forEach(el => el.style.display = 'none');
      document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
      
      const pane = document.getElementById('tab-' + tabName);
      const btn = document.getElementById('nav-' + tabName);
      if (pane) pane.style.display = 'block';
      if (btn) btn.classList.add('active');
      
      if (tabName === 'owner') loadDashboard();
      if (tabName === 'pos') renderPOSCatalog();
      if (tabName === 'sales') loadSales();
      if (tabName === 'drugs') renderDrugsTable();
      if (tabName === 'stock') loadStockView();
      if (tabName === 'lots') loadLotsView();
      if (tabName === 'customers') loadCustomersView();
      if (tabName === 'users') loadLoginsView();
      if (tabName === 'settings') loadSettings();
      if (tabName === 'subscription') loadSubscriptionView();
      if (tabName === 'superadmin') loadSuperadminView();
    }

    // Basculement Vue Mobile Propriétaire
    function toggleOwnerMobileView() {
      const desk = document.getElementById('desktop-app-layout');
      const mob = document.getElementById('mobile-owner-view');
      const btn = document.getElementById('btn-toggle-owner-mobile');
      
      if (mob.style.display === 'flex') {
        mob.style.display = 'none';
        desk.style.display = 'flex';
        btn.innerText = '📱 Vue Mobile';
      } else {
        mob.style.display = 'flex';
        desk.style.display = 'none';
        btn.innerText = '💻 Vue Bureau';
        loadDashboard();
      }
    }

    function switchMobileTab(t) {
      document.querySelectorAll('.mobile-nav-item').forEach(el => el.classList.remove('active'));
      if (event && event.currentTarget) event.currentTarget.classList.add('active');
      
      if (t === 'home') {
        loadDashboard();
      } else if (t === 'stocks') {
        toggleOwnerMobileView();
        showTab('stock');
      } else if (t === 'alerts') {
        toggleOwnerMobileView();
        showTab('lots');
      } else if (t === 'account') {
        toggleOwnerMobileView();
        showTab('settings');
      }
    }

    // Authentification
    function showLogin() {
      document.getElementById('login-modal').style.display = 'flex';
    }

    function fillLogin(u, p) {
      document.getElementById('login-username').value = u;
      document.getElementById('login-password').value = p;
    }

    async function handleLogin(e) {
      e.preventDefault();
      const u = document.getElementById('login-username').value.trim();
      const p = document.getElementById('login-password').value;
      try {
        const res = await api('/login', 'POST', { username: u, password: p });
        localStorage.setItem('token', res.token);
        document.getElementById('login-modal').style.display = 'none';
        await checkAuth();
      } catch (err) {
        alert('Échec de connexion : ' + err.message);
      }
    }

    async function checkAuth() {
      const token = localStorage.getItem('token');
      if (!token) return showLogin();
      try {
        const me = await api('/me');
        CURRENT_USER = me;
        document.getElementById('topbar-user-badge').innerText = me.username + ' (' + me.role + ')';
        
        // Ajustement selon rôle
        if (me.role === 'owner' || me.role === 'superadmin') {
          document.getElementById('btn-toggle-owner-mobile').style.display = 'inline-block';
        }
        if (me.role === 'superadmin') {
          document.getElementById('nav-superadmin').style.display = 'flex';
        }
        
        PharmaSync.checkNetwork();
        PharmaSync.pullDelta();
        showTab(me.role === 'cashier' ? 'pos' : 'owner');
      } catch (e) {
        showLogin();
      }
    }

    function logout() {
      localStorage.removeItem('token');
      location.reload();
    }

    // Tableau de Bord & Ventes
    async function loadDashboard() {
      try {
        const stats = await api('/owner/stats');
        // KPIs Desktop
        document.getElementById('dash-date-str').innerText = stats.today_date;
        document.getElementById('kpi-rev').innerText = (stats.total_revenue_today || 0).toLocaleString() + ' F';
        document.getElementById('kpi-profit').innerText = (stats.estimated_profit || 0).toLocaleString() + ' F';
        document.getElementById('kpi-sales').innerText = stats.count_sales_today + ' vente(s)';
        document.getElementById('kpi-basket').innerText = 'Panier: ' + (stats.avg_basket_today || 0).toLocaleString() + ' F';
        document.getElementById('kpi-exp').innerText = stats.expiring_count + ' lot(s)';
        
        const trendEl = document.getElementById('kpi-trend');
        trendEl.innerText = (stats.trend_pct >= 0 ? '+' : '') + stats.trend_pct + '%';
        
        document.getElementById('pm-cash').innerText = (stats.payment_methods.cash || 0).toLocaleString() + ' F';
        document.getElementById('pm-om').innerText = (stats.payment_methods.om || 0).toLocaleString() + ' F';
        document.getElementById('pm-card').innerText = (stats.payment_methods.card || 0).toLocaleString() + ' F';
        
        // Table des ventes récentes
        const body = document.getElementById('dash-recent-sales');
        body.innerHTML = (stats.recent_sales || []).map(s => `
          <tr>
            <td><b>${s.receipt_no}</b></td>
            <td>${s.time}</td>
            <td>${s.cashier}</td>
            <td>${s.method.toUpperCase()}</td>
            <td><b>${s.total.toLocaleString()} F</b></td>
            <td><button class="btn btn-secondary btn-sm" onclick="showReceipt(${s.id})">Ticket</button></td>
          </tr>
        `).join('') || '<tr><td colspan="6" style="text-align:center; color:#94a3b8;">Aucune vente enregistrée aujourd hui.</td></tr>';

        // Vue Mobile Propriétaire
        document.getElementById('mob-sales-val').innerText = (stats.total_revenue_today || 0).toLocaleString() + ' F';
        document.getElementById('mob-sales-trend').innerText = (stats.trend_pct >= 0 ? '+' : '') + stats.trend_pct + '% par rapport a hier';
        document.getElementById('mob-profit-val').innerText = (stats.estimated_profit || 0).toLocaleString() + ' F';
        document.getElementById('mob-tx-val').innerText = stats.count_sales_today;
        document.getElementById('mob-emp-val').innerText = stats.active_employees_ratio || '1 / 1';
        document.getElementById('mob-diff-val').innerText = (stats.cash_discrepancy || 0).toLocaleString() + ' F';
        document.getElementById('mob-low-stock-text').innerText = stats.low_stock_count + ' produit(s) en stock faible';
        document.getElementById('mob-exp-text').innerText = stats.expiring_count + ' lot(s) a peremption imminente';
        
        if (stats.pharmacy && stats.pharmacy.name) {
          applyPharmacySettingsUI(stats.pharmacy);
        }
      } catch (e) {
        console.warn('Dashboard online load failed:', e);
      }
    }

    function applyPharmacySettingsUI(ph) {
      document.getElementById('topbar-ph-name').innerText = ph.name || 'PharmaClair';
      document.getElementById('mob-ph-name').innerText = ph.name || 'Votre pharmacie';
    }

    // POS & Panier
    window.DRUGS_CACHE = [];
    async function renderPOSCatalog() {
      const drugs = window.DRUGS_CACHE.length ? window.DRUGS_CACHE : await PharmaLocalDB.getDrugs();
      window.DRUGS_CACHE = drugs;
      const q = (document.getElementById('pos-search').value || '').toLowerCase().trim();
      
      const filtered = drugs.filter(d => 
        d.name.toLowerCase().includes(q) || 
        d.ref.toLowerCase().includes(q) || 
        (d.barcode && d.barcode.includes(q))
      );

      const tbody = document.getElementById('pos-catalog-body');
      tbody.innerHTML = filtered.map(d => `
        <tr>
          <td><b>${d.name}</b><br><small style="color:var(--text-muted)">${d.pack}</small></td>
          <td><b>${d.price.toLocaleString()} F</b></td>
          <td><span class="badge ${d.sellable > 0 ? 'badge-success' : 'badge-danger'}">${d.sellable} boîtes</span></td>
          <td>${d.next_expiry ? `<span class="badge badge-info">${d.next_expiry} (Lot ${d.next_lot_no || 'N/A'})</span>` : '<span style="color:#94a3b8">Aucun</span>'}</td>
          <td>
            <button class="btn btn-primary btn-sm" onclick="addToCart(${d.id})" ${d.sellable <= 0 ? 'disabled' : ''}>+ Ajouter</button>
          </td>
        </tr>
      `).join('') || '<tr><td colspan="5" style="text-align:center; color:#94a3b8;">Aucun médicament trouvé.</td></tr>';
    }

    function filterPOSCatalog() {
      renderPOSCatalog();
    }

    function addToCart(drugId) {
      const drug = window.DRUGS_CACHE.find(d => d.id === drugId);
      if (!drug) return;
      const exist = CART.find(item => item.drug_id === drugId);
      if (exist) {
        if (exist.qty + 1 > drug.sellable) {
          return alert('Stock vendable maximum atteint pour ce médicament.');
        }
        exist.qty += 1;
      } else {
        CART.push({ drug_id: drugId, name: drug.name, price: drug.price, qty: 1, max: drug.sellable });
      }
      renderCart();
    }

    function renderCart() {
      const container = document.getElementById('cart-items-container');
      if (CART.length === 0) {
        container.innerHTML = '<div style="text-align:center; padding:2rem; color:var(--text-muted); font-size:0.85rem;">Panier vide. Cliquez sur "+ Ajouter" dans le catalogue.</div>';
        document.getElementById('cart-subtotal').innerText = '0 F';
        document.getElementById('cart-total').innerText = '0 F';
        return;
      }

      let total = 0;
      container.innerHTML = CART.map((item, idx) => {
        const lineTotal = item.price * item.qty;
        total += lineTotal;
        return `
          <div class="cart-item">
            <div>
              <div style="font-weight:600; font-size:0.85rem;">${item.name}</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">${item.price.toLocaleString()} F × ${item.qty}</div>
            </div>
            <div style="display:flex; align-items:center; gap:0.4rem;">
              <b>${lineTotal.toLocaleString()} F</b>
              <button class="btn btn-secondary btn-sm" style="padding:0.2rem 0.45rem;" onclick="changeCartQty(${idx}, -1)">-</button>
              <button class="btn btn-secondary btn-sm" style="padding:0.2rem 0.45rem;" onclick="changeCartQty(${idx}, 1)">+</button>
            </div>
          </div>
        `;
      }).join('');

      document.getElementById('cart-subtotal').innerText = total.toLocaleString() + ' F';
      document.getElementById('cart-total').innerText = total.toLocaleString() + ' F';
      calcChange();
    }

    function changeCartQty(idx, delta) {
      CART[idx].qty += delta;
      if (CART[idx].qty <= 0) CART.splice(idx, 1);
      renderCart();
    }

    function clearCart() {
      CART = [];
      renderCart();
    }

    function setPayMethod(m) {
      CURRENT_PAY_METHOD = m;
      document.querySelectorAll('#tab-pos .cart-summary button').forEach(b => {
        if (b.id && b.id.startsWith('pm-btn-')) b.classList.replace('btn-primary', 'btn-secondary');
      });
      const act = document.getElementById('pm-btn-' + m);
      if (act) act.classList.replace('btn-secondary', 'btn-primary');
      document.getElementById('cash-paid-box').style.display = (m === 'cash') ? 'block' : 'none';
      calcChange();
    }

    function calcChange() {
      const total = CART.reduce((acc, it) => acc + (it.price * it.qty), 0);
      const paid = parseInt(document.getElementById('pos-paid-amount').value || total);
      const change = Math.max(0, paid - total);
      document.getElementById('pos-change-val').innerText = change.toLocaleString() + ' F';
    }

    // Encaissement Atomique (Online & Offline avec FEFO Local)
    async function processCheckout() {
      if (CART.length === 0) return alert('Le panier est vide.');
      const total = CART.reduce((acc, it) => acc + (it.price * it.qty), 0);
      const paidInput = document.getElementById('pos-paid-amount').value;
      const paid = CURRENT_PAY_METHOD === 'cash' ? parseInt(paidInput || total) : total;
      if (paid < total) return alert('Le montant payé est inférieur au total.');

      const items = CART.map(i => [i.drug_id, i.qty]);
      const idem = 'IDEM-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8).toUpperCase();
      const customerId = document.getElementById('pos-customer-select').value || null;

      // Si online, on tente la vente directe
      if (PharmaSync.isOnline) {
        try {
          const res = await api('/sale', 'POST', {
            idem, items, method: CURRENT_PAY_METHOD, paid, customer_id: customerId
          });
          clearCart();
          showReceipt(res.sale_id);
          PharmaSync.pullDelta();
          return;
        } catch (e) {
          console.warn('Vente en ligne échouée, bascule offline:', e.message);
        }
      }

      // Traitement Offline-First en IndexedDB
      const offlineSale = {
        event_id: 'EVT-' + crypto.randomUUID(),
        event_type: 'sale',
        timestamp: new Date().toISOString(),
        payload: { idem, items, method: CURRENT_PAY_METHOD, paid, customer_id: customerId, is_offline: 1 }
      };
      await PharmaLocalDB.queueOutbox(offlineSale);
      clearCart();
      alert('Vente enregistrée en mode HORS-LIGNE. Le stock local a été réservé et le ticket sera synchronisé automatiquement.');
      PharmaSync.updateStatusPill();
    }

    // Affichage Reçu Thermique 58mm / 80mm
    async function showReceipt(saleId) {
      try {
        const rcpt = await api('/receipt/' + saleId);
        const modal = document.getElementById('receipt-modal');
        const box = document.getElementById('receipt-paper-box');
        box.className = 'receipt-paper' + (rcpt.pharmacy.format === '58mm' ? ' format-58mm' : '');
        
        let linesHtml = (rcpt.lines || []).map(l => `
          <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem;">
            <span>${l.qty}x ${l.label}</span>
            <b>${(l.price * l.qty).toLocaleString()}</b>
          </div>
        `).join('');

        document.getElementById('receipt-content').innerHTML = `
          <div style="text-align:center; border-bottom:1px dashed #475569; padding-bottom:0.6rem; margin-bottom:0.6rem;">
            <div style="font-weight:900; font-size:1.15rem;">${rcpt.pharmacy.name}</div>
            <div>${rcpt.pharmacy.address}</div>
            <div>Tél: ${rcpt.pharmacy.phone || 'N/A'}</div>
            <div>NIF: ${rcpt.pharmacy.tax_id} | RCCM: ${rcpt.pharmacy.rccm || ''}</div>
          </div>

          <div style="font-size:0.8rem; margin-bottom:0.6rem;">
            <div><b>TICKET N° : ${rcpt.receipt_no}</b></div>
            <div>Date : ${rcpt.full_timestamp}</div>
            <div>Caissier : ${rcpt.cashier}</div>
            ${rcpt.customer ? `<div>Patient : ${rcpt.customer.name}</div>` : ''}
            ${rcpt.is_offline ? `<div style="color:var(--accent); font-weight:700;">[VENTE VALIDÉE HORS-LIGNE]</div>` : ''}
            ${rcpt.reprint ? `<div style="color:var(--danger); font-weight:700;">*** DUPLICATA ***</div>` : ''}
          </div>

          <div style="border-top:1px dashed #475569; border-bottom:1px dashed #475569; padding:0.6rem 0; margin-bottom:0.6rem;">
            ${linesHtml}
          </div>

          <div style="display:flex; justify-content:space-between; font-size:1.1rem; font-weight:900; margin-bottom:0.35rem;">
            <span>TOTAL :</span>
            <span>${rcpt.total.toLocaleString()} ${rcpt.pharmacy.currency}</span>
          </div>

          <div style="font-size:0.82rem; margin-bottom:0.75rem;">
            <div>Payé (${rcpt.method.toUpperCase()}) : ${rcpt.paid.toLocaleString()} ${rcpt.pharmacy.currency}</div>
            <div>Rendu monnaie : ${rcpt.change.toLocaleString()} ${rcpt.pharmacy.currency}</div>
          </div>

          <div style="text-align:center; font-size:0.75rem; color:#475569; border-top:1px dashed #475569; padding-top:0.5rem;">
            ${rcpt.pharmacy.footer || 'Merci pour votre confiance. Bon rétablissement.'}
          </div>
        `;
        modal.style.display = 'flex';
      } catch (e) {
        alert('Impossible de charger le reçu : ' + e.message);
      }
    }

    function closeReceiptModal() {
      document.getElementById('receipt-modal').style.display = 'none';
    }

    // Gestion Paramètres Officine (Titulaire)
    async function loadSettings() {
      try {
        const ph = await api('/api/settings');
        document.getElementById('set-name').value = ph.name || '';
        document.getElementById('set-city').value = ph.city || 'Douala';
        document.getElementById('set-address').value = ph.address || '';
        document.getElementById('set-phone').value = ph.phone || '';
        document.getElementById('set-email').value = ph.email || '';
        document.getElementById('set-tax-id').value = ph.tax_id || '';
        document.getElementById('set-rccm').value = ph.rccm || '';
        document.getElementById('set-currency').value = ph.currency || 'FCFA';
        document.getElementById('set-receipt-format').value = ph.receipt_format || '80mm';
        document.getElementById('set-footer').value = ph.footer || '';
      } catch (e) {
        console.error('Settings load error:', e);
      }
    }

    async function handleSaveSettings(e) {
      e.preventDefault();
      try {
        const data = {
          name: document.getElementById('set-name').value,
          city: document.getElementById('set-city').value,
          address: document.getElementById('set-address').value,
          phone: document.getElementById('set-phone').value,
          email: document.getElementById('set-email').value,
          tax_id: document.getElementById('set-tax-id').value,
          rccm: document.getElementById('set-rccm').value,
          currency: document.getElementById('set-currency').value,
          receipt_format: document.getElementById('set-receipt-format').value,
          footer: document.getElementById('set-footer').value
        };
        const updated = await api('/api/settings', 'POST', data);
        applyPharmacySettingsUI(updated);
        alert('Paramètres officine enregistrés avec succès !');
      } catch (err) {
        alert('Erreur enregistrement : ' + err.message);
      }
    }

    // Gestion Abonnement SasPay
    function selectSubPlan(months, amount, cardEl) {
      SUB_PLAN_MONTHS = months;
      document.querySelectorAll('.plan-card').forEach(c => {
        c.style.borderColor = 'var(--border)';
        c.style.background = 'white';
      });
      cardEl.style.borderColor = 'var(--primary)';
      cardEl.style.background = '#f0fdf4';
    }

    function setSubPayMethod(m) {
      SUB_PAY_METHOD = m;
      document.getElementById('sub-pay-om').classList.replace('btn-primary', 'btn-secondary');
      document.getElementById('sub-pay-momo').classList.replace('btn-primary', 'btn-secondary');
      document.getElementById('sub-pay-card').classList.replace('btn-primary', 'btn-secondary');
      
      if (m === 'orange_money') document.getElementById('sub-pay-om').classList.replace('btn-secondary', 'btn-primary');
      if (m === 'mtn_momo') document.getElementById('sub-pay-momo').classList.replace('btn-secondary', 'btn-primary');
      if (m === 'card') document.getElementById('sub-pay-card').classList.replace('btn-secondary', 'btn-primary');
    }

    async function processSaspaySubscription() {
      const phone = document.getElementById('sub-phone-input').value.trim();
      if (!phone) return alert('Veuillez renseigner votre numéro de téléphone.');
      try {
        const res = await api('/api/subscription/pay', 'POST', {
          months: SUB_PLAN_MONTHS,
          method: SUB_PAY_METHOD,
          phone: phone
        });
        alert(`Paiement SasPay validé avec succès !\nRéf: ${res.payment_ref}\nVotre abonnement est maintenant actif jusqu'au ${res.new_expiry}.`);
        loadSubscriptionView();
      } catch (err) {
        alert('Erreur SasPay : ' + err.message);
      }
    }

    async function loadSubscriptionView() {
      try {
        const ph = await api('/api/settings');
        const exp = ph.subscription_expires_at || '2026-12-31';
        document.getElementById('sub-expiry-date').innerText = "Valide jusqu'au " + exp;
        const diff = Math.max(0, Math.ceil((new Date(exp) - new Date()) / (1000 * 60 * 60 * 24)));
        document.getElementById('sub-days-left').innerText = diff + ' jour(s) restants';
      } catch (e) {}
    }

    // Gestion Super-Admin (SaaS Plateforme)
    async function loadSuperadminView() {
      try {
        const data = await api('/api/superadmin/stats');
        document.getElementById('sa-total-ph').innerText = data.total_pharmacies;
        document.getElementById('sa-mrr').innerText = data.mrr.toLocaleString() + ' F';
        document.getElementById('sa-active-subs').innerText = `${data.active_subscriptions} / ${data.trial_subscriptions}`;
        document.getElementById('sa-total-sales').innerText = data.total_sales_volume.toLocaleString() + ' F';

        const tbody = document.getElementById('sa-pharmacies-table');
        tbody.innerHTML = (data.pharmacies || []).map(p => `
          <tr>
            <td>#${p.id}</td>
            <td><b>${p.name}</b><br><small>${p.address}</small></td>
            <td>${p.city || 'Douala'}</td>
            <td>${p.phone || 'N/A'}</td>
            <td><span class="badge ${p.subscription_status === 'active' ? 'badge-success' : 'badge-warning'}">${p.subscription_status || 'trial'}</span></td>
            <td>${p.subscription_expires_at || 'N/A'}</td>
            <td>
              <button class="btn btn-secondary btn-sm" onclick="superadminExtend(${p.id}, 30)">+30 jours</button>
              <button class="btn btn-secondary btn-sm" onclick="superadminExtend(${p.id}, 90)">+90 jours</button>
            </td>
          </tr>
        `).join('');
      } catch (e) {
        console.error('Superadmin view error:', e);
      }
    }

    async function superadminExtend(phId, days) {
      try {
        await api('/api/superadmin/extend', 'POST', { pharmacy_id: phId, days: days });
        alert(`Abonnement prolongé de ${days} jours pour la pharmacie #${phId}.`);
        loadSuperadminView();
      } catch (err) {
        alert('Erreur : ' + err.message);
      }
    }

    // Clôture Z & Dépenses
    async function handleClosing(e) {
      e.preventDefault();
      const initCash = parseInt(document.getElementById('close-initial').value || 0);
      const counted = parseInt(document.getElementById('close-counted').value);
      try {
        const res = await api('/cash_closing', 'POST', { initial_cash: initCash, counted_cash: counted });
        const box = document.getElementById('closing-result-box');
        box.style.display = 'block';
        box.innerHTML = `
          <div style="font-weight:700; margin-bottom:0.5rem;">Rapport Z de Caisse Validé</div>
          <div>Total Ventes du Jour : <b>${res.total_day.toLocaleString()} F</b></div>
          <div>Espèces Théoriques : <b>${res.theoretical_cash.toLocaleString()} F</b></div>
          <div>Espèces Comptées : <b>${res.counted_cash.toLocaleString()} F</b></div>
          <div style="margin-top:0.35rem; font-weight:700; color:${res.diff_cash === 0 ? 'var(--primary-dark)' : 'var(--danger)'}">
            Écart de Caisse : ${res.diff_cash >= 0 ? '+' : ''}${res.diff_cash.toLocaleString()} F (${res.status.toUpperCase()})
          </div>
        `;
        alert('Clôture Z enregistrée.');
      } catch (err) {
        alert('Erreur clôture : ' + err.message);
      }
    }

    async function handleExpense(e) {
      e.preventDefault();
      const amt = parseInt(document.getElementById('exp-amount').value);
      const cat = document.getElementById('exp-category').value;
      const desc = document.getElementById('exp-desc').value;
      try {
        await api('/api/expenses/create', 'POST', { amount: amt, category: cat, description: desc });
        alert('Dépense enregistrée.');
        document.getElementById('exp-amount').value = '';
        document.getElementById('exp-desc').value = '';
      } catch (err) {
        alert('Erreur dépense : ' + err.message);
      }
    }

    // Autres vues secondaires
    async function loadSales() {
      try {
        const sales = await api('/sales');
        const tbody = document.getElementById('sales-table-body');
        tbody.innerHTML = sales.map(s => `
          <tr>
            <td><b>${s.receipt_no}</b></td>
            <td>${s.full_ts}</td>
            <td>${s.cashier_name}</td>
            <td>${s.method.toUpperCase()}</td>
            <td><b>${s.total.toLocaleString()} F</b></td>
            <td><span class="badge ${s.is_offline ? 'badge-warning' : 'badge-success'}">${s.is_offline ? 'Offline' : 'Direct'}</span></td>
            <td><button class="btn btn-secondary btn-sm" onclick="showReceipt(${s.id})">Reçu</button></td>
          </tr>
        `).join('') || '<tr><td colspan="7" style="text-align:center;">Aucune vente enregistrée.</td></tr>';
      } catch (e) {}
    }

    function renderDrugsTable() {
      const q = (document.getElementById('drug-filter') ? document.getElementById('drug-filter').value : '').toLowerCase().trim();
      const tbody = document.getElementById('drugs-table-body');
      if (!tbody) return;
      const drugs = window.DRUGS_CACHE || [];
      const filtered = drugs.filter(d => d.name.toLowerCase().includes(q) || d.ref.toLowerCase().includes(q));
      tbody.innerHTML = filtered.map(d => `
        <tr>
          <td><code>${d.ref}</code></td>
          <td><b>${d.name}</b></td>
          <td>${d.pack}</td>
          <td><b>${d.price.toLocaleString()} F</b></td>
          <td><span class="badge ${d.physical > d.min_stock ? 'badge-success' : 'badge-danger'}">${d.physical}</span></td>
          <td>${d.min_stock}</td>
        </tr>
      `).join('') || '<tr><td colspan="6" style="text-align:center;">Aucun médicament.</td></tr>';
    }

    async function loadStockView() {
      const drugs = await api('/drugs');
      window.DRUGS_CACHE = drugs;
      const tbody = document.getElementById('stock-view-body');
      tbody.innerHTML = drugs.map(d => `
        <tr>
          <td><b>${d.name}</b><br><small>${d.pack}</small></td>
          <td>${d.physical}</td>
          <td><span class="badge ${d.sellable > 0 ? 'badge-success' : 'badge-danger'}">${d.sellable} boîtes</span></td>
          <td>${d.next_expiry || 'N/A'}</td>
          <td><code>${d.next_lot_no || 'N/A'}</code></td>
        </tr>
      `).join('');
    }

    async function loadLotsView() {
      const stats = await api('/owner/stats');
      const tbody = document.getElementById('expiring-lots-body');
      tbody.innerHTML = (stats.expiring_lots || []).map(l => `
        <tr>
          <td><b>${l.drug_name}</b></td>
          <td><code>${l.lot_no}</code></td>
          <td><span class="badge badge-warning">${l.expiry}</span></td>
          <td><b>${l.qty} boîtes</b></td>
          <td><span class="badge ${l.status === 'ok' ? 'badge-success' : 'badge-danger'}">${l.status}</span></td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="toggleLotBlock(${l.id}, '${l.status === 'ok' ? 'blocked' : 'ok'}')">
              ${l.status === 'ok' ? 'Bloquer' : 'Débloquer'}
            </button>
          </td>
        </tr>
      `).join('') || '<tr><td colspan="6" style="text-align:center;">Aucun lot à risque immédiat.</td></tr>';
    }

    async function toggleLotBlock(lotId, status) {
      try {
        await api('/lot/block', 'POST', { lot_id: lotId, status: status });
        loadLotsView();
      } catch (err) {
        alert(err.message);
      }
    }

    async function loadCustomersView() {
      const prescs = await api('/prescriptions');
      const tbody = document.getElementById('prescriptions-table-body');
      tbody.innerHTML = prescs.map(p => `
        <tr>
          <td><b>${p.customer_name}</b></td>
          <td>${p.customer_phone}</td>
          <td>${p.doctor}</td>
          <td>${p.drug_name}</td>
          <td>${p.posology}</td>
          <td><span class="badge badge-info">${p.refills_left} restants</span></td>
        </tr>
      `).join('');
    }

    async function sendSmsReminders() {
      try {
        const res = await api('/notifications/send_reminders', 'POST');
        alert(`${res.reminders_sent} rappel(s) SMS envoyé(s) avec succès !`);
      } catch (err) {
        alert(err.message);
      }
    }

    async function loadLoginsView() {
      const rows = await api('/employee_logins');
      const tbody = document.getElementById('logins-table-body');
      tbody.innerHTML = rows.map(r => `
        <tr>
          <td>${r.date}</td>
          <td><b>${r.time}</b></td>
          <td><b>${r.username}</b></td>
          <td><span class="badge badge-info">${r.role}</span></td>
          <td>${r.action}</td>
          <td><span class="badge badge-success">Enregistré</span></td>
        </tr>
      `).join('');
    }

    async function handleReceive(e) {
      e.preventDefault();
      try {
        await api('/receive', 'POST', {
          drug_id: parseInt(document.getElementById('rec-drug').value),
          lot_no: document.getElementById('rec-lot').value.trim(),
          expiry: document.getElementById('rec-exp').value.trim(),
          qty: parseInt(document.getElementById('rec-qty').value),
          supplier: document.getElementById('rec-supplier').value.trim(),
          bl: document.getElementById('rec-bl').value.trim()
        });
        alert('Réception enregistrée avec succès.');
        showTab('stock');
      } catch (err) {
        alert(err.message);
      }
    }

    function exportCSV() {
      window.location.href = '/export';
    }

    // Initialisation au chargement
    window.addEventListener('DOMContentLoaded', () => {
      PharmaLocalDB.init();
      checkAuth();
      setInterval(() => PharmaSync.checkNetwork(), 30000);
      window.addEventListener('online', () => PharmaSync.checkNetwork());
      window.addEventListener('offline', () => PharmaSync.checkNetwork());
    });
  </script>
</body>
</html>"""

def make_handler(c):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, data, content_type="application/json; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            b = data.encode("utf-8") if isinstance(data, str) else json.dumps(data).encode("utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()

        def _get_auth_user(self):
            token = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
            if not token and "?" in self.path:
                from urllib.parse import parse_qs, urlparse
                qs = parse_qs(urlparse(self.path).query)
                token = qs.get("token", [""])[0]
            return auth(c, token)

        def _run(self, method):
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(self.path)
            parsed_path = parsed.path
            qs = parse_qs(parsed.query)
            p = parsed_path.split("/")

            # Route PWA Manifest & Service Worker
            if method == "GET" and (parsed_path in ("/", "/index.html", "/app")):
                return self._send(200, HTML_PAGE, "text/html; charset=utf-8")

            if method == "GET" and (parsed_path in ("/manifest.webmanifest", "/manifest.json")):
                return self._send(200, PWA_MANIFEST, "application/manifest+json; charset=utf-8")

            if method == "GET" and parsed_path == "/sw.js":
                return self._send(200, SERVICE_WORKER_JS, "application/javascript; charset=utf-8")

            if method == "GET" and parsed_path.startswith("/icons/"):
                return self._send(200, PWA_ICON_SVG, "image/svg+xml; charset=utf-8")

            # Route Ping réseau
            if method == "GET" and parsed_path == "/api/ping":
                return self._send(200, {"status": "ok", "server_time": now()})

            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}") if n > 0 else {}
            client_ip = self.headers.get("X-Forwarded-For") or self.client_address[0]

            try:
                if method == "POST" and parsed_path == "/login":
                    return self._send(200, {"token": login(c, body["username"], body["password"], client_ip)})

                u = self._get_auth_user()

                if method == "GET" and parsed_path == "/me":
                    return self._send(200, {
                        "id": u["id"], "username": u["username"], "role": u["role"],
                        "pharmacy_id": u["pharmacy_id"], "can_block": u["can_block"], "can_cash": u["can_cash"]
                    })

                # Moteur de Synchronisation Hors-Ligne
                if method == "POST" and parsed_path == "/api/sync/push":
                    res = sync_push_events(c, u, body.get("device_uuid", ""), body.get("events", []))
                    return self._send(200, res)

                if method == "GET" and parsed_path == "/api/sync/pull":
                    device_uuid = qs.get("device_uuid", [""])[0]
                    since = qs.get("since", [None])[0]
                    return self._send(200, sync_pull_delta(c, u, since, device_uuid))

                # Paramètres de l'officine
                if method == "GET" and parsed_path == "/api/settings":
                    return self._send(200, get_pharmacy_settings(c, u))

                if method == "POST" and parsed_path == "/api/settings":
                    return self._send(200, update_pharmacy_settings(c, u, body))

                # Abonnements SasPay
                if method == "POST" and parsed_path == "/api/subscription/pay":
                    res = pay_subscription_saspay(c, u, int(body.get("months", 1)), body.get("method", "orange_money"), body.get("phone", ""))
                    return self._send(200, res)

                # Dépenses de caisse
                if method == "POST" and parsed_path == "/api/expenses/create":
                    eid = record_expense(c, u, int(body["amount"]), body.get("category", "autre"), body.get("description", ""))
                    return self._send(200, {"expense_id": eid})

                if method == "GET" and parsed_path == "/api/expenses":
                    return self._send(200, list_expenses(c, u))

                # Super-Admin (SaaS Plateforme)
                if method == "GET" and parsed_path == "/api/superadmin/stats":
                    return self._send(200, superadmin_stats(c, u))

                if method == "POST" and parsed_path == "/api/superadmin/extend":
                    res = superadmin_extend_subscription(c, u, int(body["pharmacy_id"]), int(body["days"]))
                    return self._send(200, res)

                # Dashboard & Statistiques Direction
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

                if method == "GET" and parsed_path == "/customers":
                    return self._send(200, list_customers(c, u))

                if method == "POST" and parsed_path == "/customer/create":
                    cid = create_customer(c, u, body["name"], body["phone"], body.get("consent_sms", 1))
                    return self._send(200, {"customer_id": cid})

                if method == "GET" and parsed_path == "/prescriptions":
                    cid = int(qs.get("customer_id", [0])[0]) if "customer_id" in qs else None
                    return self._send(200, list_prescriptions(c, u, cid))

                if method == "POST" and parsed_path == "/prescription/create":
                    pid = create_prescription(c, u, int(body["customer_id"]), body["doctor"], int(body["drug_id"]),
                                              body["posology"], int(body["refills_total"]), body["expiry_date"])
                    return self._send(200, {"prescription_id": pid})

                if method == "GET" and parsed_path == "/notifications":
                    return self._send(200, list_sms_notifs(c, u))

                if method == "POST" and parsed_path == "/notifications/send_reminders":
                    return self._send(200, send_automated_reminders(c, u))

                if method == "GET" and parsed_path == "/employee_logins":
                    return self._send(200, list_employee_logins(c, u))

                if method == "GET" and parsed_path == "/cameras":
                    return self._send(200, list_cameras(c, u))

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
                    return self._send(200, {"sale_id": sell(c, u, body["idem"], body["items"], body["method"],
                                                            body.get("paid"), body.get("customer_id"), body.get("prescription_id"),
                                                            is_offline=int(body.get("is_offline", 0)))})

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
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    db_file = os.environ.get("DB", "pharmaclair.db")
    conn = connect(db_file)
    seed_demo_data(conn)
    
    primary_port = int(os.environ.get("PORT", 8000))
    handler = make_handler(conn)
    
    ports_to_try = [primary_port]
    for p in (8000, 8080):
        if p not in ports_to_try:
            ports_to_try.append(p)
            
    active_servers = []
    for p in ports_to_try:
        try:
            srv = ThreadingHTTPServer(("0.0.0.0", p), handler)
            print(f"🚀 PharmaClair à l'écoute sur http://0.0.0.0:{p}", flush=True)
            active_servers.append(srv)
        except Exception as e:
            print(f"Port {p} non disponible: {e}", flush=True)
            
    if not active_servers:
        print("Erreur critique: Aucun port n'a pu être ouvert.", flush=True)
        sys.exit(1)
        
    for srv in active_servers[1:]:
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        
    try:
        active_servers[0].serve_forever()
    except KeyboardInterrupt:
        pass
