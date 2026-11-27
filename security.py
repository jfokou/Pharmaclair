"""
PharmaClair — Sécurité, Authentification, RBAC & Isolation Multi-Tenant.
Garantit le principe de moindre privilège et la séparation stricte Plateforme vs Officine.
"""
import hashlib
import secrets
import json
import datetime as dt
from schema import DB_LOCK, TZ, now

class Denied(Exception): pass
class Conflict(Exception): pass

PLATFORM_ROLES = {"superadmin", "sales_rep", "support"}
PHARMACY_ROLES = {"owner", "pharmacist", "branch_manager", "cashier", "stock", "accountant", "auditor"}

PLATFORM_PERMS = {
    "superadmin": {"platform_admin", "platform_billing", "platform_crm", "platform_support", "platform_plans", "platform_expenses"},
    "sales_rep": {"platform_crm"},
    "support": {"platform_support"}
}

PHARMACY_PERMS = {
    "owner": {"pharmacy_all"},
    "pharmacist": {
        "sell", "stock_view", "receive", "customers", "prescriptions",
        "clinical_validate", "notifs", "own_sales", "return_approve"
    },
    "branch_manager": {
        "sell", "stock_view", "receive", "count", "cash_count", "customers",
        "prescriptions", "own_sales", "branch_reports", "users_view", "expenses"
    },
    "cashier": {
        "sell", "stock_view", "own_sales", "return_request", "cash_count"
    },
    "stock": {
        "stock_view", "receive", "count", "suppliers_view", "purchase_orders"
    },
    "accountant": {
        "finance_view", "expenses", "cash_count", "exports", "suppliers_view", "reports"
    },
    "auditor": {
        "audit_view", "finance_view", "stock_view", "reports", "exports"
    }
}

def hpw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()

def get_user_perms(c, u):
    role = u.get("role", "")
    if role in PLATFORM_ROLES:
        return set(PLATFORM_PERMS.get(role, set()))
    p = set(PHARMACY_PERMS.get(role, set()))
    if role == "stock":
        if u.get("can_cash"): p |= PHARMACY_PERMS["cashier"]
        if u.get("can_block"): p.add("block")
    if u.get("custom_role_id"):
        with DB_LOCK:
            cr = c.execute("SELECT permissions_json FROM custom_roles WHERE id=? AND pharmacy_id=?",
                           (u["custom_role_id"], u["pharmacy_id"])).fetchone()
            if cr:
                try:
                    p |= set(json.loads(cr["permissions_json"]))
                except Exception:
                    pass
    return p

def need_pharmacy(c, u, perm):
    """Vérifie strictement que l'utilisateur appartient à une pharmacie et possède la permission."""
    if not u:
        raise Denied("Authentification requise")
    if u.get("role") in PLATFORM_ROLES:
        raise Denied("Confidentialité SaaS : Les comptes plateforme n'ont aucun accès aux données opérationnelles privées des officines.")
    if not u.get("pharmacy_id"):
        raise Denied("Aucune organisation officinale associée")
    p = get_user_perms(c, u)
    if "pharmacy_all" not in p and perm not in p:
        raise Denied(f"Permission refusée : {perm}")

def need_platform(u, perm):
    """Vérifie strictement que l'utilisateur est membre de l'administration plateforme."""
    if not u:
        raise Denied("Authentification requise")
    if u.get("role") not in PLATFORM_ROLES:
        raise Denied("Accès réservé à l'administration plateforme SaaS.")
    p = PLATFORM_PERMS.get(u["role"], set())
    if perm not in p and "platform_admin" not in p:
        raise Denied(f"Permission plateforme refusée : {perm}")

def verify_branch_access(c, u, target_branch_id):
    """Vérifie qu'une succursale appartient à la pharmacie de l'utilisateur et qu'il y a accès."""
    if not target_branch_id:
        return u.get("branch_id")
    with DB_LOCK:
        b = c.execute("SELECT id, pharmacy_id FROM branches WHERE id=? AND pharmacy_id=?",
                      (target_branch_id, u["pharmacy_id"])).fetchone()
        if not b:
            raise Denied("Succursale introuvable ou non autorisée pour votre organisation.")
    if u.get("role") not in ("owner", "accountant", "auditor") and u.get("branch_id") and u["branch_id"] != target_branch_id:
        raise Denied("Accès restreint à votre succursale assignée.")
    return target_branch_id

def audit_pharmacy(c, u, action, data, prev_val="", new_val="", reason="", device_uuid=""):
    if not u or not u.get("pharmacy_id"):
        return
    with DB_LOCK:
        c.execute("""
            INSERT INTO audit(pharmacy_id, branch_id, user_id, device_uuid, action, prev_val, new_val, reason, data, ts)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        """, (u["pharmacy_id"], u.get("branch_id"), u["id"], device_uuid, action,
              str(prev_val), str(new_val), reason, json.dumps(data), now()))

def audit_platform(c, u, action, target_pharmacy_id=None, data=None):
    with DB_LOCK:
        uid = u["id"] if u else 0
        c.execute("""
            INSERT INTO platform_audit(actor_user_id, action, target_pharmacy_id, data, ts)
            VALUES(?,?,?,?,?)
        """, (uid, action, target_pharmacy_id, json.dumps(data or {}), now()))

def login(c, username, pw, client_ip="127.0.0.1"):
    with DB_LOCK:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not r or not r["active"] or r["fails"] >= 5:
            if r:
                c.execute("INSERT INTO user_logins(pharmacy_id, user_id, action, ip, ts) VALUES(?,?,?,?,?)",
                          (r["pharmacy_id"], r["id"], "login_failed", client_ip, now()))
            raise Denied("Identifiants incorrects ou compte temporairement verrouillé (5 échecs).")
        if not secrets.compare_digest(r["pw"], hpw(pw, r["salt"])):
            c.execute("UPDATE users SET fails=fails+1 WHERE id=?", (r["id"],))
            c.execute("INSERT INTO user_logins(pharmacy_id, user_id, action, ip, ts) VALUES(?,?,?,?,?)",
                      (r["pharmacy_id"], r["id"], "login_failed", client_ip, now()))
            raise Denied("Identifiants incorrects.")
        c.execute("UPDATE users SET fails=0 WHERE id=?", (r["id"],))
        t = secrets.token_urlsafe(32)
        exp = (dt.datetime.now(TZ) + dt.timedelta(hours=12)).isoformat(timespec="seconds")
        c.execute("INSERT INTO sessions(token, user_id, pharmacy_id, branch_id, expires_at, ip, created_at) VALUES(?,?,?,?,?,?,?)",
                  (t, r["id"], r["pharmacy_id"], r["branch_id"], exp, client_ip, now()))
        c.execute("INSERT INTO user_logins(pharmacy_id, user_id, action, ip, ts) VALUES(?,?,?,?,?)",
                  (r["pharmacy_id"], r["id"], "login", client_ip, now()))
        return t

def auth(c, token):
    if not token:
        raise Denied("Session manquante")
    with DB_LOCK:
        r = c.execute("""
            SELECT u.*, s.expires_at
            FROM sessions s
            JOIN users u ON u.id=s.user_id
            WHERE s.token=? AND u.active=1
        """, (token,)).fetchone()
        if not r:
            raise Denied("Session invalide ou révoquée")
        if r["expires_at"] and r["expires_at"] < now():
            c.execute("DELETE FROM sessions WHERE token=?", (token,))
            raise Denied("Session expirée, veuillez vous reconnecter.")
        return dict(r)

def logout_session(c, token):
    with DB_LOCK:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))
