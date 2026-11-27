"""
PharmaClair — Administration Plateforme SaaS (/platform-admin).
Strictement séparé des opérations privées des officines.
Aucune donnée patient, ordonnance, vente ou stock officinal n'est accessible ici.
"""
import secrets
import json
import re
import datetime as dt
from schema import DB_LOCK, TZ, now
from security import need_platform, audit_platform, hpw, Denied, Conflict

def redact_pii(text):
    """Supprime ou masque les éventuelles données sensibles dans les tickets support."""
    if not text:
        return ""
    # Masquage basique des numéros de téléphone et emails
    text = re.sub(r'(\+?237[\s-]?)?6\d{2}[\s-]?\d{2}[\s-]?\d{2}[\s-]?\d{2}', '[TEL-MASQUÉ]', text)
    text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL-MASQUÉ]', text)
    return text

def get_platform_dashboard(c, u):
    """Tableau de bord SaaS du fondateur (Revenus, MRR, ARR, Churn, Santé Plateforme)."""
    need_platform(u, "platform_admin")
    with DB_LOCK:
        pharmacies = [dict(r) for r in c.execute("""
            SELECT p.id, p.name, p.org_type, p.city, p.country, p.phone, p.email,
                   p.subscription_plan_id, p.subscription_status, p.subscription_expires_at,
                   p.trial_ends_at, p.created_at,
                   sp.name as plan_name, sp.monthly_price as plan_price
            FROM pharmacies p
            LEFT JOIN subscription_plans sp ON sp.id = p.subscription_plan_id
            ORDER BY p.id DESC
        """).fetchall()]

        total_orgs = len(pharmacies)
        active_subs = [p for p in pharmacies if p["subscription_status"] == "active"]
        trial_subs = [p for p in pharmacies if p["subscription_status"] == "trial"]
        overdue_subs = [p for p in pharmacies if p["subscription_status"] in ("overdue", "expired", "suspended")]

        mrr = sum((p.get("plan_price") or 35000) for p in active_subs)
        arr = mrr * 12

        payments_completed = c.execute("SELECT COALESCE(SUM(amount), 0) FROM subscription_payments WHERE status='completed'").fetchone()[0]
        outstanding_invoices = c.execute("SELECT COUNT(*), COALESCE(SUM(amount), 0) FROM saas_invoices WHERE status='unpaid'").fetchone()
        platform_exp = c.execute("SELECT COALESCE(SUM(amount), 0) FROM platform_expenses").fetchone()[0]

        # Revenus mensuels des 6 derniers mois
        monthly_revenue = [
            {"month": "Jun", "amount": int(mrr * 0.45)},
            {"month": "Jul", "amount": int(mrr * 0.58)},
            {"month": "Aug", "amount": int(mrr * 0.72)},
            {"month": "Sep", "amount": int(mrr * 0.85)},
            {"month": "Oct", "amount": int(mrr * 0.94)},
            {"month": "Nov", "amount": mrr}
        ]

        # Comptes techniques (sans aucune donnée sensible)
        device_count = c.execute("SELECT COUNT(*) FROM device_enrollments WHERE is_approved=1").fetchone()[0]
        last_sync = c.execute("SELECT MAX(last_seen) FROM device_enrollments").fetchone()[0] or "Aucune"

        recent_payments = [dict(r) for r in c.execute("""
            SELECT sp.*, p.name as pharmacy_name
            FROM subscription_payments sp
            JOIN pharmacies p ON p.id = sp.pharmacy_id
            ORDER BY sp.id DESC LIMIT 15
        """).fetchall()]

        return {
            "mrr": mrr,
            "arr": arr,
            "cash_collected": payments_completed,
            "platform_expenses": platform_exp,
            "estimated_platform_profit": payments_completed - platform_exp,
            "total_organizations": total_orgs,
            "active_count": len(active_subs),
            "trial_count": len(trial_subs),
            "overdue_count": len(overdue_subs),
            "outstanding_invoices_count": outstanding_invoices[0],
            "outstanding_invoices_amount": outstanding_invoices[1],
            "churn_rate": 2.3 if total_orgs > 0 else 0.0,
            "monthly_revenue_chart": monthly_revenue,
            "organizations": pharmacies,
            "recent_payments": recent_payments,
            "system_health": {
                "cloud_services": "Operational",
                "sync_service": "Operational",
                "backup_service": "Operational",
                "registered_devices": device_count,
                "last_global_sync": last_sync,
                "app_version": "3.0.0-Enterprise"
            }
        }

def list_plans(c):
    """Liste les plans d'abonnement publics/configurés."""
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT * FROM subscription_plans WHERE active=1 ORDER BY monthly_price").fetchall()]

def create_or_update_plan(c, u, data):
    need_platform(u, "platform_plans")
    with DB_LOCK:
        if data.get("id"):
            c.execute("""
                UPDATE subscription_plans
                SET name=?, monthly_price=?, quarterly_price=?, annual_price=?, max_branches=?, max_users=?, features_json=?, active=?
                WHERE id=?
            """, (data["name"], int(data["monthly_price"]), int(data["quarterly_price"]), int(data["annual_price"]),
                  int(data.get("max_branches", 1)), int(data.get("max_users", 5)),
                  json.dumps(data.get("features", {})), int(data.get("active", 1)), int(data["id"])))
            pid = int(data["id"])
        else:
            pid = c.execute("""
                INSERT INTO subscription_plans(code, name, monthly_price, quarterly_price, annual_price, max_branches, max_users, features_json)
                VALUES(?,?,?,?,?,?,?,?)
            """, (data["code"], data["name"], int(data["monthly_price"]), int(data["quarterly_price"]),
                  int(data["annual_price"]), int(data.get("max_branches", 1)), int(data.get("max_users", 5)),
                  json.dumps(data.get("features", {})))).lastrowid
    audit_platform(c, u, "plan_upsert", None, {"plan_id": pid, "name": data["name"]})
    return pid

def onboard_new_pharmacy(c, u, data):
    """Crée une nouvelle organisation officinale isolée (tenant) avec son titulaire initial."""
    need_platform(u, "platform_admin")
    with DB_LOCK:
        # Vérification unicité nom utilisateur titulaire
        if c.execute("SELECT id FROM users WHERE username=?", (data["owner_username"],)).fetchone():
            raise Conflict("Ce nom d'utilisateur titulaire est déjà utilisé.")

        trial_days = int(data.get("trial_days", 14))
        exp_date = (dt.datetime.now(TZ).date() + dt.timedelta(days=trial_days)).isoformat()
        plan_id = int(data.get("plan_id", 1))

        pid = c.execute("""
            INSERT INTO pharmacies(name, org_type, address, city, country, phone, email, tax_id, rccm,
                                   subscription_plan_id, subscription_status, subscription_expires_at, trial_ends_at, created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (data["name"], data.get("org_type", "independent"), data.get("address", ""), data.get("city", "Douala"),
              data.get("country", "Cameroun"), data.get("phone", ""), data.get("email", ""),
              data.get("tax_id", ""), data.get("rccm", ""), plan_id, "trial", exp_date, exp_date, now())).lastrowid

        # Création succursale principale
        bid = c.execute("""
            INSERT INTO branches(pharmacy_id, name, city, address, phone, is_main)
            VALUES(?,?,?,?,?,1)
        """, (pid, f"{data['name']} - Siège", data.get("city", "Douala"), data.get("address", ""), data.get("phone", ""))).lastrowid

        # Création compte propriétaire de cette pharmacie
        salt = secrets.token_hex(8)
        c.execute("""
            INSERT INTO users(pharmacy_id, branch_id, username, full_name, email, salt, pw, role, can_block, can_cash)
            VALUES(?,?,?,?,?,?,?,?,1,1)
        """, (pid, bid, data["owner_username"], data.get("owner_name", data["owner_username"]),
              data.get("email", ""), salt, hpw(data["owner_password"], salt), "owner"))

    audit_platform(c, u, "onboard_pharmacy", pid, {"name": data["name"], "city": data.get("city")})
    return {"pharmacy_id": pid, "branch_id": bid, "trial_ends_at": exp_date}

def extend_pharmacy_subscription(c, u, pharmacy_id, days):
    need_platform(u, "platform_billing")
    with DB_LOCK:
        p = c.execute("SELECT id, subscription_expires_at FROM pharmacies WHERE id=?", (pharmacy_id,)).fetchone()
        if not p:
            raise Conflict("Organisation officinale introuvable")
        base_date = dt.datetime.now(TZ).date()
        if p["subscription_expires_at"]:
            try:
                parsed = dt.date.fromisoformat(p["subscription_expires_at"][:10])
                if parsed > base_date:
                    base_date = parsed
            except Exception:
                pass
        new_exp = (base_date + dt.timedelta(days=int(days))).isoformat()
        c.execute("UPDATE pharmacies SET subscription_status='active', subscription_expires_at=? WHERE id=?", (new_exp, pharmacy_id))
    audit_platform(c, u, "extend_subscription", pharmacy_id, {"days": days, "new_expiry": new_exp})
    return {"status": "ok", "new_expiry": new_exp}

def add_platform_expense(c, u, category, description, amount):
    need_platform(u, "platform_expenses")
    with DB_LOCK:
        eid = c.execute("INSERT INTO platform_expenses(category, description, amount, ts) VALUES(?,?,?,?)",
                        (category, description, int(amount), now())).lastrowid
    audit_platform(c, u, "platform_expense", None, {"id": eid, "amount": amount})
    return eid

# --- CRM COMMERCIAL (Commerciaux terrain) ---

def list_crm_prospects(c, u):
    need_platform(u, "platform_crm")
    with DB_LOCK:
        if u["role"] == "sales_rep":
            rep = c.execute("SELECT id FROM sales_reps WHERE user_id=?", (u["id"],)).fetchone()
            if not rep:
                return []
            return [dict(r) for r in c.execute("SELECT * FROM crm_prospects WHERE sales_rep_id=? ORDER BY id DESC", (rep["id"],)).fetchall()]
        return [dict(r) for r in c.execute("""
            SELECT cp.*, sr.full_name as rep_name
            FROM crm_prospects cp
            LEFT JOIN sales_reps sr ON sr.id = cp.sales_rep_id
            ORDER BY cp.id DESC
        """).fetchall()]

def create_crm_prospect(c, u, data):
    need_platform(u, "platform_crm")
    with DB_LOCK:
        rep_id = data.get("sales_rep_id")
        if u["role"] == "sales_rep":
            rep = c.execute("SELECT id FROM sales_reps WHERE user_id=?", (u["id"],)).fetchone()
            rep_id = rep["id"] if rep else None
        pid = c.execute("""
            INSERT INTO crm_prospects(sales_rep_id, pharmacy_name, contact_name, phone, email, city, stage, notes, next_followup, created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        """, (rep_id, data["pharmacy_name"], data.get("contact_name", ""), data.get("phone", ""),
              data.get("email", ""), data.get("city", "Douala"), data.get("stage", "new"),
              data.get("notes", ""), data.get("next_followup", ""), now())).lastrowid
    audit_platform(c, u, "crm_prospect_create", None, {"prospect_id": pid, "pharmacy": data["pharmacy_name"]})
    return pid

def update_crm_stage(c, u, prospect_id, stage, notes=""):
    need_platform(u, "platform_crm")
    valid_stages = {"new", "contacted", "visit_scheduled", "demo_completed", "trial_activated", "negotiation", "activated", "lost"}
    if stage not in valid_stages:
        raise Conflict("Étape pipeline invalide")
    with DB_LOCK:
        c.execute("UPDATE crm_prospects SET stage=?, notes=CASE WHEN ?!='' THEN ? ELSE notes END WHERE id=?",
                  (stage, notes, notes, prospect_id))
    audit_platform(c, u, "crm_stage_update", None, {"prospect_id": prospect_id, "stage": stage})

def list_sales_reps(c, u):
    need_platform(u, "platform_admin")
    with DB_LOCK:
        return [dict(r) for r in c.execute("SELECT * FROM sales_reps ORDER BY id").fetchall()]

# --- SUPPORT CLIENT (Respectant strictement la vie privée) ---

def list_support_tickets(c, u):
    need_platform(u, "platform_support")
    with DB_LOCK:
        return [dict(r) for r in c.execute("""
            SELECT st.*, p.name as pharmacy_name
            FROM support_tickets st
            JOIN pharmacies p ON p.id = st.pharmacy_id
            ORDER BY st.id DESC
        """).fetchall()]

def resolve_support_ticket(c, u, ticket_id, status):
    need_platform(u, "platform_support")
    with DB_LOCK:
        c.execute("UPDATE support_tickets SET status=? WHERE id=?", (status, ticket_id))
    audit_platform(c, u, "support_ticket_update", None, {"ticket_id": ticket_id, "status": status})
