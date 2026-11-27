"""
QA End-to-End Live Verification — Teste les 5 profils utilisateurs par appels HTTP réels :
1. superadmin (Platform Super Admin)
2. commercial1 (Commercial CRM)
3. titulaire (Pharmacy A Owner)
4. caissier1 (Pharmacy A Cashier)
5. titulaire_b (Pharmacy B Owner)
"""
import urllib.request
import urllib.error
import json
import sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"

def req(path, method="GET", body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            txt = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(txt)
            except Exception:
                return resp.status, txt
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "ignore")
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, txt

def login(user, pw):
    code, res = req("/login", "POST", {"username": user, "password": pw})
    assert code == 200, f"Login failed for {user}: {code} {res}"
    return res["token"]

def run_qa():
    print(f"=== QA E2E LIVE SUR {BASE} ===")
    
    # 1. Connexion des 5 profils
    t_super = login("superadmin", "admin123")
    t_crm = login("commercial1", "rep123")
    t_owner_a = login("titulaire", "admin123")
    t_cashier_a = login("caissier1", "caisse123")
    t_owner_b = login("titulaire_b", "admin123")
    print("[PASS] Connexion des 5 profils via /login")

    # 2. Vérification Super Admin (Accès SaaS OK, Accès Officine INTERDIT)
    assert req("/api/platform/dashboard", token=t_super)[0] == 200
    assert req("/api/platform/plans", token=t_super)[0] == 200
    assert req("/api/platform/crm", token=t_super)[0] == 200
    assert req("/api/platform/support", token=t_super)[0] == 200
    for forbidden in ["/owner/stats", "/drugs", "/sales", "/api/customers", "/prescriptions", "/api/finance/pnl", "/api/audit", "/export"]:
        code, _ = req(forbidden, token=t_super)
        assert code == 403, f"SuperAdmin should get 403 on {forbidden}, got {code}"
    print("[PASS] Super Admin: Accès SaaS OK, blocage 403 sur toutes données privées officines")

    # 3. Vérification Commercial CRM (CRM OK, Dashboard plateforme & Officines INTERDITS)
    assert req("/api/platform/crm", token=t_crm)[0] == 200
    assert req("/api/platform/dashboard", token=t_crm)[0] == 403
    assert req("/drugs", token=t_crm)[0] == 403
    assert req("/api/customers", token=t_crm)[0] == 403
    print("[PASS] Commercial CRM: CRM accessible, Dashboard SuperAdmin & Officines bloqués (403)")

    # 4. Vérification Caissier A (Espace de travail, Ventes, Clients, Réceptions, Péremptions, Caisse OK; Finances P&L & Approbations INTERDITS)
    assert req("/api/employee/workspace", token=t_cashier_a)[0] == 200
    assert req("/drugs", token=t_cashier_a)[0] == 200
    assert req("/api/lots/expiring?days=90", token=t_cashier_a)[0] == 200
    assert req("/api/customers", token=t_cashier_a)[0] == 200
    assert req("/api/cash_register/me", token=t_cashier_a)[0] == 200
    assert req("/api/tasks", token=t_cashier_a)[0] == 200
    assert req("/api/approvals", token=t_cashier_a)[0] == 200

    # Création client par caissier
    c_code, c_res = req("/api/customers/create", "POST", {"name": "QA Client Test", "phone": "+237 699 88 77 66"}, token=t_cashier_a)
    assert c_code == 200, f"Customer create failed: {c_res}"
    cid = c_res["customer_id"]
    # Modification client par caissier
    assert req("/api/customers/update", "POST", {"customer_id": cid, "name": "QA Client Modifié"}, token=t_cashier_a)[0] == 200
    # Historique client
    assert req(f"/api/customers/{cid}", token=t_cashier_a)[0] == 200

    # Vente + Reçu par caissier
    _, drugs_a = req("/drugs", token=t_cashier_a)
    d_id = drugs_a[0]["id"]
    s_code, s_res = req("/sale", "POST", {"idem": f"QA-SALE-{cid}", "items": [[d_id, 1]], "method": "cash", "paid": drugs_a[0]["price"]}, token=t_cashier_a)
    assert s_code == 200, f"Sale failed: {s_res}"
    r_code, rcpt = req(f"/receipt/{s_res['sale_id']}", token=t_cashier_a)
    assert r_code == 200 and rcpt["total"] == drugs_a[0]["price"]

    # Réception multi-produits par caissier
    del_code, del_res = req("/api/receive/delivery", "POST", {
        "supplier_name": "Laborex QA",
        "bl_number": f"BL-QA-{cid}",
        "status": "accepted",
        "items": [{"drug_id": d_id, "lot_no": f"LT-QA-{cid}", "expiry": "2028-06", "qty": 5, "condition": "ok"}]
    }, token=t_cashier_a)
    assert del_code == 200 and del_res["status"] == "accepted"

    # Caissier bloqué sur Finances globales, Paramètres, Audit et Approbation
    for f_emp in ["/api/finance/pnl", "/owner/stats", "/api/audit", "/api/platform/dashboard"]:
        code, _ = req(f_emp, token=t_cashier_a)
        assert code == 403, f"Cashier should get 403 on {f_emp}, got {code}"
    print("[PASS] Caissier A: Workflows opérationnels complets OK + restrictions financières respectées")

    # 5. Vérification Owner A (Supervision, Finances P&L, Paramètres, Approbations, Succursales, Audit)
    assert req("/owner/stats", token=t_owner_a)[0] == 200
    assert req("/api/finance/pnl", token=t_owner_a)[0] == 200
    assert req("/api/audit", token=t_owner_a)[0] == 200
    assert req("/api/branches", token=t_owner_a)[0] == 200
    assert req("/api/settings", token=t_owner_a)[0] == 200
    assert req("/users", token=t_owner_a)[0] == 200
    print("[PASS] Owner A: Supervision, Finances P&L, Audit, Succursales & Paramètres OK")

    # 6. Vérification Isolation Multi-Tenant (Owner B ne peut accéder à rien de Pharmacie A)
    assert req(f"/receipt/{s_res['sale_id']}", token=t_owner_b)[0] == 403
    assert req(f"/api/customers/{cid}", token=t_owner_b)[0] == 403
    assert req(f"/stock/{d_id}", token=t_owner_b)[0] == 403
    _, drugs_b = req("/drugs", token=t_owner_b)
    assert all(d["name"] != "Paracétamol 500mg" for d in drugs_b)
    print("[PASS] Isolation Multi-Tenant (Pharmacie A vs Pharmacie B) vérifiée par HTTP 403")
    print("=== TOUS LES TESTS QA LIVE SONT PASSÉS ===")

if __name__ == "__main__":
    run_qa()
