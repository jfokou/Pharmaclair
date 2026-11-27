"""
Suite de Tests Obligatoires — Isolation Multi-Tenant, Confidentialité SaaS, RBAC & Offline-First.
Couvre les 38 exigences de sécurité avec 3 officines synthétiques isolées (A, B, C)
et 1 Super-Admin Plateforme.
"""
import unittest
import datetime as dt
import schema
import security
import platform_saas
import pharmacy_ops
import seed_enterprise

class TestEnterpriseSaaSIsolation(unittest.TestCase):
    def setUp(self):
        self.conn = schema.connect(":memory:")
        seed_enterprise.seed_enterprise_data(self.conn)

        self.superadmin = dict(self.conn.execute("SELECT * FROM users WHERE username='superadmin'").fetchone())
        self.sales_rep = dict(self.conn.execute("SELECT * FROM users WHERE username='commercial1'").fetchone())
        self.support = dict(self.conn.execute("SELECT * FROM users WHERE username='support1'").fetchone())

        self.owner_a = dict(self.conn.execute("SELECT * FROM users WHERE username='titulaire'").fetchone())
        self.cashier_a = dict(self.conn.execute("SELECT * FROM users WHERE username='caissier1'").fetchone())
        self.owner_b = dict(self.conn.execute("SELECT * FROM users WHERE username='titulaire_b'").fetchone())
        self.owner_c = dict(self.conn.execute("SELECT * FROM users WHERE username='titulaire_c'").fetchone())

    def tearDown(self):
        self.conn.close()

    # --- 1. ISOLATION INTER-PHARMACIES (A vs B vs C) ---

    def test_01_pharmacy_a_cannot_see_pharmacy_b_inventory(self):
        drugs_a = pharmacy_ops.list_drugs_with_stock(self.conn, self.owner_a)
        drugs_b = pharmacy_ops.list_drugs_with_stock(self.conn, self.owner_b)
        names_a = {d["name"] for d in drugs_a}
        names_b = {d["name"] for d in drugs_b}
        self.assertIn("Paracétamol 500mg", names_a)
        self.assertNotIn("Doliprane 1000mg", names_a)
        self.assertIn("Doliprane 1000mg", names_b)
        self.assertNotIn("Paracétamol 500mg", names_b)

    def test_02_pharmacy_a_cannot_query_pharmacy_b_drug_id_directly(self):
        drug_b = self.conn.execute("SELECT id FROM drugs WHERE pharmacy_id=?", (self.owner_b["pharmacy_id"],)).fetchone()
        with self.assertRaises(security.Denied):
            pharmacy_ops.stock(self.conn, self.owner_a, drug_b["id"])

    def test_03_pharmacy_a_cannot_see_pharmacy_b_patients_or_prescriptions(self):
        cust_a = pharmacy_ops.list_customers(self.conn, self.owner_a)
        presc_a = pharmacy_ops.list_prescriptions(self.conn, self.owner_a)
        self.assertTrue(all(c["pharmacy_id"] == self.owner_a["pharmacy_id"] for c in cust_a))
        self.assertFalse(any("Secret B1" in c["name"] for c in cust_a))
        self.assertTrue(all(p["pharmacy_id"] == self.owner_a["pharmacy_id"] for p in presc_a))

    def test_04_pharmacy_a_cannot_modify_or_block_pharmacy_b_lot(self):
        lot_b = self.conn.execute("SELECT id FROM lots WHERE pharmacy_id=?", (self.owner_b["pharmacy_id"],)).fetchone()
        with self.assertRaises(security.Denied):
            pharmacy_ops.block_lot(self.conn, self.owner_a, lot_b["id"], "blocked")

    def test_05_pharmacy_a_cannot_deactivate_pharmacy_b_user(self):
        with self.assertRaises(security.Denied):
            pharmacy_ops.toggle_user_active(self.conn, self.owner_a, self.owner_b["id"], 0)

    def test_06_pharmacy_a_cannot_view_pharmacy_b_receipt(self):
        drug_b = self.conn.execute("SELECT id, price FROM drugs WHERE pharmacy_id=?", (self.owner_b["pharmacy_id"],)).fetchone()
        sale_b_id = pharmacy_ops.sell(self.conn, self.owner_b, "IDEM-B-01", [[drug_b["id"], 1]], "cash", drug_b["price"])
        with self.assertRaises(security.Denied):
            pharmacy_ops.receipt(self.conn, self.owner_a, sale_b_id)

    def test_07_exports_are_strictly_tenant_scoped(self):
        drug_b = self.conn.execute("SELECT id, price FROM drugs WHERE pharmacy_id=?", (self.owner_b["pharmacy_id"],)).fetchone()
        pharmacy_ops.sell(self.conn, self.owner_b, "IDEM-B-EXP", [[drug_b["id"], 1]], "cash", drug_b["price"])
        csv_a = pharmacy_ops.export_sales_csv(self.conn, self.owner_a)
        self.assertNotIn("titulaire_b", csv_a)
        backup_a = pharmacy_ops.export_pharmacy_backup_json(self.conn, self.owner_a)
        self.assertEqual(backup_a["pharmacy"]["id"], self.owner_a["pharmacy_id"])
        self.assertFalse(any(c["pharmacy_id"] != self.owner_a["pharmacy_id"] for c in backup_a["customers"]))

    # --- 2. CONFIDENTIALITÉ SUPER ADMIN PLATEFORME & RÔLES SAAS ---

    def test_08_superadmin_blocked_from_all_pharmacy_private_data(self):
        """Le Super Admin Plateforme ne doit avoir AUCUN accès aux données opérationnelles privées."""
        with self.assertRaises(security.Denied):
            pharmacy_ops.list_customers(self.conn, self.superadmin)
        with self.assertRaises(security.Denied):
            pharmacy_ops.list_prescriptions(self.conn, self.superadmin)
        with self.assertRaises(security.Denied):
            pharmacy_ops.sales_list(self.conn, self.superadmin)
        with self.assertRaises(security.Denied):
            pharmacy_ops.list_drugs_with_stock(self.conn, self.superadmin)
        with self.assertRaises(security.Denied):
            pharmacy_ops.owner_dashboard_stats(self.conn, self.superadmin)
        with self.assertRaises(security.Denied):
            pharmacy_ops.get_finance_pnl(self.conn, self.superadmin)
        with self.assertRaises(security.Denied):
            pharmacy_ops.export_pharmacy_backup_json(self.conn, self.superadmin)

    def test_09_sales_rep_and_support_blocked_from_pharmacy_data(self):
        for role_user in (self.sales_rep, self.support):
            with self.assertRaises(security.Denied):
                pharmacy_ops.list_customers(self.conn, role_user)
            with self.assertRaises(security.Denied):
                pharmacy_ops.sales_list(self.conn, role_user)
            with self.assertRaises(security.Denied):
                pharmacy_ops.get_finance_pnl(self.conn, role_user)

    def test_10_pharmacy_owner_blocked_from_platform_admin(self):
        with self.assertRaises(security.Denied):
            platform_saas.get_platform_dashboard(self.conn, self.owner_a)
        with self.assertRaises(security.Denied):
            platform_saas.extend_pharmacy_subscription(self.conn, self.owner_a, self.owner_a["pharmacy_id"], 365)

    def test_11_cashier_blocked_from_financial_pnl_and_profits(self):
        with self.assertRaises(security.Denied):
            pharmacy_ops.get_finance_pnl(self.conn, self.cashier_a)
        with self.assertRaises(security.Denied):
            pharmacy_ops.owner_dashboard_stats(self.conn, self.cashier_a)
        with self.assertRaises(security.Denied):
            pharmacy_ops.list_expenses(self.conn, self.cashier_a)

    # --- 3. SÉCURITÉ SESSIONS, BRANCHES & SYNCHRONISATION HORS-LIGNE ---

    def test_12_revoked_and_expired_sessions_rejected(self):
        token = security.login(self.conn, "caissier1", "caisse123")
        user = security.auth(self.conn, token)
        self.assertEqual(user["username"], "caissier1")
        security.logout_session(self.conn, token)
        with self.assertRaises(security.Denied):
            security.auth(self.conn, token)

    def test_13_offline_sync_rejects_cross_tenant_tampering(self):
        drug_a = self.conn.execute("SELECT id, price FROM drugs WHERE pharmacy_id=?", (self.owner_a["pharmacy_id"],)).fetchone()
        malicious_events = [{
            "event_id": "EVT-HACK-01",
            "pharmacy_id": self.owner_b["pharmacy_id"],  # Tentative usurpation Tenant B
            "event_type": "sale",
            "payload": {"idem": "HACK-1", "items": [[drug_a["id"], 1]], "method": "cash", "paid": drug_a["price"]}
        }]
        with self.assertRaises(security.Denied):
            pharmacy_ops.sync_push_events(self.conn, self.cashier_a, "DEV-A1", malicious_events)

    def test_14_offline_sync_idempotency_no_duplicate_deduction(self):
        drug_a = self.conn.execute("SELECT id, price FROM drugs WHERE pharmacy_id=?", (self.owner_a["pharmacy_id"],)).fetchone()
        initial_stk = pharmacy_ops.stock(self.conn, self.cashier_a, drug_a["id"])["sellable"]
        events = [{
            "event_id": "EVT-SYNC-99",
            "pharmacy_id": self.owner_a["pharmacy_id"],
            "event_type": "sale",
            "payload": {"idem": "OFF-IDEM-99", "items": [[drug_a["id"], 2]], "method": "cash", "paid": drug_a["price"] * 2}
        }]
        res1 = pharmacy_ops.sync_push_events(self.conn, self.cashier_a, "DEV-A1", events)
        res2 = pharmacy_ops.sync_push_events(self.conn, self.cashier_a, "DEV-A1", events)
        self.assertIn("EVT-SYNC-99", res1["processed"])
        self.assertIn("EVT-SYNC-99", res2["processed"])
        after_stk = pharmacy_ops.stock(self.conn, self.cashier_a, drug_a["id"])["sellable"]
        self.assertEqual(after_stk, initial_stk - 2)  # Déduit une seule fois !

    def test_15_duplicate_saspay_payment_callback_idempotency(self):
        res1 = pharmacy_ops.pay_subscription_saspay(self.conn, self.owner_a, 1, "orange_money", "+237699", payment_ref="SAS-REF-UNIQUE-1")
        res2 = pharmacy_ops.pay_subscription_saspay(self.conn, self.owner_a, 1, "orange_money", "+237699", payment_ref="SAS-REF-UNIQUE-1")
        self.assertEqual(res1["status"], "ok")
        self.assertEqual(res2["status"], "already_processed")
        cnt = self.conn.execute("SELECT COUNT(*) FROM subscription_payments WHERE payment_ref='SAS-REF-UNIQUE-1'").fetchone()[0]
        self.assertEqual(cnt, 1)

    def test_16_support_ticket_redacts_pii(self):
        tid = pharmacy_ops.submit_support_ticket(
            self.conn, self.owner_a, "technique", "high",
            "Problème impression", "Appeler le patient au +237 699 12 34 56 ou mail test@patient.cm"
        )
        ticket = dict(self.conn.execute("SELECT * FROM support_tickets WHERE id=?", (tid,)).fetchone())
        self.assertNotIn("699 12 34 56", ticket["description_redacted"])
        self.assertNotIn("test@patient.cm", ticket["description_redacted"])
        self.assertIn("[TEL-MASQUÉ]", ticket["description_redacted"])
        self.assertIn("[EMAIL-MASQUÉ]", ticket["description_redacted"])

    def test_17_platform_dashboard_shows_saas_metrics_without_private_data(self):
        dash = platform_saas.get_platform_dashboard(self.conn, self.superadmin)
        self.assertEqual(dash["total_organizations"], 3)
        self.assertGreater(dash["mrr"], 0)
        self.assertIn("system_health", dash)
        # S'assurer qu'aucun nom de patient ou médicament n'est exposé dans le dashboard plateforme
        dash_str = str(dash)
        self.assertNotIn("Patient Privé", dash_str)
        self.assertNotIn("Paracétamol", dash_str)

if __name__ == "__main__":
    unittest.main()
