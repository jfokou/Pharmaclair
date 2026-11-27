"""
Suite de Tests Fonctionnels Employés & Rôles Granulaires (Section 19).
Teste les 20 scénarios opérationnels réels sur le backend.
"""
import unittest
import datetime as dt
import schema
import security
import pharmacy_ops
import seed_enterprise

class TestEmployeeOperationalWorkflows(unittest.TestCase):
    def setUp(self):
        self.conn = schema.connect(":memory:")
        seed_enterprise.seed_enterprise_data(self.conn)

        self.superadmin = dict(self.conn.execute("SELECT * FROM users WHERE username='superadmin'").fetchone())
        self.owner_a = dict(self.conn.execute("SELECT * FROM users WHERE username='titulaire'").fetchone())
        self.cashier_a = dict(self.conn.execute("SELECT * FROM users WHERE username='caissier1'").fetchone())
        self.stock_a = dict(self.conn.execute("SELECT * FROM users WHERE username='magasinier'").fetchone())
        self.owner_b = dict(self.conn.execute("SELECT * FROM users WHERE username='titulaire_b'").fetchone())

        # Créer un pharmacien pour tester les validations cliniques
        pharmacy_ops.create_user(self.conn, self.owner_a, "pharmacien1", "pharma123", "pharmacist", full_name="Dr. Pharmacien")
        self.pharmacist_a = dict(self.conn.execute("SELECT * FROM users WHERE username='pharmacien1'").fetchone())

    def tearDown(self):
        self.conn.close()

    def test_01_cashier_registers_new_customer_without_seeing_clinical_allergies(self):
        cid = pharmacy_ops.create_customer(self.conn, self.cashier_a, "Client Nouveau", "+237 699 55 44 33", allergies="Aspirine")
        self.assertGreater(cid, 0)
        custs = pharmacy_ops.list_customers_operational(self.conn, self.cashier_a)
        found = next(c for c in custs if c["id"] == cid)
        self.assertEqual(found["name"], "Client Nouveau")
        self.assertNotIn("allergies", found)  # Confidentialité clinique respectée !

    def test_02_cashier_completes_sale_and_prints_receipt(self):
        drug = self.conn.execute("SELECT id, price FROM drugs WHERE pharmacy_id=? LIMIT 1", (self.cashier_a["pharmacy_id"],)).fetchone()
        sid = pharmacy_ops.sell(self.conn, self.cashier_a, "IDEM-EMP-01", [[drug["id"], 2]], "cash", drug["price"] * 2)
        rcpt = pharmacy_ops.receipt(self.conn, self.cashier_a, sid)
        self.assertEqual(rcpt["total"], drug["price"] * 2)
        self.assertEqual(rcpt["cashier"], "caissier1")

    def test_03_04_cashier_receives_supplier_delivery_multiple_batches_without_owner_or_cost_access(self):
        drug = self.conn.execute("SELECT id FROM drugs WHERE pharmacy_id=? LIMIT 1", (self.cashier_a["pharmacy_id"],)).fetchone()
        res = pharmacy_ops.receive_supplier_delivery(self.conn, self.cashier_a, {
            "supplier_name": "Laborex Cameroun",
            "bl_number": "BL-CASH-001",
            "items": [
                {"drug_id": drug["id"], "lot_no": "LT-MULTI-1", "expiry": "2027-05", "qty": 20, "purchase_cost": 9999, "storage_location": "Étagère A2"},
                {"drug_id": drug["id"], "lot_no": "LT-MULTI-2", "expiry": "2028-01", "qty": 30, "purchase_cost": 8888, "storage_location": "Étagère A3"}
            ]
        })
        self.assertEqual(res["status"], "accepted")
        # Vérifier que le caissier n'a pas pu injecter un coût d'achat arbitraire (doit être forcé à 0)
        lot1 = self.conn.execute("SELECT purchase_cost, qty FROM lots WHERE lot_no='LT-MULTI-1'").fetchone()
        self.assertEqual(lot1["qty"], 20)
        self.assertEqual(lot1["purchase_cost"], 0)

    def test_05_employee_identifies_expiring_medication_without_financial_values(self):
        exp_lots = pharmacy_ops.list_expiring_lots(self.conn, self.cashier_a, days_filter="3650")
        self.assertGreater(len(exp_lots), 0)
        self.assertNotIn("purchase_cost", exp_lots[0])
        self.assertNotIn("value_at_risk", exp_lots[0])

        # Le titulaire voit la valeur à risque
        owner_exp = pharmacy_ops.list_expiring_lots(self.conn, self.owner_a, days_filter="3650")
        self.assertIn("value_at_risk", owner_exp[0])

    def test_06_07_08_inventory_discrepancy_and_remote_owner_approval(self):
        lot = self.conn.execute("SELECT id, qty FROM lots WHERE pharmacy_id=? LIMIT 1", (self.cashier_a["pharmacy_id"],)).fetchone()
        orig_qty = lot["qty"]
        counted = orig_qty - 2

        # 6. Caissier soumet un comptage avec écart de -2
        res_cnt = pharmacy_ops.submit_inventory_count(self.conn, self.cashier_a, lot["id"], counted, "2 boîtes abîmées")
        self.assertEqual(res_cnt["discrepancy"], -2)
        req_id = res_cnt["approval_request_id"]
        self.assertIsNotNone(req_id)

        # Le stock système ne doit pas être modifié silencieusement avant approbation
        curr_qty = self.conn.execute("SELECT qty FROM lots WHERE id=?", (lot["id"],)).fetchone()["qty"]
        self.assertEqual(curr_qty, orig_qty)

        # 19. Un caissier ne peut pas approuver sa propre demande d'ajustement
        with self.assertRaises(security.Denied):
            pharmacy_ops.review_approval_request(self.conn, self.cashier_a, req_id, "approved")

        # 7 & 8. Le titulaire approuve à distance -> le stock est ajusté atomiquement
        rev = pharmacy_ops.review_approval_request(self.conn, self.owner_a, req_id, "approved", "Validé à distance")
        self.assertEqual(rev["status"], "approved")
        new_qty = self.conn.execute("SELECT qty FROM lots WHERE id=?", (lot["id"],)).fetchone()["qty"]
        self.assertEqual(new_qty, counted)

    def test_09_cashier_opens_and_closes_own_cash_register(self):
        pharmacy_ops.open_cash_register(self.conn, self.cashier_a, 50000)
        reg = pharmacy_ops.get_my_cash_register(self.conn, self.cashier_a)
        self.assertEqual(reg["session"]["status"], "open")
        close_res = pharmacy_ops.close_cash_register(self.conn, self.cashier_a, 50000, "RAS")
        self.assertEqual(close_res["status"], "closed")
        self.assertEqual(close_res["diff_cash"], 0)

    def test_10_cashier_cannot_view_global_profits(self):
        with self.assertRaises(security.Denied):
            pharmacy_ops.get_finance_pnl(self.conn, self.cashier_a)
        with self.assertRaises(security.Denied):
            pharmacy_ops.owner_dashboard_stats(self.conn, self.cashier_a)

    def test_11_13_prescription_intake_by_cashier_and_validation_by_pharmacist(self):
        cust = self.conn.execute("SELECT id FROM customers WHERE pharmacy_id=? LIMIT 1", (self.cashier_a["pharmacy_id"],)).fetchone()
        drug = self.conn.execute("SELECT id FROM drugs WHERE pharmacy_id=? LIMIT 1", (self.cashier_a["pharmacy_id"],)).fetchone()
        res_in = pharmacy_ops.intake_prescription(self.conn, self.cashier_a, cust["id"], "Dr. Test", drug["id"], "1x2/j", 2, "2027-01-01")
        self.assertEqual(res_in["status"], "pending_validation")

        # Caissier ne peut pas valider cliniquement
        with self.assertRaises(security.Denied):
            pharmacy_ops.validate_prescription(self.conn, self.cashier_a, res_in["prescription_id"], "active")

        # Pharmacien valide cliniquement
        val = pharmacy_ops.validate_prescription(self.conn, self.pharmacist_a, res_in["prescription_id"], "active")
        self.assertEqual(val["status"], "active")

    def test_14_15_cross_tenant_and_superadmin_isolation(self):
        with self.assertRaises(security.Denied):
            pharmacy_ops.employee_workspace_summary(self.conn, self.superadmin)
        with self.assertRaises(security.Denied):
            pharmacy_ops.list_tasks(self.conn, self.superadmin)

        lot_b = self.conn.execute("SELECT id FROM lots WHERE pharmacy_id=?", (self.owner_b["pharmacy_id"],)).fetchone()
        with self.assertRaises(security.Denied):
            pharmacy_ops.submit_inventory_count(self.conn, self.cashier_a, lot_b["id"], 5)

    def test_18_employee_cannot_elevate_own_permissions(self):
        with self.assertRaises(security.Denied):
            pharmacy_ops.create_custom_role(self.conn, self.cashier_a, "hacked_admin", ["pharmacy_all"])
        with self.assertRaises(security.Denied):
            pharmacy_ops.create_user(self.conn, self.cashier_a, "hacker", "123", "owner")

    def test_20_employee_workspace_and_tasks_completion(self):
        ws = pharmacy_ops.employee_workspace_summary(self.conn, self.cashier_a)
        self.assertGreater(len(ws["tasks"]), 0)
        tid = ws["tasks"][0]["id"]
        res = pharmacy_ops.complete_employee_task(self.conn, self.cashier_a, tid, "Vérifié en rayon")
        self.assertEqual(res["status"], "completed")

if __name__ == "__main__":
    unittest.main()
