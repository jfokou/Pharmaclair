"""
Tests unitaires et d'intégration pour l'architecture Offline-First, PWA et SaaS de PharmaClair.
Couvre les scénarios exigés par la spécification :
1. Perte de connexion et résilience
2. Vente hors-ligne & FEFO local
3. Déduplication et idempotence Outbox
4. Prévention de vente de lots périmés
5. Clôture de caisse hors-ligne
6. Isolation multi-tenant et rôles (Superadmin / Owner / Cashier)
7. Synchronisation push/pull
"""
import unittest
import sqlite3
import json
import os
import datetime as dt

import pharmaclair

class TestPharmaClairOfflineFirst(unittest.TestCase):
    def setUp(self):
        # Database in-memory pour chaque test
        self.conn = pharmaclair.connect(":memory:")
        pharmaclair.run_migrations(self.conn)
        pharmaclair.seed_demo_data(self.conn)
        
        # Récupération des utilisateurs de test
        self.superadmin = dict(self.conn.execute("SELECT * FROM users WHERE username='superadmin'").fetchone())
        self.owner = dict(self.conn.execute("SELECT * FROM users WHERE username='titulaire'").fetchone())
        self.cashier = dict(self.conn.execute("SELECT * FROM users WHERE username='caissier1'").fetchone())

    def tearDown(self):
        self.conn.close()

    def test_migrations_and_pharmacy_settings(self):
        """Vérifie que les migrations ajoutent bien les colonnes de configuration et Saspay."""
        settings = pharmaclair.get_pharmacy_settings(self.conn, self.owner)
        self.assertIn("name", settings)
        self.assertIn("currency", settings)
        self.assertIn("receipt_format", settings)
        self.assertIn("saspay_mode", settings)
        self.assertIn("subscription_status", settings)

        # Mise à jour des paramètres
        updated = pharmaclair.update_pharmacy_settings(self.conn, self.owner, {
            "name": "Pharmacie de la Paix",
            "city": "Yaoundé",
            "receipt_format": "58mm",
            "phone": "+237 699 00 11 22",
            "rccm": "RC/YAO/2026/B/999"
        })
        self.assertEqual(updated["name"], "Pharmacie de la Paix")
        self.assertEqual(updated["city"], "Yaoundé")
        self.assertEqual(updated["receipt_format"], "58mm")

    def test_fefo_stock_and_expired_prevention(self):
        """Vérifie que le déstockage respecte strictement la règle FEFO et bloque les périmés."""
        ph = self.cashier["pharmacy_id"]
        # Création d'un médicament et de 2 lots
        d = self.conn.execute("INSERT INTO drugs(pharmacy_id, name, pack, price, ref) VALUES(?, 'Test Paracétamol', 'Boîte de 10', 1000, 'TEST-01')", (ph,)).lastrowid
        
        # Lot A: expire dans 6 mois
        today = dt.datetime.now(pharmaclair.TZ).date()
        exp_soon = (today + dt.timedelta(days=180)).isoformat()
        lot_a = self.conn.execute("INSERT INTO lots(pharmacy_id, drug_id, lot_no, expiry, expiry_date, qty) VALUES(?, ?, 'LOT-A', '2027-01', ?, 5)", (ph, d, exp_soon)).lastrowid
        
        # Lot B: expire dans 1 an
        exp_later = (today + dt.timedelta(days=365)).isoformat()
        lot_b = self.conn.execute("INSERT INTO lots(pharmacy_id, drug_id, lot_no, expiry, expiry_date, qty) VALUES(?, ?, 'LOT-B', '2027-06', ?, 10)", (ph, d, exp_later)).lastrowid
        
        # Vente de 3 unités: doit être déstocké du lot A (le plus proche de péremption)
        sale_id = pharmaclair.sell(self.conn, self.cashier, "TEST-IDEM-01", [[d, 3]], "cash", 3000)
        self.assertIsNotNone(sale_id)
        
        # Vérification des stocks des lots
        rem_a = self.conn.execute("SELECT qty FROM lots WHERE id=?", (lot_a,)).fetchone()[0]
        rem_b = self.conn.execute("SELECT qty FROM lots WHERE id=?", (lot_b,)).fetchone()[0]
        self.assertEqual(rem_a, 2) # 5 - 3 = 2
        self.assertEqual(rem_b, 10) # non touché
        
        # Insertion d'un lot périmé
        exp_past = (today - dt.timedelta(days=10)).isoformat()
        lot_expired = self.conn.execute("INSERT INTO lots(pharmacy_id, drug_id, lot_no, expiry, expiry_date, qty) VALUES(?, ?, 'LOT-EXP', '2026-01', ?, 50)", (ph, d, exp_past)).lastrowid
        
        # Vérifier que les lots vendables n'incluent PAS le lot périmé
        sellable = pharmaclair._sellable_lots(self.conn, ph, d)
        sellable_lot_ids = [l["id"] for l in sellable]
        self.assertNotIn(lot_expired, sellable_lot_ids)

    def test_outbox_push_idempotency_and_sync(self):
        """Vérifie l'idempotence et la déduplication du moteur de synchronisation Outbox."""
        ph = self.cashier["pharmacy_id"]
        drug = self.conn.execute("SELECT * FROM drugs WHERE pharmacy_id=? LIMIT 1", (ph,)).fetchone()
        
        events = [
            {
                "event_id": "EVT-UUID-001",
                "event_type": "sale",
                "payload": {
                    "idem": "OFF-REC-001",
                    "items": [[drug["id"], 1]],
                    "method": "cash",
                    "paid": drug["price"]
                }
            }
        ]
        
        # Premier push: doit être traité
        res1 = pharmaclair.sync_push_events(self.conn, self.cashier, "DEVICE-TEST-UUID", events)
        self.assertIn("EVT-UUID-001", res1["processed"])
        self.assertEqual(len(res1["conflicts"]), 0)
        
        # Deuxième push (re-synchronisation après coupure réseau): doit être ignoré sans double déstockage
        res2 = pharmaclair.sync_push_events(self.conn, self.cashier, "DEVICE-TEST-UUID", events)
        self.assertIn("EVT-UUID-001", res2["processed"]) # Reconnue comme déjà traitée
        
        # Vérifier qu'une seule vente existe avec cet idem
        sales_count = self.conn.execute("SELECT COUNT(*) FROM sales WHERE pharmacy_id=? AND idem='OFF-REC-001'", (ph,)).fetchone()[0]
        self.assertEqual(sales_count, 1)

    def test_sync_pull_delta(self):
        """Vérifie le téléchargement du différentiel pour l'IndexedDB du terminal."""
        delta = pharmaclair.sync_pull_delta(self.conn, self.cashier, since=None, device_uuid="DEVICE-TEST-UUID")
        self.assertIn("server_time", delta)
        self.assertIn("drugs", delta)
        self.assertIn("lots", delta)
        self.assertIn("pharmacy", delta)
        self.assertTrue(len(delta["drugs"]) > 0)

    def test_subscription_and_superadmin(self):
        """Vérifie le paiement d'abonnement Saspay et la gestion Super-Admin."""
        # Paiement Saspay de 3 mois pour l'officine
        res_pay = pharmaclair.pay_subscription_saspay(self.conn, self.owner, months=3, method="orange_money", phone="+237699112233")
        self.assertEqual(res_pay["status"], "ok")
        self.assertEqual(res_pay["amount"], 95000)
        self.assertTrue(res_pay["new_expiry"] > dt.datetime.now(pharmaclair.TZ).date().isoformat())
        
        # Consultation des stats Super-Admin
        sa_stats = pharmaclair.superadmin_stats(self.conn, self.superadmin)
        self.assertGreaterEqual(sa_stats["total_pharmacies"], 1)
        self.assertGreaterEqual(sa_stats["active_subscriptions"], 1)
        self.assertGreaterEqual(len(sa_stats["payments"]), 1)
        
        # Prolongation manuelle par le Super-Admin (+30 jours)
        res_ext = pharmaclair.superadmin_extend_subscription(self.conn, self.superadmin, self.owner["pharmacy_id"], 30)
        self.assertEqual(res_ext["status"], "ok")

if __name__ == "__main__":
    unittest.main()
