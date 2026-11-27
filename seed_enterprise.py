"""
PharmaClair — Données de Démonstration Synthétiques Multi-Tenant.
Crée : 1 Super Admin Plateforme, 1 Commercial CRM, 1 Support,
et 3 Pharmacies complètement isolées (Pharmacie A avec succursales, Pharmacie B, Pharmacie C).
"""
import secrets
import datetime as dt
from schema import DB_LOCK, TZ, now
from security import hpw

def seed_enterprise_data(c):
    with DB_LOCK:
        # 1. Plans d'abonnement SaaS configurables
        if not c.execute("SELECT id FROM subscription_plans LIMIT 1").fetchone():
            c.execute("INSERT INTO subscription_plans(code, name, monthly_price, quarterly_price, annual_price, max_branches, max_users) VALUES(?,?,?,?,?,?,?)",
                      ("essential", "Essential", 25000, 68000, 250000, 1, 5))
            c.execute("INSERT INTO subscription_plans(code, name, monthly_price, quarterly_price, annual_price, max_branches, max_users) VALUES(?,?,?,?,?,?,?)",
                      ("professional", "Professional", 35000, 95000, 350000, 3, 15))
            c.execute("INSERT INTO subscription_plans(code, name, monthly_price, quarterly_price, annual_price, max_branches, max_users) VALUES(?,?,?,?,?,?,?)",
                      ("enterprise", "Enterprise Groupe", 65000, 175000, 650000, 20, 100))

        # 2. Comptes Plateforme (Strictement sans pharmacy_id)
        platform_accounts = [
            ("superadmin", "admin123", "superadmin", "Fondateur PharmaClair"),
            ("commercial1", "rep123", "sales_rep", "Jean-Marc Commercial"),
            ("support1", "sup123", "support", "Support Technique N1")
        ]
        for uname, pw, role, fname in platform_accounts:
            if not c.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone():
                salt = secrets.token_hex(8)
                uid = c.execute("INSERT INTO users(pharmacy_id, branch_id, username, full_name, salt, pw, role) VALUES(NULL,NULL,?,?,?,?,?)",
                                (uname, fname, salt, hpw(pw, salt), role)).lastrowid
                if role == "sales_rep":
                    c.execute("INSERT INTO sales_reps(user_id, full_name, territory, phone) VALUES(?,?,?,?)",
                              (uid, fname, "Littoral & Centre", "+237 690 00 00 01"))
            else:
                # S'assurer que superadmin n'a aucun pharmacy_id hérité
                if role == "superadmin":
                    c.execute("UPDATE users SET pharmacy_id=NULL, branch_id=NULL, role='superadmin' WHERE username=?", (uname,))

        # 3. Pharmacies Isolées (A, B, C)
        exp_active = (dt.datetime.now(TZ).date() + dt.timedelta(days=30)).isoformat()
        exp_trial = (dt.datetime.now(TZ).date() + dt.timedelta(days=14)).isoformat()
        exp_overdue = (dt.datetime.now(TZ).date() - dt.timedelta(days=5)).isoformat()

        # Pharmacie A (Groupe)
        ph_a = c.execute("SELECT id FROM pharmacies WHERE id=1").fetchone()
        if not ph_a:
            ph_a_id = c.execute("""
                INSERT INTO pharmacies(id, name, org_type, address, city, phone, email, tax_id, rccm, footer, subscription_plan_id, subscription_status, subscription_expires_at, created_at)
                VALUES(1, 'Grande Pharmacie du Centre (A)', 'group', 'Avenue de la Liberté, Akwa', 'Douala', '+237 233 42 00 00', 'contact@centre-pharma.cm', 'M051812345678X', 'RC/DLA/2018/B/142', 'Merci pour votre confiance', 2, 'active', ?, ?)
            """, (exp_active, now())).lastrowid
        else:
            ph_a_id = ph_a["id"]
            c.execute("UPDATE pharmacies SET subscription_status='active', subscription_plan_id=2 WHERE id=1 AND (subscription_status IS NULL OR subscription_status='')")

        if not c.execute("SELECT id FROM branches WHERE pharmacy_id=?", (ph_a_id,)).fetchone():
            b_a1 = c.execute("INSERT INTO branches(pharmacy_id, name, city, address, is_main) VALUES(?, 'Succursale Akwa (Siège)', 'Douala', 'Avenue de la Liberté', 1)", (ph_a_id,)).lastrowid
            b_a2 = c.execute("INSERT INTO branches(pharmacy_id, name, city, address, is_main) VALUES(?, 'Succursale Bonapriso', 'Douala', 'Rue des Palmiers', 0)", (ph_a_id,)).lastrowid
        else:
            b_a1 = c.execute("SELECT id FROM branches WHERE pharmacy_id=? ORDER BY id LIMIT 1", (ph_a_id,)).fetchone()["id"]

        # Pharmacie B (Indépendante)
        ph_b = c.execute("SELECT id FROM pharmacies WHERE name LIKE '%Pharmacie de la Paix%'").fetchone()
        if not ph_b:
            ph_b_id = c.execute("""
                INSERT INTO pharmacies(name, org_type, address, city, phone, email, tax_id, rccm, subscription_plan_id, subscription_status, subscription_expires_at, created_at)
                VALUES('Pharmacie de la Paix (B)', 'independent', 'Quartier Bastos', 'Yaoundé', '+237 222 20 11 00', 'paix@pharma.cm', 'M092098765432Y', 'RC/YAO/2020/B/88', 1, 'active', ?, ?)
            """, (exp_active, now())).lastrowid
            b_b1 = c.execute("INSERT INTO branches(pharmacy_id, name, city, address, is_main) VALUES(?, 'Officine Principale Bastos', 'Yaoundé', 'Quartier Bastos', 1)", (ph_b_id,)).lastrowid
        else:
            ph_b_id = ph_b["id"]
            b_b1 = c.execute("SELECT id FROM branches WHERE pharmacy_id=? LIMIT 1", (ph_b_id,)).fetchone()["id"]

        # Pharmacie C (En essai ou retard)
        ph_c = c.execute("SELECT id FROM pharmacies WHERE name LIKE '%Pharmacie Espoir%'").fetchone()
        if not ph_c:
            ph_c_id = c.execute("""
                INSERT INTO pharmacies(name, org_type, address, city, phone, email, tax_id, subscription_plan_id, subscription_status, subscription_expires_at, created_at)
                VALUES('Pharmacie Espoir (C)', 'independent', 'Avenue Principale', 'Bafoussam', '+237 677 11 22 33', 'espoir@pharma.cm', 'M012255443322Z', 2, 'overdue', ?, ?)
            """, (exp_overdue, now())).lastrowid
            b_c1 = c.execute("INSERT INTO branches(pharmacy_id, name, city, address, is_main) VALUES(?, 'Officine Bafoussam', 'Bafoussam', 'Avenue Principale', 1)", (ph_c_id,)).lastrowid
        else:
            ph_c_id = ph_c["id"]
            b_c1 = c.execute("SELECT id FROM branches WHERE pharmacy_id=? LIMIT 1", (ph_c_id,)).fetchone()["id"]

        # Utilisateurs de Pharmacie A, B et C
        ph_users = [
            (ph_a_id, b_a1, "titulaire", "admin123", "owner", "Dr. Alain Fokou", 1, 1),
            (ph_a_id, b_a1, "caissier1", "caisse123", "cashier", "Sarah Caisse", 0, 1),
            (ph_a_id, b_a1, "magasinier", "stock123", "stock", "Marc Stock", 1, 0),
            (ph_a_id, b_a1, "comptable_a", "compta123", "accountant", "Pauline Compta", 0, 0),
            (ph_b_id, b_b1, "titulaire_b", "admin123", "owner", "Dr. Beatrice Ndi", 1, 1),
            (ph_b_id, b_b1, "caissier_b", "caisse123", "cashier", "Eric Caisse B", 0, 1),
            (ph_c_id, b_c1, "titulaire_c", "admin123", "owner", "Dr. Kamga C", 1, 1)
        ]
        for ph_id, br_id, uname, pw, role, fname, cb, cc in ph_users:
            if not c.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone():
                salt = secrets.token_hex(8)
                c.execute("""
                    INSERT INTO users(pharmacy_id, branch_id, username, full_name, salt, pw, role, can_block, can_cash)
                    VALUES(?,?,?,?,?,?,?,?,?)
                """, (ph_id, br_id, uname, fname, salt, hpw(pw, salt), role, cb, cc))

        # Médicaments isolés pour Pharmacie A et Pharmacie B
        today = dt.datetime.now(TZ).date()
        if not c.execute("SELECT id FROM drugs WHERE pharmacy_id=?", (ph_a_id,)).fetchone():
            d1 = c.execute("INSERT INTO drugs(pharmacy_id, name, generic_name, dosage, form, pack, price, ref, barcode) VALUES(?, 'Paracétamol 500mg', 'Paracétamol', '500mg', 'Comprimé', 'Boîte de 16', 500, 'PAR-500', '6940001')",(ph_a_id,)).lastrowid
            d2 = c.execute("INSERT INTO drugs(pharmacy_id, name, generic_name, dosage, form, pack, price, ref, barcode) VALUES(?, 'Amoxicilline 500mg', 'Amoxicilline', '500mg', 'Gélule', 'Boîte de 12', 2500, 'AMO-500', '6940002')",(ph_a_id,)).lastrowid
            d3 = c.execute("INSERT INTO drugs(pharmacy_id, name, generic_name, dosage, form, pack, price, ref, barcode) VALUES(?, 'Coartem 20/120mg', 'Artéméther+Luméfantrine', '20/120mg', 'Comprimé', 'Plaquette 24', 3500, 'COA-ACT', '6940003')",(ph_a_id,)).lastrowid
            c.execute("INSERT INTO lots(pharmacy_id, branch_id, drug_id, lot_no, expiry, expiry_date, qty, purchase_cost) VALUES(?,?,?, 'LT-A01', '2027-08', ?, 120, 320)", (ph_a_id, b_a1, d1, (today + dt.timedelta(days=500)).isoformat()))
            c.execute("INSERT INTO lots(pharmacy_id, branch_id, drug_id, lot_no, expiry, expiry_date, qty, purchase_cost) VALUES(?,?,?, 'LT-A02', '2027-04', ?, 60, 1750)", (ph_a_id, b_a1, d2, (today + dt.timedelta(days=400)).isoformat()))
            c.execute("INSERT INTO lots(pharmacy_id, branch_id, drug_id, lot_no, expiry, expiry_date, qty, purchase_cost) VALUES(?,?,?, 'LT-A03', '2026-12', ?, 45, 2400)", (ph_a_id, b_a1, d3, (today + dt.timedelta(days=300)).isoformat()))

        if not c.execute("SELECT id FROM drugs WHERE pharmacy_id=?", (ph_b_id,)).fetchone():
            db1 = c.execute("INSERT INTO drugs(pharmacy_id, name, generic_name, dosage, form, pack, price, ref, barcode) VALUES(?, 'Doliprane 1000mg', 'Paracétamol', '1000mg', 'Comprimé', 'Boîte de 8', 1200, 'DOL-1000', '6950001')",(ph_b_id,)).lastrowid
            c.execute("INSERT INTO lots(pharmacy_id, branch_id, drug_id, lot_no, expiry, expiry_date, qty, purchase_cost) VALUES(?,?,?, 'LT-B01', '2027-10', ?, 90, 800)", (ph_b_id, b_b1, db1, (today + dt.timedelta(days=600)).isoformat()))

        # Patients isolés (Pharmacie A vs Pharmacie B)
        if not c.execute("SELECT id FROM customers WHERE pharmacy_id=?", (ph_a_id,)).fetchone():
            ca1 = c.execute("INSERT INTO customers(pharmacy_id, name, phone, allergies, ts) VALUES(?, 'Patient Privé A1', '+237 699 11 11 11', 'Pénicilline', ?)", (ph_a_id, now())).lastrowid
            da = c.execute("SELECT id FROM drugs WHERE pharmacy_id=? LIMIT 1", (ph_a_id,)).fetchone()["id"]
            c.execute("INSERT INTO prescriptions(pharmacy_id, customer_id, doctor, drug_id, posology, refills_total, refills_left, expiry_date, ts) VALUES(?,?, 'Dr. Mbarga', ?, '1 cp x 3/j', 3, 2, ?, ?)",
                      (ph_a_id, ca1, da, (today + dt.timedelta(days=90)).isoformat(), now()))

        if not c.execute("SELECT id FROM customers WHERE pharmacy_id=?", (ph_b_id,)).fetchone():
            cb1 = c.execute("INSERT INTO customers(pharmacy_id, name, phone, allergies, ts) VALUES(?, 'Patient Secret B1', '+237 677 22 22 22', 'Aucune', ?)", (ph_b_id, now())).lastrowid
            db_id = c.execute("SELECT id FROM drugs WHERE pharmacy_id=? LIMIT 1", (ph_b_id,)).fetchone()["id"]
            c.execute("INSERT INTO prescriptions(pharmacy_id, customer_id, doctor, drug_id, posology, refills_total, refills_left, expiry_date, ts) VALUES(?,?, 'Dr. Tchoua', ?, '1 cp matin', 2, 2, ?, ?)",
                      (ph_b_id, cb1, db_id, (today + dt.timedelta(days=60)).isoformat(), now()))

        # Prospects CRM Commerciaux
        if not c.execute("SELECT id FROM crm_prospects LIMIT 1").fetchone():
            rep = c.execute("SELECT id FROM sales_reps LIMIT 1").fetchone()
            rid = rep["id"] if rep else None
            c.execute("INSERT INTO crm_prospects(sales_rep_id, pharmacy_name, contact_name, phone, city, stage, created_at) VALUES(?, 'Pharmacie du Wouri', 'Dr. Nguema', '+237 691 22 33 44', 'Douala', 'demo_completed', ?)", (rid, now()))
            c.execute("INSERT INTO crm_prospects(sales_rep_id, pharmacy_name, contact_name, phone, city, stage, created_at) VALUES(?, 'Pharmacie des Montagnes', 'Dr. Fotso', '+237 675 44 55 66', 'Bafoussam', 'negotiation', ?)", (rid, now()))
