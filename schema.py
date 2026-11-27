"""
PharmaClair — Schéma de Base de Données Multi-Tenant & Migrations Rétrocompatibles.
Garantit l'isolation stricte par pharmacy_id et branch_id.
"""
import sqlite3
import threading
import datetime as dt

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("Africa/Douala")
except Exception:
    TZ = dt.timezone(dt.timedelta(hours=1))

DB_LOCK = threading.RLock()

def now():
    return dt.datetime.now(TZ).isoformat(timespec="seconds")

SCHEMA = """
-- ============================================================================
-- 1. TABLES PLATEFORME SAAS (Administration PharmaClair)
-- ============================================================================
CREATE TABLE IF NOT EXISTS subscription_plans(
  id INTEGER PRIMARY KEY,
  code TEXT UNIQUE,
  name TEXT,
  monthly_price INT,
  quarterly_price INT,
  annual_price INT,
  max_branches INT DEFAULT 1,
  max_users INT DEFAULT 5,
  features_json TEXT DEFAULT '{}',
  active INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS pharmacies(
  id INTEGER PRIMARY KEY,
  name TEXT,
  org_type TEXT DEFAULT 'independent',
  address TEXT,
  tax_id TEXT,
  footer TEXT,
  phone TEXT DEFAULT '',
  email TEXT DEFAULT '',
  city TEXT DEFAULT 'Douala',
  country TEXT DEFAULT 'Cameroun',
  rccm TEXT DEFAULT '',
  currency TEXT DEFAULT 'FCFA',
  receipt_format TEXT DEFAULT '80mm',
  saspay_client_id TEXT DEFAULT '',
  saspay_secret TEXT DEFAULT '',
  saspay_mode TEXT DEFAULT 'sandbox',
  subscription_plan_id INT DEFAULT 1,
  subscription_status TEXT DEFAULT 'trial',
  subscription_expires_at TEXT DEFAULT '',
  trial_ends_at TEXT DEFAULT '',
  grace_period_days INT DEFAULT 7,
  sales_rep_id INT DEFAULT NULL,
  created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS saas_invoices(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  invoice_no TEXT UNIQUE,
  plan_id INT,
  amount INT,
  discount INT DEFAULT 0,
  status TEXT DEFAULT 'unpaid',
  period_start TEXT,
  period_end TEXT,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS subscription_payments(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  invoice_id INT DEFAULT NULL,
  amount INT,
  months INT,
  payment_method TEXT,
  payment_ref TEXT UNIQUE,
  provider TEXT DEFAULT 'saspay',
  status TEXT DEFAULT 'completed',
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS platform_expenses(
  id INTEGER PRIMARY KEY,
  category TEXT,
  description TEXT,
  amount INT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS sales_reps(
  id INTEGER PRIMARY KEY,
  user_id INT,
  full_name TEXT,
  territory TEXT,
  phone TEXT,
  commission_rate REAL DEFAULT 0.10,
  active INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS crm_prospects(
  id INTEGER PRIMARY KEY,
  sales_rep_id INT,
  pharmacy_name TEXT,
  contact_name TEXT,
  phone TEXT,
  email TEXT,
  city TEXT,
  stage TEXT DEFAULT 'new',
  notes TEXT DEFAULT '',
  next_followup TEXT DEFAULT '',
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS crm_commissions(
  id INTEGER PRIMARY KEY,
  sales_rep_id INT,
  pharmacy_id INT,
  amount INT,
  status TEXT DEFAULT 'pending',
  ts TEXT
);

CREATE TABLE IF NOT EXISTS support_tickets(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  created_by_user_id INT,
  category TEXT,
  priority TEXT DEFAULT 'normal',
  subject TEXT,
  description_redacted TEXT,
  status TEXT DEFAULT 'open',
  assigned_to INT DEFAULT NULL,
  satisfaction_rating INT DEFAULT NULL,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS platform_audit(
  id INTEGER PRIMARY KEY,
  actor_user_id INT,
  action TEXT,
  target_pharmacy_id INT DEFAULT NULL,
  data TEXT,
  ts TEXT
);

-- ============================================================================
-- 2. TABLES UTILISATEURS, SUCCURSALES & SESSIONS (Isolation Multi-Tenant)
-- ============================================================================
CREATE TABLE IF NOT EXISTS branches(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  name TEXT NOT NULL,
  city TEXT DEFAULT 'Douala',
  address TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  is_main INT DEFAULT 0,
  active INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS custom_roles(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  name TEXT NOT NULL,
  permissions_json TEXT NOT NULL,
  UNIQUE(pharmacy_id, name)
);

CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT DEFAULT NULL,
  branch_id INT DEFAULT NULL,
  username TEXT UNIQUE,
  full_name TEXT DEFAULT '',
  email TEXT DEFAULT '',
  salt TEXT,
  pw TEXT,
  role TEXT,
  custom_role_id INT DEFAULT NULL,
  active INT DEFAULT 1,
  can_block INT DEFAULT 0,
  can_cash INT DEFAULT 0,
  fails INT DEFAULT 0,
  mfa_enabled INT DEFAULT 0,
  mfa_secret TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INT NOT NULL,
  pharmacy_id INT DEFAULT NULL,
  branch_id INT DEFAULT NULL,
  expires_at TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  created_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS user_logins(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT DEFAULT NULL,
  user_id INT,
  action TEXT,
  ip TEXT,
  ts TEXT
);

-- ============================================================================
-- 3. TABLES OPÉRATIONNELLES OFFICINALES (Strictement isolées par pharmacy_id)
-- ============================================================================
CREATE TABLE IF NOT EXISTS drugs(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  name TEXT NOT NULL,
  generic_name TEXT DEFAULT '',
  dosage TEXT DEFAULT '',
  form TEXT DEFAULT '',
  manufacturer TEXT DEFAULT '',
  category TEXT DEFAULT 'Général',
  pack TEXT,
  price INT NOT NULL,
  ref TEXT,
  barcode TEXT,
  min_stock INT DEFAULT 10,
  max_stock INT DEFAULT 200,
  reorder_threshold INT DEFAULT 15
);

CREATE TABLE IF NOT EXISTS suppliers(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  name TEXT NOT NULL,
  contact TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  email TEXT DEFAULT '',
  payment_terms TEXT DEFAULT '30 jours',
  balance INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS lots(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  drug_id INT NOT NULL,
  lot_no TEXT NOT NULL,
  expiry TEXT,
  expiry_date TEXT,
  qty INT NOT NULL,
  purchase_cost INT DEFAULT 0,
  supplier_id INT DEFAULT NULL,
  storage_location TEXT DEFAULT 'Rayon Principal',
  status TEXT DEFAULT 'ok',
  UNIQUE(pharmacy_id, drug_id, lot_no)
);

CREATE TABLE IF NOT EXISTS purchase_orders(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  supplier_id INT NOT NULL,
  po_no TEXT,
  status TEXT DEFAULT 'draft',
  total_amount INT DEFAULT 0,
  created_by INT,
  approved_by INT DEFAULT NULL,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS purchase_order_lines(
  id INTEGER PRIMARY KEY,
  po_id INT NOT NULL,
  pharmacy_id INT NOT NULL,
  drug_id INT NOT NULL,
  qty_ordered INT NOT NULL,
  qty_received INT DEFAULT 0,
  unit_cost INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS movements(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  lot_id INT NOT NULL,
  type TEXT,
  qty INT,
  ref TEXT,
  user_id INT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS sales(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  user_id INT NOT NULL,
  customer_id INT DEFAULT NULL,
  idem TEXT NOT NULL,
  receipt_no TEXT,
  total INT NOT NULL,
  total_cost INT DEFAULT 0,
  discount INT DEFAULT 0,
  method TEXT,
  paid INT,
  change INT,
  payment_status TEXT DEFAULT 'provider_confirmed',
  snapshot TEXT DEFAULT '',
  is_offline INT DEFAULT 0,
  ts TEXT,
  UNIQUE(pharmacy_id, idem)
);

CREATE TABLE IF NOT EXISTS sale_lines(
  id INTEGER PRIMARY KEY,
  sale_id INT NOT NULL,
  pharmacy_id INT NOT NULL,
  drug_id INT NOT NULL,
  lot_id INT NOT NULL,
  qty INT NOT NULL,
  price INT NOT NULL,
  unit_cost INT DEFAULT 0,
  label TEXT
);

CREATE TABLE IF NOT EXISTS returns(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  sale_id INT NOT NULL,
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
  pharmacy_id INT DEFAULT NULL,
  qty INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cash_closings(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
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
  pharmacy_id INT NOT NULL,
  name TEXT,
  phone TEXT,
  allergies TEXT DEFAULT '',
  insurance_info TEXT DEFAULT '',
  consent_sms INT DEFAULT 1,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS prescriptions(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  customer_id INT NOT NULL,
  doctor TEXT,
  drug_id INT NOT NULL,
  posology TEXT,
  refills_total INT,
  refills_left INT,
  expiry_date TEXT,
  status TEXT DEFAULT 'active',
  ts TEXT
);

CREATE TABLE IF NOT EXISTS sms_notifs(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  customer_id INT,
  phone TEXT,
  message TEXT,
  status TEXT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS cameras(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  name TEXT,
  location TEXT,
  stream_url TEXT,
  active INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS expenses(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  user_id INT,
  amount INT,
  category TEXT,
  description TEXT,
  ts TEXT
);

CREATE TABLE IF NOT EXISTS device_enrollments(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
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
  pharmacy_id INT NOT NULL,
  device_uuid TEXT,
  event_id TEXT UNIQUE,
  event_type TEXT,
  payload TEXT,
  server_status TEXT DEFAULT 'processed',
  conflict_details TEXT,
  processed_at TEXT
);

CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  user_id INT,
  device_uuid TEXT DEFAULT '',
  action TEXT,
  prev_val TEXT DEFAULT '',
  new_val TEXT DEFAULT '',
  reason TEXT DEFAULT '',
  data TEXT,
  ts TEXT
);

-- ============================================================================
-- 4. WORKFLOWS OPÉRATIONNELS EMPLOYÉS, APPROBATIONS, TÂCHES & CAISSES
-- ============================================================================
CREATE TABLE IF NOT EXISTS cash_sessions(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  user_id INT NOT NULL,
  opening_balance INT DEFAULT 0,
  counted_cash INT DEFAULT 0,
  expected_cash INT DEFAULT 0,
  diff_cash INT DEFAULT 0,
  total_om INT DEFAULT 0,
  total_card INT DEFAULT 0,
  status TEXT DEFAULT 'open',
  comments TEXT DEFAULT '',
  opened_at TEXT,
  closed_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS approval_requests(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  user_id INT NOT NULL,
  request_type TEXT NOT NULL,
  target_id INT DEFAULT NULL,
  payload_json TEXT DEFAULT '{}',
  reason TEXT DEFAULT '',
  status TEXT DEFAULT 'pending',
  reviewed_by INT DEFAULT NULL,
  review_note TEXT DEFAULT '',
  created_at TEXT,
  reviewed_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS inventory_counts(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  user_id INT NOT NULL,
  drug_id INT NOT NULL,
  lot_id INT NOT NULL,
  system_qty INT NOT NULL,
  counted_qty INT NOT NULL,
  discrepancy INT NOT NULL,
  note TEXT DEFAULT '',
  status TEXT DEFAULT 'pending_review',
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS employee_tasks(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  assigned_to INT NOT NULL,
  assigned_by INT NOT NULL,
  title TEXT NOT NULL,
  instructions TEXT DEFAULT '',
  priority TEXT DEFAULT 'normal',
  due_date TEXT DEFAULT '',
  status TEXT DEFAULT 'pending',
  completion_note TEXT DEFAULT '',
  created_at TEXT,
  completed_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS goods_receipts(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  branch_id INT DEFAULT NULL,
  user_id INT NOT NULL,
  supplier_id INT DEFAULT NULL,
  supplier_name TEXT DEFAULT '',
  bl_number TEXT DEFAULT '',
  items_json TEXT DEFAULT '[]',
  notes TEXT DEFAULT '',
  status TEXT DEFAULT 'accepted',
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS operational_notifications(
  id INTEGER PRIMARY KEY,
  pharmacy_id INT NOT NULL,
  target_role TEXT DEFAULT 'all',
  target_user_id INT DEFAULT NULL,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  category TEXT DEFAULT 'info',
  is_read INT DEFAULT 0,
  created_at TEXT
);

-- Index d'isolation multi-tenant pour hautes performances
CREATE INDEX IF NOT EXISTS idx_drugs_ph ON drugs(pharmacy_id);
CREATE INDEX IF NOT EXISTS idx_lots_ph_drug ON lots(pharmacy_id, drug_id);
CREATE INDEX IF NOT EXISTS idx_sales_ph_ts ON sales(pharmacy_id, ts);
CREATE INDEX IF NOT EXISTS idx_customers_ph ON customers(pharmacy_id);
CREATE INDEX IF NOT EXISTS idx_audit_ph ON audit(pharmacy_id, ts);
"""

def _add_col_if_missing(c, table, col_name, col_def):
    cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})").fetchall()]
    if col_name not in cols:
        try:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
        except Exception:
            pass

def run_migrations(c):
    with DB_LOCK:
        # Migrations rétrocompatibles sur bases existantes
        ph_cols = {
            "org_type": "TEXT DEFAULT 'independent'",
            "phone": "TEXT DEFAULT ''",
            "email": "TEXT DEFAULT ''",
            "city": "TEXT DEFAULT 'Douala'",
            "country": "TEXT DEFAULT 'Cameroun'",
            "rccm": "TEXT DEFAULT ''",
            "currency": "TEXT DEFAULT 'FCFA'",
            "receipt_format": "TEXT DEFAULT '80mm'",
            "saspay_client_id": "TEXT DEFAULT ''",
            "saspay_secret": "TEXT DEFAULT ''",
            "saspay_mode": "TEXT DEFAULT 'sandbox'",
            "subscription_plan_id": "INT DEFAULT 1",
            "subscription_status": "TEXT DEFAULT 'trial'",
            "subscription_expires_at": "TEXT DEFAULT ''",
            "trial_ends_at": "TEXT DEFAULT ''",
            "grace_period_days": "INT DEFAULT 7",
            "sales_rep_id": "INT DEFAULT NULL",
            "created_at": "TEXT DEFAULT ''"
        }
        for k, v in ph_cols.items():
            _add_col_if_missing(c, "pharmacies", k, v)

        _add_col_if_missing(c, "users", "branch_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "users", "full_name", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "users", "email", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "users", "custom_role_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "users", "mfa_enabled", "INT DEFAULT 0")
        _add_col_if_missing(c, "users", "mfa_secret", "TEXT DEFAULT ''")

        _add_col_if_missing(c, "sessions", "pharmacy_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "sessions", "branch_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "sessions", "expires_at", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "sessions", "ip", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "sessions", "created_at", "TEXT DEFAULT ''")

        _add_col_if_missing(c, "drugs", "generic_name", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "drugs", "dosage", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "drugs", "form", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "drugs", "manufacturer", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "drugs", "category", "TEXT DEFAULT 'Général'")
        _add_col_if_missing(c, "drugs", "min_stock", "INT DEFAULT 10")
        _add_col_if_missing(c, "drugs", "max_stock", "INT DEFAULT 200")
        _add_col_if_missing(c, "drugs", "reorder_threshold", "INT DEFAULT 15")

        _add_col_if_missing(c, "lots", "branch_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "lots", "purchase_cost", "INT DEFAULT 0")
        _add_col_if_missing(c, "lots", "supplier_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "lots", "storage_location", "TEXT DEFAULT 'Rayon Principal'")

        _add_col_if_missing(c, "sales", "customer_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "sales", "branch_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "sales", "total_cost", "INT DEFAULT 0")
        _add_col_if_missing(c, "sales", "discount", "INT DEFAULT 0")
        _add_col_if_missing(c, "sales", "payment_status", "TEXT DEFAULT 'provider_confirmed'")
        _add_col_if_missing(c, "sales", "is_offline", "INT DEFAULT 0")

        _add_col_if_missing(c, "sale_lines", "pharmacy_id", "INT DEFAULT 1")
        _add_col_if_missing(c, "sale_lines", "unit_cost", "INT DEFAULT 0")

        _add_col_if_missing(c, "customers", "allergies", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "customers", "insurance_info", "TEXT DEFAULT ''")

        _add_col_if_missing(c, "audit", "branch_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "audit", "device_uuid", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "audit", "prev_val", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "audit", "new_val", "TEXT DEFAULT ''")
        _add_col_if_missing(c, "audit", "reason", "TEXT DEFAULT ''")

        _add_col_if_missing(c, "user_logins", "pharmacy_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "movements", "branch_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "cash_closings", "branch_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "expenses", "branch_id", "INT DEFAULT NULL")
        _add_col_if_missing(c, "device_enrollments", "branch_id", "INT DEFAULT NULL")

def connect(path=":memory:"):
    c = sqlite3.connect(path, isolation_level=None, timeout=15, check_same_thread=False)
    c.row_factory = sqlite3.Row
    with DB_LOCK:
        c.executescript(SCHEMA)
        run_migrations(c)
    return c
