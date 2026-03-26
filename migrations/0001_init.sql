-- Echo SDK Dashboard v1.0.0 — Initial schema
-- Dashboard widgets configuration per tenant
CREATE TABLE IF NOT EXISTS dashboard_configs (
  tenant_id TEXT PRIMARY KEY,
  layout TEXT DEFAULT '{}',
  widgets TEXT DEFAULT '[]',
  theme TEXT DEFAULT 'dark',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

-- Saved reports
CREATE TABLE IF NOT EXISTS saved_reports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  report_type TEXT NOT NULL,
  filters TEXT DEFAULT '{}',
  schedule TEXT,
  last_run TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_reports_tenant ON saved_reports(tenant_id);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  type TEXT NOT NULL,
  threshold REAL NOT NULL,
  channel TEXT DEFAULT 'email',
  enabled INTEGER DEFAULT 1,
  last_triggered TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_alerts_tenant ON alerts(tenant_id);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  details TEXT DEFAULT '{}',
  ip TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_audit_tenant ON audit_log(tenant_id, created_at DESC);

-- Daily usage rollups (aggregated from SDK Gateway)
CREATE TABLE IF NOT EXISTS usage_rollups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id TEXT NOT NULL,
  date TEXT NOT NULL,
  total_requests INTEGER DEFAULT 0,
  total_errors INTEGER DEFAULT 0,
  avg_latency_ms REAL DEFAULT 0,
  p95_latency_ms REAL DEFAULT 0,
  p99_latency_ms REAL DEFAULT 0,
  top_endpoints TEXT DEFAULT '[]',
  error_breakdown TEXT DEFAULT '{}',
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(tenant_id, date)
);
CREATE INDEX idx_rollups_tenant_date ON usage_rollups(tenant_id, date DESC);
