CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  normalized_url TEXT NOT NULL,
  hostname TEXT NOT NULL,
  status TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL,
  report_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_expires_at ON scans(expires_at);

CREATE TABLE IF NOT EXISTS rate_limits (
  client_key TEXT NOT NULL,
  window_date TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (client_key, window_date)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_date ON rate_limits(window_date);

CREATE TABLE IF NOT EXISTS provider_usage (
  provider TEXT NOT NULL,
  window_key TEXT NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (provider, window_key)
);

CREATE INDEX IF NOT EXISTS idx_provider_usage_updated_at ON provider_usage(updated_at);

CREATE TABLE IF NOT EXISTS schema_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_metadata (key, value, updated_at)
VALUES ('schema_version', '1', datetime('now'));
