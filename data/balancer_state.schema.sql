CREATE TABLE IF NOT EXISTS nodes (
  name       TEXT PRIMARY KEY,
  status     TEXT NOT NULL DEFAULT 'unknown',
  delay_ms   INTEGER,
  last_check INTEGER NOT NULL DEFAULT 0,
  fails      INTEGER NOT NULL DEFAULT 0,
  uses       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rotation_state (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  position   INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rotation_log (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       INTEGER NOT NULL,
  node     TEXT NOT NULL,
  delay_ms INTEGER,
  reason   TEXT NOT NULL DEFAULT 'rotate'
);

CREATE INDEX IF NOT EXISTS idx_nodes_status_check ON nodes (status, last_check);
CREATE INDEX IF NOT EXISTS idx_rotation_log_ts ON rotation_log (ts);
