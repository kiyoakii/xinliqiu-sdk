-- Storage contract hardening: canonical device identity, explicit encryption
-- labels for diagnostics, and content-addressed idempotency per raw device.
--
-- Applied by the tracked migration runner in setup.sh, in filename order,
-- after 0001_init.sql and 0002_sync.sql, on fresh and existing deploys.

-- Canonical object-key component: lowercase hex of the UTF-8 device identity.
-- SQLite's hex() produces exactly the same value the Worker and the Python
-- LocalStorage compute, so existing rows are backfilled without a rewrite.
ALTER TABLE objects ADD COLUMN device_key TEXT;
ALTER TABLE objects ADD COLUMN encryption TEXT;

UPDATE objects
   SET device_key = 'd1-' || lower(hex(CAST(device_id AS BLOB)))
 WHERE device_key IS NULL;

-- Rows written before seq existed keep a deterministic order.
UPDATE objects SET seq = rowid WHERE seq IS NULL;

-- Idempotent completion of 0001/0002 for deploys where they were applied by
-- hand (or only partly applied) before migrations were tracked.
CREATE INDEX IF NOT EXISTS idx_objects_device_time ON objects (device_id, device_end_ms);
CREATE INDEX IF NOT EXISTS idx_objects_kind ON objects (kind);
CREATE UNIQUE INDEX IF NOT EXISTS idx_objects_seq ON objects (seq);
CREATE INDEX IF NOT EXISTS idx_objects_device_seq ON objects (device_id, seq);
CREATE VIEW IF NOT EXISTS inventory_digest AS
SELECT
  device_id,
  COUNT(*)                      AS object_count,
  COALESCE(SUM(size_bytes), 0)  AS total_bytes,
  MAX(seq)                      AS latest_seq
FROM objects
GROUP BY device_id;

-- One object per (raw device identity, content hash). This makes retries
-- idempotent even for rows whose object_key predates canonical encoding.
CREATE UNIQUE INDEX IF NOT EXISTS idx_objects_device_sha
  ON objects (device_id, sha256);
CREATE INDEX IF NOT EXISTS idx_objects_device_key
  ON objects (device_key);
CREATE INDEX IF NOT EXISTS idx_objects_device_range
  ON objects (device_id, device_start_ms, device_end_ms);

-- Defence in depth behind the Worker's own kind whitelist: direct SQL writes
-- cannot reintroduce plaintext/diagnostic kinds. Existing legacy rows are
-- untouched; this only constrains new inserts.
CREATE TRIGGER IF NOT EXISTS trg_objects_kind_insert
BEFORE INSERT ON objects
WHEN NEW.kind NOT IN ('audio', 'note-audio', 'end-marker', 'mark', 'diagnostic')
BEGIN
  SELECT RAISE(ABORT, 'unsupported object kind');
END;

-- Aggregate view used by the inventory endpoint; never exposes content.
DROP VIEW IF EXISTS inventory;
CREATE VIEW inventory AS
SELECT
  device_id,
  COUNT(*)                                              AS object_count,
  COALESCE(SUM(size_bytes), 0)                          AS total_bytes,
  SUM(CASE WHEN kind = 'audio' THEN 1 ELSE 0 END)       AS audio_count,
  SUM(CASE WHEN kind = 'note-audio' THEN 1 ELSE 0 END)  AS note_audio_count,
  SUM(CASE WHEN kind = 'end-marker' THEN 1 ELSE 0 END)  AS end_marker_count,
  SUM(CASE WHEN kind = 'mark' THEN 1 ELSE 0 END)        AS mark_count,
  SUM(CASE WHEN kind = 'diagnostic' THEN 1 ELSE 0 END)  AS diagnostic_count,
  SUM(CASE WHEN kind = 'trace-point' THEN 1 ELSE 0 END) AS trace_point_count,
  MAX(seq)                                              AS latest_seq
FROM objects
GROUP BY device_id;
