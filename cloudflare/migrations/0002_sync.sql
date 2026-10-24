-- Incremental sync support.
-- `synced_at` is the storage-side ingestion time; `seq` is a monotonic
-- per-database counter that makes cursors stable even when two objects share
-- the same millisecond.

ALTER TABLE objects ADD COLUMN seq INTEGER;

-- Backfill any pre-existing rows deterministically.
UPDATE objects SET seq = rowid WHERE seq IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_objects_seq ON objects (seq);
CREATE INDEX IF NOT EXISTS idx_objects_device_seq ON objects (device_id, seq);

-- Inventory digest view: exposes only what is needed to compare two clients.
CREATE VIEW IF NOT EXISTS inventory_digest AS
SELECT
  device_id,
  COUNT(*)                      AS object_count,
  COALESCE(SUM(size_bytes), 0)  AS total_bytes,
  MAX(seq)                      AS latest_seq
FROM objects
GROUP BY device_id;
