-- Heartball encrypted-object index.
-- Only metadata is stored here. Object bytes live in R2 and are always ciphertext.

CREATE TABLE IF NOT EXISTS objects (
  object_key   TEXT PRIMARY KEY,
  device_id    TEXT NOT NULL,
  entry_name   TEXT NOT NULL,
  kind         TEXT NOT NULL,          -- audio | end-marker | note-audio | trace-point | unknown
  size_bytes   INTEGER NOT NULL,
  sha256       TEXT NOT NULL,
  device_start_ms INTEGER,             -- start time parsed from the entry name, when present
  device_end_ms   INTEGER,
  synced_at    INTEGER NOT NULL,       -- unix ms when the object was accepted
  r2_key       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_objects_device_time
  ON objects (device_id, device_end_ms);

CREATE INDEX IF NOT EXISTS idx_objects_kind
  ON objects (kind);

-- Aggregate view used by the inventory endpoint; never exposes content.
CREATE VIEW IF NOT EXISTS inventory AS
SELECT
  device_id,
  COUNT(*)                                   AS object_count,
  COALESCE(SUM(size_bytes), 0)               AS total_bytes,
  SUM(CASE WHEN kind = 'audio' THEN 1 ELSE 0 END)       AS audio_count,
  SUM(CASE WHEN kind = 'end-marker' THEN 1 ELSE 0 END)  AS end_marker_count,
  SUM(CASE WHEN kind = 'trace-point' THEN 1 ELSE 0 END) AS trace_point_count
FROM objects
GROUP BY device_id;
