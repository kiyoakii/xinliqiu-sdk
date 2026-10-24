/**
 * Xinliqiu encrypted-object store.
 *
 * Design commitments:
 *   - Only ciphertext is ever stored. The Worker never receives, holds or
 *     returns a decryption key.
 *   - Device credentials (KSC, peer id, owner private key) must never be sent
 *     here. There is no endpoint for them.
 *   - The only secret the Worker knows is a bearer token you set yourself.
 *
 * Storage contract (see migrations/0003_storage_contract.sql):
 *   - Raw device identities are kept in D1 and checked on every write; the
 *     canonical object-key component is lowercase hex of the UTF-8 identity,
 *     so two distinct identities can never collide on one object key.
 *   - Range queries use inclusive interval overlap, not "end inside range".
 *   - The digest is versioned and depends only on device, range, untimed
 *     policy and content hashes, so a LocalStorage mirror agrees with it.
 */

const MAX_OBJECT_BYTES = 2 * 1024 * 1024;
const MAX_PAGE_LIMIT = 1000;
const MAX_SAFE_MS = Number.MAX_SAFE_INTEGER;
const DIGEST_VERSION = "xinliqiu-storage-digest/v1";
const DEVICE_KEY_PREFIX = "d1-";
const SHA256_RE = /^[0-9a-f]{64}$/;
const ENPT_HEADER = 280;
const ENPT_TRAILER = 24;
const CIPHERTEXT_KINDS = new Set(["audio", "note-audio", "end-marker", "mark"]);
const DIAGNOSTIC_KIND = "diagnostic";
const KIND_UPLOAD_ALLOWED = new Set([...CIPHERTEXT_KINDS, DIAGNOSTIC_KIND]);
const KIND_FILTER_ALLOWED = new Set([
  ...KIND_UPLOAD_ALLOWED, "trace-point", "unknown", "compat-tp",
]);
const SORT_EXPRESSION = `
  MIN(COALESCE(device_start_ms, device_end_ms), COALESCE(device_end_ms, device_start_ms)) AS lo,
  MAX(COALESCE(device_start_ms, device_end_ms), COALESCE(device_end_ms, device_start_ms)) AS hi,
  CASE WHEN device_start_ms IS NULL AND device_end_ms IS NULL THEN 1 ELSE 0 END AS bucket`;
const LIST_COLUMNS = `object_key, device_id, device_key, entry_name, kind, size_bytes,
  sha256, device_start_ms, device_end_ms, synced_at, seq, encryption`;

class HttpError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...extra },
  });
}

function unauthorized() {
  return json({ error: "unauthorized" }, 401, { "www-authenticate": "Bearer" });
}

async function authorize(request, env) {
  const header = request.headers.get("authorization") || "";
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) return false;
  const presented = match[1].trim();
  const expected = env.XINLIQIU_TOKEN || "";
  if (!expected || presented.length !== expected.length) return false;
  // Constant-time-ish compare.
  let diff = 0;
  for (let i = 0; i < expected.length; i += 1) {
    diff |= presented.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function textBytes(value) {
  return new TextEncoder().encode(value);
}

function validateDeviceId(value) {
  if (typeof value !== "string" || !value) throw new HttpError("device identity required");
  if (value.trim() !== value) throw new HttpError("device identity has surrounding whitespace");
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(value)) throw new HttpError("device identity has control characters");
  if (textBytes(value).length > 256) throw new HttpError("device identity exceeds 256 UTF-8 bytes");
  return value;
}

function canonicalDeviceKey(deviceId) {
  validateDeviceId(deviceId);
  return DEVICE_KEY_PREFIX + Array.from(textBytes(deviceId))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function decodeHeader(request, name) {
  const raw = request.headers.get(name);
  if (raw === null) return null;
  if (request.headers.get(`${name}-encoding`) === "percent") {
    try {
      return decodeURIComponent(raw);
    } catch {
      throw new HttpError(`${name} is not valid percent-encoded UTF-8`);
    }
  }
  return raw;
}

function parseMsParam(value, label, fallback) {
  if (value === null || value === undefined || value === "") return fallback;
  if (!/^[0-9]{1,16}$/.test(String(value))) throw new HttpError(`${label} must be a non-negative integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > MAX_SAFE_MS) {
    throw new HttpError(`${label} exceeds the safe integer range`);
  }
  return parsed;
}

function parseRange(url) {
  const startMs = parseMsParam(url.searchParams.get("start_ms"), "start_ms", 0);
  const endMs = parseMsParam(url.searchParams.get("end_ms"), "end_ms", MAX_SAFE_MS);
  if (endMs < startMs) throw new HttpError("end_ms must be >= start_ms");
  return { startMs, endMs };
}

function parseLimit(url, fallback) {
  const raw = url.searchParams.get("limit");
  if (raw === null || raw === "") return fallback;
  if (!/^[0-9]{1,4}$/.test(raw)) throw new HttpError("limit must be an integer");
  const limit = Number(raw);
  if (limit < 1 || limit > MAX_PAGE_LIMIT) {
    throw new HttpError(`limit must be within 1..${MAX_PAGE_LIMIT}`);
  }
  return limit;
}

function parseUntimed(url) {
  const raw = url.searchParams.get("include_untimed");
  if (raw === null || raw === "") return 1;
  if (raw !== "0" && raw !== "1") throw new HttpError("include_untimed must be 0 or 1");
  return Number(raw);
}

function base64urlEncode(text) {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
}

function encodeCursor(row) {
  return base64urlEncode(JSON.stringify({
    v: 1, b: Number(row.bucket), t: Number(row.bucket) === 0 ? Number(row.lo) : null, s: Number(row.seq),
  }));
}

function decodeCursor(raw) {
  if (!raw || raw.length > 256) throw new HttpError("invalid cursor");
  let data;
  try {
    data = JSON.parse(base64urlDecode(raw));
  } catch {
    throw new HttpError("invalid cursor");
  }
  if (!data || data.v !== 1 || (data.b !== 0 && data.b !== 1)) throw new HttpError("unsupported cursor");
  if (!Number.isSafeInteger(data.s) || data.s < 0) throw new HttpError("invalid cursor sequence");
  if (data.b === 0) {
    if (!Number.isSafeInteger(data.t) || data.t < 0) throw new HttpError("invalid cursor timestamp");
  } else if (data.t !== null) {
    throw new HttpError("untimed cursor must not carry a timestamp");
  }
  return data;
}

// Device timestamps from an entry name, mirroring storage.entry_times in the
// Python SDK so both backends agree on what is timed and what is untimed.
// Values beyond the JavaScript safe-integer range are dropped.
const FILENAME_SUFFIXES = [
  ".end.enc.opus", ".end.opus",
  ".enc.note.opus", ".note.opus",
  ".enc.noise.opus", ".noise.opus",
  ".enc.vp.opus", ".vp.opus",
  ".compat", ".mark", ".enc.opus", ".opus",
];
const INT64_MIN = -(2n ** 63n);
const INT64_MAX = 2n ** 63n - 1n;
const MAX_SAFE_BIGINT = BigInt(MAX_SAFE_MS);

function signedLong(text) {
  if (!/^\+?[0-9]+$/.test(text)) return null;
  const value = BigInt(text[0] === "+" ? text.slice(1) : text);
  if (value < INT64_MIN || value > INT64_MAX) return null;
  return value;
}

function parseEntryTimes(name) {
  const base = name.replace(/\\/g, "/").split("/").pop();
  const lowered = base.toLowerCase();
  const suffix = FILENAME_SUFFIXES.find((candidate) => lowered.endsWith(candidate)) || "";
  const stem = suffix ? base.slice(0, base.length - suffix.length) : base;
  const none = { start: null, end: null };
  let parts = stem.split("_");
  if (suffix === ".mark") {
    if (parts.length !== 2) {
      if (parts.length !== 1) return none;
      parts = stem.split("-");
      if (parts.length >= 3) return none;
    }
    if (parts.length === 1) {
      const n = signedLong(parts[0]);
      if (n === null || n <= 0n || n >= INT64_MAX || n + 1n > MAX_SAFE_BIGINT) return none;
      return { start: Number(n), end: Number(n + 1n) };
    }
    const start = signedLong(parts[0]);
    const end = signedLong(parts[1]);
    if (start === null || end === null || start <= 0n || end <= 0n || end <= start) return none;
    if (start > MAX_SAFE_BIGINT || end > MAX_SAFE_BIGINT) return none;
    return { start: Number(start), end: Number(end) };
  }
  if (parts.length !== 2) parts = stem.split("-");
  if (parts.length !== 2) return none;
  const start = signedLong(parts[0]);
  const end = signedLong(parts[1]);
  if (start === null || end === null || start <= 0n || end <= 0n) return none;
  if (start > MAX_SAFE_BIGINT || end > MAX_SAFE_BIGINT) return none;
  return { start: Number(start), end: Number(end) };
}

function validateEnpt(bytes) {  const view = new DataView(bytes);
  const length = bytes.byteLength;
  if (length < ENPT_HEADER + ENPT_TRAILER) throw new HttpError("enpt payload too short");
  const magic = new TextDecoder("ascii").decode(new Uint8Array(bytes, 0, 4));
  if (magic !== "enpt") throw new HttpError("payload is not enpt ciphertext");
  if (view.getUint16(4, true) !== 256) throw new HttpError("enpt wrapped key length must be 256");
  if (view.getUint16(6, true) !== 12) throw new HttpError("enpt nonce length must be 12");
  if (view.getUint16(276, true) !== ENPT_HEADER) throw new HttpError("enpt header length mismatch");
  if (view.getUint16(length - 8, true) !== 16) throw new HttpError("enpt GCM tag length must be 16");
  if (view.getUint16(length - 6, true) !== ENPT_TRAILER) throw new HttpError("enpt trailer length must be 24");
  const trailerMagic = new TextDecoder("ascii").decode(new Uint8Array(bytes, length - 4, 4));
  if (trailerMagic !== "enpt") throw new HttpError("enpt trailer magic mismatch");
}

async function digestResponse(env, deviceId, startMs, endMs, includeUntimed) {
  const deviceKey = canonicalDeviceKey(deviceId);
  const rowsQuery = env.DB.prepare(
    `SELECT sha256, size_bytes FROM (
       SELECT sha256, size_bytes, ${SORT_EXPRESSION}
         FROM objects WHERE device_id = ?1
     )
      WHERE (bucket = 0 AND lo <= ?3 AND hi >= ?2) OR (bucket = 1 AND ?4 = 1)
      ORDER BY sha256 ASC, size_bytes ASC`
  ).bind(deviceId, startMs, endMs, includeUntimed);
  const seqQuery = env.DB.prepare(
    "SELECT COALESCE(MAX(seq), 0) AS latest_seq FROM objects WHERE device_id = ?1"
  ).bind(deviceId);
  // D1 batches run in one transaction: rows and latest_seq are one snapshot.
  const [rowsResult, seqResult] = await env.DB.batch([rowsQuery, seqQuery]);
  const rows = rowsResult.results || [];
  const lines = [
    DIGEST_VERSION,
    `device=${deviceKey}`,
    `range=${startMs}:${endMs}`,
    `untimed=${includeUntimed}`,
    "objects=",
  ];
  for (const row of rows) lines.push(`${row.sha256}:${Number(row.size_bytes)}`);
  const material = textBytes(lines.join("\n"));
  const digestBuffer = await crypto.subtle.digest("SHA-256", material);
  const digest = Array.from(new Uint8Array(digestBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const latestSeq = Number(seqResult.results && seqResult.results[0]
    ? seqResult.results[0].latest_seq : 0) || 0;
  return {
    digest_version: DIGEST_VERSION,
    device: deviceId,
    device_key: deviceKey,
    start_ms: startMs,
    end_ms: endMs,
    include_untimed: includeUntimed === 1,
    count: rows.length,
    total_bytes: rows.reduce((acc, r) => acc + Number(r.size_bytes || 0), 0),
    digest,
    latest_seq: latestSeq,
  };
}

async function repairOrDuplicate(env, row, bytes, actualSha) {
  // Self-healing: the D1 row may point at an R2 object that a previous
  // attempt never published (or that was removed). Re-put the verified bytes
  // instead of leaving a permanent metadata/blob split.
  const head = await env.BUCKET.head(row.r2_key);
  let status = "duplicate";
  let intact = false;
  if (head && Number(head.size) === Number(row.size_bytes)) {
    const existing = await env.BUCKET.get(row.r2_key);
    if (existing) {
      const actual = await sha256Hex(await existing.arrayBuffer());
      intact = actual === actualSha;
    }
  }
  if (!intact) {
    await env.BUCKET.put(row.r2_key, bytes, {
      customMetadata: {
        device_key: row.device_key || "", kind: row.kind, sha256: actualSha,
        repair: "r2-missing-or-corrupt",
      },
    });
    status = "repaired";
  }
  return {
    status,
    object_key: row.object_key,
    sha256: actualSha,
    size: Number(row.size_bytes),
    seq: row.seq === null || row.seq === undefined ? null : Number(row.seq),
  };
}

async function handlePut(request, env) {
  const deviceId = decodeHeader(request, "x-xinliqiu-device") || "";
  const entryName = decodeHeader(request, "x-xinliqiu-name") || "";
  const kind = request.headers.get("x-xinliqiu-kind") || "";
  const encryption = request.headers.get("x-xinliqiu-encryption") || null;
  const declaredSha = (request.headers.get("x-xinliqiu-sha256") || "").toLowerCase();
  const headerStart = parseMsParam(request.headers.get("x-xinliqiu-start-ms"), "x-xinliqiu-start-ms", null);
  const headerEnd = parseMsParam(request.headers.get("x-xinliqiu-end-ms"), "x-xinliqiu-end-ms", null);

  validateDeviceId(deviceId);
  if (!entryName) return json({ error: "missing x-xinliqiu-name" }, 400);
  // Explicit headers win; otherwise the device timestamps are derived from
  // the entry name with the same rules the Python SDK uses, so a bare upload
  // still gets correct range/digest behaviour.
  const parsedTimes = parseEntryTimes(entryName);
  const startMs = headerStart === null ? parsedTimes.start : headerStart;
  const endMs = headerEnd === null ? parsedTimes.end : headerEnd;
  if (textBytes(entryName).length > 1024 || entryName.includes("\0")) {
    return json({ error: "invalid entry name" }, 400);
  }
  if (!KIND_UPLOAD_ALLOWED.has(kind)) {
    return json({
      error: `unsupported kind: ${kind}`,
      detail: "only enpt ciphertext kinds (audio, note-audio, end-marker, mark) and explicitly encrypted diagnostics are uploadable",
    }, 400);
  }
  if (kind === DIAGNOSTIC_KIND && !encryption) {
    return json({ error: "diagnostic uploads require x-xinliqiu-encryption" }, 400);
  }
  if (declaredSha && !SHA256_RE.test(declaredSha)) {
    return json({ error: "x-xinliqiu-sha256 must be 64 lowercase hex chars" }, 400);
  }

  const length = Number(request.headers.get("content-length") || 0);
  if (length > MAX_OBJECT_BYTES) return json({ error: "object too large" }, 413);

  const bytes = await request.arrayBuffer();
  if (bytes.byteLength === 0) return json({ error: "empty body" }, 400);
  if (bytes.byteLength > MAX_OBJECT_BYTES) return json({ error: "object too large" }, 413);
  if (CIPHERTEXT_KINDS.has(kind)) validateEnpt(bytes);

  const actualSha = await sha256Hex(bytes);
  if (declaredSha && declaredSha !== actualSha) {
    return json({ error: "sha256 mismatch" }, 400);
  }

  const deviceKey = canonicalDeviceKey(deviceId);
  const objectKey = `${deviceKey}/${actualSha}`;
  const r2Key = `objects/${deviceKey}/${actualSha}`;

  const keyRow = await env.DB.prepare(
    "SELECT device_id FROM objects WHERE object_key = ?1"
  ).bind(objectKey).first();
  if (keyRow && keyRow.device_id !== deviceId) {
    // Raw identity check: never merge two devices because keys collided.
    return json({ error: "object key identity conflict" }, 409);
  }

  const existing = await env.DB.prepare(
    `SELECT object_key, device_id, device_key, entry_name, kind, size_bytes, sha256, r2_key, seq
       FROM objects WHERE device_id = ?1 AND sha256 = ?2`
  ).bind(deviceId, actualSha).first();
  if (existing) {
    if (Number(existing.size_bytes) !== bytes.byteLength) {
      return json({ error: "stored size conflicts with uploaded content" }, 409);
    }
    return json(await repairOrDuplicate(env, existing, bytes, actualSha), 200);
  }

  await env.BUCKET.put(r2Key, bytes, {
    customMetadata: {
      device_key: deviceKey, name: entryName, kind, sha256: actualSha,
      ...(encryption ? { encryption } : {}),
    },
  });

  // Assign the sequence inside the INSERT so that D1's serialized writes
  // cannot hand the same seq to two concurrent uploads. A conflicting insert
  // is idempotent: re-read and answer duplicate/repaired instead of failing.
  try {
    await env.DB.prepare(
      `INSERT INTO objects
         (object_key, device_id, device_key, entry_name, kind, size_bytes, sha256,
          device_start_ms, device_end_ms, synced_at, r2_key, seq, encryption)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
               (SELECT COALESCE(MAX(seq), 0) + 1 FROM objects), ?12)`
    ).bind(
      objectKey, deviceId, deviceKey, entryName, kind, bytes.byteLength, actualSha,
      startMs, endMs, Date.now(), r2Key, encryption
    ).run();
  } catch (err) {
    if (!/UNIQUE|constraint/i.test(String(err && err.message || err))) throw err;
    const winner = await env.DB.prepare(
      `SELECT object_key, device_id, device_key, entry_name, kind, size_bytes, sha256, r2_key, seq
         FROM objects WHERE device_id = ?1 AND sha256 = ?2`
    ).bind(deviceId, actualSha).first();
    if (!winner) throw err;
    return json(await repairOrDuplicate(env, winner, bytes, actualSha), 200);
  }

  const stored = await env.DB.prepare(
    "SELECT seq FROM objects WHERE object_key = ?1"
  ).bind(objectKey).first();

  return json({
    status: "stored",
    object_key: objectKey,
    device_key: deviceKey,
    sha256: actualSha,
    size: bytes.byteLength,
    seq: stored ? Number(stored.seq) : null,
  }, 201);
}

async function handleList(request, env) {
  const url = new URL(request.url);
  const deviceId = url.searchParams.get("device") || "";
  validateDeviceId(deviceId);
  const { startMs, endMs } = parseRange(url);
  const includeUntimed = parseUntimed(url);
  const kind = url.searchParams.get("kind");
  if (kind && !KIND_FILTER_ALLOWED.has(kind)) {
    return json({ error: `unsupported kind filter: ${kind}` }, 400);
  }
  const limit = parseLimit(url, 200);
  const rawCursor = url.searchParams.get("cursor");
  const cursor = rawCursor ? decodeCursor(rawCursor) : null;

  const binds = [deviceId, startMs, endMs, includeUntimed];
  let sql = `SELECT * FROM (
      SELECT ${LIST_COLUMNS}, ${SORT_EXPRESSION} FROM objects WHERE device_id = ?1
    )
    WHERE ((bucket = 0 AND lo <= ?3 AND hi >= ?2) OR (bucket = 1 AND ?4 = 1))`;
  if (kind) {
    binds.push(kind);
    sql += ` AND kind = ?${binds.length}`;
  }
  if (cursor) {
    binds.push(cursor.b, cursor.b === 0 ? cursor.t : 0, cursor.s);
    const base = binds.length - 2;
    sql += ` AND (bucket > ?${base}
      OR (bucket = ?${base} AND (
        (?${base} = 0 AND (lo > ?${base + 1} OR (lo = ?${base + 1} AND seq > ?${base + 2})))
        OR (?${base} = 1 AND seq > ?${base + 2}))))`;
  }
  binds.push(limit + 1);
  sql += ` ORDER BY bucket ASC, lo ASC, seq ASC LIMIT ?${binds.length}`;
  const { results } = await env.DB.prepare(sql).bind(...binds).all();
  const rows = results || [];
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  const objects = page.map((row) => {
    const { lo, hi, bucket, ...metadata } = row;
    return metadata;
  });
  return json({
    objects,
    count: objects.length,
    has_more: hasMore,
    next_cursor: hasMore && page.length ? encodeCursor(page[page.length - 1]) : null,
  });
}

async function handleGet(request, env, key) {
  const row = await env.DB.prepare(
    `SELECT r2_key, size_bytes, sha256, entry_name, kind, device_key
       FROM objects WHERE object_key = ?1`
  ).bind(key).first();
  if (!row) return json({ error: "not found" }, 404);
  const object = await env.BUCKET.get(row.r2_key);
  if (!object) {
    return json({
      error: "object missing in R2",
      detail: "re-upload the same ciphertext to repair this metadata/blob split",
    }, 410);
  }
  const bytes = await object.arrayBuffer();
  if (Number(bytes.byteLength) !== Number(row.size_bytes)) {
    return json({ error: "stored object size does not match its metadata" }, 409);
  }
  const actualSha = await sha256Hex(bytes);
  if (actualSha !== row.sha256) {
    return json({ error: "stored object hash does not match its metadata" }, 409);
  }
  return new Response(bytes, {
    headers: {
      "content-type": "application/octet-stream",
      "content-length": String(row.size_bytes),
      "x-xinliqiu-sha256": row.sha256,
      "x-xinliqiu-name": encodeURIComponent(row.entry_name),
      "x-xinliqiu-name-encoding": "percent",
      "x-xinliqiu-kind": row.kind,
      "x-xinliqiu-device-key": row.device_key || "",
    },
  });
}

async function handleInventory(request, env) {
  const url = new URL(request.url);
  const deviceId = url.searchParams.get("device");
  if (deviceId) {
    const row = await env.DB.prepare(
      "SELECT * FROM inventory WHERE device_id = ?1"
    ).bind(deviceId).first();
    return json({ inventory: row || null });
  }
  const { results } = await env.DB.prepare("SELECT * FROM inventory").all();
  return json({ inventory: results || [] });
}

async function handleChanges(request, env) {
  const url = new URL(request.url);
  const deviceId = url.searchParams.get("device") || "";
  validateDeviceId(deviceId);
  const since = parseMsParam(url.searchParams.get("since"), "since", 0);
  const limit = parseLimit(url, 500);

  const { results } = await env.DB.prepare(
    `SELECT ${LIST_COLUMNS}
       FROM objects WHERE device_id = ?1 AND seq > ?2
      ORDER BY seq ASC LIMIT ?3`
  ).bind(deviceId, since, limit + 1).all();

  const rows = results || [];
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  const cursor = page.length ? Number(page[page.length - 1].seq) : since;
  const latest = await env.DB.prepare(
    "SELECT COALESCE(MAX(seq), 0) AS latest_seq FROM objects WHERE device_id = ?1"
  ).bind(deviceId).first();
  return json({
    objects: page,
    cursor,
    has_more: hasMore,
    latest_seq: Number(latest && latest.latest_seq) || 0,
  });
}

async function handleDigest(request, env) {
  const url = new URL(request.url);
  const deviceId = url.searchParams.get("device") || "";
  validateDeviceId(deviceId);
  const { startMs, endMs } = parseRange(url);
  const includeUntimed = parseUntimed(url);
  return json(await digestResponse(env, deviceId, startMs, endMs, includeUntimed));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return json({ ok: true, digest_version: DIGEST_VERSION });

    if (!(await authorize(request, env))) return unauthorized();

    try {
      if (url.pathname === "/objects/changes" && request.method === "GET") {
        return await handleChanges(request, env);
      }
      if (url.pathname === "/digest" && request.method === "GET") {
        return await handleDigest(request, env);
      }
      if (url.pathname === "/objects" && request.method === "POST") {
        return await handlePut(request, env);
      }
      if (url.pathname === "/objects" && request.method === "GET") {
        return await handleList(request, env);
      }
      if (url.pathname.startsWith("/objects/") && request.method === "GET") {
        let key;
        try {
          key = decodeURIComponent(url.pathname.slice("/objects/".length));
        } catch {
          return json({ error: "invalid object key encoding" }, 400);
        }
        return await handleGet(request, env, key);
      }
      if (url.pathname === "/inventory" && request.method === "GET") {
        return await handleInventory(request, env);
      }
      return json({ error: "not found" }, 404);
    } catch (err) {
      const message = String(err && err.message || err);
      if (/no such table|no such column/i.test(message)) {
        return json({
          error: "storage schema is not migrated",
          detail: "run ./setup.sh migrate --remote (or npm run migrate)",
        }, 503);
      }
      const status = err instanceof HttpError ? err.status : 500;
      return json({ error: status === 400 ? "bad request" : "internal", detail: message }, status);
    }
  },
};
