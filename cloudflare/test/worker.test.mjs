// Behavioural tests for the Xinliqiu Worker, fully offline.
//
// D1 is mocked with node:sqlite (real SQL, real constraints, real migrations);
// R2 is an in-memory map with fault injection. No network, no Cloudflare
// account, no device and no real recordings are involved: every payload is a
// synthetic enpt-shaped buffer built below.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import worker from '../src/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const TOKEN = 'test-token';
const DIGEST_VECTOR = '4c996802aed26698664451a130087ba423e7c1250e15b5840e7c5e8a5f67076b';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

class D1Statement {
  constructor(db, sql, params = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }

  bind(...params) {
    return new D1Statement(this.db, this.sql, params);
  }

  _params() {
    return this.params.map((p) => (p === undefined ? null : p));
  }

  async run() {
    this.db._before(this.sql, this._params());
    const info = this.db.raw.prepare(this.sql).run(...this._params());
    return { success: true, meta: { changes: Number(info.changes) } };
  }

  async all() {
    this.db._before(this.sql, this._params());
    const rows = this.db.raw.prepare(this.sql).all(...this._params());
    return { success: true, results: rows.map((r) => ({ ...r })) };
  }

  async first() {
    const { results } = await this.all();
    return results.length ? results[0] : null;
  }
}

class MockD1 {
  constructor(db) {
    this.raw = db;
    this.batchCalls = 0;
    this.hook = null;
  }

  _before(sql, params) {
    if (this.hook && this.hook.match.test(sql)) {
      const hook = this.hook;
      this.hook = null;
      hook.fn(sql, params);
    }
  }

  prepare(sql) {
    return new D1Statement(this, sql);
  }

  exec(sql) {
    this.raw.exec(sql);
  }

  async batch(statements) {
    this.batchCalls += 1;
    this.raw.exec('BEGIN');
    try {
      const out = [];
      for (const statement of statements) out.push(await statement.all());
      this.raw.exec('COMMIT');
      return out;
    } catch (err) {
      this.raw.exec('ROLLBACK');
      throw err;
    }
  }
}

class MockR2 {
  constructor() {
    this.objects = new Map();
  }

  async put(key, bytes, options = {}) {
    this.objects.set(key, {
      bytes: Buffer.from(bytes),
      customMetadata: options.customMetadata || {},
    });
  }

  async head(key) {
    const object = this.objects.get(key);
    return object ? { size: object.bytes.length, customMetadata: object.customMetadata } : null;
  }

  async get(key) {
    const object = this.objects.get(key);
    if (!object) return null;
    const bytes = object.bytes;
    return {
      size: bytes.length,
      body: bytes,
      customMetadata: object.customMetadata,
      arrayBuffer: async () =>
        bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    };
  }
}

function applyMigrations(db, names) {
  for (const name of names) {
    db.exec(fs.readFileSync(path.join(ROOT, 'migrations', name), 'utf8'));
  }
}

function makeEnv({ migrations = ['0001_init.sql', '0002_sync.sql', '0003_storage_contract.sql'] } = {}) {
  const raw = new DatabaseSync(':memory:');
  applyMigrations(raw, migrations);
  const db = new MockD1(raw);
  return { DB: db, BUCKET: new MockR2(), XINLIQIU_TOKEN: TOKEN, raw };
}

function makeEnpt(payload = Buffer.alloc(40, 7)) {
  const head = Buffer.alloc(280);
  head.write('enpt', 0, 'ascii');
  head.writeUInt16LE(256, 4);
  head.writeUInt16LE(12, 6);
  head.writeUInt16LE(280, 276);
  head[278] = 1;
  const trailer = Buffer.alloc(24);
  trailer.writeUInt16LE(16, 16);
  trailer.writeUInt16LE(24, 18);
  trailer.write('enpt', 20, 'ascii');
  return Buffer.concat([head, payload, trailer]);
}

function request(method, url, { body, headers = {}, token = TOKEN } = {}) {
  return new Request(`https://store.test${url}`, {
    method,
    body,
    headers: { authorization: `Bearer ${token}`, ...headers },
  });
}

async function call(env, req) {
  const response = await worker.fetch(req, env);
  const text = await response.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: response.status, body, response };
}

function putHeaders(device, name, kind, extra = {}) {
  return {
    'x-xinliqiu-device': encodeURIComponent(device),
    'x-xinliqiu-device-encoding': 'percent',
    'x-xinliqiu-name': encodeURIComponent(name),
    'x-xinliqiu-name-encoding': 'percent',
    'x-xinliqiu-kind': kind,
    ...extra,
  };
}

async function put(env, device, name, kind, payload, extra = {}) {
  return call(env, request('POST', '/objects', {
    body: payload,
    headers: putHeaders(device, name, kind, extra),
  }));
}

async function shaHex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Buffer.from(digest).toString('hex');
}

// ---------------------------------------------------------------------------
// Upload contract
// ---------------------------------------------------------------------------

test('health and auth are enforced', async () => {
  const env = makeEnv();
  assert.equal((await call(env, request('GET', '/healthz', { token: '' }))).status, 200);
  assert.equal((await call(env, request('GET', '/objects?device=dev1', { token: 'wrong' }))).status, 401);
});

test('put stores enpt ciphertext and duplicate retries are idempotent', async () => {
  const env = makeEnv();
  const payload = makeEnpt();
  const first = await put(env, 'dev1', '100_200.enc.opus', 'audio', payload);
  assert.equal(first.status, 201);
  assert.equal(first.body.status, 'stored');
  assert.equal(first.body.seq, 1);
  const again = await put(env, 'dev1', '100_200.enc.opus', 'audio', payload);
  assert.equal(again.status, 200);
  assert.equal(again.body.status, 'duplicate');
  assert.equal(again.body.seq, 1);
  assert.equal(again.body.object_key, first.body.object_key);
  assert.equal(env.raw.prepare('SELECT COUNT(*) c FROM objects').get().c, 1);
});

test('mark and end-marker kinds are accepted; plaintext and unknown kinds are refused', async () => {
  const env = makeEnv();
  assert.equal((await put(env, 'dev1', '100.mark', 'mark', makeEnpt(Buffer.alloc(40, 1)))).status, 201);
  assert.equal((await put(env, 'dev1', '100_200.end.enc.opus', 'end-marker', makeEnpt(Buffer.alloc(40, 2)))).status, 201);
  assert.equal((await put(env, 'dev1', '100.enc.note.opus', 'note-audio', makeEnpt(Buffer.alloc(40, 3)))).status, 201);
  const plaintext = await put(env, 'dev1', '300_400.enc.opus', 'audio', Buffer.alloc(400, 1));
  assert.equal(plaintext.status, 400);
  const tp = await put(env, 'dev1', '1.tp', 'trace-point', makeEnpt());
  assert.equal(tp.status, 400);
  const unknown = await put(env, 'dev1', 'strange.bin', 'unknown', makeEnpt());
  assert.equal(unknown.status, 400);
  assert.equal(env.raw.prepare('SELECT COUNT(*) c FROM objects').get().c, 3);
});

test('diagnostics need an explicit encryption label and malformed enpt is rejected', async () => {
  const env = makeEnv();
  const denied = await put(env, 'dev1', 'diag.jsonl', 'diagnostic', Buffer.from('ciphertext'));
  assert.equal(denied.status, 400);
  const allowed = await put(env, 'dev1', 'diag.jsonl', 'diagnostic', Buffer.from('ciphertext'), {
    'x-xinliqiu-encryption': 'owner-enpt',
  });
  assert.equal(allowed.status, 201);
  const broken = makeEnpt();
  broken.writeUInt16LE(7, broken.length - 6); // wrong trailer length
  assert.equal((await put(env, 'dev1', '1_2.enc.opus', 'audio', broken)).status, 400);
  const truncated = makeEnpt().subarray(0, 100);
  assert.equal((await put(env, 'dev1', '1_2.enc.opus', 'audio', truncated)).status, 400);
});

test('declared sha256 and size conflicts are explicit', async () => {
  const env = makeEnv();
  const payload = makeEnpt();
  const mismatch = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload, {
    'x-xinliqiu-sha256': '0'.repeat(64),
  });
  assert.equal(mismatch.status, 400);
  const good = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload, {
    'x-xinliqiu-sha256': await shaHex(payload),
  });
  assert.equal(good.status, 201);
  env.raw.prepare("UPDATE objects SET size_bytes = size_bytes + 1 WHERE object_key = ?1")
    .run(good.body.object_key);
  const conflict = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  assert.equal(conflict.status, 409);
});

test('canonical device encoding is collision-free and non-ASCII identities round-trip', async () => {
  const env = makeEnv();
  const payload = makeEnpt();
  const a = await put(env, 'a/b', '1_2.enc.opus', 'audio', payload);
  const b = await put(env, 'a_b', '1_2.enc.opus', 'audio', payload);
  assert.equal(a.status, 201);
  assert.equal(b.status, 201);
  assert.notEqual(a.body.object_key, b.body.object_key);
  assert.equal(a.body.object_key, `d1-612f62/${await shaHex(payload)}`);
  const unicode = await put(env, '设备/一', '录音 1_2.enc.opus', 'audio', makeEnpt(Buffer.alloc(40, 9)));
  assert.equal(unicode.status, 201);
  const listed = await call(env, request('GET', `/objects?device=${encodeURIComponent('设备/一')}`));
  assert.equal(listed.body.count, 1);
  assert.equal(listed.body.objects[0].entry_name, '录音 1_2.enc.opus');
  const forA = await call(env, request('GET', '/objects?device=a%2Fb'));
  assert.equal(forA.body.count, 1);
});

test('raw identity conflicts cannot merge two devices onto one key', async () => {
  const env = makeEnv();
  const payload = makeEnpt();
  const sha = await shaHex(payload);
  env.raw.prepare(
    `INSERT INTO objects (object_key, device_id, entry_name, kind, size_bytes, sha256, synced_at, r2_key, seq)
     VALUES (?1, 'someone-else', 'x', 'audio', ?2, ?3, 1, 'objects/legacy/x', 1)`
  ).run(`d1-64657631/${sha}`, payload.length, sha);
  const conflict = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  assert.equal(conflict.status, 409);
});

// ---------------------------------------------------------------------------
// R2/D1 self-healing
// ---------------------------------------------------------------------------

test('a missing R2 object is repaired by re-upload instead of staying split', async () => {
  const env = makeEnv();
  const payload = makeEnpt();
  const stored = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  const key = stored.body.object_key;
  env.BUCKET.objects.clear();
  const gone = await call(env, request('GET', `/objects/${encodeURIComponent(key)}`));
  assert.equal(gone.status, 410);
  const repaired = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  assert.equal(repaired.status, 200);
  assert.equal(repaired.body.status, 'repaired');
  const fetched = await call(env, request('GET', `/objects/${encodeURIComponent(key)}`));
  assert.equal(fetched.status, 200);
  assert.equal(fetched.body.length, payload.length);
});

test('a truncated R2 object is rejected on read and repaired on re-upload', async () => {
  const env = makeEnv();
  const payload = makeEnpt();
  const stored = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  const r2Key = `objects/${stored.body.device_key}/${stored.body.sha256}`;
  env.BUCKET.objects.get(r2Key).bytes = env.BUCKET.objects.get(r2Key).bytes.subarray(0, 10);
  const read = await call(env, request('GET', `/objects/${encodeURIComponent(stored.body.object_key)}`));
  assert.equal(read.status, 409);
  const repaired = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  assert.equal(repaired.body.status, 'repaired');
});

test('a same-size corrupted R2 object is repaired by hash on re-upload', async () => {
  const env = makeEnv();
  const payload = makeEnpt();
  const stored = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  const r2Key = `objects/${stored.body.device_key}/${stored.body.sha256}`;
  const object = env.BUCKET.objects.get(r2Key);
  object.bytes = Buffer.from(object.bytes);
  object.bytes[object.bytes.length - 20] ^= 0xff; // same length, different bytes
  assert.equal(object.bytes.length, payload.length);
  const read = await call(env, request('GET', `/objects/${encodeURIComponent(stored.body.object_key)}`));
  assert.equal(read.status, 409);
  const repaired = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  assert.equal(repaired.body.status, 'repaired');
  const fetched = await call(env, request('GET', `/objects/${encodeURIComponent(stored.body.object_key)}`));
  assert.equal(fetched.status, 200);
  assert.deepEqual(Buffer.from(fetched.body), Buffer.from(payload));
});

test('a concurrent insert conflict resolves to a duplicate, not a 500', async () => {
  const env = makeEnv();
  const payload = makeEnpt();
  const sha = await shaHex(payload);
  env.DB.hook = {
    match: /^INSERT INTO objects/,
    fn: () => {
      // Another writer wins the race between our existence check and INSERT.
      env.raw.prepare(
        `INSERT INTO objects (object_key, device_id, device_key, entry_name, kind, size_bytes,
                              sha256, synced_at, r2_key, seq)
         VALUES (?1, 'dev1', 'd1-64657631', '1_2.enc.opus', 'audio', ?2, ?3, 1, ?4, 1)`
      ).run(`d1-64657631/${sha}`, payload.length, sha, `objects/d1-64657631/${sha}`);
    },
  };
  const result = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  assert.equal(result.status, 200);
  assert.equal(result.body.status, 'duplicate');
  assert.equal(result.body.seq, 1);
});

test('a D1 failure after the R2 write heals on the next attempt', async () => {
  const env = makeEnv();
  const payload = makeEnpt();
  env.DB.hook = {
    match: /^INSERT INTO objects/,
    fn: () => {
      throw new Error('simulated D1 outage');
    },
  };
  const failed = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  assert.equal(failed.status, 500);
  assert.equal(env.raw.prepare('SELECT COUNT(*) c FROM objects').get().c, 0);
  assert.equal(env.BUCKET.objects.size, 1); // orphan blob, no metadata
  const retried = await put(env, 'dev1', '1_2.enc.opus', 'audio', payload);
  assert.equal(retried.status, 201);
  assert.equal(env.raw.prepare('SELECT COUNT(*) c FROM objects').get().c, 1);
});

// ---------------------------------------------------------------------------
// Range queries, pagination, cursors
// ---------------------------------------------------------------------------

async function seedObjects(env) {
  const specs = [
    ['100_200.enc.opus', 'audio', Buffer.alloc(40, 1)],
    ['300_400.enc.opus', 'audio', Buffer.alloc(40, 2)],
    ['500.mark', 'mark', Buffer.alloc(40, 3)],
    ['diag.jsonl', 'diagnostic', Buffer.from('ciphertext')],
  ];
  for (const [name, kind, body] of specs) {
    const extra = kind === 'diagnostic' ? { 'x-xinliqiu-encryption': 'owner-enpt' } : {};
    const result = await put(env, 'dev1', name, kind, makeEnpt(body), extra);
    assert.equal(result.status, 201, JSON.stringify(result.body));
  }
}

test('range matching is inclusive interval overlap, including boundary touches', async () => {
  const env = makeEnv();
  await seedObjects(env);
  const cases = [
    [0, 99, 0],
    [0, 100, 1], // ends exactly at the object start
    [150, 160, 1], // strictly inside
    [200, 250, 1], // starts exactly at the object end
    [201, 250, 0],
    [100, 400, 2],
    [500, 500, 1], // single-point mark interval [500,501]
    [501, 501, 1],
    [502, 600, 0],
  ];
  for (const [start, end, expected] of cases) {
    const result = await call(env, request('GET', `/objects?device=dev1&start_ms=${start}&end_ms=${end}&include_untimed=0`));
    assert.equal(result.body.count, expected, `range ${start}-${end}: ${JSON.stringify(result.body)}`);
  }
  const withUntimed = await call(env, request('GET', '/objects?device=dev1&start_ms=201&end_ms=250'));
  assert.equal(withUntimed.body.count, 1); // the untimed diagnostic
});

test('list paginates with validated cursors and no duplicates', async () => {
  const env = makeEnv();
  await seedObjects(env);
  const seen = [];
  let cursor = null;
  let pages = 0;
  do {
    const url = `/objects?device=dev1&limit=2${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`;
    const result = await call(env, request('GET', url));
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.ok(result.body.count <= 2);
    seen.push(...result.body.objects.map((o) => o.object_key));
    assert.ok(!('lo' in result.body.objects[0]), 'internal sort columns must not leak');
    cursor = result.body.next_cursor;
    pages += 1;
    if (!result.body.has_more) break;
    assert.ok(cursor, 'has_more requires a next cursor');
  } while (pages < 10);
  assert.equal(pages, 2);
  assert.equal(new Set(seen).size, 4);
  // Untimed diagnostic sorts after all timed entries.
  assert.equal(seen.length, 4);
  const last = await call(env, request('GET', '/objects?device=dev1&limit=1000'));
  assert.equal(last.body.objects[3].kind, 'diagnostic');
  for (const bad of ['0', '1001', 'abc', '-1']) {
    const result = await call(env, request('GET', `/objects?device=dev1&limit=${bad}`));
    assert.equal(result.status, 400, `limit ${bad}`);
  }
  for (const bad of ['not-a-cursor', 'e30', 'eyJ2Ijo5fQ']) {
    const result = await call(env, request('GET', `/objects?device=dev1&cursor=${bad}`));
    assert.equal(result.status, 400, `cursor ${bad}`);
  }
  assert.equal((await call(env, request('GET', '/objects?device=dev1&start_ms=9&end_ms=2'))).status, 400);
  assert.equal((await call(env, request('GET', '/objects?device=dev1&start_ms=nope'))).status, 400);
  assert.equal((await call(env, request('GET', '/objects?device=dev1&kind=bogus'))).status, 400);
});

test('kind filter and changes pagination work with validated limits', async () => {
  const env = makeEnv();
  await seedObjects(env);
  const marks = await call(env, request('GET', '/objects?device=dev1&kind=mark'));
  assert.equal(marks.body.count, 1);
  const first = await call(env, request('GET', '/objects/changes?device=dev1&since=0&limit=3'));
  assert.equal(first.body.objects.length, 3);
  assert.equal(first.body.has_more, true);
  assert.equal(first.body.cursor, 3);
  assert.equal(first.body.latest_seq, 4);
  const rest = await call(env, request('GET', `/objects/changes?device=dev1&since=${first.body.cursor}&limit=3`));
  assert.equal(rest.body.objects.length, 1);
  assert.equal(rest.body.has_more, false);
  assert.equal(rest.body.cursor, 4);
  const empty = await call(env, request('GET', '/objects/changes?device=dev1&since=4'));
  assert.equal(empty.body.cursor, 4);
  assert.equal(empty.body.objects.length, 0);
  assert.equal((await call(env, request('GET', '/objects/changes?device=dev1&since=-1'))).status, 400);
});

// ---------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------

test('digest matches the backend-independent vector and the same-snapshot seq', async () => {
  const env = makeEnv();
  const before = env.DB.batchCalls;
  const rows = [
    { sha: 'a'.repeat(64), size: 344 },
    { sha: 'b'.repeat(64), size: 100 },
  ];
  for (const [index, row] of rows.entries()) {
    env.raw.prepare(
      `INSERT INTO objects (object_key, device_id, device_key, entry_name, kind, size_bytes,
                            sha256, device_start_ms, device_end_ms, synced_at, r2_key, seq)
       VALUES (?1, 'dev1', 'd1-64657631', ?2, 'audio', ?3, ?4, 100, 200, 1, 'objects/x', ?5)`
    ).run(`d1-64657631/${row.sha}`, `${100 + index}_200.enc.opus`, row.size, row.sha, index + 1);
  }
  const result = await call(env, request('GET', '/digest?device=dev1&start_ms=0&end_ms=9007199254740991&include_untimed=1'));
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.digest, DIGEST_VECTOR); // same constant as the Python suite
  assert.equal(result.body.digest_version, 'xinliqiu-storage-digest/v1');
  assert.equal(result.body.count, 2);
  assert.equal(result.body.total_bytes, 444);
  assert.equal(result.body.latest_seq, 2);
  assert.equal(env.DB.batchCalls, before + 1, 'digest rows and latest_seq must be one batch');
  const ranged = await call(env, request('GET', '/digest?device=dev1&start_ms=201&end_ms=300&include_untimed=0'));
  assert.equal(ranged.body.count, 0);
  assert.notEqual(ranged.body.digest, result.body.digest);
});

// ---------------------------------------------------------------------------
// Migrations: fresh, existing, and the tracked setup runner
// ---------------------------------------------------------------------------

test('an existing pre-0003 deploy keeps its objects and dedupes by raw identity', async () => {
  const raw = new DatabaseSync(':memory:');
  applyMigrations(raw, ['0001_init.sql', '0002_sync.sql']);
  const payload = makeEnpt();
  const sha = await shaHex(payload);
  // Legacy row: old safeSegment object key, no device_key, kind trace-point.
  raw.prepare(
    `INSERT INTO objects (object_key, device_id, entry_name, kind, size_bytes, sha256,
                          device_start_ms, device_end_ms, synced_at, r2_key, seq)
     VALUES ('dev_1/old', 'dev/1', '100_200.enc.opus', 'audio', ?1, ?2, 100, 200, 1, 'objects/dev_1/old', 1)`
  ).run(payload.length, sha);
  applyMigrations(raw, ['0003_storage_contract.sql']);
  assert.equal(raw.prepare('SELECT device_key FROM objects').get().device_key, 'd1-6465762f31');
  const env = { DB: new MockD1(raw), BUCKET: new MockR2(), XINLIQIU_TOKEN: TOKEN, raw };
  const duplicate = await put(env, 'dev/1', '100_200.enc.opus', 'audio', payload);
  assert.equal(duplicate.status, 200);
  assert.equal(duplicate.body.object_key, 'dev_1/old'); // legacy key preserved
  const fresh = await put(env, 'dev/1', '300_400.enc.opus', 'audio', makeEnpt(Buffer.alloc(40, 5)));
  assert.equal(fresh.status, 201);
  assert.ok(fresh.body.object_key.startsWith('d1-6465762f31/'));
  const digest = await call(env, request('GET', '/digest?device=dev%2F1'));
  assert.equal(digest.body.count, 2);
});

test('a deploy missing the storage schema reports a migration error, not a crash', async () => {
  const raw = new DatabaseSync(':memory:');
  applyMigrations(raw, ['0001_init.sql']);
  const env = { DB: new MockD1(raw), BUCKET: new MockR2(), XINLIQIU_TOKEN: TOKEN, raw };
  const result = await call(env, request('GET', '/objects?device=dev1'));
  assert.equal(result.status, 503);
  assert.match(result.body.detail, /setup\.sh migrate/);
});

const FAKE_WRANGLER = `#!/usr/bin/env node
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
const db = new DatabaseSync(process.env.FAKE_D1_PATH);
const args = process.argv.slice(2);
if (args[0] !== 'd1' || args[1] !== 'execute') {
  console.error('unsupported: ' + args.join(' '));
  process.exit(1);
}
const commandAt = args.indexOf('--command');
const fileArg = args.find((a) => a.startsWith('--file='));
try {
  if (commandAt >= 0) {
    const sql = args[commandAt + 1];
    const statement = db.prepare(sql);
    const results = /^\\s*SELECT/i.test(sql) ? statement.all() : (statement.run(), []);
    console.log(JSON.stringify([{ results }]));
  } else if (fileArg) {
    db.exec(fs.readFileSync(fileArg.slice('--file='.length), 'utf8'));
    console.log(JSON.stringify([{ results: [] }]));
  }
} catch (err) {
  console.error(String(err && err.message || err));
  process.exit(1);
}
`;

function runSetupMigrate(fakeDir, dbPath) {
  return execFileSync('bash', [path.join(ROOT, 'setup.sh'), 'migrate', '--local'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PATH: process.env.PATH,
      WRANGLER: `node ${path.join(fakeDir, 'fake-wrangler.mjs')}`,
      FAKE_D1_PATH: dbPath,
    },
    encoding: 'utf8',
  });
}

test('setup.sh migrates fresh and hand-migrated databases in tracked order', () => {
  const fakeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'xlq-wrangler-'));
  fs.writeFileSync(path.join(fakeDir, 'fake-wrangler.mjs'), FAKE_WRANGLER);

  // Fresh deploy: all three migrations apply in order, and a rerun is a no-op.
  const freshPath = path.join(fakeDir, 'fresh.db');
  const first = runSetupMigrate(fakeDir, freshPath);
  assert.match(first, /applying 0001_init\.sql/);
  assert.match(first, /applying 0002_sync\.sql/);
  assert.match(first, /applying 0003_storage_contract\.sql/);
  const fresh = new DatabaseSync(freshPath);
  const names = fresh.prepare('SELECT name FROM xinliqiu_migrations ORDER BY rowid').all();
  assert.deepEqual(names.map((r) => r.name), [
    '0001_init.sql', '0002_sync.sql', '0003_storage_contract.sql',
  ]);
  assert.ok(fresh.prepare("SELECT name FROM pragma_table_info('objects') WHERE name='device_key'").get());
  const second = runSetupMigrate(fakeDir, freshPath);
  assert.doesNotMatch(second, /applying 000/);

  // Existing deploy: 0001+0002 were applied by hand, without tracking, and it
  // already holds a legacy object. Only 0003 may run (0002's ALTER would fail).
  const existingPath = path.join(fakeDir, 'existing.db');
  const existing = new DatabaseSync(existingPath);
  applyMigrations(existing, ['0001_init.sql', '0002_sync.sql']);
  existing.prepare(
    `INSERT INTO objects (object_key, device_id, entry_name, kind, size_bytes, sha256, synced_at, r2_key, seq)
     VALUES ('dev1/abc', 'dev1', '1_2.enc.opus', 'audio', 10, '${'c'.repeat(64)}', 1, 'objects/dev1/abc', 1)`
  ).run();
  existing.close();
  const migrated = runSetupMigrate(fakeDir, existingPath);
  assert.doesNotMatch(migrated, /applying 0002_sync\.sql/);
  assert.match(migrated, /applying 0003_storage_contract\.sql/);
  const upgraded = new DatabaseSync(existingPath);
  assert.equal(upgraded.prepare('SELECT device_key FROM objects').get().device_key, 'd1-64657631');
  assert.equal(upgraded.prepare('SELECT COUNT(*) c FROM xinliqiu_migrations').get().c, 3);
  const again = runSetupMigrate(fakeDir, existingPath);
  assert.doesNotMatch(again, /applying 000/);
});

test('setup.sh completes a partial 0003 even when it was already recorded', () => {
  const fakeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'xlq-wrangler-'));
  fs.writeFileSync(path.join(fakeDir, 'fake-wrangler.mjs'), FAKE_WRANGLER);

  for (const alreadyRecorded of [false, true]) {
    const dbPath = path.join(fakeDir, `partial-${alreadyRecorded ? 'tracked' : 'untracked'}.db`);
    const partial = new DatabaseSync(dbPath);
    applyMigrations(partial, ['0001_init.sql', '0002_sync.sql']);
    partial.exec('ALTER TABLE objects ADD COLUMN device_key TEXT');
    partial.exec('ALTER TABLE objects ADD COLUMN encryption TEXT');
    partial.prepare(
      `INSERT INTO objects (object_key, device_id, entry_name, kind, size_bytes, sha256,
                            device_start_ms, device_end_ms, synced_at, r2_key, seq)
       VALUES ('dev1/legacy', 'dev1', '1_2.enc.opus', 'audio', 10, '${'d'.repeat(64)}',
               1, 2, 1, 'objects/dev1/legacy', NULL)`
    ).run();
    assert.equal(partial.prepare("SELECT name FROM sqlite_master WHERE name='idx_objects_device_range'").get(), undefined);
    assert.equal(partial.prepare("SELECT name FROM sqlite_master WHERE name='trg_objects_kind_insert'").get(), undefined);
    if (alreadyRecorded) {
      partial.exec(`CREATE TABLE xinliqiu_migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);
        INSERT INTO xinliqiu_migrations VALUES ('0001_init.sql', 1), ('0002_sync.sql', 1),
          ('0003_storage_contract.sql', 1);`);
    }
    partial.close();

    const output = runSetupMigrate(fakeDir, dbPath);
    if (alreadyRecorded) assert.match(output, /verifying storage contract/);
    else assert.match(output, /applying 0003_storage_contract\.sql/);

    const repaired = new DatabaseSync(dbPath);
    const requiredObjects = [
      'idx_objects_device_time', 'idx_objects_kind', 'idx_objects_seq',
      'idx_objects_device_seq', 'idx_objects_device_sha', 'idx_objects_device_key',
      'idx_objects_device_range', 'inventory_digest', 'inventory', 'trg_objects_kind_insert',
    ];
    for (const name of requiredObjects) {
      assert.ok(repaired.prepare('SELECT name FROM sqlite_master WHERE name = ?').get(name), name);
    }
    const row = repaired.prepare('SELECT device_key, seq FROM objects').get();
    assert.equal(row.device_key, 'd1-64657631');
    assert.equal(row.seq, 1);
    assert.deepEqual({ ...repaired.prepare('SELECT note_audio_count, mark_count, diagnostic_count, latest_seq FROM inventory').get() }, {
      note_audio_count: 0, mark_count: 0, diagnostic_count: 0, latest_seq: 1,
    });
    assert.throws(() => repaired.prepare(
      `INSERT INTO objects (object_key, device_id, entry_name, kind, size_bytes, sha256,
                            synced_at, r2_key, seq, device_key)
       VALUES ('dev1/plaintext', 'dev1', 'plain.txt', 'trace-point', 1, '${'e'.repeat(64)}',
               2, 'objects/dev1/plaintext', 2, 'd1-64657631')`
    ).run(), /unsupported object kind/);
    assert.equal(repaired.prepare('SELECT COUNT(*) c FROM xinliqiu_migrations').get().c, 3);
    repaired.close();

    const again = runSetupMigrate(fakeDir, dbPath);
    assert.doesNotMatch(again, /applying 000/);
  }
});
