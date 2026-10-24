# Storage

`cloudflare/` implements a ciphertext object store with R2 for bytes, D1 for metadata, and a Worker API. `LocalStorage` implements the same client contracts on a filesystem. Neither backend receives device pairing material or owner private keys.

## Deploy only when intended

Requires Node.js 22+ for development and the Worker test suite.

```bash
cd cloudflare
npm install
npx wrangler login
./setup.sh
npm run deploy
```

`setup.sh` creates or uses the configured bucket and database, applies migrations, and writes a new bearer token. These commands change local configuration or cloud resources only when you explicitly run them; tests do not deploy. Record the printed token as a secret and configure the client:

```bash
export XINLIQIU_STORE_URL=https://<your-worker-hostname>
export XINLIQIU_STORE_TOKEN=<printed-token>
```

Apply later migrations without reprovisioning:

```bash
npm run migrate          # remote D1
npm run migrate:local    # local Wrangler D1
```

Migrations run in filename order. Existing partially migrated schemas are baselined by inspecting columns so the non-repeatable alteration is not replayed. Keep `.wrangler/`, `.dev.vars`, tokens, and deployment credentials out of version control.

## Upload through the SDK

```bash
xinliqiu sync 0 <past-device-time-ms> --out ./captures --store cloudflare
xinliqiu sync 0 <past-device-time-ms> --out ./captures \
  --store local --store-path ./xinliqiu-store
```

Use a finite past device-clock value informed by `status.device_timestamp_ms`. The CLI runs content-based `ingest_files` on every published outer file and validates store configuration and stable identity before BLE work.

- CMPT and direct-enpt `audio`, `note-audio`, `end-marker`, and `mark` entries are structurally validated and uploaded.
- Plaintext trace-point/compat-tp, JSONL, and unknown entries stay local and appear in `not_uploaded`.
- Malformed CMPT/enpt and I/O errors abort instead of being hidden as skips.
- `EncryptedDiagnosticPolicy` is an explicit library opt-in for caller-encrypted diagnostics and a scheme label. A Worker label check is not independent proof of correct encryption.

A store report does not upgrade a partial device range to success. See [Sync](sync.md) for range states and identity precedence.

## HTTP API

All endpoints except `/healthz` require `Authorization: Bearer <token>`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/objects` | Store one ciphertext object |
| `GET` | `/objects?device=&start_ms=&end_ms=&kind=&limit=&cursor=&include_untimed=` | Paginated metadata |
| `GET` | `/objects/changes?device=&since=&limit=` | Sequence-based incremental metadata |
| `GET` | `/objects/<key>` | Fetch ciphertext and metadata headers |
| `GET` | `/digest?device=&start_ms=&end_ms=&include_untimed=` | Versioned set digest |
| `GET` | `/inventory?device=` | Aggregate stored counts/bytes |
| `GET` | `/healthz` | Liveness and digest version |

`POST /objects` uses these headers, percent-encoded by the Python client where needed:

| Header | Meaning |
|---|---|
| `x-xinliqiu-device` | Raw storage identity |
| `x-xinliqiu-name` | Original entry name as metadata, never a path |
| `x-xinliqiu-kind` | `audio`, `note-audio`, `end-marker`, `mark`, or `diagnostic` |
| `x-xinliqiu-encryption` | Required for diagnostic objects |
| `x-xinliqiu-sha256` | Required lowercase hex; verified server-side |
| `x-xinliqiu-start-ms`, `x-xinliqiu-end-ms` | Optional device-time bounds |

Plaintext `trace-point` and `unknown` uploads are rejected. Audio-family objects must pass enpt envelope checks. The Worker recomputes SHA-256, validates raw identity against its canonical key, and repairs missing object/index state where possible. Responses distinguish `duplicate` from `repaired`; missing or corrupt reads return 410/409, and an unmigrated schema returns 503 with a migration hint.

## Identity, objects, and digests

Canonical device keys are `d1-` plus lowercase UTF-8 hex. Object keys derive from canonical identity and content hash. Raw identity is retained and checked so canonical collisions cannot merge devices.

Pin the old identity before migrating an existing store or changing pairing. `save_storage_device_id()` atomically saves a stable identity while preserving other public config. The CLI refuses unstable BLE UUID fallback before radio work.

Digests use `xinliqiu-storage-digest/v1` over device key, range, untimed policy, and content hashes. Both backends produce the same digest and `latest_seq` from one snapshot. `compare()` rejects comparisons across different devices, ranges, versions, or untimed policies.

## LocalStorage

- Uses canonical path-safe directories and reads/deduplicates supported legacy raw-directory records.
- Uses thread locks plus POSIX `flock`; Windows has in-process locking only.
- Writes blobs and index updates atomically and repairs torn/duplicate index lines, reporting `last_repair` and `repair()` results.
- Supports `changes`, `list_page`, `list`, `digest`, `get`, and `inventory`.
- Refuses unsafe legacy identities rather than traversing paths.

## Limits

- Maximum object size: 2 MiB.
- List/change limits: 1–1000; list cursors are opaque base64url values.
- Device-time filtering uses inclusive interval overlap; `include_untimed` controls entries without usable timestamps.
- D1 digest reads matching rows in one query and may need chunking for very large devices.
- Old plaintext trace-point/unknown rows remain readable, but those kinds cannot be newly uploaded.
- Stored totals and digests describe the store, not total device capacity or global device inventory.

## Offline checks

```bash
node --test cloudflare/test/
node --check cloudflare/src/index.js
bash -n cloudflare/setup.sh
```

Tests execute migrations with `node:sqlite`, fault-inject R2/D1, and use a fake Wrangler. They require Node.js 22+, no Cloudflare account, and no real recordings.
