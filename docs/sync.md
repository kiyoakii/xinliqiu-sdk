# Synchronization

Device retrieval, storage upload, storage mirroring, and decryption are separate operations. None of the first three requires the owner private key; decryption always does.

| Operation | Direction | API |
|---|---|---|
| Fetch a device range | device → host | `Xinliqiu.sync_range` / `sync_ranges` |
| Upload fetched ciphertext | host → store | `push_range` or CLI `sync --store` |
| Mirror stored ciphertext | store → host | `pull_changes` |
| Decrypt an enpt payload | local only | `decrypt_enpt` |

## Device to host

Read `status.device_timestamp_ms` to establish the device clock, then request a finite past range. Do not assume host time equals device time or use a fixed future end. A future end may delay EOF until the device reaches it.

```bash
xinliqiu sync --out ./captures --seconds 300   # 0 .. current device time
xinliqiu sync 0 <past-device-time-ms> --out ./captures --seconds 300
```

Ranges are not one-shot delivery queues. A past range can be requested again on a new authenticated connection, including after a controlled host interruption. Recovery is whole-file re-fetch:

1. Close or abandon the old operation.
2. Authenticate a new connection with the existing pairing material.
3. Request the required past range once, following the previous result's `retry` guidance.
4. Accept each retransmitted file as a new complete transaction.

Never concatenate `.part` files or treat their length as a resume offset. The Python receiver removes unpublished staging files when it abandons them; a partial is never a completed recording.

### Three completion boundaries

1. **File transaction:** exact declared bytes, fsync/optional MD5 sealing, and a matching `complete-rsp result == 0` succeed before `.part` is published. Rejection or abandonment does not publish a final file. Existing files are not overwritten.
2. **Container:** CMPT parsing validates declared length, table, and entry boundaries. Its count is per-container entries. An outer file can instead be direct enpt or JSONL; classify by content, not suffix.
3. **Range:** after the request is written, an authenticated `06/08` echoes the exact range and every transaction drains without file/service failure. `06/01`, a first file, silence, a local write, deadline, or disconnect is not range completion.

An empty range with exact EOF is a successful empty result. An empty result without EOF is unverified. A zero-width sync range is valid; inventory and storage queries require `end > start`. A completed finite range still does not prove global inventory, and normal sync may consume diagnostic trace-point sources on the device.

### Result states

Common fields include `state`, `ok`, `verified`, `range_complete`, `files`, `count`, `bytes`, `offers`, `rejected`, `rejected_total`, `rejected_pairs`, `published`, `failures`, `abandoned`, `diagnostics`, and `retry`. Files in `files` are complete published files; their presence alone does not verify the range. `rejected` is always an integer count in both `sync_range` and `sync_ranges`; `rejected_pairs` holds the per-offer details, and `rejected_total` counts refusals even when the detail window is full.

| `state` | `ok` | Meaning |
|---|---:|---|
| `range_completed` | true | Exact EOF and clean drain; zero files is success |
| `range_completed_with_failures` | false | EOF arrived, but file/service failures occurred |
| `range_completed_drain_timeout` | false | EOF arrived with transactions open at the deadline |
| `transfer_failed` | false | Transfer or local sink failure stopped the operation |
| `window_elapsed_files_published_range_unverified` | false | Files published, but no matching EOF |
| `window_elapsed_partial_unverified` | false | Unfinished/failed work and no matching EOF |
| `window_elapsed_no_files` | false | No files and no EOF; not proof of an empty range |
| `link_lost` | false | Link dropped; published files remain, unfinished ones do not publish |
| `range_request_not_written` | false | Request did not reach the link |
| `connect_failed` | false | Authenticated channel did not open; no range was requested |
| `not_started` | false | A previous range in a multi-range sequence failed |

CLI exits are 0 for verified success, 1 for usage/local errors, and 3 for structured non-success. `require_ok(result)` raises `OperationIncomplete` when `ok` is false.

### Multiple ranges and sessions

```bash
xinliqiu sync --ranges '0:<past-device-time-ms>' \
  --out ./captures --seconds 600
```

`sync_ranges` accepts distinct finite `start:end` pairs on one authenticated connection under one overall deadline. Outputs go to `range-0`, `range-1`, and so on. It stops at the first non-success and marks later ranges `not_started`.

Most other high-level calls open and close a link, so poll infrequently and avoid tight retry loops. Control and file-transfer session identifiers are negotiated dynamically; callers must not hard-code them. The plain-channel flag and file-chunk header are independent protocol fields.

## Host to store

```python
from aipin_sdk import CloudflareStorage, push_range

store = CloudflareStorage(url, token)
report = push_range(ball, store, device_id, start_ms, end_ms)
print(report["state"], report["ok"], report["storage_identity"])
print(report["upload"], report["not_uploaded"])
```

`push_range` preserves the full device result in `device_sync` and exposes top-level `state`, `ok`, `verified`, `range_complete`, and `retry`. Already published files may be ingested after a partial range, but upload never makes that range successful. Upload or local I/O failures raise before a report returns.

Every outer file is classified by content:

- valid enpt `audio`, `note-audio`, `end-marker`, and `mark` entries upload, including direct enpt outer files;
- plaintext `.tp`, compat-tp, JSONL, and unknown content stays local in `not_uploaded`;
- malformed CMPT/enpt and I/O errors raise instead of becoming skips;
- `EncryptedDiagnosticPolicy(encrypt, scheme)` is an explicit library opt-in for diagnostic ciphertext; policies returning plaintext are rejected.

CLI `sync --store local|cloudflare` uses the same `ingest_files` path. Its report includes `containers`, `direct_enpt`, `stored`, `duplicates`, `total`, `files`, and `not_uploaded`.

### Stable storage identity

The local BLE UUID is not a stable cross-host storage identity. Resolution order is:

1. explicit `storage_device_id` / `--storage-device-id`;
2. `XINLIQIU_STORAGE_DEVICE_ID`;
3. saved `storage_device_id` config;
4. identity derived from the pairing provider device id;
5. library-only BLE UUID fallback, marked `stable: false`.

The CLI refuses the last fallback before sync radio work. Pin the existing identity before changing pairing or hosts to avoid re-upload under a new key. `save_storage_device_id()` updates config atomically without storing credential contents. Canonical keys use `d1-` plus lowercase UTF-8 hex; raw identity is also checked to prevent collisions from merging devices.

## Store to host

```python
from pathlib import Path
from aipin_sdk import pull_changes

page = pull_changes(store, device_id, since=cursor,
                    download=True, local_dir=Path("./mirror"))
cursor = page["cursor"]
while page["has_more"]:
    page = pull_changes(store, device_id, since=cursor,
                        download=True, local_dir=Path("./mirror"))
    cursor = page["cursor"]
```

Storage cursors are sequence numbers, not device timestamps. `download=True` requires `local_dir`. Every object is checked against declared size and SHA-256, then published atomically with mode 0600. Valid existing files are reused; corrupt ones are replaced and reported. Failure raises before the new cursor is returned.

## Listing and comparison

`list_page` supports bounded limits, opaque cursors, inclusive interval overlap, and `include_untimed`; `list()` follows all pages. Digests use `xinliqiu-storage-digest/v1` over device key, range, untimed policy, and content hashes.

Use `compare()` so different devices, ranges, versions, or untimed policies return `comparable: false` instead of a false out-of-sync verdict:

```python
from aipin_sdk import compare
verdict = compare(store, device_id, remote_digest)
print(verdict["comparable"], verdict["in_sync"], verdict["mismatches"])
```

Backend endpoints and object limits are specified in [Storage](storage.md). Voiceprint collection is not a persistent re-fetch API; retrying creates a new capture.
