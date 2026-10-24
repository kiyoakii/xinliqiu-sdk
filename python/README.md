# Xinliqiu SDK for Python

Python 3.10+ library and CLI for operator-authorized pairing, encrypted retrieval, local decryption, and ciphertext storage. Package version: 0.2.1.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install "xinliqiu-sdk[all] @ git+https://github.com/kiyoakii/xinliqiu-sdk.git@v0.2.1#subdirectory=python"
```

Use `xinliqiu-sdk` for offline parsing/decryption/storage, `[ble]` for BLE, or `[all]` (currently equivalent to `[ble]`). `cryptography` is always installed. WAV export additionally requires `ffmpeg`; Ogg export does not.

Pair from the CLI and keep the resulting files private:

```bash
xinliqiu scan
xinliqiu pair --device <device-id> --out-dir ./xinliqiu-creds
xinliqiu status
```

If pairing is uncertain, do not pair again; follow the explicit [pending recovery](https://github.com/kiyoakii/xinliqiu-sdk/blob/main/docs/getting-started.md#pending-pairing-recovery). Back up the owner private key before any INIT. INIT will erase existing content, requires separate authorization and `--allow-format`, and must never be repeated to obtain missing confirmation. See [Getting started](https://github.com/kiyoakii/xinliqiu-sdk/blob/main/docs/getting-started.md).

## Example

This example syncs a finite range ending at the authenticated device timestamp, classifies every outer file by content, and decrypts only supported enpt entries. JSONL and unknown files remain local. It does not send marker plaintext to an audio decoder.

```python
from pathlib import Path

from aipin_sdk import Credentials, Xinliqiu, classify_outer_file, decrypt_enpt

ball = Xinliqiu(Credentials(
    device_id="<device-id>",
    peer_id_file=Path("./xinliqiu-creds/peer-id.txt"),
    key_file=Path("./xinliqiu-creds/pairing.json"),
))
status = ball.status()
if status.device_timestamp_ms is None:
    raise RuntimeError("device timestamp unavailable; choose a finite past end")

result = ball.require_ok(ball.sync_range(
    0, status.device_timestamp_ms, Path("./captures"), seconds=300
))
owner_key = Path("~/.config/xinliqiu/owner.pem").expanduser()
ciphertext_kinds = {"audio", "note-audio", "end-marker", "mark"}

for path in result["files"]:
    outer = classify_outer_file(path)
    if outer.format == "cmpt":
        payloads = [
            entry.payload for entry in outer.container.entries
            if entry.kind in ciphertext_kinds
        ]
    elif outer.format == "enpt":
        payloads = [outer.payload]
    elif outer.format == "jsonl":
        print("JSONL kept local:", outer.path)
        continue
    else:
        print("Unknown content kept local:", outer.path)
        continue

    for encrypted in payloads:
        plaintext = decrypt_enpt(encrypted, owner_key)
        print(outer.path, "authenticated plaintext bytes:", len(plaintext))
```

`require_ok` raises `OperationIncomplete` unless range completion is verified. A published file alone does not prove range success. Existing past ranges can be fetched again as whole files; `.part` files are not resume state.

For audio entries, use `to_ogg` or `to_wav` only after checking the declared layout. Use `parse_marker` for `end-marker` and `mark`. `Entry.output_name()` and `generated_output_name()` avoid trusting device names as paths.

## Storage and outcomes

`ingest_files` uses the same classification shown above. Valid supported ciphertext can upload; plaintext diagnostics and unknown content remain local in `not_uploaded`. `EncryptedDiagnosticPolicy` is an explicit library opt-in for caller-encrypted diagnostics; plaintext-returning policies are rejected.

Pin a stable identity with `resolve_storage_identity`, `save_storage_device_id`, or `XINLIQIU_STORAGE_DEVICE_ID`. The CLI refuses BLE UUID fallback before radio work. `push_range` preserves device outcome fields, `pull_changes` verifies size/SHA-256 before atomic publication, and `compare()` distinguishes incomparable digests from a real mismatch.

Multi-outcome APIs return `state`, `ok`, diagnostics, and `retry`. START/STOP require independent status observation; voiceprint retry is a new capture; INIT acceptance without readback is not verified success. `storage_info()` does not expose total or free capacity, so periodic sync is prudent but not a data-loss guarantee.

The top-level package exports client/configuration, container/enpt, audio, storage/sync, task, and result helpers. See [CLI](https://github.com/kiyoakii/xinliqiu-sdk/blob/main/docs/cli.md), [capabilities](https://github.com/kiyoakii/xinliqiu-sdk/blob/main/docs/capabilities.md), [sync](https://github.com/kiyoakii/xinliqiu-sdk/blob/main/docs/sync.md), [storage](https://github.com/kiyoakii/xinliqiu-sdk/blob/main/docs/storage.md), and [security](https://github.com/kiyoakii/xinliqiu-sdk/blob/main/docs/security.md).

Offline tests:

```bash
cd python
python -m pytest -q
```
