# Getting started

Use only a device and credentials you are authorized to operate. This is the canonical setup and recovery guide. Show real outputs and stop on ambiguity rather than retrying blindly.

## Requirements and installation

- Python 3.10+
- A platform supported by `bleak` for BLE
- `ffmpeg` only for WAV export
- Node.js 22+ only for Cloudflare Worker development and tests

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install "xinliqiu-sdk[all] @ git+https://github.com/kiyoakii/xinliqiu-sdk.git@v0.2.1#subdirectory=python"
```

The base package supports offline parsing, decryption, and storage. `[ble]` installs BLE support; `[all]` is currently equivalent. Offline operations do not import `bleak`.

## 1. Pair and verify

```bash
xinliqiu scan
xinliqiu pair --device <device-id> --out-dir ./xinliqiu-creds
xinliqiu doctor \
  --device <device-id> \
  --peer-id-file ./xinliqiu-creds/peer-id.txt \
  --key-file ./xinliqiu-creds/pairing.json
xinliqiu status
```

A confirmed pair writes:

```text
./xinliqiu-creds/pairing.json   # private pairing material
./xinliqiu-creds/peer-id.txt    # host peer identifier
```

Pairing does not format the device or install an owner key. Existing `pairing.json` is not overwritten. Absolute paths are saved in `~/.config/xinliqiu/config.json`, subject to `XINLIQIU_CONFIG` and `XDG_CONFIG_HOME`; flags override environment variables, which override saved config. Preserve the saved pairing alias and do not assume repeated pairing cannot affect another client.

`doctor.ready` is a local-file verdict. `status` is a separate authenticated device read. If your integration uses an agent public key, pass `--agent-public-key`; its package and bind-delay options are integration settings, not universal device timing guarantees. See [CLI](cli.md).

### Pending pairing recovery

If `pair` returns `pairing_outcome_unknown`, do **not** pair again. The pending exchange may have succeeded remotely. Test the pending file explicitly:

```bash
xinliqiu status \
  --device <device-id> \
  --peer-id-file ./xinliqiu-creds/peer-id.txt \
  --key-file ./xinliqiu-creds/pairing.pending.json
```

Only after that authenticated status succeeds, promote it:

```bash
xinliqiu pair --device <device-id> \
  --out-dir ./xinliqiu-creds --promote-pending
```

If status fails, move `pairing.pending.json` aside and report the result before considering another attempt. Do not loop pairing or overwrite the pending evidence.

## 2. Establish device time and fetch ciphertext

Read `status.device_timestamp_ms` and choose a finite past end on that device clock. Replace the placeholder below; do not use a fixed future timestamp or assume the host clock matches the device.

```bash
xinliqiu inventory --start-ms 0 --end-ms <past-device-time-ms>
xinliqiu sync --out ./captures --seconds 300   # 0 .. current device time
xinliqiu sync 0 <past-device-time-ms> --out ./captures --seconds 300
```

Inventory returns aggregates, not a file list, cursor, capacity report, or global-inventory proof. Sync allows a zero-width range; inventory requires `end > start`.

A successful empty range returns `range_completed`, `ok: true`, and exit 0. Files without an exact authenticated range EOF are published transactions but not a verified range. Read `state`, `diagnostics`, and `retry`; do not infer success from a write, first file, silence, deadline, or disconnect. Completed ranges can be requested again as whole files, but no completion state proves every device object was enumerated.

Normal sync may consume device diagnostic trace-point sources. Save all outer files, including JSONL and unknown content. See [Sync](sync.md).

## 3. Generate and back up an owner key

Ciphertext retrieval does not require the owner private key; decryption does. If a matching owner key is not already installed and held, generate one:

```bash
xinliqiu keygen
xinliqiu keycheck --owner-key ~/.config/xinliqiu/owner.pem
```

Defaults are `~/.config/xinliqiu/owner.pem` (private, mode 0400) and `owner.spki.txt` (public SPKI). Back up the private key outside the machine before INIT. Loss of that key makes existing and future recordings under its public half undecryptable. `keygen --force`, key replacement, and INIT do not recover old ciphertext; do not use them to solve a decrypt failure.

To check the pair locally, add both paths to `doctor`:

```bash
xinliqiu doctor \
  --device <device-id> \
  --peer-id-file ./xinliqiu-creds/peer-id.txt \
  --key-file ./xinliqiu-creds/pairing.json \
  --owner-key ~/.config/xinliqiu/owner.pem \
  --owner-public-key ~/.config/xinliqiu/owner.spki.txt
```

## 4. Optional owner-key INIT

INIT erases existing device content and installs an owner public key. It is not required for ordinary pairing, status, or ciphertext retrieval and is not a recovery procedure.

Before considering INIT, preserve needed data with a finite past-range sync. Even a completed range is not a global-inventory guarantee. If you do not hold the private key matching existing ciphertext, the SDK can preserve it but cannot decrypt it.

Run INIT only after the operator explicitly confirms **for this invocation** that:

- all existing device content may be erased;
- the owner private key is backed up and matches the public SPKI;
- the challenge and signing material are authorized and appropriate;
- this is not a retry of an uncertain earlier INIT.

The generic protocol seam is `aipin_sdk.protocol.init.Signer`. `Pkcs8Signer` loads an operator-authorized, unencrypted P-256 PKCS#8 private key from an external file; the CLI uses that form by default. For the official-APK signing-material workflow, use the [README Agent instruction](../README.md#给-agent准备-init-签名材料) and keep the APK, key, and private implementation outside the public repository.

```bash
xinliqiu init \
  --owner-key ~/.config/xinliqiu/owner.pem \
  --owner-public-key ~/.config/xinliqiu/owner.spki.txt \
  --signing-key /absolute/path/authorized-signing-key.pem \
  --account local-owner \
  --allow-format
```

The SDK validates the owner private/public match before radio use.

| `state` | Meaning | Exit |
|---|---|---:|
| `init_verified` | Accepted, account matched, and public-key readback matched | 0 |
| `init_accepted_unverified` | Accepted/account matched, but key readback was absent | 3 |
| `init_written_no_ack` | INIT was written; no authenticated ACK arrived | 3 |
| `init_ack_unparseable` | A reply arrived but could not be parsed | 3 |
| `init_rejected` | Device rejected the request | 3 |
| `init_account_mismatch` | Reply named another account | 3 |
| `init_readback_mismatch` | Device returned a different key | 3 |

**Never repeat INIT to obtain an ACK, readback, or stronger outcome.** Once written, its result may be uncertain even if the host saw no confirmation. Follow `retry` and report the exact state.

## 5. Record and export

```bash
xinliqiu record start
xinliqiu record stop
xinliqiu voiceprint 30 --out ./captures --window 300
```

START/STOP succeed only as `recording_observed` / `stopped_observed`. `write_attempted_unconfirmed` means inspect `status`, not resend blindly. Voiceprint is one bounded capture; success is `voiceprint_collected`, `--window` is a host wait, and retrying starts a new capture rather than retrieving an old one.

Use `classify_outer_file` before parsing outer content. Decrypt only supported enpt payloads, parse markers with `parse_marker`, and use generated output names rather than device-supplied paths. The [Python example](../python/README.md#example) handles CMPT, direct enpt, JSONL, and unknown files explicitly.

## Troubleshooting

| Symptom | Safe next step |
|---|---|
| Pending pairing | Use the explicit pending `status` command above; promote only after success |
| `doctor` not ready | Fix the named local check; it does not replace authenticated `status` |
| Files published, sync exit 3 | Range remains unverified; follow `retry`, normally one new-connection whole-range request |
| No files and no EOF | Not an empty-range proof; inspect `state` and diagnostics |
| Record command unconfirmed | Read `status`; do not blind-retry START or STOP |
| Decryption fails | Check key/ciphertext correspondence; never use INIT as recovery |
| Store rejects BLE identity | Pin `--storage-device-id` or `XINLIQIU_STORAGE_DEVICE_ID`, or provide valid pairing data |
