# Security and privacy

Use this model when operating the SDK, adding a backend, or automating it with an agent. These are design goals and implementation checks, not a guarantee against every legal, operational, or security risk.

## Data and trust boundaries

| Item | Normal location | When it leaves the machine |
|---|---|---|
| Pairing material | Caller-selected `pairing.json` or `pairing.pending.json` | Not sent to storage by SDK APIs |
| Peer id | Caller-selected `peer-id.txt` | Not sent to storage by SDK APIs |
| Owner private key | Caller-selected path / `XINLIQIU_OWNER_KEY` | Never needed by storage; explicit local decryption only |
| Signing material | Operator-supplied external input | Used for authorized INIT signing; never shipped by the SDK |
| Encrypted audio/markers | Local capture directory | Only when a store or caller-managed transfer is enabled |
| Plaintext audio | Bytes returned by explicit decrypt/export | Only if caller code writes or sends it |
| JSONL, diagnostics, unknown content | Local output directory | Stays local by default; diagnostics require caller encryption and opt-in |

`pair` generates and privately writes pairing material. `Credentials` reads selected files; `UserConfig` stores absolute paths and public settings, not credential contents. The config may still reveal local paths and device identifiers, so protect it as sensitive metadata.

The device, host OS, BLE stack, owner-key backup, storage Worker, D1/R2 account, and any caller-supplied diagnostic encryption are separate trust domains. Possession of a store token authorizes store operations, not device access. Compromise of the owner private key compromises confidentiality of recordings encrypted to it.

## Two keys, different jobs

- The **KSC pairing key** authenticates a host connection. It does not decrypt
  recordings. Preserve pairing aliases; repeated pairing is not guaranteed to
  leave every other client unaffected.
- The **owner RSA key pair** controls who can decrypt recordings. The device
  stores its public half; the operator must protect the private half. It is
  installed by INIT, not by pairing.

Business-channel keys and nonces are derived from the pairing key, both
challenges, and independent counters. Host counters start at 2^63, separate
from the device range, so both directions can increase without nonce reuse.
Replies are accepted only after authentication and while counters increase.

## Ciphertext-only ingestion

`ingest_files`, `ingest_outer`, and the backends accept valid enpt `audio`, `note-audio`, `end-marker`, and `mark` objects without decrypting them. Structural enpt validation is not cryptographic authentication.

Plaintext `.tp`, compat-tp, JSONL, and unknown content stays local and is reported in `not_uploaded`. `EncryptedDiagnosticPolicy` is required for diagnostic uploads and must return non-plaintext with an explicit scheme label. The Worker cannot prove the caller encrypted correctly. Malformed CMPT/enpt and I/O errors raise rather than becoming silent skips.

## Authenticated outcomes

- Status, storage, and INIT replies require authentication.
- Files publish only after exact-size reception, fsync/optional-MD5 sealing, and matching peer completion.
- Range success additionally requires an authenticated exact range EOF and clean drain.
- INIT acceptance is distinct from `init_verified`, which requires matching public-key readback. Missing or unparseable confirmation never justifies repeating INIT.
- START/STOP write completion is not an application ACK; independent status observations determine success.

A verified protocol outcome does not prove global inventory, future device behavior, or secure handling by another system.

## Explicit decryption

`decrypt_enpt(data, private_key)` requires an RSA-2048 private key and returns plaintext only after AES-GCM authentication. `to_wav` is a separate export operation and does not discover keys. Sync and storage do not implicitly produce plaintext.

Use generated output names rather than device-supplied paths. Treat captured names, diagnostics, and JSONL as untrusted data even when transport authentication succeeded.

## Operational safeguards

- Keep credentials, pending pairing files, owner keys, signing material, SPKI files, and private captures outside the repository with owner-only permissions.
- Back up `owner.pem` offline before INIT. Losing it makes recordings under that public key undecryptable; INIT cannot recover them.
- Resolve pending pairing explicitly and follow `retry`; do not blind-retry pairing, recording, sync, or INIT.
- Run INIT only with separate authorization for an operation that will erase existing content, `--allow-format`, matching backed-up owner keys, and authorized signing material. Firmware flashing is outside the SDK.
- Pin `XINLIQIU_STORAGE_DEVICE_ID` when moving an existing store between hosts.
- Use a rotatable store token, restrict Worker/account access, and protect deployment state and logs.
- Do not log key contents, tokens, private recordings, capture contents, or secret-bearing command arguments.
- Review both current files and git history before publication; `.gitignore` does not remove historical secrets or prohibited content.

For vulnerability reporting and release checks, see [SECURITY.md](../SECURITY.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).
