# Agent operating rules

Use this SDK only with operator-authorized devices, credentials, signing material, and data. Preserve useful generic functionality and make uncertainty explicit. Start with [Getting started](docs/getting-started.md); use [CLI](docs/cli.md) and the [capability matrix](docs/capabilities.md) to choose operations.

## Choose the interface

- Use `import aipin_sdk` for structured results, storage, and protocol integration.
- Use `xinliqiu <command>` for shell automation, JSON, and process exit codes.

Python 3.10+ is required. `[all]` installs BLE; offline parsing/decryption/storage needs neither BLE nor Node. WAV export needs `ffmpeg`. Cloudflare Worker development and tests require Node.js 22+.

## Hard rules

1. Never flash firmware.
2. Never run INIT without separate explicit authorization for that invocation, `--allow-format` in the CLI, backed-up matching owner keys, and authorized signing material. INIT will erase existing device content.
3. Never repeat INIT to obtain a missing ACK/readback or to resolve an uncertain earlier attempt.
4. Never claim success from a write, first file, silence, acceptance, or file count alone. Follow `state`, `ok`, diagnostics, and `retry`.
5. Never blind-retry pairing, START/STOP, sync, or voiceprint. Pending pairing requires an explicit `status` with `pairing.pending.json`, then promotion only after success.
6. Never upload plaintext audio/diagnostics under the default store policy. JSONL, plaintext diagnostics, and unknown content stay local and are reported.
7. Never put credentials, pending credentials, private keys, secret signing material, private captures, real device identifiers, or vendor binaries/source in the public repository. Public certificate fingerprints used only to verify genuine vendor artifacts are acceptable.
8. Use finite past device-clock ranges informed by `status.device_timestamp_ms`; do not use fixed future timestamps or assume host time matches.
9. Do not remove generic `Signer`, `Pkcs8Signer`, parsing, retrieval, or other useful functionality merely to simplify publication or tests.

## Outcome contract

- File publication requires a confirmed complete file transaction.
- CMPT validity is separate from outer direct-enpt/JSONL classification.
- `range_completed` requires exact authenticated EOF, clean drain, and no failures; an empty completed range is success.
- START/STOP succeed only as `recording_observed` / `stopped_observed`.
- Voiceprint succeeds only as `voiceprint_collected`; retry is a new capture.
- INIT succeeds only as `init_verified`; accepted-unverified and unknown outcomes are not success.
- CLI exits: 0 success, 1 usage/local error, 3 rejected/partial/unverified, 130 interrupted.

Ranges can be re-fetched as whole files on a new authenticated connection. Never resume from `.part` length or claim that a completed range proves global inventory. Normal sync may consume diagnostic trace-point sources.

## Keys, signing, and storage

Pairing does not install the owner key. Back up the owner private key outside the machine: losing it makes recordings under its public half undecryptable, and INIT/key replacement cannot recover them.

Keep the generic `Signer` protocol and `Pkcs8Signer`. For the official-APK signing-material workflow, follow the [README Agent instruction](README.md#给-agent准备-init-签名材料): work only with authorized materials in a private directory, validate the recovered P-256 key with synthetic data, and never publish the APK, key, or private implementation. INIT still requires separate explicit authorization.

Storage identity precedence is explicit > environment > saved config > pairing-derived > unstable BLE UUID. The CLI rejects the last fallback before radio work. Store upload never upgrades a partial range to success; decryption is always explicit.

## Reference

| Document | Use |
|---|---|
| [Getting started](docs/getting-started.md) | Setup, pending recovery, owner keys, INIT |
| [CLI](docs/cli.md) | Commands, options, environment, exits |
| [Capabilities](docs/capabilities.md) | Single capability matrix and evidence limits |
| [Python](python/README.md) | Install and CMPT/direct-enpt/JSONL example |
| [Sync](docs/sync.md) / [Storage](docs/storage.md) | Detailed transfer and backend contracts |
| [Security](docs/security.md) | Privacy and threat model |
| [Contributing](CONTRIBUTING.md) | Publication policy, tests, release checklist |
| [Legal](LEGAL.md) | Scope, operator duties, risk notice |
