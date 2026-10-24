# CLI reference

```text
xinliqiu --version
xinliqiu [--common-options] <command> [command-options]
```

Device-related common options are accepted before or after the subcommand. Values resolve as **flag > environment > saved config**. The config is `~/.config/xinliqiu/config.json` unless overridden; it stores paths and public settings, not credential contents.

## Commands

| Command | Purpose and principal options |
|---|---|
| `capabilities [--json]` | Show the runtime capability matrix; `--json` includes evidence and validation scope |
| `scan [--name TEXT] [--seconds N]` | Discover nearby devices; no results returns 1 |
| `pair --device ID --out-dir DIR [--promote-pending]` | Pair and save credential paths, or promote pending material after verified status |
| `doctor [--owner-public-key PATH]` | Check local credentials/configuration without contacting the device |
| `status` | Authenticated recording, battery, error, and `device_timestamp_ms` read |
| `inventory [--start-ms N --end-ms N]` | Aggregate counts/bytes for a strictly increasing device-clock range; use a finite past end |
| `storage` | Authenticated usage information; total/free capacity are unknown |
| `record start\|stop` | Write once, then require independent status observation |
| `voiceprint [SECONDS] [--out DIR] [--window SECONDS]` | Collect one bounded voiceprint; host window must exceed capture duration |
| `sync [START] [END] [--out DIR] [--seconds N]` | Fetch one finite device-clock range; defaults are `START=0` and `END=device_timestamp_ms`, zero-width sync is allowed |
| `sync --ranges 'START:END;START:END' [--out DIR] [--seconds N]` | Fetch distinct ranges on one connection/deadline; stop at first failure |
| `keygen [--out-dir DIR] [--force]` | Create owner private/public keys; `--force` can break key continuity |
| `keycheck [--owner-key PATH] [--sample PATH]` | Validate owner key usability and optionally test a synced CMPT sample |
| `init --owner-key PATH --owner-public-key PATH --signing-key PATH [--account NAME] [--public-key-version N] --allow-format` | Destructively install an owner public key; requires explicit authorization every time |

For INIT, `--owner-key` must identify the matching owner private key. The signing input is an operator-authorized unencrypted P-256 PKCS#8 file; the [README Agent instruction](../README.md#给-agent准备-init-签名材料) explains the private official-APK workflow. Python integrations may alternatively supply a generic `Signer`. Never repeat INIT to resolve an uncertain result.

## Common options

| Option | Environment | Meaning |
|---|---|---|
| `--device` | `XINLIQIU_DEVICE_ID` | Local BLE/CoreBluetooth connection identifier |
| `--peer-id-file` | `XINLIQIU_PEER_ID_FILE` | Host peer-id file |
| `--key-file` | `XINLIQIU_KEY_FILE` | Pairing JSON; use `pairing.pending.json` explicitly during recovery |
| `--owner-key` | `XINLIQIU_OWNER_KEY` | Owner private key for INIT or caller-selected operations |
| `--agent-public-key` | `XINLIQIU_AGENT_PUBLIC_KEY` | Optional agent public SPKI in DER/PEM/base64 form |
| `--agent-package` | `XINLIQIU_AGENT_PACKAGE` | Agent registration package |
| `--bind-start-delay-ms` | `XINLIQIU_BIND_START_DELAY_MS` | Delay before the first business request |

Other environment:

| Variable | Meaning |
|---|---|
| `XINLIQIU_CONFIG` | Override the config file path |
| `XDG_CONFIG_HOME` | Override the default config parent when `XINLIQIU_CONFIG` is unset |
| `XINLIQIU_STORAGE_DEVICE_ID` | Stable storage identity; see precedence below |
| `XINLIQIU_STORE_URL` | Cloudflare Worker base URL |
| `XINLIQIU_STORE_TOKEN` | Cloudflare bearer token |

## Sync storage options

`sync` additionally accepts:

- `--store local|cloudflare` — ingest every published outer file after device sync;
- `--store-path DIR` — local backend directory, default `./xinliqiu-store`;
- `--storage-device-id ID` — pin stable storage identity.

Cloudflare requires both store environment variables. Storage identity resolves as explicit option > `XINLIQIU_STORAGE_DEVICE_ID` > saved config > pairing-derived identity > unstable BLE UUID. The CLI rejects the BLE fallback before radio work. Store ingestion does not turn a partial or unverified device range into success.

## Outcomes and exit codes

Most operation output is JSON. Multi-outcome operations include `state`, `ok`, diagnostics or detail, and safe `retry` guidance.

| Exit | Meaning |
|---:|---|
| 0 | Command-specific success; for multi-outcome operations, verified success |
| 1 | Usage, configuration, local I/O, or other local error; `scan` also uses it for no results |
| 3 | The operation ran but was rejected, partial, or unverified |
| 130 | Interrupted with Ctrl-C |

Important success states are `range_completed`, `recording_observed`, `stopped_observed`, `voiceprint_collected`, and `init_verified`. Acceptance, a local write, published files, or an empty result without EOF is not equivalent. See [Sync](sync.md) and [Getting started](getting-started.md).

For scripting, replace every `<past-device-time-ms>` placeholder in documentation with a finite past device-clock value informed by `status.device_timestamp_ms`; do not use fixed future timestamps. Avoid automated retry loops.
