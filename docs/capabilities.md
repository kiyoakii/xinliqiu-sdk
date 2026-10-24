# Capabilities

This is the single documentation matrix. The runtime source is `python/aipin_sdk/capabilities.py`; use `xinliqiu capabilities --json` or `Xinliqiu.capabilities()` for its machine-readable notes and evidence labels.

`unavailable` means no established SDK path on the tested setup, not a universal statement about other hardware, firmware, or applications. Hardware observations are scoped to the tested device. This Python implementation has offline synthetic validation plus scoped tested-device acceptance: pairing, authenticated status, inventory, single/multi-range and zero-width sync, voiceprint collection, record start/stop, storage mirror, whole-file recovery after a host interruption, and INIT with matching public-key readback followed by authenticated new audio. Live Cloudflare deployment has not been tested.

| Capability | Status | Contract and boundary |
|---|---|---|
| `auth.reuse_existing_ksc` | supported | Authenticate with existing pairing material without pairing or INIT |
| `record.status` | supported | Authenticated recording byte, battery, error byte, and device timestamp |
| `record.start_stop` | bounded | One write plus independent status observations; a write is not an application ACK and recording state does not guarantee audio |
| `record.vad_gated_audio` | supported | Observed audio creation is voice-activity gated; START alone does not guarantee an audio file |
| `record.segmentation` | bounded | Speech segments and entry rollover have bounded observations; do not generalize them to every recording mode |
| `record.silence_retention` | bounded | Trailing-silence behavior is bounded; exact timing and native trim are not a sample-accurate contract |
| `voiceprint.collect` | bounded | One 1–127 second capture and one post-START file; retry is a new capture, not re-fetch or continuous recording |
| `device.init_owner_key` | bounded | INIT erases existing content; requires authorized signing material and matching backed-up owner keys. Only the tested slot-1 path is implemented, with account and public-key readback verification |
| `files.sync_range` | supported | Fetch CMPT, direct enpt, or JSONL outer files; file transaction and exact range completion are separate |
| `files.inventory_totals` | supported | Aggregate counts/bytes for a strictly increasing device-clock range; not a list, cursor, or global-inventory proof |
| `crypto.owner_key_decrypt` | supported | RSA-2048 unwrap and AES-256-GCM with the caller's matching owner private key |
| `audio.opustowav` | bounded | Tested 40-byte/20 ms Opus, 16 kHz mono; duration is packet-count based, not native microphone duration |
| `mark.add` | unavailable | No established SDK command creates a highlight; existing `.mark` entries can still be parsed and stored |
| `note.archive` | unavailable | No established SDK trigger or BLE control path; do not infer a universal hardware negative |
| `key.ai_manual` | bounded | Physical-key recording-toggle observations are bounded; the SDK does not synthesize presses or define a complete key mapping |

Preserve these distinctions when adding features. A bounded or unavailable entry must not be promoted without reproducible, scoped evidence, and useful parsing or retrieval support must not be removed merely because a producer command is unavailable.
