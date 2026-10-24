# -*- coding: utf-8 -*-
"""Evidence-scoped capability table for the OPPO AI Xinliqiu (心力球).

``supported`` and ``bounded`` describe feature behaviour evidenced on the
tested-device unit. The hardware evidence comes from authorized observations on
the tested device and scoped acceptance of this Python implementation.
``unavailable`` means no established, reproducible integration path on the
tested setup, not a universal negative about every device or firmware.
"""

SUPPORTED = "supported"
BOUNDED = "bounded"
UNAVAILABLE = "unavailable"

TESTED_DEVICE = "tested-device"

CAPABILITIES = {
    "auth.reuse_existing_ksc": {
        "status": SUPPORTED,
        "evidence": TESTED_DEVICE,
        "note": "Authenticate with an existing KSC/peer-id pair without pairing or INIT.",
    },
    "record.status": {
        "status": SUPPORTED,
        "evidence": TESTED_DEVICE,
        "note": "Authenticated read-only state query: recording byte, battery and error byte.",
    },
    "record.start_stop": {
        "status": BOUNDED,
        "evidence": TESTED_DEVICE,
        "note": ("Write START or STOP once, then confirm through independent status reads. "
                 "Write completion is not an application ACK; an unconfirmed result must not "
                 "be blindly retried, and recording state does not guarantee an audio file."),
    },
    "record.vad_gated_audio": {
        "status": SUPPORTED,
        "evidence": TESTED_DEVICE,
        "note": ("Accepted on the tested device: runtime VAD/drop evidence is linked to file-close "
                 "timing, and ordinary audio is created only with detected voice activity. "
                 "START alone does not guarantee an audio file."),
    },
    "record.segmentation": {
        "status": BOUNDED,
        "evidence": TESTED_DEVICE,
        "note": ("Accepted (bounded) on the tested device: two speech segments produced two files; "
                 "a full 120,000-byte ordinary entry was also observed. Do not generalise "
                 "these observations to every recording mode."),
    },
    "record.silence_retention": {
        "status": BOUNDED,
        "evidence": TESTED_DEVICE,
        "note": ("Accepted (bounded) on the tested device: trailing silence is retained for a "
                 "limited period, not indefinitely. Exact timing and native trim are not "
                 "a complete sample-accurate contract."),
    },
    "voiceprint.collect": {
        "status": BOUNDED,
        "evidence": TESTED_DEVICE,
        "note": ("One post-START voiceprint file, 1..127 seconds per request. Ordinary-range "
                 "re-read is unproven and a retry is a new capture; this is not a continuous "
                 "recorder or archive API."),
    },
    "device.init_owner_key": {
        "status": BOUNDED,
        "evidence": TESTED_DEVICE,
        "note": ("INIT will erase existing content. Requires authorized signing material and "
                 "matching backed-up owner keys; only the tested slot-1 path is implemented. "
                 "Verified only when the account and public-key readback match."),
    },
    "files.sync_range": {
        "status": SUPPORTED,
        "evidence": TESTED_DEVICE,
        "note": ("Request a device-clock range and receive CMPT, direct enpt or JSONL outer "
                 "files. Files publish only after transaction confirmation; range_completed "
                 "also requires an exact authenticated 06/08 and a clean drain."),
    },
    "files.inventory_totals": {
        "status": SUPPORTED,
        "evidence": TESTED_DEVICE,
        "note": ("Aggregate record + voice-input counts and byte totals for a strictly "
                 "increasing range. Not a file list or cursor; full-inventory claims "
                 "require separate aggregate/enumeration reconciliation."),
    },
    "crypto.owner_key_decrypt": {
        "status": SUPPORTED,
        "evidence": TESTED_DEVICE,
        "note": "RSA-2048 unwrap + AES-256-GCM using the caller-supplied owner private key.",
    },
    "audio.opustowav": {
        "status": BOUNDED,
        "evidence": TESTED_DEVICE,
        "note": ("Tested ordinary/voiceprint layout is 40-byte / 20 ms Opus, 16 kHz mono. "
                 "Duration is packet-count based because native source trim is unavailable; "
                 "other layouts must be declared explicitly."),
    },
    "mark.add": {
        "status": UNAVAILABLE,
        "evidence": "tested-device observations plus bounded app observations",
        "note": ("No supported SDK command creates a highlight. Tested device contains authenticated "
                 ".mark entries, but the tested physical-key/App paths did not establish a "
                 "producer; this is not a universal hardware negative."),
    },
    "note.archive": {
        "status": UNAVAILABLE,
        "evidence": "tested-device observations; SDK path unconfirmed",
        "note": ("No confirmed BLE entry or tested-device physical-key trigger "
                 "establishes .note.opus archive creation as an SDK feature."),
    },
    "key.ai_manual": {
        "status": BOUNDED,
        "evidence": TESTED_DEVICE,
        "note": ("Tested device key behaviour is a recording toggle: a short press starts and "
                 "a second short press stops. In the tested approximately four-second "
                 "hold/release window, release did not stop recording; do not generalise "
                 "that window to every hold duration or infer a universal key/numeric mapping."),
    },
}


def describe() -> dict:
    """Return a JSON-serialisable capability summary with evidence scope."""
    buckets = {SUPPORTED: [], BOUNDED: [], UNAVAILABLE: []}
    for name, entry in CAPABILITIES.items():
        buckets[entry["status"]].append({
            "name": name,
            "note": entry["note"],
            "evidence": entry["evidence"],
        })
    return {
        "device": "心力球 / OPPO AI Pin (CNMABWC301)",
        "implementation_validation": ("offline suites plus scoped tested-device acceptance: pair, status, "
                                      "inventory, sync/multi-range/zero-width, voiceprint, record start/stop, "
                                      "INIT with matching readback, post-INIT authenticated audio, storage "
                                      "mirror and whole-file recovery; live Cloudflare deployment not tested"),
        "evidence_scope": {
            "actual": "Hardware behaviour observed on the tested device.",
            "python": ("Offline suites plus scoped tested-device acceptance of this implementation, "
                       "including INIT and post-INIT audio; live Cloudflare deployment remains untested."),
        },
        "statuses": buckets,
        "guidance": {
            "unavailable": ("No established SDK path on the tested setup. Do not build product "
                            "flows on these entries or read them as universal hardware negatives."),
        },
    }
