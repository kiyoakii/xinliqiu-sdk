# -*- coding: utf-8 -*-
"""Offline tests for the storage/sync contract. No device, network or keys.

Every payload is synthetic: enpt-shaped buffers built in this file, never a
real recording or credential. Run with ``python tests/test_fixes_storage.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

from aipin_sdk import storage as st
from aipin_sdk import sync as sync_mod
from aipin_sdk.container import parse_cmpt
from aipin_sdk.errors import ContainerError, XinliqiuError

DIGEST_VECTOR = "4c996802aed26698664451a130087ba423e7c1250e15b5840e7c5e8a5f67076b"


def make_enpt(payload: bytes = b"x" * 40) -> bytes:
    head = b"enpt" + struct.pack("<HH", 256, 12) + b"\x00" * 256 + b"\x00" * 12
    head += struct.pack("<H", 0x0118) + bytes([1, 0])
    trailer = b"\x00" * 16 + struct.pack("<HH", 16, 24) + b"enpt"
    return head + payload + trailer


def make_cmpt(entries: list[tuple[str, bytes]]) -> bytes:
    table = bytearray()
    offset = 12 + len(entries) * 68
    for name, payload in entries:
        raw = name.encode("utf-8")[:64].ljust(64, b"\x00")
        table += raw + struct.pack("<I", len(payload))
    body = b"".join(p for _, p in entries)
    if offset % 4:
        pad = 4 - offset % 4
        offset += pad
        table += b"\x00" * pad
    declared = offset + len(body)
    return b"CMPT" + struct.pack("<HHI", len(entries), offset, declared) + bytes(table) + body


def entry(name: str, payload: bytes | None = None, index: int = 0):
    return st.StorageItem(name=name, payload=payload or make_enpt(), kind=st.storage_kind(name), index=index)


def expect_raises(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type as exc:
        return exc
    raise AssertionError(f"{fn.__name__} should have raised {exc_type.__name__}")


def test_kind_and_time_classification():
    assert st.storage_kind("1_2.end.enc.opus") == "end-marker"
    assert st.storage_kind("1_2.end.opus") == "end-marker"
    assert st.storage_kind("1_2.enc.opus") == "audio"
    assert st.storage_kind("1_2.enc.note.opus") == "note-audio"
    assert st.storage_kind("1_2.enc.vp.opus") == "audio"
    assert st.storage_kind("100.mark") == "mark"
    assert st.storage_kind("1.tp") == "diagnostic"
    assert st.storage_kind("1.compat.tp") == "diagnostic"
    assert st.storage_kind("mystery.bin") == "unknown"
    assert st.entry_times("100_200.enc.opus") == (100, 200)
    assert st.entry_times("100-200.enc.opus") == (100, 200)
    assert st.entry_times("100.mark") == (100, 101)
    assert st.entry_times("100_200.mark") == (100, 200)
    assert st.entry_times("200-100.mark") == (None, None)
    assert st.entry_times("1_2_3.mark") == (None, None)
    assert st.entry_times("diag.jsonl") == (None, None)
    print("ok kind and time classification")


def test_enpt_structure_validation():
    st.validate_enpt(make_enpt())
    expect_raises(ContainerError, st.validate_enpt, make_enpt()[:100])
    expect_raises(ContainerError, st.validate_enpt, b"plaintext" * 100)
    bad_trailer = bytearray(make_enpt())
    struct.pack_into("<H", bad_trailer, len(bad_trailer) - 6, 7)
    expect_raises(ContainerError, st.validate_enpt, bytes(bad_trailer))
    bad_header = bytearray(make_enpt())
    struct.pack_into("<H", bad_header, 276, 12)
    expect_raises(ContainerError, st.validate_enpt, bytes(bad_header))
    bad_magic = bytearray(make_enpt())
    bad_magic[-4:] = b"nope"
    expect_raises(ContainerError, st.validate_enpt, bytes(bad_magic))
    print("ok enpt structure validation")


def test_outer_file_classification_and_ingest(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    cmpt_path = tmp_path / "audio-outer.bin"
    cmpt_path.write_bytes(make_cmpt([
        ("100_200.enc.opus", make_enpt(b"a" * 40)),
        ("150.mark", make_enpt(b"m" * 40)),
        ("100_200.end.enc.opus", make_enpt(b"e" * 40)),
        ("diag.tp", b'{"reason":2}\n'),
    ]))
    enpt_path = tmp_path / "300_400.end.enc.opus"
    enpt_path.write_bytes(make_enpt(b"z" * 40))
    jsonl_path = tmp_path / "diagnostics"
    jsonl_path.write_text('{"a":1}\n{"b":2}\n', encoding="utf-8")
    unknown_path = tmp_path / "unknown.dat"
    unknown_path.write_bytes(b"\x00\x01\x02\x03 not json")
    result = st.ingest_files([cmpt_path, enpt_path, jsonl_path, unknown_path], store, "dev1")
    assert result["containers"] == 1
    assert result["direct_enpt"] == 1
    assert result["stored"] == 4, result
    assert result["total"] == 4
    kinds = {item["kind"] for item in result["not_uploaded"]}
    assert kinds == {"diagnostic", "jsonl", "unknown"}, result["not_uploaded"]
    assert result["not_uploaded_count"] == 3
    formats = {f["path"]: f["format"] for f in result["files"]}
    assert formats[str(jsonl_path)] == "jsonl"
    assert formats[str(unknown_path)] == "unknown"
    # Only ciphertext was uploaded; diagnostics stayed in the output dir.
    assert jsonl_path.exists()
    listed = store.list("dev1", 0, 1000)
    assert {o.kind for o in listed} == {"audio", "mark", "end-marker"}
    for obj in listed:
        st.validate_enpt(store.get(obj.object_key))
    print("ok outer file classification and ingest")


def test_malformed_inputs_fail(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    bad_cmpt = tmp_path / "bad.bin"
    data = bytearray(make_cmpt([("1_2.enc.opus", make_enpt())]))
    data[-1] ^= 0xFF  # declared length no longer matches? mutate payload instead
    bad_cmpt.write_bytes(b"CMPT" + b"\x00" * 20)
    expect_raises(ContainerError, st.ingest_files, [bad_cmpt], store, "dev1")
    bad_enpt = tmp_path / "1_2.enc.opus"
    bad_enpt.write_bytes(b"enpt" + b"\x00" * 50)
    expect_raises(ContainerError, st.ingest_files, [bad_enpt], store, "dev1")
    expect_raises(OSError, st.ingest_files, [tmp_path / "missing.bin"], store, "dev1")
    container = parse_cmpt(make_cmpt([("1_2.enc.opus", b"enpt" + b"\x00" * 40)]))
    expect_raises(ContainerError, st.ingest_container, container, store, "dev1")
    print("ok malformed inputs fail")


def test_plaintext_audio_stays_local(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    container = parse_cmpt(make_cmpt([
        ("1_2.opus", b"OggS" + b"\x00" * 200),
        ("3_4.enc.opus", make_enpt()),
    ]))
    result = st.ingest_container(container, store, "dev1")
    assert result["stored"] == 1
    assert result["not_uploaded_count"] == 1
    assert result["not_uploaded"][0]["reason"] == "payload-is-not-enpt-ciphertext"
    expect_raises(ContainerError, store.put_entry, "dev1", entry("9.bin", b"plaintext"))
    print("ok plaintext audio stays local")


def test_diagnostic_policy_encrypts_before_upload(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    policy = st.EncryptedDiagnosticPolicy(
        encrypt=lambda data, name: make_enpt(data[:40]), scheme="test-envelope"
    )
    jsonl_path = tmp_path / "diag.jsonl"
    jsonl_path.write_text('{"a":1}\n', encoding="utf-8")
    container_path = tmp_path / "c.bin"
    container_path.write_bytes(make_cmpt([("d.tp", b'{"reason":2}')]))
    result = st.ingest_files([jsonl_path, container_path], store, "dev1", diagnostic_policy=policy)
    assert result["stored"] == 2
    assert result["encrypted_diagnostics"] == 2
    assert result["not_uploaded"] == []
    assert result["diagnostic_policy"] == "test-envelope"
    objects = store.list("dev1", 0, 10)
    assert all(o.kind == "diagnostic" and o.encryption == "test-envelope" for o in objects)
    # A policy that returns plaintext is refused outright.
    bad = st.EncryptedDiagnosticPolicy(encrypt=lambda data, name: data)
    expect_raises(ContainerError, st.ingest_files, [jsonl_path], store, "dev1", diagnostic_policy=bad)
    print("ok diagnostic policy encrypts before upload")


def test_local_storage_identity_paths_and_duplicates(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    assert st.canonical_device_key("a/b") == "d1-612f62"
    assert st.canonical_device_key("a_b") != st.canonical_device_key("a/b")
    expect_raises(ValueError, st.canonical_device_key, "")
    expect_raises(ValueError, st.canonical_device_key, " dev")
    expect_raises(ValueError, st.canonical_device_key, "dev\x00")
    first = store.put_entry("设备/一", entry("100_200.enc.opus"))
    assert first["status"] == "stored"
    assert first["object_key"].startswith("d1-")
    # The on-disk directory is canonical hex, never the raw identity.
    dirs = [p for p in (tmp_path / "store").iterdir() if p.is_dir()]
    assert [p.name for p in dirs] == [st.canonical_device_key("设备/一")]
    assert store.put_entry("设备/一", entry("100_200.enc.opus"))["status"] == "duplicate"
    other = store.put_entry("a/b", entry("100_200.enc.opus"))
    assert other["status"] == "stored"
    assert other["object_key"] != first["object_key"]
    assert store.get(first["object_key"]) == make_enpt()
    expect_raises(XinliqiuError, store.get, "../escape/" + "0" * 64)
    expect_raises(XinliqiuError, store.get, "no-such/" + "0" * 64)
    print("ok local identity paths and duplicates")


def test_local_range_overlap_pagination_and_limits(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    store.put_entry("dev1", entry("100_200.enc.opus", make_enpt(b"a" * 40)))
    store.put_entry("dev1", entry("300_400.enc.opus", make_enpt(b"b" * 40)))
    store.put_entry("dev1", entry("500.mark", make_enpt(b"c" * 40)))
    store.put_entry("dev1", st.StorageItem(
        name="diag.jsonl", payload=make_enpt(b"d" * 40), kind="diagnostic", encryption="test"
    ))
    cases = [
        (0, 99, 0), (0, 100, 1), (150, 160, 1), (200, 250, 1), (201, 250, 0),
        (100, 400, 2), (500, 500, 1), (501, 501, 1), (502, 600, 0),
    ]
    for start, end, expected in cases:
        got = store.list("dev1", start, end, include_untimed=False)
        assert len(got) == expected, (start, end, got)
    assert len(store.list("dev1", 201, 250)) == 1  # untimed diagnostic
    assert [o.kind for o in store.list("dev1", 0, 10**15, kind="mark")] == ["mark"]
    expect_raises(ValueError, store.list, "dev1", 10, 2)
    expect_raises(ValueError, store.list_page, "dev1", 0, 100, limit=0)
    expect_raises(ValueError, store.list_page, "dev1", 0, 100, limit=1001)
    expect_raises(ValueError, store.list_page, "dev1", 0, 100, cursor="bogus")
    seen = []
    cursor = None
    pages = 0
    while True:
        page = store.list_page("dev1", 0, 10**15, limit=2, cursor=cursor)
        assert page["count"] <= 2
        seen.extend(o.object_key for o in page["objects"])
        pages += 1
        if not page["has_more"]:
            break
        cursor = page["next_cursor"]
        assert cursor
    assert pages == 2
    assert len(set(seen)) == 4
    assert store.list_page("dev1", 0, 10**15, limit=1000)["objects"][-1].kind == "diagnostic"
    print("ok local range overlap, pagination and limits")


def test_digest_vector_and_snapshot(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    for index, name in enumerate(("100_200.enc.opus", "101_200.enc.opus")):
        payload = make_enpt(bytes([index]) * 40)
        record = store.put_entry("dev1", entry(name, payload))
        assert record["sha256"] == hashlib.sha256(payload).hexdigest()
    digest = store.digest("dev1")
    assert digest["digest_version"] == st.DIGEST_VERSION
    assert digest["latest_seq"] == 2
    assert digest["count"] == 2
    # Independent recomputation from the returned rows must match exactly.
    rows = sorted((o.sha256, o.size_bytes) for o in store.list("dev1", 0, st.MAX_SAFE_MS))
    assert digest["digest"] == st.compute_digest("dev1", 0, st.MAX_SAFE_MS, True, rows)
    vector = st.compute_digest("dev1", 0, 2**53 - 1, True, [("a" * 64, 344), ("b" * 64, 100)])
    assert vector == DIGEST_VECTOR  # the Worker suite asserts the same constant
    ranged = store.digest("dev1", 201, 300, include_untimed=False)
    assert ranged["count"] == 0
    assert ranged["digest"] != digest["digest"]
    untimed = store.digest("dev1", 201, 300, include_untimed=True)
    assert untimed["count"] == 0
    print("ok digest vector and snapshot")


def test_changes_cursor_and_repair(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    for index in range(3):
        store.put_entry("dev1", entry(f"{100 + index}_200.enc.opus", make_enpt(bytes([index]) * 40)))
    first = store.changes("dev1", since=0, limit=2)
    assert len(first["objects"]) == 2
    assert first["cursor"] == 2 and first["has_more"]
    rest = store.changes("dev1", since=first["cursor"], limit=2)
    assert len(rest["objects"]) == 1 and not rest["has_more"]
    assert rest["latest_seq"] == 3
    assert store.changes("dev1", since=3)["cursor"] == 3
    expect_raises(ValueError, store.changes, "dev1", since=-1)
    expect_raises(ValueError, store.changes, "dev1", limit=0)
    # Torn trailing line and a duplicated record are repaired atomically.
    with store.index_path.open("a", encoding="utf-8") as fh:
        fh.write('{"object_key": "truncated')
    valid_lines = store.index_path.read_text(encoding="utf-8").splitlines()
    with store.index_path.open("a", encoding="utf-8") as fh:
        fh.write("\n" + valid_lines[0] + "\n")
    report = store.repair()
    assert report["dropped_lines"] == 1, report
    assert report["duplicates"] == 1, report
    assert report["missing"] == [] and report["corrupt"] == []
    assert len(store.list("dev1", 0, 10**15)) == 3
    assert store.changes("dev1", since=0, limit=10)["latest_seq"] == 3
    print("ok changes cursor and index repair")


def test_local_storage_concurrent_writes(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    errors = []

    def worker(index: int) -> None:
        try:
            for n in range(4):
                store.put_entry("dev1", entry(f"{index}_{n}.enc.opus", make_enpt(bytes([index, n]) * 40)))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors, errors
    objects = store.list("dev1", 0, 10**15)
    assert len(objects) == 16
    seqs = sorted(o.seq for o in objects)
    assert seqs == list(range(1, 17))
    print("ok local storage concurrent writes")


class FakeIncrementalStore:
    def __init__(self, objects, blobs):
        self.objects = objects
        self.blobs = blobs
        self.calls = 0

    def changes(self, device_id, since=0, limit=500):
        self.calls += 1
        window = self.objects[since:since + limit]
        return {
            "objects": window,
            "cursor": since + len(window),
            "has_more": since + len(window) < len(self.objects),
            "latest_seq": len(self.objects),
        }

    def get(self, object_key):
        return self.blobs[object_key]


def fake_object(name: str, payload: bytes, seq: int) -> st.StoredObject:
    return st.StoredObject(
        object_key=f"{st.canonical_device_key('dev1')}/{hashlib.sha256(payload).hexdigest()}",
        entry_name=name, kind="audio", size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(), start_ms=100, end_ms=200, seq=seq,
    )


def test_pull_changes_verification(tmp_path: Path):
    good = make_enpt(b"g" * 40)
    obj = fake_object("100_200.enc.opus", good, 1)
    store = FakeIncrementalStore([obj], {obj.object_key: good})
    mirror = tmp_path / "mirror"
    page = sync_mod.pull_changes(store, "dev1", download=True, local_dir=mirror)
    assert page["cursor"] == 1 and len(page["written"]) == 1
    target = Path(page["written"][0])
    assert target.read_bytes() == good
    assert not list(mirror.glob("*.part"))
    # Existing valid files are verified and reused, not re-downloaded.
    store.blobs.clear()
    again = sync_mod.pull_changes(store, "dev1", download=True, local_dir=mirror)
    assert again["verified_existing"] == [str(target)]
    # A corrupt mirror file is replaced by a verified copy.
    target.write_bytes(b"corrupt")
    store.blobs[obj.object_key] = good
    repaired = sync_mod.pull_changes(store, "dev1", download=True, local_dir=mirror)
    assert repaired["replaced"] == [str(target)]
    assert target.read_bytes() == good
    # Content that fails verification raises: no file, no advanced cursor.
    bad = fake_object("300_400.enc.opus", make_enpt(b"h" * 40), 2)
    store.objects.append(bad)
    store.blobs[bad.object_key] = b"x" * bad.size_bytes
    expect_raises(
        XinliqiuError, sync_mod.pull_changes, store, "dev1",
        since=1, download=True, local_dir=mirror,
    )
    assert not (mirror / sync_mod._local_name(bad.object_key)).exists()
    store.blobs[bad.object_key] = make_enpt(b"h" * 40)[:-1]
    expect_raises(
        XinliqiuError, sync_mod.pull_changes, store, "dev1",
        since=1, download=True, local_dir=mirror,
    )
    expect_raises(ValueError, sync_mod.pull_changes, store, "dev1", download=True)
    print("ok pull_changes verification")


def test_compare_checks_device_range_version(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    store.put_entry("dev1", entry("100_200.enc.opus"))
    mine = store.digest("dev1")
    assert sync_mod.compare(store, "dev1", mine)["in_sync"] is True
    other_device = dict(mine, device="dev2")
    result = sync_mod.compare(store, "dev1", other_device)
    assert result["in_sync"] is False and result["comparable"] is False
    assert "device" in result["mismatches"]
    assert "range" in sync_mod.compare(store, "dev1", mine, start_ms=5)["mismatches"]
    assert "range" in sync_mod.compare(store, "dev1", mine, end_ms=5)["mismatches"]
    other_version = dict(mine, digest_version="other/v0")
    assert "digest-version" in sync_mod.compare(store, "dev1", other_version)["mismatches"]
    changed = dict(mine, digest="0" * 64)
    assert sync_mod.compare(store, "dev1", changed)["in_sync"] is False
    print("ok compare checks device, range and version")


def test_identity_resolution_and_config(tmp_path: Path):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"device": "BLE-UUID", "other": 1}), encoding="utf-8")
    env = {}
    identity = st.resolve_storage_identity(config_path=config, environ=env, ble_device_id="BLE-UUID")
    assert identity.source == "ble-uuid" and identity.stable is False
    st.save_storage_device_id("my-ball", config)
    saved = json.loads(config.read_text(encoding="utf-8"))
    assert saved["storage_device_id"] == "my-ball" and saved["other"] == 1
    assert (config.stat().st_mode & 0o777) == 0o600
    identity = st.resolve_storage_identity(config_path=config, environ=env)
    assert identity.device_id == "my-ball" and identity.source == "config" and identity.stable
    env[st.STORAGE_DEVICE_ENV] = "env-ball"
    assert st.resolve_storage_identity(config_path=config, environ=env).device_id == "env-ball"
    assert st.resolve_storage_identity("explicit", config_path=config, environ=env).device_id == "explicit"
    del env[st.STORAGE_DEVICE_ENV]
    key_file = tmp_path / "key.json"
    key_file.write_text(json.dumps({"providerDeviceIdHex": "A1B2", "kscHex": "secret"}), encoding="utf-8")

    class Creds:
        device_id = "BLE-UUID"

    creds = Creds()
    creds.key_file = key_file
    derived = st.resolve_storage_identity(credentials=creds, config_path=tmp_path / "none.json", environ={})
    assert derived.source == "pairing-derived" and derived.stable
    assert derived.device_id == st.derive_storage_device_id("a1b2")
    assert "a1b2" not in derived.device_id and "secret" not in derived.device_id
    expect_raises(ValueError, st.derive_storage_device_id, "not-hex")
    print("ok identity resolution and config")


def test_push_range_shared_ingestion(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    out = tmp_path / "capture"
    out.mkdir()
    (out / "audio.bin").write_bytes(make_cmpt([
        ("100_200.enc.opus", make_enpt(b"a" * 40)),
        ("diag.tp", b'{"reason":2}'),
    ]))
    (out / "marker").write_bytes(make_enpt(b"e" * 40))
    (out / "diag").write_text('{"x":1}\n', encoding="utf-8")
    # The direct enpt outer file only ingests under a recognised name.
    (out / "300_400.end.enc.opus").write_bytes(make_enpt(b"z" * 40))

    class Ball:
        credentials = None

        def sync_range(self, start_ms, end_ms, output_dir, seconds=300):
            return {
                "_output_dir": str(out),
                "files": [str(out / "audio.bin"), str(out / "300_400.end.enc.opus"), str(out / "diag")],
                "count": 3, "bytes": 100, "offers": 3, "rejected": [],
            }

    report = sync_mod.push_range(Ball(), store, "BLE-UUID", 0, 1000, storage_device_id="stable-ball")
    assert report["storage_identity"] == {"device_id": "stable-ball", "source": "explicit", "stable": True}
    assert report["upload"]["stored"] == 2, report["upload"]
    assert report["upload"]["containers"] == 1
    assert report["upload"]["direct_enpt"] == 1
    assert report["not_uploaded_count"] == 2
    assert {item["reason"] for item in report["not_uploaded"]} == {"diagnostic-or-unknown-kept-local"}
    assert report["device_sync"]["count"] == 3
    assert report["output_dir"] == str(out)
    print("ok push_range shared ingestion")


def test_push_range_preserves_an_unverified_sync_outcome(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    synced = {
        "state": "window_elapsed_no_files",
        "ok": False,
        "verified": False,
        "range_complete": False,
        "retry": "inspect before retrying",
        "files": [], "count": 0, "bytes": 0, "offers": 0, "rejected": [],
        "diagnostics": {"eof_seen": False},
        "_output_dir": str(tmp_path / "capture"),
    }

    class Ball:
        credentials = None

        def sync_range(self, start_ms, end_ms, output_dir, seconds=300):
            return dict(synced)

    report = sync_mod.push_range(Ball(), store, "BLE-UUID", 0, 1000)
    assert report["device_sync"] == synced
    for key in ("state", "ok", "verified", "range_complete", "retry"):
        assert report[key] == synced[key]
    assert report["ok"] is False
    print("ok push_range preserves unverified sync state")


def test_cloudflare_client_contract():
    client = st.CloudflareStorage("https://store.test", "token")
    calls = []

    def fake_request(method, path, *, body=None, headers=None):
        calls.append((method, path, headers))
        if method == "POST":
            sha = hashlib.sha256(body).hexdigest()
            return 201, json.dumps({"status": "stored", "object_key": f"d1-x/{sha}", "seq": 1}).encode(), {}
        if path.startswith("/objects?"):
            if len(calls) < 4:
                return 200, json.dumps({
                    "objects": [], "count": 0, "has_more": False, "next_cursor": None,
                }).encode(), {}
            return 200, json.dumps({"objects": [], "count": 0, "has_more": False}).encode(), {}
        if path.startswith("/digest?"):
            return 200, json.dumps({"digest_version": "old/v0", "device": "dev1"}).encode(), {}
        raise AssertionError(path)

    client._request = fake_request
    result = client.put_entry("设备/一", entry("100_200.enc.opus"))
    assert result["status"] == "stored"
    _, _, headers = calls[0]
    assert headers["x-xinliqiu-device-encoding"] == "percent"
    assert "%" in headers["x-xinliqiu-device"]
    assert headers["x-xinliqiu-start-ms"] == "100"
    assert headers["x-xinliqiu-kind"] == "audio"
    client.list("dev1", 0, 1000)
    _, list_path, _ = calls[-1]
    assert "device=dev1" in list_path and "include_untimed=1" in list_path
    expect_raises(XinliqiuError, client.digest, "dev1")
    expect_raises(ValueError, client.list_page, "dev1", 0, 100, limit=0)
    expect_raises(ValueError, client.changes, "dev1", since=-2)
    print("ok cloudflare client contract")


def test_legacy_local_records_and_blobs(tmp_path: Path):
    for device in ("dev1", "d1-abc"):
        store = st.LocalStorage(tmp_path / device)
        payload = make_enpt()
        sha = hashlib.sha256(payload).hexdigest()
        legacy_dir = tmp_path / device / device
        legacy_dir.mkdir(parents=True)
        (legacy_dir / f"{sha}.bin").write_bytes(payload)
        record = {
            "object_key": f"{device}/{sha}", "device_id": device,
            "entry_name": "100_200.enc.opus", "kind": "audio",
            "size_bytes": len(payload), "sha256": sha,
            "device_start_ms": 100, "device_end_ms": 200,
        }
        store.index_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        listed = store.list(device, 0, 10_000)
        assert len(listed) == 1 and listed[0].seq == 1
        assert store.get(record["object_key"]) == payload
        duplicate = store.put_entry(device, entry("100_200.enc.opus"))
        assert duplicate["status"] == "duplicate"
        assert duplicate["object_key"] == record["object_key"]
        fresh = store.put_entry(device, entry("300_400.enc.opus", make_enpt(b"n" * 40)))
        assert fresh["status"] == "stored"
        assert fresh["object_key"].startswith(st.canonical_device_key(device) + "/")
        assert store.digest(device)["count"] == 2
    print("ok legacy local records and blobs")


WORKER_HARNESS = r"""
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const [workerPath, migrationsDir, port] = process.argv.slice(2);
const { default: worker } = await import(pathToFileURL(workerPath).href);
const raw = new DatabaseSync(':memory:');
for (const name of fs.readdirSync(migrationsDir).sort()) {
  raw.exec(fs.readFileSync(path.join(migrationsDir, name), 'utf8'));
}
class Statement {
  constructor(sql, params = []) { this.sql = sql; this.params = params; }
  bind(...params) { return new Statement(this.sql, params); }
  values() { return this.params.map((p) => (p === undefined ? null : p)); }
  async run() { raw.prepare(this.sql).run(...this.values()); return { success: true }; }
  async all() {
    return { success: true, results: raw.prepare(this.sql).all(...this.values()).map((r) => ({ ...r })) };
  }
  async first() { const { results } = await this.all(); return results[0] || null; }
}
const env = {
  DB: {
    prepare: (sql) => new Statement(sql),
    batch: async (statements) => {
      raw.exec('BEGIN');
      try {
        const out = [];
        for (const statement of statements) out.push(await statement.all());
        raw.exec('COMMIT');
        return out;
      } catch (err) { raw.exec('ROLLBACK'); throw err; }
    },
  },
  BUCKET: {
    objects: new Map(),
    async put(key, bytes) { this.objects.set(key, Buffer.from(bytes)); },
    async head(key) {
      const value = this.objects.get(key);
      return value ? { size: value.length } : null;
    },
    async get(key) {
      const value = this.objects.get(key);
      return value ? {
        size: value.length,
        body: value,
        arrayBuffer: async () => value.buffer.slice(
          value.byteOffset, value.byteOffset + value.byteLength),
      } : null;
    },
  },
  XINLIQIU_TOKEN: 'integration-token',
};
const server = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  const request = new Request(`http://127.0.0.1${req.url}`, {
    method: req.method,
    headers: req.headers,
    body: req.method === 'GET' || req.method === 'HEAD' ? undefined : body,
  });
  try {
    const response = await worker.fetch(request, env);
    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (err) {
    res.writeHead(500, { 'content-type': 'text/plain' });
    res.end(String(err && err.stack || err));
  }
});
server.listen(Number(port), '127.0.0.1', () => console.log('ready'));
"""


def test_python_client_against_real_worker(tmp_path: Path):
    """Loopback integration: Python client <-> actual Worker, mocked D1/R2."""
    import shutil
    import socket
    import subprocess

    node = shutil.which("node")
    if not node:
        print("skip python/worker integration (node unavailable)")
        return
    harness = tmp_path / "harness.mjs"
    harness.write_text(WORKER_HARNESS, encoding="utf-8")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen(
        [node, str(harness), str(ROOT / "cloudflare" / "src" / "index.js"),
         str(ROOT / "cloudflare" / "migrations"), str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        line = process.stdout.readline().strip()
        assert line == "ready", f"worker harness failed: {line} {process.stderr.read()}"
        client = st.CloudflareStorage(f"http://127.0.0.1:{port}", "integration-token", timeout=10)
        local = st.LocalStorage(tmp_path / "local")
        device = "设备/一"
        container = parse_cmpt(make_cmpt([
            ("100_200.enc.opus", make_enpt(b"a" * 40)),
            ("150.mark", make_enpt(b"m" * 40)),
            ("diag.tp", b'{"reason":2}'),
        ]))
        remote_counts = st.ingest_container(container, client, device)
        local_counts = st.ingest_container(container, local, device)
        assert remote_counts["stored"] == local_counts["stored"] == 2
        assert remote_counts["not_uploaded_count"] == local_counts["not_uploaded_count"] == 1
        assert st.ingest_container(container, client, device)["duplicates"] == 2
        remote_objects = client.list(device, 0, 1000)
        local_objects = local.list(device, 0, 1000)
        assert [o.object_key for o in remote_objects] == [o.object_key for o in local_objects]
        assert remote_objects[0].start_ms == local_objects[0].start_ms == 100
        # Page both backends one object at a time: identical order and cursors.
        remote_page = client.list_page(device, 0, 1000, limit=1)
        local_page = local.list_page(device, 0, 1000, limit=1)
        assert remote_page["next_cursor"] == local_page["next_cursor"]
        assert remote_page["has_more"] is local_page["has_more"] is True
        remote_digest = client.digest(device)
        local_digest = local.digest(device)
        assert remote_digest["digest"] == local_digest["digest"]
        assert remote_digest["latest_seq"] == local_digest["latest_seq"] == 2
        assert remote_digest["device_key"] == local_digest["device_key"]
        assert sync_mod.compare(client, device, local_digest)["in_sync"] is True
        mirror = tmp_path / "mirror"
        pulled = sync_mod.pull_changes(client, device, download=True, local_dir=mirror)
        assert pulled["cursor"] == 2 and len(pulled["written"]) == 2
        for obj in remote_objects:
            mirrored = mirror / sync_mod._local_name(obj.object_key)
            assert mirrored.read_bytes() == local.get(obj.object_key)
        print("ok python client against real worker")
    finally:
        process.kill()
        process.wait()


def run() -> int:
    import inspect
    import tempfile

    candidates = [
        (name, obj) for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj) and not inspect.iscoroutine(obj)
    ]
    failures = 0
    ran = 0
    for name, fn in candidates:
        ran += 1
        try:
            if inspect.signature(fn).parameters:
                with tempfile.TemporaryDirectory() as tmp:
                    fn(Path(tmp))
            else:
                fn()
        except Exception as exc:  # noqa: BLE001 - report every failure
            failures += 1
            import traceback

            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
            traceback.print_exc()
    print(f"\n{ran - failures}/{ran} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
