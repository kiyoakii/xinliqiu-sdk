# -*- coding: utf-8 -*-
"""Offline test suite. No device, no network, no keys."""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

import aipin_sdk as hb
from aipin_sdk import oggopus


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


def make_enpt(payload: bytes = b"x" * 40) -> bytes:
    head = b"enpt" + struct.pack("<HH", 256, 12) + b"\x00" * 256 + b"\x00" * 12
    head += struct.pack("<H", 0x0118) + bytes([1, 0])
    trailer = b"\x00" * 16 + struct.pack("<HH", 16, 24) + b"enpt"
    return head + payload + trailer


def test_capabilities_shape():
    caps = hb.Xinliqiu.capabilities()
    assert "CNMABWC301" in caps["device"]
    assert caps["implementation_validation"] == (
        "offline suites plus scoped tested-device acceptance: pair, status, inventory, "
        "sync/multi-range/zero-width, voiceprint, record start/stop, INIT with matching "
        "readback, post-INIT authenticated audio, storage mirror and whole-file recovery; "
        "live Cloudflare deployment not tested"
    )
    unavailable = {c["name"] for c in caps["statuses"]["unavailable"]}
    assert "mark.add" in unavailable
    assert all(c["note"] for c in caps["statuses"]["unavailable"])
    supported = {c["name"]: c for c in caps["statuses"]["supported"]}
    bounded = {c["name"]: c for c in caps["statuses"]["bounded"]}
    assert supported["record.vad_gated_audio"]["evidence"] == "tested-device"
    assert bounded["record.silence_retention"]["evidence"] == "tested-device"
    assert bounded["key.ai_manual"]["evidence"] == "tested-device"
    assert bounded["device.init_owner_key"]["evidence"] == "tested-device"
    assert "second short press stops" in bounded["key.ai_manual"]["note"]
    print("ok capabilities")


def test_require_capability_blocks_unavailable():
    try:
        hb.Xinliqiu.require_capability("mark.add")
    except hb.Unsupported as exc:
        assert "no established SDK path on the tested setup" in str(exc)
    else:
        raise AssertionError("mark.add should be refused")
    hb.Xinliqiu.require_capability("record.status")
    print("ok require_capability")


def test_parse_cmpt_roundtrip():
    audio = make_enpt(b"a" * 80)
    marker = make_enpt(b"m" * 40)
    data = make_cmpt([("1000-2000.enc.opus", audio), ("3000-3100.end.enc.opus", marker)])
    container = hb.parse_cmpt(data)
    assert len(container.entries) == 2
    assert container.entries[0].kind == "audio"
    assert container.entries[1].kind == "end-marker"
    assert container.entries[0].size == len(audio)
    assert len(container.by_kind("audio")) == 1
    print("ok parse_cmpt")


def test_parse_cmpt_rejects_bad_magic():
    try:
        hb.parse_cmpt(b"XXXX" + b"\x00" * 20)
    except hb.ContainerError:
        pass
    else:
        raise AssertionError("bad magic accepted")
    print("ok parse_cmpt rejects bad magic")


def test_parse_enpt_fields():
    info = hb.parse_enpt(make_enpt(b"z" * 40))
    assert info.wrapped_key_length == 256
    assert info.nonce_length == 12
    assert info.public_key_version == 1
    assert info.plaintext_length == 40
    assert len(info.tag) == 16
    print("ok parse_enpt")


def test_opus_layout():
    layout = hb.OpusLayout()
    payload = b"\x00" * 200
    assert layout.packet_count(payload) == 5
    assert abs(layout.duration_seconds(payload) - 0.1) < 1e-9
    try:
        layout.packet_count(b"\x00" * 41)
    except hb.ContainerError:
        pass
    else:
        raise AssertionError("misaligned payload accepted")
    print("ok opus layout")


def test_ogg_muxer():
    ogg = oggopus.encode(b"\x00" * 120, packet_bytes=40)
    assert ogg.startswith(b"OggS")
    assert b"OpusHead" in ogg
    assert b"OpusTags" in ogg
    try:
        oggopus.encode(b"\x00" * 41, packet_bytes=40)
    except ValueError:
        pass
    else:
        raise AssertionError("misaligned payload accepted by muxer")
    print("ok ogg muxer")


def test_local_storage_roundtrip(tmp_path: Path):
    storage = hb.LocalStorage(tmp_path / "store")
    entry = hb.parse_cmpt(make_cmpt([("100-200.enc.opus", make_enpt(b"q" * 40))])).entries[0]
    first = storage.put_entry("dev1", entry)
    assert first["status"] == "stored"
    second = storage.put_entry("dev1", entry)
    assert second["status"] == "duplicate"
    listed = storage.list("dev1", 0, 10_000)
    assert len(listed) == 1
    assert listed[0].kind == "audio"
    assert storage.get(first["object_key"]) == entry.payload
    print("ok local storage")


def test_sync_helpers(tmp_path: Path):
    """pull_changes must work against a fake incremental store."""
    from aipin_sdk.sync import pull_changes as pc

    class FakeStore:
        def __init__(self):
            self.data = {}
            self.seq = 0
            self.blobs = {}

        def put_entry(self, device_id, entry):
            self.seq += 1
            key = f"{device_id}/{entry.index}"
            self.data[key] = hb.StoredObject(
                object_key=key, entry_name=entry.name, kind=entry.kind,
                size_bytes=len(entry.payload), sha256="0" * 64, start_ms=None, end_ms=None,
            )
            self.blobs[key] = entry.payload
            return {"status": "stored", "seq": self.seq}

        def changes(self, device_id, since=0, limit=500):
            items = list(self.data.values())[since:since + limit]
            return {"objects": items, "cursor": since + len(items), "has_more": False}

        def get(self, key):
            return self.blobs[key]

    store = FakeStore()
    container = hb.parse_cmpt(make_cmpt([("1-2.enc.opus", make_enpt(b"a" * 40))]))
    hb.ingest_container(container, store, "dev")
    result = pc(store, "dev", since=0)
    assert result["count"] == 1
    assert result["objects"][0]["kind"] == "audio"
    print("ok pull_changes")

def test_cli_sync_store_uses_shared_ingestion_and_stable_identity(tmp_path: Path):
    """CMPT, direct enpt and JSONL share one upload path and one stable ID."""
    import contextlib
    import io
    import os
    from unittest import mock

    from aipin_sdk import cli

    out = tmp_path / "captures"
    out.mkdir()
    cmpt_path = out / "container.any-suffix"
    cmpt_path.write_bytes(make_cmpt([
        ("100_200.enc.opus", make_enpt(b"a" * 40)),
        ("150.mark", make_enpt(b"m" * 40)),
    ]))
    direct_path = out / "300_400.end.enc.opus"
    direct_path.write_bytes(make_enpt(b"e" * 40))
    diagnostic_path = out / "diagnostics"
    diagnostic_path.write_text('{"reason":2}\n', encoding="utf-8")
    pairing_path = tmp_path / "pairing.json"
    pairing_path.write_text(json.dumps({"providerDeviceIdHex": "010203040506"}))

    class FakeCredentials:
        device_id = "HOST-BLE-UUID"
        key_file = pairing_path

    class FakeBall:
        credentials = FakeCredentials()

        def sync_range(self, start, end, output_dir, *, seconds):
            assert (start, end) == (0, 1000)
            return {
                "state": "range_completed", "ok": True, "verified": True,
                "files": [str(cmpt_path), str(direct_path), str(diagnostic_path)],
                "count": 3, "bytes": 0, "offers": 3, "rejected": [],
                "retry": "none needed", "_output_dir": str(out),
            }

    args = cli.build_parser().parse_args([
        "sync", "0", "1000", "--store", "local",
        "--store-path", str(tmp_path / "store"),
    ])
    stdout = io.StringIO()
    with mock.patch.object(cli, "_client", return_value=FakeBall()), \
            mock.patch.dict(os.environ, {
                "XINLIQIU_CONFIG": str(tmp_path / "no-config.json"),
                "XINLIQIU_STORAGE_DEVICE_ID": "",
            }), contextlib.redirect_stdout(stdout):
        assert cli.cmd_sync(args) == 0
    summary = json.loads(stdout.getvalue())
    assert summary["verified"] is True and summary["range_complete"] is True
    store = summary["store"]
    assert store["stored"] == 3 and store["duplicates"] == 0
    assert store["containers"] == 1 and store["direct_enpt"] == 1
    assert store["not_uploaded_count"] == 1
    assert store["not_uploaded"][0]["kind"] == "jsonl"
    identity = store["storage_identity"]
    assert identity["source"] == "pairing-derived" and identity["stable"] is True
    assert identity["device_id"].startswith("pd-")
    assert identity["device_id"] != "HOST-BLE-UUID"
    stored = hb.LocalStorage(tmp_path / "store").list(identity["device_id"], 0, 1000)
    assert {item.kind for item in stored} == {"audio", "mark", "end-marker"}

    pairing_path.write_text("{}", encoding="utf-8")
    class NoIdentityBall(FakeBall):
        called = False
        def sync_range(self, *args, **kwargs):
            self.called = True
            raise AssertionError("sync ran without a stable storage identity")
    with mock.patch.object(cli, "_client", return_value=NoIdentityBall()), \
            mock.patch.dict(os.environ, {
                "XINLIQIU_CONFIG": str(tmp_path / "no-config.json"),
                "XINLIQIU_STORAGE_DEVICE_ID": "",
            }):
        try:
            cli.cmd_sync(args)
        except cli.CliError as exc:
            assert "stable storage identity" in str(exc)
        else:
            raise AssertionError("CLI silently used the BLE UUID as storage identity")
    print("ok CLI sync store uses shared ingestion and stable identity")


def test_cli_version_flag():
    import contextlib
    import io
    from aipin_sdk import cli

    stdout = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout):
            cli.build_parser().parse_args(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("--version did not exit")
    assert "0.2.1" in stdout.getvalue()
    print("ok CLI --version")


def test_doctor_reports_missing(tmp_path: Path):
    result = hb.doctor("dev-1", None, None)
    assert result["ready"] is False
    names = {c["check"] for c in result["checks"]}
    assert {"device_id", "peer_id_file", "key_file"} <= names
    print("ok doctor reports missing")


def _real_pairing_file(path: Path) -> Path:
    """A key file shaped like the one `pair` actually writes."""
    import os as _os
    from aipin_sdk.protocol import provision as proto_provision
    from aipin_sdk.protocol.auth import Pairing

    pairing = Pairing(
        ksc=_os.urandom(16), alias=_os.urandom(6),
        seeker_id=_os.urandom(6), provider_id=_os.urandom(6),
    )
    proto_provision.save_pairing(pairing, path)
    return path


def test_doctor_ready_with_files(tmp_path: Path):
    peer = tmp_path / "peer-id.txt"
    peer.write_text(hb.generate_peer_id(), encoding="utf-8")
    key = _real_pairing_file(tmp_path / "key.json")
    result = hb.doctor("dev-1", peer, key)
    assert result["ready"] is True, result
    print("ok doctor ready")


def test_doctor_rejects_an_unusable_key_file(tmp_path: Path):
    """A JSON object that lacks the pairing fields is not a credential."""
    peer = tmp_path / "peer-id.txt"
    peer.write_text(hb.generate_peer_id(), encoding="utf-8")
    key = tmp_path / "key.json"
    key.write_text(json.dumps({"k": 1}), encoding="utf-8")
    result = hb.doctor("dev-1", peer, key)
    assert result["ready"] is False, result
    print("ok doctor rejects an unusable key file")


def test_peer_id_shape():
    pid = hb.generate_peer_id()
    assert len(pid) == 36, f"peer id must be 36 characters, got {len(pid)}: {pid!r}"
    assert pid.startswith("OAFP_"), pid
    assert all(32 <= ord(c) < 127 for c in pid), "peer id must be printable ASCII"
    assert hb.generate_peer_id() != pid, "peer id must not repeat"
    print("ok peer id shape")


def test_peer_id_validation_rejects_bad_values():
    from aipin_sdk.protocol import provision

    good = hb.generate_peer_id()
    assert provision.validate_peer_id(good) == good

    for bad in (good + "x", good[:-1], "XXXX_" + good[5:], good[:10] + "\x7f" + good[11:]):
        try:
            provision.validate_peer_id(bad)
        except provision.ProvisionError:
            continue
        raise AssertionError(f"peer id {bad!r} was accepted")
    print("ok peer id validation")


def test_pair_refuses_overwrite(tmp_path: Path):
    from aipin_sdk.protocol import provision

    out = tmp_path / "creds"
    out.mkdir()
    (out / "pairing.json").write_text("{}", encoding="utf-8")
    # The existing-file check runs before any link is touched, so a None session
    # proves the guard fires first.
    try:
        provision.pair(None, out_dir=out)
    except provision.ProvisionError as exc:
        assert "already exists" in str(exc), str(exc)
    else:
        raise AssertionError("pair overwrote existing pairing material")
    print("ok pair refuses overwrite")


def test_pairing_roundtrip(tmp_path: Path):
    import os as _os
    from aipin_sdk.protocol import provision
    from aipin_sdk.protocol.auth import Pairing

    pairing = Pairing(
        ksc=_os.urandom(16), alias=_os.urandom(6),
        seeker_id=_os.urandom(6), provider_id=_os.urandom(6),
    )
    path = tmp_path / "pairing.json"
    provision.save_pairing(pairing, path)
    assert oct(path.stat().st_mode & 0o777) == "0o600", "pairing file must be private"

    loaded = provision.load_pairing(path)
    assert loaded == pairing, "pairing material did not survive a round trip"

    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    try:
        provision.load_pairing(tmp_path / "broken.json")
    except provision.ProvisionError:
        pass
    else:
        raise AssertionError("malformed pairing file was accepted")
    print("ok pairing roundtrip and 0600 permissions")


def test_sync_receiver_accepts_and_writes_a_file(tmp_path: Path):
    """The file-stream state machine, exercised without Bluetooth."""
    import hashlib
    import json
    from aipin_sdk.protocol import sync, systemft

    receiver = sync.SyncReceiver(tmp_path / "files")

    def service_request(channels):
        """Mirror the service request layout: parallel arrays, ; profile."""
        sessions = [session for _channel, session in channels]
        channel_ids = [channel for channel, _session in channels]
        out = bytearray([sync.SERVICE_REQUEST_TYPE])
        out += (5).to_bytes(2, "big")
        out += (43).to_bytes(2, "big")
        out += b"system:filetransfer" + bytes([0x3B])
        out += len(channels).to_bytes(2, "big")
        for session in sessions:
            out += session.to_bytes(2, "big")
        for channel in channel_ids:
            out += channel.to_bytes(2, "big")
        for _ in channels:
            out += bytes([0x09, 0x02])
        for _ in channels:
            out.append(0x00)
        return bytes(out)

    accept = receiver.feed(1, service_request([(100, 34), (101, 35)]))
    assert accept is not None and accept[0] == sync.SERVICE_ACCEPT_TYPE
    assert receiver.channels.control_session == 34
    assert receiver.channels.data_channels == {101}

    payload = b"recording bytes" * 5
    digest = hashlib.md5(payload).hexdigest()
    offer = json.dumps({
        "msgId": "filetransfer-setup-req", "transId": 3,
        "fileName": "a.enc.opus", "filePath": "/oplus_record/opus/a.enc.opus",
        "fileSize": len(payload), "peerId": "p", "containerId": "1",
        "channelId": "101", "md5": digest,
    }).encode()
    reply = receiver.feed(34, systemft.wrap_control(offer))
    assert json.loads(reply)["result"] == 0, "setup was not accepted"

    receiver.feed(35, bytes([systemft.PLAIN_CHANNEL_FLAG]) + systemft.wrap_chunk(payload))
    staged = tmp_path / "files" / "a.enc.opus.part"
    written = tmp_path / "files" / "a.enc.opus"
    assert not written.exists(), "data alone must not publish the final name"
    assert staged.exists() and staged.read_bytes() == payload
    assert receiver.result.bytes_received == len(payload)
    assert receiver.result.files == []

    receiver.feed(34, systemft.wrap_control(json.dumps({
        "msgId": "filetransfer-complete-rsp", "transId": 3,
        "result": 0, "reason": 0,
    }).encode()))
    assert written.read_bytes() == payload
    assert not staged.exists()
    assert receiver.result.files == [written]
    assert receiver.finished
    print("ok sync receiver writes and completes a file")


def test_sync_receiver_rejects_a_corrupt_file(tmp_path: Path):
    import json
    from aipin_sdk.protocol import sync, systemft

    receiver = sync.SyncReceiver(tmp_path / "files")
    request = bytearray([sync.SERVICE_REQUEST_TYPE])
    request += (5).to_bytes(2, "big") + (43).to_bytes(2, "big")
    request += b"system:filetransfer" + bytes([0x3B])
    request += (1).to_bytes(2, "big")
    request += (34).to_bytes(2, "big")   # the only session offered
    request += (100).to_bytes(2, "big")  # and it is the control channel
    request += bytes([0x09, 0x02, 0x00])
    receiver.feed(1, bytes(request))
    offer = json.dumps({
        "msgId": "filetransfer-setup-req", "transId": 4,
        "fileName": "bad.bin", "filePath": "/x/bad.bin", "fileSize": 4,
        "peerId": "p", "containerId": "1", "channelId": "100",
    }).encode()
    # channelId 100 is the control channel, not a data channel
    reply = receiver.feed(34, systemft.wrap_control(offer))
    assert json.loads(reply)["result"] == 1, "a bad channel was accepted"
    print("ok sync receiver rejects an unusable channel")


def test_sync_receiver_rejects_overflow(tmp_path: Path):
    """More bytes than the setup declared must abort, not truncate silently."""
    import json
    from aipin_sdk.protocol import sync, systemft

    receiver = sync.SyncReceiver(tmp_path / "files")
    request = bytearray([sync.SERVICE_REQUEST_TYPE])
    request += (5).to_bytes(2, "big") + (43).to_bytes(2, "big")
    request += b"system:filetransfer" + bytes([0x3B])
    request += (2).to_bytes(2, "big")
    request += (34).to_bytes(2, "big") + (35).to_bytes(2, "big")
    request += (100).to_bytes(2, "big") + (101).to_bytes(2, "big")
    request += bytes([0x09, 0x02]) * 2
    request += bytes([0x00, 0x00])
    receiver.feed(1, bytes(request))

    offer = json.dumps({
        "msgId": "filetransfer-setup-req", "transId": 9,
        "fileName": "small.bin", "filePath": "/x/small.bin", "fileSize": 4,
        "peerId": "p", "containerId": "1", "channelId": "101",
    }).encode()
    assert json.loads(receiver.feed(34, systemft.wrap_control(offer)))["result"] == 0

    receiver.feed(35, bytes([systemft.PLAIN_CHANNEL_FLAG]) + systemft.wrap_chunk(b"12345678"))
    assert receiver.error is not None, "overflow was accepted"
    assert not (tmp_path / "files" / "small.bin").exists(), "oversized file was kept"
    print("ok sync receiver aborts on overflow")


def test_sync_receiver_honours_a_cancel(tmp_path: Path):
    import json
    from aipin_sdk.protocol import sync, systemft

    receiver = sync.SyncReceiver(tmp_path / "files")
    request = bytearray([sync.SERVICE_REQUEST_TYPE])
    request += (5).to_bytes(2, "big") + (43).to_bytes(2, "big")
    request += b"system:filetransfer" + bytes([0x3B])
    request += (2).to_bytes(2, "big")
    request += (34).to_bytes(2, "big") + (35).to_bytes(2, "big")
    request += (100).to_bytes(2, "big") + (101).to_bytes(2, "big")
    request += bytes([0x09, 0x02]) * 2
    request += bytes([0x00, 0x00])
    receiver.feed(1, bytes(request))

    offer = json.dumps({
        "msgId": "filetransfer-setup-req", "transId": 11,
        "fileName": "cancelled.bin", "filePath": "/x/c.bin", "fileSize": 100,
        "peerId": "p", "containerId": "1", "channelId": "101",
    }).encode()
    receiver.feed(34, systemft.wrap_control(offer))
    receiver.feed(35, bytes([systemft.PLAIN_CHANNEL_FLAG]) + systemft.wrap_chunk(b"partial"))

    receiver.feed(34, systemft.wrap_control(json.dumps({
        "msgId": "filetransfer-cancel-req", "transId": 11, "reason": 4,
    }).encode()))
    assert not (tmp_path / "files" / "cancelled.bin").exists(), "partial file survived a cancel"
    assert receiver.result.files == []
    print("ok sync receiver honours a cancel")


def test_sync_receiver_answers_a_type_1_after_seeding(tmp_path: Path):
    """A seeded receiver must still answer the device's service request.

    Regression: a receiver that adopted an already-open control session used to
    skip the type-2 accept, and the device's initiator then blocked forever
    without sending a single file.
    """
    from aipin_sdk.protocol import sync

    receiver = sync.SyncReceiver(tmp_path / "files", control_session=34)

    request = bytearray([sync.SERVICE_REQUEST_TYPE])
    request += (5).to_bytes(2, "big") + (43).to_bytes(2, "big")
    request += b"system:filetransfer" + bytes([0x3B])
    request += (3).to_bytes(2, "big")
    for session in (34, 35, 36):
        request += session.to_bytes(2, "big")
    for channel in (100, 101, 102):
        request += channel.to_bytes(2, "big")
    for _ in range(3):
        request += bytes([0x09, 0x02])
    for _ in range(3):
        request.append(0x00)

    reply = receiver.feed(1, bytes(request))
    assert reply is not None, "a type-1 was swallowed; the device would stall"
    assert reply[0] == sync.SERVICE_ACCEPT_TYPE
    assert receiver.service_acknowledged
    # the adopted control session survives, and the declared channels are merged
    assert receiver.channels.control_session == 34
    assert receiver.channels.data_channels == {101, 102}
    print("ok seeded receiver answers a type-1")


def test_sync_receiver_rejects_a_foreign_profile(tmp_path: Path):
    from aipin_sdk.protocol import sync

    receiver = sync.SyncReceiver(tmp_path / "files", control_session=34)
    request = bytearray([sync.SERVICE_REQUEST_TYPE])
    request += (5).to_bytes(2, "big") + (43).to_bytes(2, "big")
    request += b"jg.pipe.message" + bytes([0x3B])
    request += (1).to_bytes(2, "big") + (34).to_bytes(2, "big")
    request += (100).to_bytes(2, "big")
    request += bytes([0x09, 0x02, 0x00])

    try:
        receiver.feed(1, bytes(request))
    except sync.SyncError as exc:
        assert "system:filetransfer" in str(exc), str(exc)
    else:
        raise AssertionError("a foreign profile was accepted")
    print("ok sync receiver rejects a foreign profile")


def test_sync_receiver_does_not_overwrite_a_finished_file(tmp_path: Path):
    """Two containers with the same name must both survive.

    The device names a container after its time range, so overlapping sync
    windows deliver the same name twice. Overwriting would delete a completed
    transfer while still reporting success.
    """
    import json
    from aipin_sdk.protocol import sync, systemft

    def start(receiver):
        request = bytearray([sync.SERVICE_REQUEST_TYPE])
        request += (5).to_bytes(2, "big") + (43).to_bytes(2, "big")
        request += b"system:filetransfer" + bytes([0x3B])
        request += (2).to_bytes(2, "big")
        request += (34).to_bytes(2, "big") + (35).to_bytes(2, "big")
        request += (100).to_bytes(2, "big") + (101).to_bytes(2, "big")
        request += bytes([0x09, 0x02]) * 2
        request += bytes([0x00, 0x00])
        receiver.feed(1, bytes(request))

    receiver = sync.SyncReceiver(tmp_path / "files")
    start(receiver)

    def deliver(trans_id, payload):
        offer = json.dumps({
            "msgId": "filetransfer-setup-req", "transId": trans_id,
            "fileName": "same.compat", "filePath": "/x/same.compat",
            "fileSize": len(payload), "peerId": "p", "containerId": "1",
            "channelId": "101",
        }).encode()
        receiver.feed(34, systemft.wrap_control(offer))
        receiver.feed(35, bytes([systemft.PLAIN_CHANNEL_FLAG]) + systemft.wrap_chunk(payload))
        receiver.feed(34, systemft.wrap_control(json.dumps({
            "msgId": "filetransfer-complete-rsp", "transId": trans_id,
            "result": 0, "reason": 0,
        }).encode()))

    deliver(21, b"first payload")
    deliver(22, b"second payload")

    written = sorted(p.name for p in (tmp_path / "files").iterdir())
    assert written == ["same-2.compat", "same.compat"], written
    assert (tmp_path / "files" / "same.compat").read_bytes() == b"first payload"
    assert (tmp_path / "files" / "same-2.compat").read_bytes() == b"second payload"
    assert receiver.result.bytes_received == 27
    print("ok sync receiver keeps both files when names collide")


def test_storage_info_leaves_unverified_thresholds_unknown():
    ball = object.__new__(hb.Xinliqiu)
    ball.inventory_totals = lambda start, end: {
        "start_ms": start, "end_ms": end,
        "count": 2, "bytes": 123, "highlight_count": 0, "highlight_bytes": 0,
    }
    info = ball.storage_info(1, 2)
    assert info["start_ms"] == 1 and info["end_ms"] == 2
    assert info["free_bytes"] is None and info["total_bytes"] is None
    thresholds = info["thresholds"]
    assert thresholds["almost_full_below_free_bytes"] is None
    assert thresholds["delete_oldest_below_free_bytes"] is None
    assert thresholds["create_refused_below_free_bytes"] is None
    assert thresholds["status"] == "unverified"
    assert "Low-space thresholds are unverified" in info["note"]
    print("ok storage thresholds remain unverified")


def test_keygen_creates_private_key(tmp_path: Path):
    info = hb.generate_owner_key(tmp_path)
    key = Path(info["private_key"])
    assert key.exists(), "private key not written"
    mode = key.stat().st_mode & 0o777
    assert mode == 0o400, f"private key mode {oct(mode)} is too open"
    assert Path(info["public_key_spki"]).exists()
    assert "Back this file up" in info["warning"]
    print("ok keygen writes a 0400 private key and warns")


def test_keygen_refuses_overwrite(tmp_path: Path):
    hb.generate_owner_key(tmp_path)
    try:
        hb.generate_owner_key(tmp_path)
    except hb.XinliqiuError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("keygen replaced an existing key; that orphans every recording")
    print("ok keygen refuses overwrite")


def test_default_key_path_is_not_cwd():
    path = hb.default_owner_key_path()
    assert path.is_absolute(), f"default key path {path} is not absolute"
    assert Path.cwd() not in path.parents, f"default key path {path} sits inside a working directory"
    assert path.name == "owner.pem"
    print("ok default key path is outside the working directory")


def test_keycheck_reports_missing_and_valid(tmp_path: Path):
    hb.generate_owner_key(tmp_path)
    good = hb.verify_owner_key(tmp_path / "owner.pem")
    assert good["ok"] is True, good
    assert good["bits"] == 2048

    missing = hb.verify_owner_key(tmp_path / "nope.pem")
    assert missing["ok"] is False and missing["reason"] == "missing"
    print("ok keycheck reports valid and missing keys")


def _creds(tmp_path: Path):
    peer = tmp_path / "peer.txt"
    peer.write_text("x" * 36, encoding="utf-8")
    key = tmp_path / "key.json"
    key.write_text("{}", encoding="utf-8")
    return hb.Credentials("dev", peer, key)


def run() -> int:
    """Discover every ``test_*`` function and run it, counting exactly.

    A test that takes a parameter gets a fresh temporary directory. Counting is
    derived from what actually ran: a hard-coded total silently drifts away from
    the number of tests the moment one is added.
    """
    import inspect
    import tempfile

    candidates = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj) and not inspect.iscoroutine(obj)
    ]

    failures = 0
    ran = 0
    for name, fn in candidates:
        ran += 1
        try:
            parameters = inspect.signature(fn).parameters
            if parameters:
                with tempfile.TemporaryDirectory() as tmp:
                    fn(Path(tmp))
            else:
                fn()
        except Exception as exc:  # noqa: BLE001 - a test failure must not stop the run
            failures += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")

    print(f"\n{ran - failures}/{ran} passed")
    return 0 if failures == 0 else 1


# --- CMPT/enpt hostile-input regressions ------------------------------------


def _expect_container_error(label: str, call, *args, **kwargs) -> None:
    """Require ContainerError; any other exception type is the defect under test."""
    try:
        call(*args, **kwargs)
    except hb.ContainerError:
        return
    except Exception as exc:  # noqa: BLE001 - wrong exception type is a failure
        raise AssertionError(f"{label} raised {type(exc).__name__}: {exc}") from exc
    raise AssertionError(f"{label} was accepted")


def test_container_rejects_declared_length_mismatch():
    base = make_cmpt([("1-2.enc.opus", make_enpt(b"a" * 40))])
    for declared in (10_000_000, 1, len(base) + 1, len(base) - 1):
        data = bytearray(base)
        struct.pack_into("<I", data, 8, declared)
        try:
            hb.parse_cmpt(bytes(data))
        except hb.ContainerError as exc:
            text = str(exc)
            assert str(declared) in text, f"declared length missing from {text!r}"
            assert str(len(data)) in text, f"actual length missing from {text!r}"
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"declared={declared} raised {type(exc).__name__}: {exc}"
            ) from exc
        else:
            raise AssertionError(f"declared={declared} was accepted for {len(data)} bytes")
    print("ok container rejects declared-length mismatch")


def test_container_rejects_data_offset_outside_the_body():
    base = make_cmpt([("1-2.enc.opus", make_enpt(b"b" * 40))])
    count = struct.unpack_from("<H", base, 4)[0]
    table_end = 12 + count * 68
    for data_off in (0, 11, table_end - 1, len(base) + 1):
        data = bytearray(base)
        struct.pack_into("<H", data, 6, data_off)
        _expect_container_error(
            f"cmpt data_offset={data_off}", hb.parse_cmpt, bytes(data)
        )
    # With zero entries the body must still start inside the file.
    empty = b"CMPT" + struct.pack("<HHI", 0, 13, 12)
    _expect_container_error("empty cmpt data_offset=13", hb.parse_cmpt, empty)
    print("ok container rejects data_offset outside the body")


def test_container_rejects_unexpected_enpt_key_and_nonce_lengths():
    base = make_enpt(b"x" * 40)
    for key_len, nonce_len in (
        (5000, 12),
        (256, 5000),
        (0, 0),
        (255, 12),
        (256, 11),
        (65535, 65535),
    ):
        data = bytearray(base)
        struct.pack_into("<HH", data, 4, key_len, nonce_len)
        _expect_container_error(
            f"enpt key_len={key_len} nonce_len={nonce_len}", hb.parse_enpt, bytes(data)
        )
    print("ok container rejects bad enpt key/nonce lengths")


def test_container_rejects_truncated_enpt_without_index_error():
    base = make_enpt(b"x" * 40)
    # Every truncation, including one just past the header, must raise
    # ContainerError rather than IndexError or struct.error.
    for n in range(len(base)):
        _expect_container_error(f"enpt truncated to {n}", hb.parse_enpt, base[:n])
    _expect_container_error(
        "enpt hostile header", hb.parse_enpt, b"enpt" + b"\xff" * 400
    )
    print("ok container rejects truncated enpt")


def test_container_decrypt_enpt_rejects_non_pem_key():
    data = make_enpt(b"x" * 40)
    for pem in (
        b"",
        b"not a pem",
        "not a pem",
        "\ud800",
        b"-----BEGIN PRIVATE KEY-----\nnot base64\n-----END PRIVATE KEY-----\n",
    ):
        try:
            hb.decrypt_enpt(data, pem)
        except hb.DecryptError:
            continue
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"non-PEM key {pem!r} raised {type(exc).__name__}: {exc}"
            ) from exc
        raise AssertionError(f"non-PEM key {pem!r} was accepted")
    print("ok container decrypt rejects non-PEM key")


def test_container_rejects_hostile_cmpt_structure():
    base = make_cmpt([
        ("100-200.enc.opus", make_enpt(b"a" * 40)),
        ("300-400.end.enc.opus", make_enpt(b"b" * 40)),
    ])
    # An entry count that no file of this length can hold.
    data = bytearray(base)
    struct.pack_into("<H", data, 4, 0xFFFF)
    _expect_container_error("cmpt count overflow", hb.parse_cmpt, bytes(data))
    # An entry payload length that runs past the buffer.
    data = bytearray(base)
    struct.pack_into("<I", data, 12 + 64, 0xFFFFFFFF)
    _expect_container_error("cmpt entry size overflow", hb.parse_cmpt, bytes(data))
    # A truncated file whose declared length was not adjusted.
    _expect_container_error("cmpt truncated", hb.parse_cmpt, base[:-1])
    # A body offset that points into the entry table.
    data = bytearray(base)
    struct.pack_into("<H", data, 6, 12)
    _expect_container_error("cmpt body over table", hb.parse_cmpt, bytes(data))
    print("ok container rejects hostile CMPT structures")


# --- sync receiver regressions ---------------------------------------------


def _sync_open_service(tmp_path: Path, channels=((100, 34), (101, 35), (102, 36))):
    """A receiver with the file service open and those channels declared."""
    from aipin_sdk.protocol import sync

    receiver = sync.SyncReceiver(tmp_path / "files")
    request = bytearray([sync.SERVICE_REQUEST_TYPE])
    request += (5).to_bytes(2, "big") + (43).to_bytes(2, "big")
    request += b"system:filetransfer" + bytes([0x3B])
    request += len(channels).to_bytes(2, "big")
    for _channel, session in channels:
        request += session.to_bytes(2, "big")
    for channel, _session in channels:
        request += channel.to_bytes(2, "big")
    for _ in channels:
        request += bytes([0x09, 0x02])
    for _ in channels:
        request.append(0x00)
    reply = receiver.feed(1, bytes(request))
    assert reply is not None and reply[0] == sync.SERVICE_ACCEPT_TYPE
    return receiver


def _sync_offer(
    receiver,
    trans_id: int,
    name: str,
    payload: bytes,
    *,
    channel: int = 101,
    md5=None,
    file_size=None,
):
    """Send a setup offer on the control session and return the reply."""
    import hashlib
    import json

    from aipin_sdk.protocol import systemft

    if md5 is None:
        md5 = hashlib.md5(payload).hexdigest()
    offer = {
        "msgId": "filetransfer-setup-req",
        "transId": trans_id,
        "fileName": name,
        "filePath": f"/x/{name}",
        "fileSize": len(payload) if file_size is None else file_size,
        "peerId": "p",
        "containerId": "1",
        "channelId": str(channel),
        "md5": md5,
    }
    return receiver.feed(34, systemft.wrap_control(json.dumps(offer).encode()))


def _sync_chunk(receiver, session_id: int, data: bytes):
    """Send one plain data frame on a data session."""
    from aipin_sdk.protocol import systemft

    body = bytes([systemft.PLAIN_CHANNEL_FLAG]) + systemft.wrap_chunk(data)
    return receiver.feed(session_id, body)


def _sync_complete(receiver, trans_id: int, result: int = 0):
    """Answer a pending complete-req on the control session."""
    import json

    from aipin_sdk.protocol import systemft

    body = json.dumps({
        "msgId": "filetransfer-complete-rsp", "transId": trans_id,
        "result": result, "reason": 0,
    }).encode()
    return receiver.feed(34, systemft.wrap_control(body))


def test_sync_receiver_blocks_a_dangling_symlink(tmp_path: Path):
    """A dangling link at a file name must not redirect a write outside.

    ``Path.exists`` follows links, so the planted link looks free; the receiver
    must notice it with ``lexists`` and take the next name.
    """
    import json
    import os

    from aipin_sdk.protocol import systemft

    out = tmp_path / "files"
    out.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "escaped.bin"
    os.symlink(target, out / "evil.bin")  # dangling: the target does not exist

    receiver = _sync_open_service(tmp_path)
    payload = b"payload that must stay inside"
    assert json.loads(_sync_offer(receiver, 1, "evil.bin", payload))["result"] == 0
    _sync_chunk(receiver, 35, payload)
    assert not (out / "evil-2.bin").exists(), "data alone published the file"
    _sync_complete(receiver, 1)

    assert not target.exists(), "a dangling symlink redirected the write outside"
    assert [p.name for p in receiver.result.files] == ["evil-2.bin"]
    assert (out / "evil-2.bin").read_bytes() == payload
    print("ok sync receiver blocks a dangling symlink")


def test_sync_receiver_leaves_no_part_on_failure(tmp_path: Path):
    """A failed digest must remove the final name and the staging file."""
    import hashlib
    import json

    out = tmp_path / "files"
    receiver = _sync_open_service(tmp_path)
    payload = b"0123456789abcdef"
    wrong = hashlib.md5(b"different bytes").hexdigest()
    reply = _sync_offer(receiver, 1, "broken.bin", payload, md5=wrong)
    assert json.loads(reply)["result"] == 0

    _sync_chunk(receiver, 35, payload[:8])
    part = out / "broken.bin.part"
    assert part.exists(), "bytes were not staged in a .part file"
    assert not (out / "broken.bin").exists(), "the final name was written early"

    _sync_chunk(receiver, 35, payload[8:])
    assert receiver.error and "MD5" in receiver.error, receiver.error
    assert not part.exists(), ".part survived a failed digest"
    assert not (out / "broken.bin").exists(), "an unverified file was published"
    assert receiver.result.files == []
    print("ok sync receiver leaves no .part on failure")


def test_sync_receiver_attributes_two_inflight_transfers(tmp_path: Path):
    """A learned binding wins, and ambiguity is dropped instead of guessed."""
    import json

    receiver = _sync_open_service(tmp_path, channels=((100, 34),))
    first = b"AAAA" + b"BBBBBB"
    second = b"CCCCCCCC"
    assert json.loads(
        _sync_offer(receiver, 1, "a.enc.opus", first, channel=101)
    )["result"] == 0

    # Only one file in flight: this unannounced session is learned for it.
    _sync_chunk(receiver, 35, first[:4])
    assert receiver.files[1].received == 4
    assert receiver.session_channels[35] == 101

    assert json.loads(
        _sync_offer(receiver, 2, "b.enc.opus", second, channel=102)
    )["result"] == 0

    # Two in flight: a new session cannot be attributed to either file, so it
    # must be dropped. Guessing used to append file 2's bytes to file 1.
    _sync_chunk(receiver, 36, second)
    assert receiver.files[1].received == 4, "a dropped frame reached the wrong file"
    assert receiver.files[2].received == 0
    assert receiver.result.anomalies == 1
    assert receiver.error is None

    # The learned binding still routes the rest of file 1 to file 1. Its final
    # name remains unpublished until the peer confirms the transaction.
    _sync_chunk(receiver, 35, first[4:])
    assert not (tmp_path / "files" / "a.enc.opus").exists()
    _sync_complete(receiver, 1)
    assert (tmp_path / "files" / "a.enc.opus").read_bytes() == first
    assert 1 not in receiver.files

    # With one transfer left, the reused session binds to it and completes.
    _sync_chunk(receiver, 36, second)
    assert not (tmp_path / "files" / "b.enc.opus").exists()
    _sync_complete(receiver, 2)
    assert (tmp_path / "files" / "b.enc.opus").read_bytes() == second
    assert receiver.result.files == [
        tmp_path / "files" / "a.enc.opus",
        tmp_path / "files" / "b.enc.opus",
    ]
    print("ok sync receiver attributes two in-flight transfers")


def test_sync_receiver_rejects_an_oversized_offer(tmp_path: Path):
    """An offer past MAX_FILE_BYTES is refused with a policy reason."""
    import json

    from aipin_sdk.protocol import sync, systemft

    receiver = _sync_open_service(tmp_path)
    reply = _sync_offer(
        receiver, 7, "huge.bin", b"", file_size=sync.MAX_FILE_BYTES + 1
    )
    body = json.loads(reply)
    assert body["result"] == 1
    assert body["reason"] == systemft.REASON_POLICY
    assert receiver.files == {}
    assert receiver.result.rejected_total == 1
    assert receiver.result.rejected == [(7, systemft.REASON_POLICY)]
    assert not any((tmp_path / "files").iterdir()), "a rejected offer created a file"

    # The limit is a ceiling, not a threshold: exactly MAX_FILE_BYTES is fine.
    reply = _sync_offer(
        receiver, 8, "edge.bin", b"", file_size=sync.MAX_FILE_BYTES
    )
    assert json.loads(reply)["result"] == 0
    print("ok sync receiver rejects an oversized offer")


def test_sync_receiver_rejects_a_bad_md5(tmp_path: Path):
    """A digest that is not 32 hex characters cannot be verified: reject it."""
    import json

    from aipin_sdk.protocol import systemft

    receiver = _sync_open_service(tmp_path)
    for index, bad in enumerate(("abc", "z" * 32, "0" * 31, "0" * 33), start=1):
        reply = _sync_offer(receiver, index, f"bad{index}.bin", b"data", md5=bad)
        body = json.loads(reply)
        assert body["result"] == 1, f"md5 {bad!r} was accepted"
        assert body["reason"] == systemft.REASON_SINK_FAILED
    assert receiver.files == {}
    assert not any((tmp_path / "files").iterdir()), "a rejected offer left bytes behind"

    # A well-formed digest is still accepted: those refusals are per-offer.
    body = json.loads(_sync_offer(receiver, 9, "good.bin", b"data"))
    assert body["result"] == 0
    print("ok sync receiver rejects a bad md5")


# -- local INIT (offline formatting + signature seam) -----------------------


def test_init_bind_challenge_and_slot_guard():
    """Parse the 02 0d payload, keep trailing bytes, and refuse slot 2."""
    from aipin_sdk.protocol import init

    nonce = bytes(range(16))
    device = bytes(range(12))
    payload = (
        b"\x01" + nonce + device + (60_000).to_bytes(4, "little") + b"\x01" + b"\xaa\xbb"
    )
    challenge = init.parse_bind_challenge(payload)
    assert challenge.version == 1
    assert challenge.nonce == nonce
    assert challenge.device_id == device
    assert challenge.ttl_ms == 60_000
    assert challenge.key_slot == init.LOCAL_KEY_SLOT
    assert challenge.trailing == b"\xaa\xbb"
    challenge.require_local_slot_one()

    # The TTL is a duration from the caller's clock, inclusive at zero and
    # exclusive at the advertised bound.
    challenge.require_fresh(100.0, 159.999)
    for now in (160.0, 99.999):
        try:
            challenge.require_fresh(100.0, now)
        except init.InitError:
            pass
        else:
            raise AssertionError(f"stale/negative challenge accepted at {now}")

    slot2 = payload[:33] + b"\x02" + b"\xaa\xbb"
    try:
        init.parse_bind_challenge(slot2)
    except init.InitError as exc:
        message = str(exc)
        assert "keySlot=2" in message
        assert "this implementation supports local INIT only for keySlot=1" in message
    else:
        raise AssertionError("keySlot=2 challenge was accepted")

    # A hand-built challenge cannot bypass the guard either.
    try:
        init.BindChallenge(
            version=1, nonce=nonce, device_id=device, ttl_ms=1, key_slot=2
        ).require_local_slot_one()
    except init.InitError:
        pass
    else:
        raise AssertionError("hand-built slot 2 passed require_local_slot_one")

    bad = {
        "short": payload[:33],
        "version": b"\x02" + payload[1:],
        "zero ttl": b"\x01" + nonce + device + b"\x00\x00\x00\x00" + b"\x01",
    }
    for label, raw in bad.items():
        try:
            init.parse_bind_challenge(raw)
        except init.InitError:
            pass
        else:
            raise AssertionError(f"bad challenge accepted: {label}")
    print("ok init bind challenge")


def test_init_tbs_and_token_are_byte_exact(tmp_path: Path):
    """The TBS layout is exact and the signature is raw r||s over it."""
    import hashlib

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    from aipin_sdk.protocol import init

    private_key = ec.generate_private_key(ec.SECP256R1())
    pem_path = tmp_path / "signer.pem"
    pem_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    der_path = tmp_path / "signer.der"
    der_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signer = init.Pkcs8Signer(pem_path)
    der_signer = init.Pkcs8Signer(der_path)
    assert isinstance(signer, init.Signer)
    assert signer.public_key_sha256_hex == der_signer.public_key_sha256_hex
    point = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert signer.public_key_sha256_hex == hashlib.sha256(point).hexdigest()

    nonce = bytes(range(16))
    device = bytes(range(12))
    payload = b"\x01" + nonce + device + (60_000).to_bytes(4, "little") + b"\x01"
    challenge = init.parse_bind_challenge(payload)
    account = "acct-1"
    key_hash = bytes(range(32))
    version = 7
    expiry = 1_700_000_300

    expected_tbs = (
        b"\x01\x01\x01"
        + device
        + nonce
        + expiry.to_bytes(8, "little")
        + b"\x06acct-1"
        + b"\x07"
        + key_hash
    )
    tbs = init.build_tbs(
        challenge,
        account=account,
        key_hash=key_hash,
        public_key_version=version,
        expiry_seconds=expiry,
    )
    assert tbs == expected_tbs
    assert len(tbs) == 73 + len(account)

    token = init.build_token(
        challenge,
        account=account,
        key_hash=key_hash,
        public_key_version=version,
        signer=signer,
        expiry_seconds=expiry,
    )
    assert len(token) == len(tbs) + init.TOKEN_SIGNATURE_BYTES
    assert token[: len(tbs)] == tbs
    raw = token[len(tbs):]
    assert len(raw) == 64
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    assert 0 < r < order and 0 < s < order
    private_key.public_key().verify(
        encode_dss_signature(r, s), tbs, ec.ECDSA(hashes.SHA256())
    )

    # A non-P-256 key and a relative external path are both refused.
    p384 = ec.generate_private_key(ec.SECP384R1())
    p384_path = tmp_path / "p384.pem"
    p384_path.write_bytes(
        p384.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    for bad_path, label in (
        (p384_path, "P-384 key"),
        (Path("signer.pem"), "relative key path"),
    ):
        try:
            init.Pkcs8Signer(bad_path)
        except init.InitError:
            pass
        else:
            raise AssertionError(f"signer accepted a {label}")
    print("ok init token")


def test_init_payload_round_trips_u16_lengths():
    """INIT type 1 is byte-exact and both u16 lengths survive a rebuild."""
    from aipin_sdk.protocol import init

    account = "acct-1"
    key_text = "A" * 300
    token = bytes(range(256)) + bytes(range(256)) + b"xyz"
    timestamp = 1_700_000_000_123
    version = 7

    payload = init.build_init_payload(
        timestamp_ms=timestamp,
        account=account,
        public_key_version=version,
        public_key=key_text,
        token=token,
    )
    expected = (
        b"\x01"
        + timestamp.to_bytes(8, "little")
        + b"\x06acct-1"
        + b"\x07"
        + (300).to_bytes(2, "little")
        + key_text.encode("ascii")
        + len(token).to_bytes(2, "little")
        + token
    )
    assert payload == expected
    assert payload[0] == init.INIT_TYPE
    assert int.from_bytes(payload[1:9], "little") == timestamp

    account_length = payload[9]
    assert account_length == 6
    assert payload[10 : 10 + account_length] == account.encode("ascii")
    offset = 10 + account_length
    assert payload[offset] == version
    key_length = int.from_bytes(payload[offset + 1 : offset + 3], "little")
    assert key_length == 300
    key_bytes = payload[offset + 3 : offset + 3 + key_length]
    assert key_bytes == key_text.encode("ascii")
    offset += 3 + key_length
    token_length = int.from_bytes(payload[offset : offset + 2], "little")
    assert token_length == len(token)
    assert payload[offset + 2 :] == token

    rebuilt = init.build_init_payload(
        timestamp_ms=int.from_bytes(payload[1:9], "little"),
        account=payload[10 : 10 + account_length],
        public_key_version=version,
        public_key=key_bytes,
        token=payload[offset + 2 :],
    )
    assert rebuilt == payload

    # Both u16 fields reach their ceiling without truncation.
    maximum = init.build_init_payload(
        timestamp_ms=(1 << 63) - 1,
        account="x" * init.MAX_ACCOUNT_BYTES,
        public_key_version=255,
        public_key=b"k" * init.MAX_PUBLIC_KEY_BYTES,
        token=b"t" * init.MAX_TOKEN_BYTES,
    )
    assert maximum[0] == init.INIT_TYPE
    assert int.from_bytes(maximum[1:9], "little") == (1 << 63) - 1
    key_length_at = 10 + init.MAX_ACCOUNT_BYTES + 1
    assert int.from_bytes(maximum[key_length_at : key_length_at + 2], "little") == 0xFFFF
    token_length_at = key_length_at + 2 + 0xFFFF
    assert int.from_bytes(maximum[token_length_at : token_length_at + 2], "little") == 0xFFFF
    assert len(maximum) == token_length_at + 2 + 0xFFFF

    base = dict(
        timestamp_ms=1,
        account="acct",
        public_key_version=1,
        public_key="pk",
        token=b"t",
    )
    refused = (
        {"timestamp_ms": -1},
        {"timestamp_ms": 1 << 63},
        {"account": ""},
        {"account": "x" * (init.MAX_ACCOUNT_BYTES + 1)},
        {"account": b"a\x00b"},
        {"public_key_version": 256},
        {"public_key_version": -1},
        {"public_key": b""},
        {"public_key": b"k" * (init.MAX_PUBLIC_KEY_BYTES + 1)},
        {"public_key": b"\xff"},
        {"token": b""},
        {"token": b"t" * (init.MAX_TOKEN_BYTES + 1)},
    )
    for change in refused:
        call = dict(base)
        call.update(change)
        try:
            init.build_init_payload(**call)
        except init.InitError:
            pass
        else:
            raise AssertionError(f"INIT payload accepted {change}")
    print("ok init payload")


def test_init_response_optional_key_tail():
    """Status/account/timestamp plus the optional key readback and short tail."""
    from aipin_sdk.protocol import init

    account = b"acct-1"
    key_text = b"PUBLIC-KEY-TEXT"
    rtc = 1_700_000_001_000
    head = b"\x02\x08\x01" + rtc.to_bytes(8, "little") + bytes([len(account)]) + account
    full_tail = bytes([7]) + len(key_text).to_bytes(2, "little") + key_text

    response = init.parse_init_response(
        head + full_tail,
        expected_account=account,
        expected_public_key=key_text,
        expected_public_key_version=7,
    )
    assert response.accepted
    assert response.status == 1
    assert response.timestamp_ms == rtc
    assert response.account == account
    assert response.account_matched
    assert response.public_key_version == 7
    assert response.public_key_matched is True
    assert response.trailing_bytes == 0

    # A key readback mismatch is diagnostic only in the reviewed reference.
    mismatch = init.parse_init_response(
        head + full_tail,
        expected_account=account,
        expected_public_key=b"other-key",
        expected_public_key_version=7,
    )
    assert mismatch.accepted and mismatch.public_key_matched is False
    version_mismatch = init.parse_init_response(
        head + full_tail,
        expected_account=account,
        expected_public_key=key_text,
        expected_public_key_version=8,
    )
    assert version_mismatch.accepted and version_mismatch.public_key_matched is False

    # Without the optional block, nothing is guessed.
    no_tail = init.parse_init_response(head, expected_account=account)
    assert no_tail.accepted
    assert no_tail.public_key_version is None
    assert no_tail.public_key_matched is None
    assert no_tail.trailing_bytes == 0

    # Fewer than three remaining bytes are an absent optional block, not a
    # truncated key: the reviewed parser counts them as trailing bytes.
    for extra in (b"\x07", b"\x07\x01"):
        short = init.parse_init_response(head + extra, expected_account=account)
        assert short.accepted
        assert short.public_key_version is None
        assert short.public_key_matched is None
        assert short.trailing_bytes == len(extra)

    with_trailing = init.parse_init_response(
        head + full_tail + b"\xde\xad",
        expected_account=account,
        expected_public_key=key_text,
        expected_public_key_version=7,
    )
    assert with_trailing.public_key_matched is True
    assert with_trailing.trailing_bytes == 2

    # Account mismatch and non-success status both refuse without raising.
    other = init.parse_init_response(head + full_tail, expected_account=b"other")
    assert not other.accepted and not other.account_matched
    error = init.parse_init_response(b"\x02\x08\x02\x00", expected_account=account)
    assert not error.accepted
    assert error.status == 2
    assert error.timestamp_ms is None and error.account is None
    assert error.trailing_bytes == 1

    # The caller may pass a payload after stripping 02 08.
    unframed = init.parse_init_response(
        (head + full_tail)[2:],
        expected_account=account,
        expected_public_key=key_text,
        expected_public_key_version=7,
        framed=False,
    )
    assert unframed.accepted and unframed.public_key_matched is True

    bad_responses = (
        b"\x05\x08\x01" + rtc.to_bytes(8, "little"),
        b"\x02\x08",
        b"\x02\x08\x01",
        b"\x02\x08\x01" + rtc.to_bytes(8, "little") + b"\x00",
        b"\x02\x08\x01" + rtc.to_bytes(8, "little") + b"\x01\xff",
        b"\x02\x08\x01"
        + rtc.to_bytes(8, "little")
        + bytes([len(account)])
        + account
        + b"\x07"
        + (10).to_bytes(2, "little")
        + b"short",
    )
    for raw in bad_responses:
        try:
            init.parse_init_response(raw, expected_account=account)
        except init.InitError:
            pass
        else:
            raise AssertionError(f"malformed INIT response accepted: {raw!r}")
    print("ok init response")


def test_init_owner_public_key_hash_and_validation(tmp_path: Path):
    """The v9.d key hash is over the text, and RSA-2048 SPKI is required."""
    import base64
    import hashlib

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    from aipin_sdk.protocol import init

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = rsa_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    text = base64.b64encode(der).decode("ascii")
    owner = init.OwnerPublicKey(text)
    assert owner.text == text
    assert owner.utf8 == text.encode("utf-8")
    assert owner.spki_der == der
    assert owner.key_hash == hashlib.sha256(text.encode("utf-8")).digest()
    assert owner.key_hash == init.owner_key_hash(text)
    assert owner.key_hash != hashlib.sha256(der).digest(), (
        "the wire key hash must be the text digest, not the DER digest"
    )
    assert owner.fingerprint == owner.key_hash.hex()

    path = tmp_path / "owner.txt"
    path.write_bytes(text.encode("ascii"))
    loaded = init.OwnerPublicKey.from_file(path)
    assert loaded.key_hash == owner.key_hash and loaded.spki_der == der

    newline_path = tmp_path / "newline.txt"
    newline_path.write_bytes(text.encode("ascii") + b"\n")
    long_path = tmp_path / "long.txt"
    long_path.write_bytes(b"A" * (init.MAX_OWNER_KEY_TEXT_BYTES + 1))
    for label, candidate in (
        ("whitespace", newline_path),
        ("relative", Path("owner.txt")),
        ("directory", tmp_path),
        ("too long", long_path),
    ):
        try:
            init.OwnerPublicKey.from_file(candidate)
        except init.InitError:
            pass
        else:
            raise AssertionError(f"owner key file accepted: {label}")

    # A well-formed P-256 SPKI is not an owner RSA SPKI.
    ec_text = base64.b64encode(
        ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")
    bad_texts = (
        "",
        "-----BEGIN PUBLIC KEY-----",
        text + "\n",
        "A" * (init.MAX_OWNER_KEY_TEXT_BYTES + 4),
        base64.b64encode(b"\x30\x00").decode("ascii"),
        ec_text,
    )
    for bad in bad_texts:
        try:
            init.OwnerPublicKey(bad)
        except init.InitError:
            pass
        else:
            raise AssertionError(f"owner key text accepted: {bad[:32]!r}")
    try:
        init.owner_key_hash(b"not text")
    except init.InitError:
        pass
    else:
        raise AssertionError("owner_key_hash accepted non-text input")
    print("ok init owner public key")


def test_init_synthetic_custom_signer():
    """A caller-supplied Signer produces and validates a synthetic raw signature."""
    import hashlib

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

    from aipin_sdk.protocol import init

    class SyntheticSigner:
        def __init__(self):
            self.key = ec.generate_private_key(ec.SECP256R1())
            point = self.key.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            self.public_key_sha256_hex = hashlib.sha256(point).hexdigest()
            self.calls = []

        def sign(self, tbs: bytes) -> bytes:
            self.calls.append(tbs)
            der = self.key.sign(tbs, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der)
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    signer = SyntheticSigner()
    assert isinstance(signer, init.Signer)
    challenge = init.BindChallenge(
        version=1,
        nonce=bytes(range(16)),
        device_id=bytes(range(12)),
        ttl_ms=60_000,
        key_slot=1,
    )
    token = init.build_token(
        challenge,
        account="synthetic",
        key_hash=bytes(range(32)),
        public_key_version=1,
        signer=signer,
        expiry_seconds=1_700_000_300,
    )
    expected_tbs = init.build_tbs(
        challenge,
        account="synthetic",
        key_hash=bytes(range(32)),
        public_key_version=1,
        expiry_seconds=1_700_000_300,
    )
    assert signer.calls == [expected_tbs]
    assert token[: len(expected_tbs)] == expected_tbs
    raw = token[len(expected_tbs):]
    assert len(raw) == 64
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    signer.key.public_key().verify(
        encode_dss_signature(r, s), expected_tbs, ec.ECDSA(hashes.SHA256())
    )

    class ShortSigner:
        public_key_sha256_hex = "0" * 64

        def sign(self, tbs: bytes) -> bytes:
            return b"\x00" * 63

    try:
        init.build_token(
            challenge,
            account="synthetic",
            key_hash=bytes(range(32)),
            public_key_version=1,
            signer=ShortSigner(),
            expiry_seconds=1_700_000_300,
        )
    except init.InitError as exc:
        assert "raw 64 bytes" in str(exc)
    else:
        raise AssertionError("a short custom signature was accepted")

    print("ok init synthetic custom signer")


if __name__ == "__main__":
    raise SystemExit(run())
