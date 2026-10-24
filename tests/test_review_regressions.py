# -*- coding: utf-8 -*-
"""Regression tests for the post-publication review findings.

Offline only: synthetic credentials, ciphertext-shaped buffers and an
in-memory device channel. Nothing here contacts a device or the network.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import types
from pathlib import Path

import pytest

from aipin_sdk import cli, doctor, generate_owner_key, generate_peer_id
from aipin_sdk import storage as st
from aipin_sdk.errors import XinliqiuError
from aipin_sdk.protocol import commands, provision
from aipin_sdk.protocol.auth import Pairing


def _enpt(payload: bytes = b"x" * 40) -> bytes:
    head = b"enpt" + struct.pack("<HH", 256, 12) + b"\x00" * 256 + b"\x00" * 12
    head += struct.pack("<H", 0x0118) + bytes([1, 0])
    trailer = b"\x00" * 16 + struct.pack("<HH", 16, 24) + b"enpt"
    return head + payload + trailer


def _pairing_file(path: Path) -> Path:
    provision.save_pairing(
        Pairing(
            ksc=os.urandom(16),
            alias=os.urandom(6),
            seeker_id=os.urandom(6),
            provider_id=os.urandom(6),
        ),
        path,
    )
    return path


def _credential_files(tmp_path: Path) -> tuple[Path, Path]:
    peer = tmp_path / "peer-id.txt"
    peer.write_text(generate_peer_id(), encoding="utf-8")
    return peer, _pairing_file(tmp_path / "pairing.json")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_common_flags_work_before_and_after_the_subcommand():
    parser = cli.build_parser()
    before = parser.parse_args(["--device", "D", "--key-file", "k", "status"])
    after = parser.parse_args(["status", "--device", "D", "--key-file", "k"])
    for args in (before, after):
        assert args.device == "D"
        assert args.key_file == "k"


def test_usage_errors_exit_1_instead_of_argparse_2():
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        code = cli.main(["status", "--not-a-real-option"])
    assert code == 1
    assert "unrecognized arguments" in stderr.getvalue()


def test_usage_error_before_a_subcommand_also_exits_1():
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        code = cli.main(["--not-a-real-option"])
    assert code == 1
    assert stderr.getvalue().strip()


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def test_doctor_ready_without_an_owner_key(tmp_path: Path):
    peer, key = _credential_files(tmp_path)
    result = doctor("dev-1", peer, key)
    checks = {c["check"]: c for c in result["checks"]}
    assert result["ready"] is True, result
    assert checks["pending_pairing"]["ok"] is True


def test_doctor_public_key_without_private_key_is_not_ready(tmp_path: Path):
    peer, key = _credential_files(tmp_path)
    owned = generate_owner_key(tmp_path / "owner")
    result = doctor(
        "dev-1", peer, key, owner_public_key=owned["public_key_spki"]
    )
    checks = {c["check"]: c for c in result["checks"]}
    assert result["ready"] is False
    assert checks["owner_key_matches_public"]["ok"] is False
    assert checks["owner_key"]["ok"] is False


def test_doctor_ready_with_matching_owner_key_and_public_key(tmp_path: Path):
    peer, key = _credential_files(tmp_path)
    owned = generate_owner_key(tmp_path / "owner")
    result = doctor(
        "dev-1",
        peer,
        key,
        owned["private_key"],
        owner_public_key=owned["public_key_spki"],
    )
    checks = {c["check"]: c for c in result["checks"]}
    assert result["ready"] is True, result
    assert checks["owner_key_matches_public"]["ok"] is True


def test_doctor_reports_a_mismatched_owner_public_key(tmp_path: Path):
    peer, key = _credential_files(tmp_path)
    mine = generate_owner_key(tmp_path / "mine")
    other = generate_owner_key(tmp_path / "other")
    result = doctor(
        "dev-1",
        peer,
        key,
        mine["private_key"],
        owner_public_key=other["public_key_spki"],
    )
    checks = {c["check"]: c for c in result["checks"]}
    assert result["ready"] is False
    assert checks["owner_key_matches_public"]["ok"] is False


# ---------------------------------------------------------------------------
# Inventory range
# ---------------------------------------------------------------------------


class _Channel:
    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.calls: list[tuple] = []

    def send_command(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.reply


def _totals_reply(start: int, end: int, count: int = 2, used: int = 123) -> bytes:
    payload = struct.pack("<QQIIII", start, end, count, used, 0, 0)
    return bytes(commands.STORAGE_REPLY_HEADER) + payload


def _device_ball(timestamp):
    from aipin_sdk.client import Xinliqiu

    ball = object.__new__(Xinliqiu)
    ball._read_status = lambda channel: types.SimpleNamespace(
        device_timestamp_ms=timestamp
    )
    return ball


def test_inventory_without_end_ms_uses_the_device_timestamp():
    ball = _device_ball(123_456)
    channel = _Channel(_totals_reply(0, 123_456))
    ball._with_channel = lambda worker: worker(channel)
    totals = ball.inventory_totals(0)
    assert totals["start_ms"] == 0
    assert totals["end_ms"] == 123_456
    assert totals["count"] == 2
    # One authenticated storage request, for exactly the device timestamp.
    assert len(channel.calls) == 1
    service, subcommand, payload = channel.calls[0][0]
    assert (service, subcommand) == (commands.SERVICE_STORAGE[0], commands.SERVICE_STORAGE[1])
    assert payload == commands.range_payload(0, 123_456)
    assert channel.calls[0][1]["require_authenticated"] is True


def test_inventory_refuses_a_device_without_a_timestamp():
    ball = _device_ball(None)
    ball._with_channel = lambda worker: worker(_Channel(b""))
    with pytest.raises(XinliqiuError, match="timestamp"):
        ball.inventory_totals(0)


# ---------------------------------------------------------------------------
# LocalStorage index repair and sequence stability
# ---------------------------------------------------------------------------


def _record(device: str, marker: str, seq: int, name: str = "100_200.enc.opus") -> dict:
    payload = _enpt(marker.encode())
    import hashlib

    return {
        "object_key": f"{device}/{hashlib.sha256(payload).hexdigest()}",
        "device_id": device,
        "device_key": st.canonical_device_key(device),
        "entry_name": name,
        "kind": "audio",
        "size_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "device_start_ms": 100,
        "device_end_ms": 200,
        "synced_at": 1,
        "seq": seq,
    }


def _write_index(store: st.LocalStorage, records: list[dict]) -> None:
    store.index_path.write_text(
        "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
    )


def test_repair_preserves_stored_sequences(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    _write_index(store, [_record("dev1", "a", 7), _record("dev1", "b", 3)])
    listed = store.list("dev1", 0, 10_000)
    assert sorted(obj.seq for obj in listed) == [3, 7]
    # A healthy index is not rewritten just because its seqs are not dense.
    assert store.last_repair["repaired"] == 0


def test_duplicate_sequences_are_renumbered_and_the_cursor_stays_complete(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    _write_index(store, [_record("dev1", "a", 5), _record("dev1", "b", 5)])
    listed = store.list("dev1", 0, 10_000)
    assert sorted(obj.seq for obj in listed) == [5, 6]
    assert store.last_repair["renumbered"] == 1
    # A cursor at 5 still returns the second object instead of skipping it.
    changes = store.changes("dev1", since=5)
    assert [obj.seq for obj in changes["objects"]] == [6]


def test_a_torn_line_is_repaired_without_losing_sequences(tmp_path: Path):
    store = st.LocalStorage(tmp_path / "store")
    raw = json.dumps(_record("dev1", "a", 9)) + "\n" + '{"torn":'
    store.index_path.write_text(raw, encoding="utf-8")
    listed = store.list("dev1", 0, 10_000)
    assert [obj.seq for obj in listed] == [9]
    assert store.last_repair["dropped_lines"] == 1


def test_index_append_retries_short_writes(tmp_path: Path, monkeypatch):
    store = st.LocalStorage(tmp_path / "store")
    real_write = os.write

    def short_write(fd, data):
        return real_write(fd, data[:3])

    monkeypatch.setattr(st.os, "write", short_write)
    result = store.put_entry("dev1", st.StorageItem(
        name="100_200.enc.opus", payload=_enpt(), kind="audio"
    ))
    assert result["status"] == "stored"
    monkeypatch.undo()
    lines = [line for line in store.index_path.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 1
    assert json.loads(lines[0])["seq"] == 1


# ---------------------------------------------------------------------------
# Unknown/diagnostic ingestion keeps the real bytes
# ---------------------------------------------------------------------------


def test_unknown_file_policy_encrypts_the_actual_bytes(tmp_path: Path):
    path = tmp_path / "mystery.dat"
    data = b"\x00\x01\x02 blind bytes \xff"
    path.write_bytes(data)
    store = st.LocalStorage(tmp_path / "store")
    seen: list[tuple[bytes, str]] = []

    def encrypt(plain: bytes, name: str) -> bytes:
        seen.append((plain, name))
        return b"CIPH" + plain

    policy = st.EncryptedDiagnosticPolicy(encrypt=encrypt, scheme="test")
    result = st.ingest_files([path], store, "dev1", diagnostic_policy=policy)
    assert result["stored"] == 1
    assert seen == [(data, "mystery.dat")]
    listed = store.list("dev1", 0, 10_000)
    assert len(listed) == 1
    assert listed[0].size_bytes == len(data) + 4
    assert store.get(listed[0].object_key) == b"CIPH" + data


def test_unknown_file_without_policy_reports_its_real_size(tmp_path: Path):
    path = tmp_path / "mystery.dat"
    data = b"\x00\x01\x02 blind bytes"
    path.write_bytes(data)
    store = st.LocalStorage(tmp_path / "store")
    result = st.ingest_files([path], store, "dev1")
    [skipped] = result["not_uploaded"]
    assert skipped["kind"] == "unknown"
    assert skipped["size_bytes"] == len(data)
    assert skipped["reason"] == "diagnostic-or-unknown-kept-local"


# ---------------------------------------------------------------------------
# Review follow-ups: legacy credentials, result shapes, publish durability
# ---------------------------------------------------------------------------


def test_doctor_accepts_legacy_pairing_key_names(tmp_path: Path):
    peer = tmp_path / "peer-id.txt"
    peer.write_text(generate_peer_id(), encoding="utf-8")
    canonical = _pairing_file(tmp_path / "pairing.json")
    data = json.loads(canonical.read_text(encoding="utf-8"))
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({
        "kscHex": data["kscHex"],
        "aliasHex": data["kscAliasHex"],
        "seekerIdHex": data["seekerIdHex"],
        "providerIdHex": data["providerDeviceIdHex"],
    }), encoding="utf-8")
    os.chmod(legacy, 0o600)
    result = doctor("dev-1", peer, legacy)
    checks = {c["check"]: c for c in result["checks"]}
    assert result["ready"] is True, result
    assert checks["key_file_json"]["ok"] is True


def test_doctor_accepts_the_pending_pairing_as_the_selected_key_file(tmp_path: Path):
    peer = tmp_path / "peer-id.txt"
    peer.write_text(generate_peer_id(), encoding="utf-8")
    pending = tmp_path / "pairing.pending.json"
    _pairing_file(pending)
    os.chmod(pending, 0o600)
    result = doctor("dev-1", peer, pending)
    checks = {c["check"]: c for c in result["checks"]}
    assert result["ready"] is True, result
    assert checks["pending_pairing"]["ok"] is True


def test_sync_range_reports_rejected_as_a_count_with_pair_details(tmp_path: Path):
    from aipin_sdk.client import Xinliqiu

    ball = object.__new__(Xinliqiu)
    ball._run_sync = lambda pairs, dirs, window: {
        "ranges": [{"state": "range_completed", "ok": True, "rejected": 2}],
        "rejected_pairs": [{"trans_id": 7, "reason": 1}],
        "rejected_total": 2,
    }
    result = ball.sync_range(0, 10, tmp_path)
    assert result["rejected"] == 2
    assert result["rejected_total"] == 2
    assert result["rejected_pairs"] == [{"trans_id": 7, "reason": 1}]


def test_publish_keeps_the_file_when_staging_unlink_fails(tmp_path: Path, monkeypatch):
    from aipin_sdk.protocol import systemft

    payload = b"synthetic recording bytes"
    request = systemft.SetupRequest(
        trans_id=1,
        file_name="100_200.enc.opus",
        file_path="/device/100_200.enc.opus",
        file_size=len(payload),
        peer_id="peer",
        container_id="container",
        channel_id="1",
    )
    incoming = systemft.IncomingFile(request=request, path=tmp_path / request.file_name)
    incoming.open()
    incoming.write(payload)
    incoming.seal()

    real_unlink = Path.unlink

    def failing_unlink(self, *args, **kwargs):
        if self.name.endswith(".part"):
            raise OSError("simulated cleanup failure")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", failing_unlink)
    published = incoming.publish()
    assert incoming.published is True
    assert published.read_bytes() == payload


def test_sync_without_a_range_fetches_up_to_the_device_clock(tmp_path: Path):
    from unittest import mock

    calls: list[tuple[int, int]] = []

    class Ball:
        def status(self):
            return types.SimpleNamespace(device_timestamp_ms=123_456)

        def sync_range(self, start, end, out, *, seconds=300):
            calls.append((start, end))
            return {"state": "range_completed", "ok": True, "files": []}

    args = cli.build_parser().parse_args(["sync", "--out", str(tmp_path)])
    with mock.patch.object(cli, "_client", return_value=Ball()), \
            contextlib.redirect_stdout(io.StringIO()):
        assert cli.cmd_sync(args) == 0
    assert calls == [(0, 123_456)]


def test_sync_with_only_a_start_uses_the_device_clock_as_end(tmp_path: Path):
    from unittest import mock

    calls: list[tuple[int, int]] = []

    class Ball:
        def status(self):
            return types.SimpleNamespace(device_timestamp_ms=9_000)

        def sync_range(self, start, end, out, *, seconds=300):
            calls.append((start, end))
            return {"state": "range_completed", "ok": True, "files": []}

    args = cli.build_parser().parse_args(["sync", "500", "--out", str(tmp_path)])
    with mock.patch.object(cli, "_client", return_value=Ball()), \
            contextlib.redirect_stdout(io.StringIO()):
        assert cli.cmd_sync(args) == 0
    assert calls == [(500, 9_000)]
