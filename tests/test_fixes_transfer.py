# -*- coding: utf-8 -*-
"""Offline regressions for the transfer/connect/provision fixes.

No device, no radio, no network, no real credentials: every peer is a
synthetic in-memory simulator, every key is generated in a temp directory.
Run with ``python3 tests/test_fixes_transfer.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
import weakref
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

from aipin_sdk.protocol import (  # noqa: E402
    commands,
    connect,
    framing,
    pipe,
    secure,
    sync,
    systemft,
    transport,
)
from aipin_sdk.protocol.transport import (  # noqa: E402
    LinkLost,
    LoopbackBackend,
    NotificationTimeout,
    Session,
)

KSC = bytes(range(16))
QCQS = bytes(range(16, 32))
MSG_SESSION = 32
CONTROL = 63
DATA = 116


# --------------------------------------------------------------------------
# Synthetic device
# --------------------------------------------------------------------------


class Device:
    """Builds the frames a device would send on an authenticated link."""

    def __init__(self) -> None:
        # The device's own counter range is below the host base.
        self.peer = secure.SecureChannel(KSC, QCQS, send_counter=0)

    def business(self, service: int, command: int, payload: bytes = b"",
                 *, plain: bool = False, session: int = MSG_SESSION) -> list[bytes]:
        inner = pipe.encode(bytes([service, command]) + payload)
        body = b"\x00" + inner if plain else self.peer.seal(inner)
        return framing.split(session, body)

    def control(self, obj: dict) -> list[bytes]:
        return framing.split(CONTROL, systemft.wrap_control(json.dumps(obj).encode()))

    def chunk(self, data: bytes, session: int = DATA) -> list[bytes]:
        return framing.split(session, b"\x00" + systemft.wrap_chunk(data))

    @staticmethod
    def setup(trans_id: int, name: str, payload: bytes, *, md5: bool = True) -> dict:
        offer = {
            "msgId": "filetransfer-setup-req", "transId": trans_id,
            "fileName": name, "filePath": "/x/" + name, "fileSize": len(payload),
            "peerId": "p", "containerId": "1", "channelId": "101",
        }
        if md5:
            offer["md5"] = hashlib.md5(payload).hexdigest()
        return offer

    @staticmethod
    def complete(trans_id: int, result: int = 0, reason: int = -1) -> dict:
        return {"msgId": "filetransfer-complete-rsp", "transId": trans_id,
                "result": result, "reason": reason}

    @staticmethod
    def range_bytes(start: int, end: int) -> bytes:
        return start.to_bytes(8, "little", signed=True) + end.to_bytes(8, "little", signed=True)


class ScriptedBackend(LoopbackBackend):
    """A loopback that reacts to host writes with scripted device frames.

    ``on_write(characteristic, payload, backend)`` returns frames to queue.
    An empty queue is an idle tick (NotificationTimeout) right away, so tests
    do not wait on real time unless they want to.
    """

    def __init__(self, on_write=None, *, idle_sleep: float = 0.0):
        super().__init__()
        self.on_write = on_write
        self.idle_sleep = idle_sleep
        self.connect("dev", 1.0)

    def write(self, characteristic, payload, timeout):
        super().write(characteristic, payload, timeout)
        if self.on_write is not None:
            for frame in self.on_write(characteristic, payload, self) or ():
                self.push(frame)

    def read_notification(self, timeout):
        if self._queue.empty() and not self.link_lost:
            if self.idle_sleep:
                time.sleep(min(self.idle_sleep, timeout))
            raise NotificationTimeout("idle")
        return super().read_notification(timeout)


def make_channel(backend, *, system_session: int | None = CONTROL) -> connect.ConnectedChannel:
    session = Session(backend, "dev", timeout=0.5)
    return connect.ConnectedChannel(
        session=session,
        secure=secure.SecureChannel(KSC, QCQS),
        session_id=MSG_SESSION,
        channel_id=104,
        message_provider_id=4,
        file_provider_id=5,
        device_info=None,
        bind_payload=b"",
        system_session_id=system_session,
    )


_HOST_STATE = weakref.WeakKeyDictionary()


def host_business(backend, frame: bytes) -> tuple[int, int, bytes] | None:
    """Decode a host business write the way the device would.

    Fragments of one large request share the secure counter, so they are
    reassembled before the envelope is opened (a fresh mirror per fragment
    would falsely look like a replay).
    """
    decoded = framing.decode(frame)
    if decoded.session_id != MSG_SESSION:
        return None
    state = _HOST_STATE.setdefault(backend, {})
    if state.get("done"):
        return None
    mirror = state.setdefault("mirror", secure.SecureChannel(KSC, QCQS))
    framer = state.setdefault("framer", framing.Framer())
    body = framer.feed(frame)
    if body is None:
        return None
    plaintext = mirror.open(body)
    data = pipe.decode(plaintext).data
    return data[0], data[1], data[2:]


def reassemble_control(state, frame):
    """Complete a control JSON body from possibly fragmented host writes."""
    framers = state.setdefault("_framers", {})
    framer = framers.setdefault(frame.session_id, framing.Framer())
    body = framer.feed(framing.encode(frame.session_id, frame.body, frame.fragmentation))
    if body is None:
        return None
    return json.loads(body[1:])


def written_json(backend, session: int = CONTROL) -> list[dict]:
    out = []
    for _c, payload in backend.written:
        frame = framing.decode(payload)
        if frame.session_id == session and frame.body[:1] == b"\x00":
            try:
                out.append(json.loads(frame.body[1:]))
            except ValueError:
                pass
    return out


def range_script(device: Device, transfers, *, eof=True, eof_range=None,
                 eof_plain=False, before_eof=None, complete=True,
                 complete_result=0):
    """on_write that answers each 06/00 with files and then 06/08."""
    state = {"ranges": 0}

    def on_write(characteristic, payload, backend):
        frame = framing.decode(payload)
        out = []
        if frame.session_id == MSG_SESSION:
            body = frame.body
            mirror_counter = int.from_bytes(body[1:9], "big")
            mirror = secure.SecureChannel(KSC, QCQS, send_counter=0)
            mirror.receive_counter = mirror_counter - 1
            data = pipe.decode(mirror.open(body)).data
            if data[:2] == bytes([6, 0]):
                start = int.from_bytes(data[2:10], "little", signed=True)
                end = int.from_bytes(data[10:18], "little", signed=True)
                state["ranges"] += 1
                out += device.business(6, 1, device.range_bytes(start, end))
                for trans_id, name, payload_bytes in transfers(state["ranges"]):
                    out += device.control(device.setup(trans_id, name, payload_bytes))
                    state.setdefault("pending", []).append((trans_id, payload_bytes))
                if before_eof:
                    out += before_eof(state["ranges"])
                if eof:
                    rng = eof_range or (start, end)
                    state.setdefault("eof", []).append(
                        device.business(6, 8, device.range_bytes(*rng), plain=eof_plain)
                    )
                if not transfers(state["ranges"]) and eof:
                    out += state["eof"].pop(0)
            return out
        if frame.session_id == CONTROL:
            msg = reassemble_control(state, frame)
            if msg is None:
                return out
            if msg["msgId"] == "filetransfer-setup-rsp" and msg["result"] == 0:
                for trans_id, payload_bytes in state.get("pending", []):
                    if trans_id == msg["transId"]:
                        out += device.chunk(payload_bytes)
            if msg["msgId"] == "filetransfer-complete-req":
                if complete:
                    out += device.control(device.complete(msg["transId"], complete_result))
                state["pending"] = [p for p in state.get("pending", []) if p[0] != msg["transId"]]
                if not state["pending"] and state.get("eof"):
                    out += state["eof"].pop(0)
        return out

    return on_write, state


# --------------------------------------------------------------------------
# Receiver: publication only after matching complete-rsp result 0
# --------------------------------------------------------------------------


class ReceiverPublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.r = sync.SyncReceiver(self.tmp, control_session=CONTROL, message_session=MSG_SESSION)

    def _offer(self, trans_id, name, payload, **kw):
        body = systemft.wrap_control(json.dumps(Device.setup(trans_id, name, payload, **kw)).encode())
        return self.r.feed_frames(CONTROL, body)

    def _chunk(self, data):
        return self.r.feed_frames(DATA, b"\x00" + systemft.wrap_chunk(data))

    def _complete(self, trans_id, result=0):
        body = systemft.wrap_control(json.dumps(Device.complete(trans_id, result)).encode())
        return self.r.feed_frames(CONTROL, body)

    def test_publishes_only_after_matching_complete_rsp(self):
        self._offer(1, "a.enc.opus", b"abcd")
        replies = self._chunk(b"abcd")
        self.assertEqual(len(replies), 1)
        session, body = replies[0]
        self.assertEqual(session, CONTROL, "complete-req goes on the control session")
        self.assertEqual(body[0], 0, "control replies carry the plain channel flag")
        self.assertEqual(json.loads(body[1:])["msgId"], "filetransfer-complete-req")
        self.assertFalse((self.tmp / "a.enc.opus").exists(), "published before complete-rsp")
        self.assertTrue((self.tmp / "a.enc.opus.part").exists())
        self.assertEqual(self.r.active_transactions, 1)
        self._complete(1)
        self.assertEqual((self.tmp / "a.enc.opus").read_bytes(), b"abcd")
        self.assertEqual(self.r.active_transactions, 0)
        self.assertEqual(self.r.result.published[0]["transId"], 1)

    def test_rejected_completion_abandons(self):
        self._offer(2, "b.enc.opus", b"xyz")
        self._chunk(b"xyz")
        self._complete(2, result=1)
        self.assertFalse((self.tmp / "b.enc.opus").exists())
        self.assertFalse((self.tmp / "b.enc.opus.part").exists())
        self.assertEqual(self.r.result.failures[0]["kind"], "peer_rejected_completion")
        self.assertTrue(self.r.failed)
        self.assertEqual(self.r.active_transactions, 0)

    def test_stale_complete_rsp_is_ignored(self):
        self._complete(99)
        self._offer(3, "c.enc.opus", b"1234")
        self._chunk(b"12")
        self._complete(3)  # still receiving: stale
        self.assertEqual(self.r.result.stale_complete_responses, 2)
        self.assertEqual(self.r.active_transactions, 1)
        self.assertFalse(self.r.failed)
        self._chunk(b"34")
        self._complete(3)
        self._complete(3)  # duplicate after publish: stale
        self.assertEqual(self.r.result.stale_complete_responses, 3)
        self.assertEqual(len(self.r.result.files), 1)

    def test_zero_length_file_needs_no_data_frame(self):
        replies = self._offer(0, "empty.enc.opus", b"")
        self.assertEqual(json.loads(replies[0][1][1:])["msgId"], "filetransfer-setup-rsp")
        self.assertEqual(json.loads(replies[1][1][1:])["msgId"], "filetransfer-complete-req")
        self.assertEqual(self.r.active_transactions, 1)
        self._complete(0)
        self.assertEqual((self.tmp / "empty.enc.opus").read_bytes(), b"")

    def test_late_data_for_completing_file_cannot_corrupt_next(self):
        self._offer(1, "first.enc.opus", b"aaaa")
        self._chunk(b"aaaa")
        self._offer(2, "second.enc.opus", b"bbbb")
        # Same declared channel as the sealed first file, before its response.
        self._chunk(b"XXXX")
        self.assertEqual(self.r.files[2].received, 0)
        self._complete(1)
        self._chunk(b"bbbb")
        self._complete(2)
        self.assertEqual((self.tmp / "second.enc.opus").read_bytes(), b"bbbb")

    def test_publish_never_clobbers_a_racer_final(self):
        self._offer(9, "race.enc.opus", b"device-bytes")
        self._chunk(b"device-bytes")
        final = self.tmp / "race.enc.opus"
        final.write_bytes(b"racer-must-survive")
        self._complete(9)
        self.assertEqual(final.read_bytes(), b"racer-must-survive")
        self.assertEqual(self.r.result.files, [])
        self.assertEqual(self.r.result.failures[0]["kind"], "publish_failed")
        self.assertFalse(self.r.completing)
        self.assertFalse((self.tmp / "race.enc.opus.part").exists())

    def test_complete_response_rejects_coerced_and_missing_integers(self):
        self._offer(8, "strict.enc.opus", b"strict")
        self._chunk(b"strict")
        for field in ("transId", "result", "reason"):
            for bad in ("1", 1.0, True, None):
                with self.subTest(field=field, bad=bad):
                    body = Device.complete(8)
                    body[field] = bad
                    wire = systemft.wrap_control(json.dumps(body).encode())
                    with self.assertRaises(systemft.FileTransferError):
                        systemft.CompleteResponse.from_json(wire[1:])
                    self.r.feed_frames(CONTROL, wire)
                    self.assertEqual(self.r.active_transactions, 1)
                    self.assertEqual(self.r.result.files, [])
            with self.subTest(field=field, missing=True):
                body = Device.complete(8)
                del body[field]
                wire = systemft.wrap_control(json.dumps(body).encode())
                with self.assertRaises(systemft.FileTransferError):
                    systemft.CompleteResponse.from_json(wire[1:])
                self.r.feed_frames(CONTROL, wire)
                self.assertEqual(self.r.active_transactions, 1)
                self.assertEqual(self.r.result.files, [])
        self._complete(8)
        self.assertEqual((self.tmp / "strict.enc.opus").read_bytes(), b"strict")

    def test_md5_mismatch_sends_cancel_and_publishes_nothing(self):
        body = Device.setup(4, "d.enc.opus", b"good")
        body["md5"] = hashlib.md5(b"other").hexdigest()
        self.r.feed_frames(CONTROL, systemft.wrap_control(json.dumps(body).encode()))
        replies = self._chunk(b"good")
        self.assertEqual(json.loads(replies[0][1][1:])["msgId"], "filetransfer-cancel-req")
        self.assertEqual(self.r.result.failures[0]["kind"], "md5_mismatch")
        self.assertFalse(any(self.tmp.iterdir()))

    def test_abandon_drops_sealed_unconfirmed(self):
        self._offer(5, "e.enc.opus", b"zz")
        self._chunk(b"zz")
        dropped = self.r.abandon()
        self.assertEqual(dropped[0]["state"], "awaiting_complete_rsp")
        self.assertFalse(any(self.tmp.iterdir()))

    def test_voiceprint_filter_and_rename_keeps_suffix(self):
        r = sync.SyncReceiver(self.tmp, control_session=CONTROL,
                              name_filter=systemft.is_voiceprint_name, max_accepted=1)
        reply = r.feed(CONTROL, systemft.wrap_control(json.dumps(
            Device.setup(6, "x.end.enc.opus", b"m")).encode()))
        self.assertEqual(json.loads(reply)["result"], 1)
        self.assertEqual(r.result.policy_rejected_total, 1)
        self.assertFalse(r.failed, "a policy refusal is a choice, not a loss")
        self.assertTrue(systemft.is_voiceprint_name("dir/a.enc.vp.opus"))
        self.assertEqual(sync._split_rename("a.enc.vp.opus"), ("a", ".enc.vp.opus"))


# --------------------------------------------------------------------------
# Range driver
# --------------------------------------------------------------------------


class RangeDriverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.device = Device()

    def _run(self, on_write, ranges, *, window=2.0):
        backend = ScriptedBackend(on_write)
        channel = make_channel(backend)
        receiver = sync.SyncReceiver(self.tmp, control_session=CONTROL, message_session=MSG_SESSION)
        driver = sync.RangeSyncDriver(channel, receiver, read_slice=0.05)
        deadline = time.monotonic() + window
        if len(ranges) == 1:
            return driver.run_range(*ranges[0], deadline=deadline), backend, receiver
        dirs = [self.tmp / f"range-{i}" for i in range(len(ranges))]
        return driver.run_ranges(ranges, deadline=deadline, output_dirs=dirs), backend, receiver

    def test_exact_authenticated_eof_after_drain(self):
        on_write, _ = range_script(self.device, lambda n: [(7, "a.enc.opus", b"data")])
        result, backend, _ = self._run(on_write, [(1000, 2000)])
        self.assertEqual(result["state"], sync.RANGE_COMPLETED, result)
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 1)
        self.assertTrue(result["diagnostics"]["echo_seen"])

    def test_empty_range_completes(self):
        on_write, _ = range_script(self.device, lambda n: [])
        result, _, _ = self._run(on_write, [(5, 5)])  # zero-width allowed
        self.assertEqual(result["state"], sync.RANGE_COMPLETED)
        self.assertEqual(result["count"], 0)

    def test_first_file_and_quiet_do_not_complete(self):
        on_write, _ = range_script(self.device, lambda n: [(8, "a.enc.opus", b"q")], eof=False)
        result, _, _ = self._run(on_write, [(1, 2)], window=0.4)
        self.assertEqual(result["state"], sync.WINDOW_ELAPSED_FILES_PUBLISHED_RANGE_UNVERIFIED)
        self.assertFalse(result["ok"])
        self.assertEqual(result["count"], 1, "the published file is still reported")

    def test_echo_only_does_not_complete(self):
        on_write, _ = range_script(self.device, lambda n: [], eof=False)
        result, _, _ = self._run(on_write, [(1, 2)], window=0.3)
        self.assertEqual(result["state"], sync.WINDOW_ELAPSED_NO_FILES)
        self.assertTrue(result["diagnostics"]["echo_seen"])

    def test_mismatched_and_plain_eof_ignored(self):
        on_write, _ = range_script(self.device, lambda n: [], eof_range=(1, 3))
        result, _, _ = self._run(on_write, [(1, 2)], window=0.3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"]["eof_mismatched"], 1)
        on_write, _ = range_script(Device(), lambda n: [], eof_plain=True)
        result, _, _ = self._run(on_write, [(1, 2)], window=0.3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"]["eof_unauthenticated"], 1)

    def test_nonfinite_eof_is_not_a_range_end(self):
        end = commands.INT64_MAX
        on_write, _ = range_script(self.device, lambda n: [])
        result, _, _ = self._run(on_write, [(1, end)], window=0.3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"]["eof_nonfinite"], 1)

    def test_prewrite_eof_ignored(self):
        on_write, _ = range_script(self.device, lambda n: [], eof=False)
        backend = ScriptedBackend(on_write)
        channel = make_channel(backend)
        for f in self.device.business(6, 8, Device.range_bytes(1, 2)):
            channel.pending_frames.append((MSG_SESSION, framing.decode(f).body))
        receiver = sync.SyncReceiver(self.tmp, control_session=CONTROL)
        driver = sync.RangeSyncDriver(channel, receiver, read_slice=0.05)
        result = driver.run_range(1, 2, deadline=time.monotonic() + 0.3)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"]["eof_prewrite_ignored"], 1)

    def test_eof_waits_for_pending_complete_rsp(self):
        # EOF arrives before the device answers complete-req; it never does.
        on_write, _ = range_script(self.device, lambda n: [(9, "a.enc.opus", b"zz")],
                                   complete=False)
        result, _, _ = self._run(on_write, [(1, 2)], window=0.4)
        self.assertEqual(result["state"], sync.RANGE_COMPLETED_DRAIN_TIMEOUT, result)
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["abandoned"][0]["state"], "awaiting_complete_rsp")
        self.assertFalse(any(p.name == "a.enc.opus" for p in self.tmp.iterdir()))

    def test_rejected_completion_is_failure(self):
        on_write, _ = range_script(self.device, lambda n: [(10, "a.enc.opus", b"r")],
                                   complete_result=3)
        result, _, _ = self._run(on_write, [(1, 2)])
        self.assertEqual(result["state"], sync.RANGE_COMPLETED_WITH_FAILURES)
        self.assertFalse(result["ok"])
        self.assertIn("NEW connection", result["retry"])

    def test_disconnect_is_link_lost(self):
        def on_write(c, payload, backend):
            frame = framing.decode(payload)
            if frame.session_id == MSG_SESSION:
                backend.simulate_disconnect()
            return []
        result, _, _ = self._run(on_write, [(1, 2)])
        self.assertEqual(result["state"], sync.LINK_LOST)

    def test_ranges_reuse_one_channel_and_stop_on_failure(self):
        on_write, state = range_script(self.device, lambda n: [(10 + n, f"f{n}.enc.opus", b"%d" % n)])
        result, backend, _ = self._run(on_write, [(1, 2), (3, 4), (5, 6)])
        self.assertTrue(result["ok"], result)
        self.assertEqual(state["ranges"], 3)
        self.assertEqual(result["count"], 3)
        self.assertTrue((self.tmp / "range-2" / "f3.enc.opus").exists())

        # A first range that never completes stops the sequence there.
        result, _, _ = self._run(
            range_script(Device(), lambda n: [], eof_range=(9, 9))[0],
            [(1, 2), (3, 4)], window=0.4,
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["stopped_at"], 0)
        self.assertEqual(result["ranges"][1]["state"], sync.NOT_STARTED)

    def test_sync_ranges_one_deadline_one_connection(self):
        from aipin_sdk import client as client_mod

        on_write, state = range_script(self.device, lambda n: [])
        backend = ScriptedBackend(on_write)
        channel = make_channel(backend)
        opened = []
        ball = client_mod.Xinliqiu(client_mod.Credentials("dev", self.tmp / "p", self.tmp / "k"))

        def fake_open(*, sync):
            opened.append(sync)
            return client_mod._Link(channel=channel, close=lambda: None)
        ball._open_channel = fake_open
        result = ball.sync_ranges([(1, 2), (3, 4)], self.tmp, seconds=2)
        self.assertTrue(result["ok"], result)
        self.assertEqual(opened, [True], "one authenticated connection for every range")
        self.assertEqual(state["ranges"], 2)
        with self.assertRaises(ValueError):
            ball.sync_ranges([(1, 2), (1, 2)], self.tmp)


# --------------------------------------------------------------------------
# Connect / channel
# --------------------------------------------------------------------------


class ChannelReplyTests(unittest.TestCase):
    def test_read_reply_reassembles_and_requires_authentication(self):
        device = Device()
        backend = ScriptedBackend()
        channel = make_channel(backend)
        # Plain status reply first (must be ignored), then a fragmented secure one.
        for f in device.business(2, 0xFF, bytes(12), plain=True):
            backend.push(f)
        big = bytes(range(256)) * 2
        frames = device.business(2, 0xFF, big)
        self.assertGreater(len(frames), 1, "test setup: reply must be fragmented")
        for f in frames:
            backend.push(f)
        reply = channel.read_reply(1.0, expect=(2, 0xFF))
        self.assertEqual(reply[2:], big)
        self.assertEqual(channel.unauthenticated_messages, 1)

    def test_read_reply_skips_unrelated_and_parks_other_sessions(self):
        device = Device()
        backend = ScriptedBackend()
        channel = make_channel(backend)
        backend.push(framing.encode(CONTROL, b"\x00{}"))
        for f in device.business(0x30, 2, b"\x00"):
            backend.push(f)
        for f in device.business(4, 0xFF, bytes(32)):
            backend.push(f)
        reply = channel.read_reply(1.0, expect=(4, 0xFF))
        self.assertEqual(reply[:2], b"\x04\xff")
        self.assertEqual(channel.pending_frames, [(CONTROL, b"\x00{}")])

    def test_link_lost_is_not_idle(self):
        backend = ScriptedBackend()
        channel = make_channel(backend)
        backend.simulate_disconnect()
        with self.assertRaises(LinkLost):
            channel.read_raw(0.2)
        with self.assertRaises(LinkLost):
            channel.read_reply(0.2)

    def test_read_business_accepts_only_session_32(self):
        device = Device()
        backend = ScriptedBackend()
        for f in device.business(2, 0x0D, b"\x01" + bytes(33), session=33):
            backend.push(f)
        for f in device.business(3, 0xFF, b"\x01\x01a\x01b"):
            backend.push(f)
        runner = connect._Runner(
            session=Session(backend, "dev", timeout=0.2), pairing=None,
            local_peer_id="OAFP_" + "a" * 31, agent_id=42, package="p", name="n",
            agent_auth_payload=connect.AGENT_AUTH_UNAVAILABLE,
            deadline=float("inf"),
        )
        runner.secure = secure.SecureChannel(KSC, QCQS)
        session_id, data = runner._read_business(1.0)
        self.assertEqual(session_id, MSG_SESSION)
        self.assertEqual(data[:2], b"\x03\xff")
        self.assertEqual(runner.raw_frames[0][0], 33)

    def test_storage_reply_range_must_match(self):
        payload = (1).to_bytes(8, "little") + (2).to_bytes(8, "little") + bytes(16)
        commands.StorageTotals.parse(b"\x04\xff" + payload, expected_range=(1, 2))
        with self.assertRaises(commands.ProtocolError):
            commands.StorageTotals.parse(b"\x04\xff" + payload, expected_range=(1, 3))
        self.assertEqual(len(commands.sync_request(7, 7)), 18)
        with self.assertRaises(commands.ProtocolError):
            commands.storage_request(7, 7)


class AgentKeyTests(unittest.TestCase):
    def _spki(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        return key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def test_payload_and_validation(self):
        der = self._spki()
        payload = connect.agent_auth_payload_from_spki(der)
        self.assertEqual(payload[:2], b"\x00\x01")
        self.assertEqual(int.from_bytes(payload[2:4], "big"), len(der))
        self.assertEqual(payload[4:], der)
        self.assertEqual(connect.validate_agent_spki(der), "EC")
        for bad in (b"", der[:-1], der + b"\x00", b"\x30\x00"):
            with self.assertRaises(connect.ConnectError):
                connect.validate_agent_spki(bad)

    def test_client_validates_before_radio(self):
        from aipin_sdk import client as client_mod

        tmp = Path(tempfile.mkdtemp())
        bad = tmp / "bad.der"
        bad.write_bytes(b"\x30\x03\x02\x01\x00")
        ball = client_mod.Xinliqiu(client_mod.Credentials("d", tmp / "p", tmp / "k"),
                                   agent_public_key=bad)
        with mock.patch("aipin_sdk.protocol.bleak_backend.BleakBackend") as backend:
            with self.assertRaises(connect.ConnectError):
                ball._open_channel(sync=False)
            backend.assert_not_called()
        good = tmp / "good.der"
        good.write_bytes(self._spki())
        ball = client_mod.Xinliqiu(client_mod.Credentials("d", tmp / "p", tmp / "k"),
                                   agent_public_key=good)
        options = ball.connect_options()
        self.assertEqual(options["package"], connect.OFFICIAL_AGENT_PACKAGE)
        self.assertEqual(options["bind_start_delay_ms"], 1000)

    def test_connect_rejects_bad_delay(self):
        with self.assertRaises(connect.ConnectError):
            connect.connect(None, None, "OAFP_" + "a" * 31, bind_start_delay_ms=2001)


# --------------------------------------------------------------------------
# Record control and voiceprint
# --------------------------------------------------------------------------


def status_reply(recording: int) -> bytes:
    return bytes([recording, 0, 50]) + bytes(8) + bytes([0])


class RecordAndVoiceprintTests(unittest.TestCase):
    def _ball(self, channel):
        from aipin_sdk import client as client_mod

        tmp = Path(tempfile.mkdtemp())
        ball = client_mod.Xinliqiu(client_mod.Credentials("d", tmp / "p", tmp / "k"))
        ball._open_channel = lambda *, sync: client_mod._Link(channel=channel, close=lambda: None)
        return ball, tmp

    def test_record_stop_observed_and_unconfirmed(self):
        from aipin_sdk import client as client_mod

        device = Device()
        states = iter([1, 0])

        def on_write(c, payload, backend):
            got = host_business(backend, payload)
            if got and got[:2] == (5, 2):
                return device.business(2, 0xFF, status_reply(next(states)))
            return []
        ball, _ = self._ball(make_channel(ScriptedBackend(on_write)))
        with mock.patch.object(client_mod, "STATUS_OBSERVATION_INTERVAL", 0.0):
            result = ball.record_stop()
        self.assertEqual(result["state"], "stopped_observed")
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["status_observations"]), 2)

        # No status reply at all: write attempted, unconfirmed, never resent.
        backend = ScriptedBackend(lambda c, p, b: [])
        ball, _ = self._ball(make_channel(backend))
        with mock.patch.object(client_mod, "STATUS_REPLY_SECONDS", 0.2):
            result = ball.record_start()
        self.assertEqual(result["state"], "write_attempted_unconfirmed")
        self.assertTrue(result["write_attempted"])
        starts = [host_business(backend, p) for _c, p in backend.written]
        self.assertEqual(sum(1 for s in starts if s and s[:2] == (7, 0)), 1)

    def test_voiceprint_same_connection(self):
        device = Device()
        payload = b"vp-bytes"

        def on_write(c, raw, backend):
            frame = framing.decode(raw)
            out = []
            if frame.session_id == MSG_SESSION:
                got = host_business(backend, raw)
                if got and got[:2] == (7, 2) and got[2] != b"\x00":
                    out += device.control(Device.setup(70, "x.end.enc.opus", b"m"))
                    out += device.control(Device.setup(71, "v.enc.vp.opus", payload))
            elif frame.session_id == CONTROL:
                state = getattr(on_write, "_state", on_write.__dict__)
                msg = reassemble_control(state, frame)
                if msg is None:
                    return out
                if msg["msgId"] == "filetransfer-setup-rsp" and msg["result"] == 0:
                    out += device.chunk(payload)
                if msg["msgId"] == "filetransfer-complete-req":
                    out += device.control(Device.complete(msg["transId"]))
            return out
        backend = ScriptedBackend(on_write)
        ball, tmp = self._ball(make_channel(backend))
        result = ball.collect_voiceprint(3, tmp / "vp", window_seconds=5)
        self.assertEqual(result["state"], sync.VOICEPRINT_COLLECTED, result)
        self.assertTrue(result["file"].endswith("v.enc.vp.opus"))
        self.assertEqual(result["refused_offers"], 1)
        self.assertEqual(result["cleanup_stop"], "not_needed")

    def test_voiceprint_discards_complete_prestart_pending_transfer(self):
        device = Device()
        backend = ScriptedBackend()
        channel = make_channel(backend)
        old_frames = (
            device.control(Device.setup(60, "old.vp.opus", b"old-capture"))
            + device.chunk(b"old-capture")
            + device.control(Device.complete(60))
        )
        channel.pending_frames.extend(
            (framing.decode(frame).session_id, framing.decode(frame).body)
            for frame in old_frames
        )
        out = Path(tempfile.mkdtemp())
        result = sync.collect_voiceprint(
            channel, out, duration=2, deadline=time.monotonic() + 0.2,
            read_slice=0.05, cleanup_grace=0,
        )
        self.assertEqual(result["state"], sync.VOICEPRINT_NO_FILE, result)
        self.assertEqual(result["offers"], 0)
        self.assertEqual(result["files"], [])
        self.assertEqual(result["diagnostics"]["prestart_frames_discarded"], 3)
        self.assertEqual(list(out.iterdir()), [])

    def test_voiceprint_prestart_service_negotiation_is_preserved(self):
        backend = ScriptedBackend()
        channel = make_channel(backend)
        body = bytearray([sync.SERVICE_REQUEST_TYPE])
        body += (5).to_bytes(2, "big") + (43).to_bytes(2, "big")
        body += b"system:filetransfer" + bytes([sync.PROFILE_TERMINATOR])
        body += (2).to_bytes(2, "big")
        for session in (CONTROL, DATA):
            body += session.to_bytes(2, "big")
        for channel_id in (100, 101):
            body += channel_id.to_bytes(2, "big")
        body += bytes([4, 1, 4, 0, 0, 0])
        channel.pending_frames.append((1, bytes(body)))

        result = sync.collect_voiceprint(
            channel, Path(tempfile.mkdtemp()), duration=2,
            deadline=time.monotonic() + 0.2, read_slice=0.05, cleanup_grace=0,
        )
        self.assertEqual(result["diagnostics"]["prestart_service_frames_processed"], 1)
        self.assertEqual(result["diagnostics"]["prestart_frames_discarded"], 0)
        accepts = []
        for _characteristic, payload in backend.written:
            frame = framing.decode(payload)
            if frame.session_id == 1 and frame.body[:1] == bytes([sync.SERVICE_ACCEPT_TYPE]):
                accepts.append(frame.body)
        self.assertEqual(len(accepts), 1)

    def test_voiceprint_diagnostics_are_allowlisted_and_payload_free(self):
        device = Device()
        secrets = (b"secret-unreviewed", b"secret-plain", b"secret-reviewed")

        def on_write(c, raw, backend):
            got = host_business(backend, raw)
            if got and got[:2] == (7, 2) and got[2] != b"\x00":
                return (
                    device.business(0x30, 0x99, secrets[0])
                    + device.business(2, 0x0A, secrets[1], plain=True)
                    + device.business(2, 0x0A, b"\x01")
                    + device.business(2, 0x0C, secrets[2])
                )
            return []

        backend = ScriptedBackend(on_write)
        channel = make_channel(backend)
        result = sync.collect_voiceprint(
            channel, Path(tempfile.mkdtemp()), duration=2,
            deadline=time.monotonic() + 0.3, read_slice=0.05, cleanup_grace=0,
        )
        notices = result["notifications"]
        self.assertEqual(
            [(n["service"], n["command"]) for n in notices],
            [(2, 0x0A), (2, 0x0C)],
        )
        self.assertTrue(all(n["authenticated"] for n in notices))
        self.assertTrue(all("payload_hex" not in n for n in notices))
        rendered = json.dumps(result)
        for secret in secrets:
            self.assertNotIn(secret.hex(), rendered)

    def test_voiceprint_no_file_sends_one_cleanup_stop(self):
        backend = ScriptedBackend(lambda c, p, b: [])
        channel = make_channel(backend)
        result = sync.collect_voiceprint(
            channel, Path(tempfile.mkdtemp()), duration=2,
            deadline=time.monotonic() + 0.2, read_slice=0.05, cleanup_grace=0,
        )
        self.assertEqual(result["state"], sync.VOICEPRINT_NO_FILE)
        self.assertEqual(result["cleanup_stop"], "write_attempted_unconfirmed")
        cmds = [host_business(backend, p) for _c, p in backend.written]
        self.assertEqual([c[2] for c in cmds if c and c[:2] == (7, 2)], [b"\x02", b"\x00"])


# --------------------------------------------------------------------------
# Pairing and provisioning
# --------------------------------------------------------------------------


class PairingTests(unittest.TestCase):
    def test_server_init_fragments_accumulate(self):
        from aipin_sdk.protocol import pairing

        body = b"\x08\x03\x12\x05" + b"abcde"
        backend = ScriptedBackend()
        for part in (b"\x11" + body[:3], body[3:6], body[6:]):
            backend.push(part, pairing.CHAR_HANDSHAKE)
        session = Session(backend, "d", timeout=0.2)
        got = pairing.read_server_init(session, time.monotonic() + 1)
        self.assertEqual(got, b"\x11" + body)
        backend.push(b"\x11" + body + b"x", pairing.CHAR_HANDSHAKE)
        with self.assertRaises(pairing.PairingError):
            pairing.read_server_init(session, time.monotonic() + 1)

    def _fake_pair(self, outcome):
        from aipin_sdk.protocol import pairing
        from aipin_sdk.protocol.auth import Pairing

        material = Pairing(ksc=os.urandom(16), alias=b"\x01" * 6,
                           seeker_id=os.urandom(6), provider_id=os.urandom(6))

        def fake(session, *, alias, timeout, stage):
            stage(material)
            self.staged_seen = True
            if outcome == "ok":
                return material, []
            if outcome == "uncertain":
                raise pairing.PairingUncertain("no confirmation", material)
            raise pairing.PairingError("refused")
        return fake

    def test_stage_promote_and_retain(self):
        from aipin_sdk.protocol import pairing, provision

        for outcome in ("ok", "uncertain", "refused"):
            out = Path(tempfile.mkdtemp()) / "creds"
            with mock.patch.object(pairing, "pair", self._fake_pair(outcome)):
                if outcome == "ok":
                    result = provision.pair(None, out_dir=out)
                    self.assertTrue(result.key_file.is_absolute())
                    self.assertTrue((out / "pairing.json").exists())
                    self.assertFalse((out / "pairing.pending.json").exists())
                elif outcome == "uncertain":
                    with self.assertRaises(provision.PairingOutcomeUnknown):
                        provision.pair(None, out_dir=out)
                    self.assertTrue((out / "pairing.pending.json").exists())
                    self.assertFalse((out / "pairing.json").exists())
                    with self.assertRaises(provision.ProvisionError):
                        provision.pair(None, out_dir=out)  # refuses to discard it
                    self.assertEqual(provision.read_alias(out / "pairing.pending.json"), "01" * 6)
                    provision.promote_pending_pairing(out)
                    self.assertTrue((out / "pairing.json").exists())
                else:
                    with self.assertRaises(pairing.PairingError):
                        provision.pair(None, out_dir=out)
                    self.assertFalse((out / "pairing.pending.json").exists())

    def test_stage_failure_writes_nothing(self):
        from aipin_sdk.protocol import pairing
        from aipin_sdk.protocol.auth import Pairing

        backend = ScriptedBackend()
        session = Session(backend, "d", timeout=0.2)
        handshake = mock.MagicMock()
        handshake.provider_id = b"p" * 6
        handshake.seeker_id = b"s" * 6
        handshake.seal.return_value = b"sealed"
        backend.push(bytes([1, 0, 0, 0, 0, 0]) + bytes(10), pairing.CHAR_INIT)
        backend.push(b"\x11\x08\x03\x12\x00", pairing.CHAR_HANDSHAKE)
        backend.push(bytes(38), pairing.CHAR_HANDSHAKE)
        with mock.patch.object(pairing.ukey2, "Handshake", return_value=handshake):
            with self.assertRaises(OSError):
                pairing.pair(session, stage=mock.Mock(side_effect=OSError("disk full")))
        self.assertNotIn(pairing.CHAR_KSC, [c for c, _ in backend.written])

    def test_session_open_subscribes_real_pairing_characteristics(self):
        self.assertEqual(transport.PAIRING_CHARACTERISTICS, ("0001", "1001", "1004"))
        backend = LoopbackBackend()
        Session(backend, "d").open()
        self.assertIn("AA16", backend._subscribed)
        self.assertIn("1001", backend._subscribed)


class ConfigDoctorInitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, {"XINLIQIU_CONFIG": str(self.tmp / "cfg.json")})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_config_saves_absolute_paths(self):
        from aipin_sdk import userconfig

        cwd = os.getcwd()
        os.chdir(self.tmp)
        try:
            userconfig.UserConfig(device="d", key_file="rel/k.json").save()
        finally:
            os.chdir(cwd)
        saved = json.loads((self.tmp / "cfg.json").read_text())
        self.assertTrue(Path(saved["key_file"]).is_absolute())
        merged = userconfig.UserConfig().merged(bind_start_delay_ms=0)
        self.assertEqual(merged.bind_start_delay_ms, 0)

    def test_alias_recovered_from_pairing_file(self):
        from aipin_sdk import provision as top
        from aipin_sdk.protocol import provision
        from aipin_sdk.protocol.auth import Pairing

        out = self.tmp / "creds"
        provision.save_pairing(Pairing(ksc=os.urandom(16), alias=b"\xaa" * 6,
                                       seeker_id=os.urandom(6), provider_id=os.urandom(6)),
                               out / "pairing.json")
        self.assertEqual(top.recover_alias(out), "aa" * 6)

    def test_doctor_uses_saved_config_and_validates(self):
        from aipin_sdk import cli, userconfig
        from aipin_sdk.protocol import provision
        from aipin_sdk.protocol.auth import Pairing

        key = self.tmp / "pairing.json"
        provision.save_pairing(Pairing(ksc=os.urandom(16), alias=os.urandom(6),
                                       seeker_id=os.urandom(6), provider_id=os.urandom(6)), key)
        peer = self.tmp / "peer.txt"
        peer.write_text("OAFP_" + "x" * 30 + "\x7f")  # 36 chars, not printable
        userconfig.UserConfig(device="dev", peer_id_file=str(peer), key_file=str(key)).save()
        args = cli.build_parser().parse_args(["doctor"])
        with mock.patch("sys.stdout"):
            self.assertEqual(cli.cmd_doctor(args), 1)
        peer.write_text(provision.generate_peer_id())
        with mock.patch("sys.stdout"):
            self.assertEqual(cli.cmd_doctor(args), 0)

    def test_init_requires_matching_private_key_before_radio(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from aipin_sdk import client as client_mod
        import base64

        def pair_files(name):
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            priv = self.tmp / f"{name}.pem"
            priv.write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            os.chmod(priv, 0o600)
            pub = self.tmp / f"{name}.spki.txt"
            pub.write_bytes(base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)))
            return priv, pub
        priv_a, pub_a = pair_files("a")
        _priv_b, pub_b = pair_files("b")
        ball = client_mod.Xinliqiu(client_mod.Credentials("d", self.tmp / "p", self.tmp / "k"))
        opened = []
        ball._open_channel = lambda *, sync: opened.append(sync)
        with self.assertRaises(client_mod.XinliqiuError):
            ball.init_device(owner_public_key=pub_a, signing_key=self.tmp / "s")
        with self.assertRaises(client_mod.XinliqiuError):
            ball.init_device(owner_public_key=pub_b, signing_key=self.tmp / "s",
                             owner_private_key=priv_a)
        self.assertEqual(opened, [], "no radio use before the key check")

    def test_init_states_from_readback(self):
        """Verified only with a matching readback; absent readback is distinct."""
        from aipin_sdk.protocol import init as init_mod

        text = "A" * 4
        account = "acct"
        base = bytes([1]) + (0).to_bytes(8, "little") + bytes([len(account)]) + account.encode()
        absent = init_mod.parse_init_response(base, expected_account=account, framed=False)
        self.assertIsNone(absent.public_key_matched)
        self.assertTrue(absent.accepted)


class TaskTests(unittest.TestCase):
    def test_prune_keeps_running(self):
        from aipin_sdk.tasks import Task, TaskRegistry

        registry = TaskRegistry()
        old_running = Task("a", "x", started_at=0)
        old_done = Task("b", "y", state="succeeded", started_at=0, finished_at=1)
        registry._tasks = {"a": old_running, "b": old_done}
        self.assertEqual(registry.prune(max_age=0), 1)
        self.assertIn("a", registry._tasks)


class CliOutcomeTests(unittest.TestCase):
    """The CLI surfaces the structured state, not just a file count."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, {"XINLIQIU_CONFIG": str(self.tmp / "cfg.json")})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def _ball(self, channel, captured):
        from aipin_sdk import client as client_mod

        ball = client_mod.Xinliqiu(client_mod.Credentials("dev", self.tmp / "p", self.tmp / "k"))
        ball._open_channel = lambda *, sync: client_mod._Link(
            channel=channel, close=lambda: captured.append("closed")
        )
        return ball

    def test_empty_completed_range_exits_zero(self):
        from aipin_sdk import cli

        device = Device()
        on_write, _ = range_script(device, lambda n: [])
        backend = ScriptedBackend(on_write)
        closed = []
        ball = self._ball(make_channel(backend), closed)
        args = cli.build_parser().parse_args(["sync", "0", "1000", "--out", str(self.tmp / "o")])
        with mock.patch.object(cli, "_client", return_value=ball), mock.patch("sys.stdout") as out:
            self.assertEqual(cli.cmd_sync(args), 0)
        self.assertEqual(closed, ["closed"])

    def test_unverified_sync_exits_three(self):
        from aipin_sdk import cli

        device = Device()
        on_write, _ = range_script(device, lambda n: [], eof=False)
        backend = ScriptedBackend(on_write)
        ball = self._ball(make_channel(backend), [])
        args = cli.build_parser().parse_args(
            ["sync", "0", "1000", "--seconds", "1", "--out", str(self.tmp / "o")]
        )
        with mock.patch.object(cli, "_client", return_value=ball), mock.patch("sys.stdout"):
            self.assertEqual(cli.cmd_sync(args), cli.EXIT_UNVERIFIED)

    def test_sync_rejects_bad_arguments(self):
        from aipin_sdk import cli

        args = cli.build_parser().parse_args(["sync"])
        with self.assertRaises(cli.CliError):
            cli.cmd_sync(args)
        args = cli.build_parser().parse_args(["sync", "1", "2", "--ranges", "1:2"])
        with self.assertRaises(cli.CliError):
            cli.cmd_sync(args)
        self.assertEqual(cli._parse_ranges("1:2;3:4"), [(1, 2), (3, 4)])
        with self.assertRaises(cli.CliError):
            cli._parse_ranges("1:2;3")

    def test_voiceprint_parser_has_out_and_window(self):
        from aipin_sdk import cli

        args = cli.build_parser().parse_args(
            ["voiceprint", "6", "--out", str(self.tmp), "--window", "90"]
        )
        self.assertEqual(args.out, str(self.tmp))
        self.assertEqual(args.window, 90)

    def test_record_unconfirmed_exits_three(self):
        from aipin_sdk import cli, client as client_mod

        backend = ScriptedBackend(lambda c, p, b: [])
        ball = self._ball(make_channel(backend), [])
        args = cli.build_parser().parse_args(["record", "stop"])
        with mock.patch.object(cli, "_client", return_value=ball), \
                mock.patch.object(client_mod, "STATUS_REPLY_SECONDS", 0.1), \
                mock.patch("sys.stdout"):
            self.assertEqual(cli.cmd_record(args), cli.EXIT_UNVERIFIED)
        stops = [host_business(backend, p) for _c, p in backend.written]
        self.assertEqual(sum(1 for c in stops if c and c[:2] == (7, 0)), 1)

    def test_require_ok_raises_with_result(self):
        from aipin_sdk import client as client_mod
        from aipin_sdk.errors import OperationIncomplete

        with self.assertRaises(OperationIncomplete) as caught:
            client_mod.Xinliqiu.require_ok({"state": "x", "ok": False, "retry": "later"})
        self.assertEqual(caught.exception.result["state"], "x")


class InitOutcomeTests(unittest.TestCase):
    """INIT: challenge freshness, authenticated answers, and explicit states."""

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        import base64

        self.tmp = Path(tempfile.mkdtemp())
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv = self.tmp / "owner.pem"
        priv.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        os.chmod(priv, 0o600)
        self.owner_text = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode()
        pub = self.tmp / "owner.spki.txt"
        pub.write_text(self.owner_text)
        self.pub = pub
        self.priv = priv
        signer = ec.generate_private_key(ec.SECP256R1())
        self.signer_file = self.tmp / "signer.pem"
        self.signer_file.write_bytes(signer.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))

    def _run(self, readback, *, signer=None):
        from aipin_sdk import client as client_mod
        from aipin_sdk.protocol import init as init_mod

        device = Device()
        account = "local-owner"

        def init_answer(payload):
            status = bytes([1])
            ts = (int(time.time() * 1000)).to_bytes(8, "little")
            acct = bytes([len(account)]) + account.encode()
            tail = b""
            if readback == "match":
                tail = bytes([1]) + len(self.owner_text).to_bytes(2, "little") + self.owner_text.encode()
            elif readback == "mismatch":
                tail = bytes([1]) + (2).to_bytes(2, "little") + b"xx"
            return status + ts + acct + tail

        def on_write(c, raw, backend):
            got = host_business(backend, raw)
            if not got:
                return []
            service, command, payload = got
            if (service, command) == (2, 0x0D):
                challenge = b"\x01" + bytes(16) + bytes(12) + (60000).to_bytes(4, "little") + b"\x01"
                return device.business(2, 0x0D, challenge)
            if (service, command) == (2, 8):
                return device.business(2, 8, init_answer(payload))
            return []

        backend = ScriptedBackend(on_write)
        channel = make_channel(backend)
        ball = client_mod.Xinliqiu(client_mod.Credentials("dev", self.tmp / "p", self.tmp / "k"),
                                   owner_private_key=self.priv)
        ball._open_channel = lambda *, sync: client_mod._Link(channel=channel, close=lambda: None)
        signing = {"signer": signer} if signer is not None else {"signing_key": self.signer_file}
        return ball.init_device(owner_public_key=self.pub, **signing)

    def test_verified_when_readback_matches(self):
        result = self._run("match")
        self.assertEqual(result["state"], "init_verified", result)
        self.assertTrue(result["ok"])

    def test_custom_signer_object(self):
        from aipin_sdk.protocol import init as init_mod

        class SyntheticSigner:
            def __init__(self, path):
                self.delegate = init_mod.Pkcs8Signer(path)
                self.public_key_sha256_hex = self.delegate.public_key_sha256_hex
                self.calls = []

            def sign(self, tbs):
                self.calls.append(tbs)
                return self.delegate.sign(tbs)

        signer = SyntheticSigner(self.signer_file)
        result = self._run("match", signer=signer)
        self.assertEqual(result["state"], "init_verified", result)
        self.assertTrue(result["ok"])
        self.assertEqual(len(signer.calls), 1)

    def test_requires_exactly_one_signing_identity(self):
        from aipin_sdk import client as client_mod

        ball = client_mod.Xinliqiu(
            client_mod.Credentials("dev", self.tmp / "p", self.tmp / "k"),
            owner_private_key=self.priv,
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            ball.init_device(owner_public_key=self.pub)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            ball.init_device(
                owner_public_key=self.pub,
                signing_key=self.signer_file,
                signer=object(),
            )

    def test_absent_readback_is_distinct_unverified(self):
        result = self._run("absent")
        self.assertEqual(result["state"], "init_accepted_unverified")
        self.assertFalse(result["ok"])
        self.assertIn("Do NOT run INIT again", result["retry"])

    def test_mismatched_readback_is_not_success(self):
        result = self._run("mismatch")
        self.assertEqual(result["state"], "init_readback_mismatch")
        self.assertFalse(result["ok"])

    def test_no_answer_never_suggests_resend(self):
        from aipin_sdk import client as client_mod

        device = Device()

        def on_write(c, raw, backend):
            got = host_business(backend, raw)
            if got and got[:2] == (2, 0x0D):
                challenge = b"\x01" + bytes(16) + bytes(12) + (60000).to_bytes(4, "little") + b"\x01"
                return device.business(2, 0x0D, challenge)
            return []
        backend = ScriptedBackend(on_write)
        ball = client_mod.Xinliqiu(client_mod.Credentials("dev", self.tmp / "p", self.tmp / "k"),
                                   owner_private_key=self.priv)
        ball._open_channel = lambda *, sync: client_mod._Link(
            channel=make_channel(backend), close=lambda: None)
        result = ball.init_device(owner_public_key=self.pub, signing_key=self.signer_file)
        self.assertEqual(result["state"], "init_written_no_ack", result)
        self.assertIn("Do NOT run INIT again", result["retry"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
