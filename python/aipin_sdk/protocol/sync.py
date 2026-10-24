# -*- coding: utf-8 -*-
"""Driving a recording sync: request a range, receive the files it produces.

The device answers a sync request by opening a file service and offering files
one at a time. This module owns the state machine; it never touches Bluetooth
itself, so it can be exercised against recorded frames.

Frame routing, matching the tested contract:

=====================  =========================================================
reserved session 1     service request (type 1) / accept (type 2); the sender
                       declares its control channel and data channels here
control channel        JSON messages: setup-req, complete-rsp, appalive, cancel
data channel           ``0x00`` plain flag, ``0x01`` chunk header, then bytes
=====================  =========================================================

Everything else is ignored rather than treated as an error: the device emits
events this receiver has no opinion about, and failing on them would abort a
transfer that is going fine.

Three completion boundaries are kept apart (docs/transfer-recovery.md):

1. **file**: declared size received, MD5 checked when supplied, the peer's
   ``complete-rsp`` for the same ``transId`` reports result 0 - only then is
   the file published under its final name;
2. **container**: CMPT structure, checked elsewhere;
3. **range**: an authenticated ``06/08`` carrying exactly the written range,
   *and* every local transaction drained with no failure. A first file, a
   quiet period, the host deadline, a disconnect or the ``06/01`` echo never
   complete a range.

:class:`SyncReceiver` owns (1). :class:`RangeSyncDriver` owns (3) on top of a
connected channel and reports an explicit state for every outcome.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..errors import XinliqiuError
from . import commands, framing, systemft
from .transport import LinkLost, TransportError

# Service negotiation on the reserved session.
SERVICE_REQUEST_TYPE = 1
SERVICE_ACCEPT_TYPE = 2

# Channel kinds declared by the sender.
CONTROL_CHANNEL = 100
DATA_CHANNELS_LOW = 101
DATA_CHANNELS_HIGH = 105
MAX_CHANNELS = 6
PROFILE_TERMINATOR = 0x3B
PROFILE_NAME = "system:filetransfer"

# Resource policy: one broken or hostile offer must not fill the output
# directory, pin an unbounded number of handles, or make the receiver spend
# minutes writing something no recording could be. 64 MiB is far above the
# largest container the device produces and still small enough to refuse
# outright.
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_INFLIGHT = 4

# How many colliding names are tried before an offer is rejected. Bounded so a
# directory full of planted names cannot spin the receiver.
MAX_NAME_ATTEMPTS = 100

# How many rejections are kept for diagnostics. A device that keeps offering
# unusable files must not grow the result without limit.
MAX_REJECTED_RECORDED = 20

# Suffixes whose meaning lives in the name: ``container.Entry.kind`` and
# ``storage.storage_kind`` classify the complete suffix (audio variants,
# end-marker, mark, trace-point/diagnostic). Splitting one to insert a counter
# (``a.end.enc-2.opus``) reclassifies the file, so the counter goes before the
# whole suffix and the classification survives.
_RENAME_SUFFIXES = (
    ".end.enc.opus",
    ".enc.note.opus",
    ".enc.vp.opus",
    ".vp.opus",
    ".enc.opus",
    ".tp",
)

# Bounded diagnostics: failures and ignored control messages are recorded, but
# a misbehaving peer cannot grow them without limit.
MAX_FAILURES_RECORDED = 20


def _split_rename(name: str) -> tuple[str, str]:
    """Split ``name`` so a ``-N`` counter can go between stem and suffix.

    A known classification suffix is preserved whole: ``a.end.enc.opus``
    becomes ``a-2.end.enc.opus``, which still classifies as an end marker.
    Otherwise the counter goes before the last extension only when the stem has
    no further dot; a compound name such as ``a.b.c`` keeps every extension and
    takes the counter after the whole name (``a.b.c-2``), because inventing a
    split inside it would invent a different extension.
    """
    lowered = name.lower()
    for suffix in _RENAME_SUFFIXES:
        if len(name) > len(suffix) and lowered.endswith(suffix):
            return name[: -len(suffix)], name[-len(suffix) :]
    stem, suffix = os.path.splitext(name)
    if suffix and "." not in stem.lstrip("."):
        return stem, suffix
    return name, ""


class SyncError(XinliqiuError):
    """A sync frame could not be interpreted."""


@dataclass
class ServiceChannels:
    """What the sender declared: which session carries which channel."""

    sessions: dict[int, int]  # session id -> channel id
    control_session: int
    data_channels: set[int]

    @property
    def data_sessions(self) -> set[int]:
        return {s for s, c in self.sessions.items() if c in self.data_channels}


@dataclass
class SyncResult:
    files: list[Path] = field(default_factory=list)
    #: File-data bytes written to staging, published or not.
    bytes_received: int = 0
    #: Bytes of files published after a matching complete-rsp result 0.
    bytes_published: int = 0
    setup_seen: int = 0
    rejected: list[tuple[int, int]] = field(default_factory=list)
    rejected_total: int = 0  # every refusal, even past the recorded window
    #: Refusals made because of a caller policy (``name_filter``), which are a
    #: deliberate choice rather than a lost file.
    policy_rejected_total: int = 0
    anomalies: int = 0  # data frames dropped because their owner was ambiguous
    #: Transactions that ended without a published file (local failure, peer
    #: cancel, peer completion rejection). Each is a dict with transId, kind,
    #: reason and message.
    failures: list[dict[str, Any]] = field(default_factory=list)
    failures_total: int = 0
    #: complete-rsp for a transId that is not waiting for completion.
    stale_complete_responses: int = 0
    #: A type-1 this receiver could not accept.
    service_failures: int = 0
    #: Per-file details for every published file, in publication order.
    published: list[dict[str, Any]] = field(default_factory=list)

    def add(self, path: Path, size: int, *, trans_id: int | None = None,
            remote_name: str | None = None, md5_checked: bool = False) -> None:
        self.files.append(path)
        self.bytes_published += size
        self.published.append({
            "path": str(path),
            "bytes": size,
            "transId": trans_id,
            "remoteName": remote_name,
            "md5Checked": md5_checked,
        })

    def reject(self, trans_id: int, reason: int, *, policy: bool = False) -> None:
        """Record a refusal, keeping only the first few for diagnostics."""
        self.rejected_total += 1
        if policy:
            self.policy_rejected_total += 1
        if len(self.rejected) < MAX_REJECTED_RECORDED:
            self.rejected.append((trans_id, reason))

    def fail(self, trans_id: int, kind: str, reason: int, message: str) -> None:
        self.failures_total += 1
        if len(self.failures) < MAX_FAILURES_RECORDED:
            self.failures.append({
                "transId": trans_id, "kind": kind, "reason": reason,
                "message": message,
            })

    @property
    def unplanned_rejections(self) -> int:
        """Refusals that lost a file the caller did not choose to skip."""
        return self.rejected_total - self.policy_rejected_total


class SyncReceiver:
    """State machine for one sync window.

    Feed frames with :meth:`feed`; it returns the bytes that must be written
    back to the device (control replies), which the caller sends. A return of
    ``None`` means nothing to send.
    """

    def __init__(
        self,
        output_dir: Path,
        *,
        control_session: int | None = None,
        message_session: int | None = None,
        name_filter: Callable[[str], bool] | None = None,
        max_accepted: int | None = None,
    ) -> None:
        """``control_session`` seeds a service the connection already opened.

        The device does not always wait for a fresh type-1 handshake: when the
        ``system:filetransfer`` service came up during the connection handshake
        it starts offering files straight away, and a receiver that insisted on
        a type-1 first would ignore every offer.

        ``name_filter`` is evaluated on the remote ``fileName`` when the offer
        arrives; ``False`` refuses it with :data:`systemft.REASON_POLICY` and
        counts it as a policy refusal. ``max_accepted`` bounds how many offers
        this receiver ever accepts (a voiceprint collection wants exactly one).
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.name_filter = name_filter
        self.max_accepted = max_accepted
        self.accepted_total = 0
        # Sealed files waiting for the peer's complete-rsp, by transId. They
        # still count as active transactions: a range is not drained until
        # every one of them is confirmed or abandoned.
        self.completing: dict[int, systemft.IncomingFile] = {}

        self.message_session = message_session
        self.channels: ServiceChannels | None = (
            ServiceChannels(sessions={}, control_session=control_session,
                            data_channels=set())
            if control_session is not None
            else None
        )
        # Data sessions are learned: the device opens one per file and never
        # announces which session carries which channel. Once learned the
        # binding is authoritative; re-deriving it per frame is what used to
        # attribute a chunk to the wrong file (O3).
        self.session_channels: dict[int, int] = {}
        self.service_acknowledged = False
        # Bytes the device sent after the fields this parser understands.
        self.trailing_bytes = b""
        self.files: dict[int, systemft.IncomingFile] = {}
        self.completed: dict[int, Path] = {}
        self.result = SyncResult()
        # True once any transaction received a complete-rsp result 0. Kept for
        # callers of the old API; it is a file boundary, never a range one.
        self.finished = False
        self.error: str | None = None
        # The replies produced by the frame being handled: (session, body).
        self._outbox: list[tuple[int, bytes]] = []

    # -- bookkeeping -------------------------------------------------------

    @property
    def active_transactions(self) -> int:
        """Accepted transactions not yet published or abandoned."""
        return len(self.files) + len(self.completing)

    @property
    def failed(self) -> bool:
        """Any loss: a failed transaction, an unplanned refusal, a bad type-1."""
        return bool(
            self.result.failures_total
            or self.result.unplanned_rejections
            or self.result.service_failures
        )

    def set_output_dir(self, output_dir: Path) -> None:
        """Direct later offers to another directory (between ranges only)."""
        if self.active_transactions:
            raise SyncError("cannot change the output directory mid-transfer")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _reply_control(self, body: bytes) -> None:
        if self.channels is None:
            return
        self._outbox.append((self.channels.control_session, body))

    def _fail_transaction(
        self, incoming: systemft.IncomingFile, kind: str, reason: int, message: str,
        *, send_cancel: bool,
    ) -> None:
        trans_id = incoming.request.trans_id
        incoming.abandon()
        self.files.pop(trans_id, None)
        self.completing.pop(trans_id, None)
        self._forget_bindings(incoming.request.channel)
        self.result.fail(trans_id, kind, reason, message)
        if self.error is None:
            self.error = message
        if send_cancel:
            self._reply_control(systemft.encode_cancel_request(trans_id, reason))

    # -- service negotiation ---------------------------------------------

    def accept_service_request(self, body: bytes) -> bytes | None:
        """Parse a type-1 request and build the type-2 accept.

        Field order is sender-relative and NOT symmetric between the two
        messages (the protocol):

        ====== ==========================================================
        type 1  ``1 | remote u16 | local u16 | profile ; | count u16 |
                sessions u16*  | channels u16* | qos(type u8, class u8)* |
                payload u8*``
        type 2  ``2 | initiator u16 | acceptor u16 | profile ; | 00 |
                count u16 | sessions u16*``
        ====== ==========================================================

        The profile is UTF-8 terminated by ``0x3b`` rather than length
        prefixed, and the accept swaps the two agent fields and carries a
        reserved zero byte before the count.
        """
        if not body or body[0] != SERVICE_REQUEST_TYPE:
            return None

        def u16(offset: int) -> int:
            # Short slices otherwise decode as a smaller number: a truncated
            # body would silently become a plausible channel list.
            if offset < 0 or offset + 2 > len(body):
                raise SyncError(
                    f"service request ends mid-field at offset {offset}"
                )
            return int.from_bytes(body[offset : offset + 2], "big")

        try:
            offset = 1
            remote = u16(offset)
            offset += 2
            local = u16(offset)
            offset += 2

            end_of_profile = body.index(PROFILE_TERMINATOR, offset)
            profile = body[offset:end_of_profile].decode("ascii")
            offset = end_of_profile + 1

            count = u16(offset)
            offset += 2
            if not 1 <= count <= MAX_CHANNELS:
                raise SyncError(f"service request declares {count} channels")

            sessions = [u16(offset + 2 * i) for i in range(count)]
            offset += 2 * count
            channels = [u16(offset + 2 * i) for i in range(count)]
            offset += 2 * count
            offset += 2 * count  # qos type/class pairs
            offset += count  # payload types
            if offset > len(body):
                raise SyncError("service request is shorter than it declares")
            # The device appends bytes this parser does not model (the sender keeps
            # them as `trailingBytes` and proceeds), so extra bytes are recorded
            # rather than treated as a different message. A short frame is still
            # fatal: the channel declaration would be fabricated.
            self.trailing_bytes = body[offset:]
        except (IndexError, ValueError) as exc:
            raise SyncError(f"malformed service request: {exc}") from exc

        session_map = dict(zip(sessions, channels))
        data_channels = {c for c in channels if c != CONTROL_CHANNEL}
        if CONTROL_CHANNEL not in channels:
            raise SyncError("service request declares no control channel")

        if profile != PROFILE_NAME:
            raise SyncError(
                f"service request is for {profile!r}, not {PROFILE_NAME!r}"
            )

        declared_control = sessions[channels.index(CONTROL_CHANNEL)]
        if self.channels is None or not self.channels.sessions:
            self.channels = ServiceChannels(
                sessions=session_map,
                control_session=declared_control,
                data_channels=data_channels,
            )
        else:
            # Merge, but trust the device's declaration over the session this
            # receiver adopted earlier: the device is the one that will send on
            # the control channel, so its choice is the one that must be read.
            merged = dict(self.channels.sessions)
            merged.update(session_map)
            self.channels = ServiceChannels(
                sessions=merged,
                control_session=declared_control,
                data_channels=self.channels.data_channels | data_channels,
            )
        self.service_acknowledged = True

        out = bytearray([SERVICE_ACCEPT_TYPE])
        out += local.to_bytes(2, "big")  # initiator first on the way back
        out += remote.to_bytes(2, "big")  # then acceptor
        out += profile.encode("ascii") + bytes([PROFILE_TERMINATOR])
        out.append(0)  # reserved byte the acceptor always writes
        out += len(sessions).to_bytes(2, "big")
        for session in sessions:
            out += session.to_bytes(2, "big")
        return bytes(out)

    # -- frame intake -----------------------------------------------------

    def feed(self, session_id: int, body: bytes) -> bytes | None:
        """Handle one complete session body; return the first reply body.

        Compatibility wrapper around :meth:`feed_frames`, which also says which
        session each reply belongs on. A completion request produced by a data
        frame belongs on the *control* session, not the data session it was
        triggered by, so a driver should use :meth:`feed_frames`.
        """
        replies = self.feed_frames(session_id, body)
        if not replies:
            return None
        session, reply = replies[0]
        # Legacy feed() returns the JSON itself, not the wire body; the wire
        # form (0x00 plain flag + JSON) is what feed_frames hands to a writer.
        if (
            self.channels is not None and session == self.channels.control_session
            and reply[:1] == bytes([systemft.PLAIN_CHANNEL_FLAG])
        ):
            return reply[1:]
        return reply

    def feed_frames(self, session_id: int, body: bytes) -> list[tuple[int, bytes]]:
        """Handle one complete session body.

        Returns ``[(session_id, body), ...]``: every reply to write, each with
        the session it must be written on.
        """
        self._outbox = []
        if body[:1] == bytes([SERVICE_REQUEST_TYPE]):
            # Always answer a service request, even if this receiver already
            # adopted an open service. The device's initiator does not send
            # anything else until the matching type-2 arrives, so swallowing it
            # stalls the whole sync.
            accept = self.accept_service_request(body)
            return [(session_id, accept)] if accept is not None else []
        reply = self._route(session_id, body)
        if reply is not None:
            self._outbox.insert(0, (session_id, reply))
        out, self._outbox = self._outbox, []
        # Control messages on the wire are ``00`` plain flag + JSON (the same
        # shape the device sends). The service accept on the reserved session
        # has no such flag. Every reply produced by _control() - setup-rsp,
        # complete-req, cancel, appalive - therefore gets wrapped here.
        control = self.channels.control_session if self.channels else None
        wrapped = []
        for reply_session, reply_body in out:
            if reply_session == control and reply_body[:1] != bytes([systemft.PLAIN_CHANNEL_FLAG]):
                reply_body = systemft.wrap_control(reply_body)
            wrapped.append((reply_session, reply_body))
        return wrapped

    def _route(self, session_id: int, body: bytes) -> bytes | None:
        """Route one non-type-1 body; return a reply for the same session."""
        if self.channels is None:
            return None

        if session_id == self.channels.control_session:
            return self._control(body)

        if self.message_session is not None and session_id == self.message_session:
            return None  # business traffic, not this service

        channel = self.channels.sessions.get(session_id)
        if channel is None:
            # A data session the service did not announce. Read the binding we
            # learned earlier before looking for a new one; a stale binding is
            # dropped only when its transaction is gone.
            channel = self.session_channels.get(session_id)
            if channel is not None and not self._channel_in_flight(channel):
                self.session_channels.pop(session_id, None)
                channel = None
        if channel is None:
            if body[:1] != bytes([systemft.PLAIN_CHANNEL_FLAG]):
                return None
            channel = self._learn_channel(session_id)
            if channel is None:
                return None
        if channel == CONTROL_CHANNEL:
            # The declaration maps this session to the control channel. Its
            # frames are JSON, and dropping them as "not a data channel" stalled
            # the whole sync after the service was accepted.
            return self._control(body)
        if self.channels.data_channels and channel not in self.channels.data_channels:
            return None  # a channel this service does not own
        return self._data(channel, body)

    def _channel_in_flight(self, channel: int) -> bool:
        return any(
            f.request.channel == channel
            for f in list(self.files.values()) + list(self.completing.values())
        )

    def _learn_channel(self, session_id: int) -> int | None:
        """Bind an unannounced data session to the transaction it carries.

        The device opens a fresh session per file but never says which channel
        it carries. It also never interleaves two files' chunks, so exactly one
        transfer in flight makes the owner unambiguous. With two in flight a
        guess would write one file's bytes into the other - silent corruption -
        so the frame is dropped and the anomaly counted instead.
        """
        if len(self.files) != 1:
            if self.files:
                self.result.anomalies += 1
            return None
        if self.completing:
            # An unannounced session cannot be distinguished from late data for
            # a sealed transaction. Drop it rather than risk cross-file writes.
            return None
        channel = next(iter(self.files.values())).request.channel
        self.session_channels[session_id] = channel
        return channel

    def _forget_bindings(self, channel: int) -> None:
        """Forget learned sessions for a channel whose transaction ended.

        The device may reuse the session for a later file with a different
        channel; keeping the stale binding would send those bytes to a
        transaction that no longer exists.
        """
        stale = [s for s, bound in self.session_channels.items() if bound == channel]
        for session in stale:
            self.session_channels.pop(session, None)

    def _control(self, body: bytes) -> bytes | None:
        if not body or body[0] != systemft.PLAIN_CHANNEL_FLAG:
            return None
        payload = body[1:]
        if not payload:
            return None
        try:
            msg = systemft.message_id(payload)
        except systemft.FileTransferError:
            return None

        if msg == systemft.MSG_SETUP_REQ:
            return self._setup(payload)
        if msg == systemft.MSG_COMPLETE_RSP:
            try:
                response = systemft.CompleteResponse.from_json(payload)
            except (ValueError, TypeError, systemft.FileTransferError):
                # Malformed JSON is ignored. Raising here would abort a sync
                # that is otherwise healthy because of one bad control frame.
                return None
            return self._complete_response(response)
        if msg == systemft.MSG_APPALIVE_REQ:
            try:
                trans_id = int(systemft._decode_json(payload).get("transId", 0))
            except (ValueError, TypeError, systemft.FileTransferError):
                return None
            return systemft.encode_appalive_response(trans_id)
        if msg == systemft.MSG_CANCEL_REQ:
            try:
                obj = systemft._decode_json(payload)
                trans_id = int(obj.get("transId", -1))
                reason = int(obj.get("reason", 0))
            except (ValueError, TypeError, systemft.FileTransferError):
                return None
            pending = self.files.get(trans_id) or self.completing.get(trans_id)
            if pending is None:
                return None  # a stale cancel for a file we already finished
            self._fail_transaction(
                pending, "peer_cancelled", reason,
                f"device cancelled transaction {trans_id} (reason {reason})",
                send_cancel=False,
            )
            return systemft.encode_cancel_response(trans_id, reason)
        return None  # progress/window/setup-rsp and anything new

    def _complete_response(self, response: "systemft.CompleteResponse") -> None:
        """Publish or abandon exactly the transaction the response names.

        A response for a transaction that is not sealed and waiting - unknown,
        already finished, or still receiving - is stale and ignored; it can
        neither publish nor fail anything.
        """
        incoming = self.completing.get(response.trans_id)
        if incoming is None:
            self.result.stale_complete_responses += 1
            return None
        if response.result != 0:
            self._fail_transaction(
                incoming, "peer_rejected_completion", response.reason,
                f"device rejected completion of transaction {response.trans_id} "
                f"(reason {response.reason})",
                send_cancel=False,
            )
            return None
        try:
            path = incoming.publish()
        except (systemft.FileTransferError, OSError) as exc:
            self._fail_transaction(
                incoming, "publish_failed", systemft.REASON_SINK_FAILED,
                f"publishing {incoming.request.file_name}: {exc}",
                send_cancel=False,
            )
            return None
        self.completing.pop(response.trans_id, None)
        self.completed[response.trans_id] = path
        self.result.add(
            path, incoming.request.file_size, trans_id=response.trans_id,
            remote_name=incoming.request.file_name,
            md5_checked=bool(incoming.request.md5),
        )
        self.finished = True
        return None

    def _setup(self, payload: bytes) -> bytes | None:
        """Validate and admit one offer.

        A malformed offer must be answered, never raised: one bad frame would
        otherwise abort a sync that is otherwise fine. Offers that cannot even
        be attributed to a transaction are dropped.
        """
        try:
            request = systemft.SetupRequest.from_json(payload)
        except (ValueError, TypeError, systemft.FileTransferError):
            return self._reject_unparseable(payload)

        self.result.setup_seen += 1
        try:
            reason = self._admission_reason(request)
        except (ValueError, TypeError, systemft.FileTransferError):
            return self._reject(request, systemft.REASON_SINK_FAILED)
        if reason is not None:
            return self._reject(request, reason)
        if self.name_filter is not None:
            try:
                allowed = bool(self.name_filter(request.file_name))
            except Exception:  # noqa: BLE001 - a broken filter refuses, never crashes
                allowed = False
            if not allowed:
                return self._reject(request, systemft.REASON_POLICY, policy=True)
        if self.max_accepted is not None and self.accepted_total >= self.max_accepted:
            return self._reject(request, systemft.REASON_POLICY, policy=True)

        try:
            name = Path(request.file_name).name
            if not name or name in {".", ".."}:
                # ``Path`` leaves these intact, and both would resolve to a
                # directory rather than a file.
                name = f"file-{request.trans_id}.bin"
            incoming = self._reserve_file(name, request)
        except (ValueError, TypeError, systemft.FileTransferError, OSError):
            incoming = None
        if incoming is None:
            # No writable name, exhausted candidates, or an unusable sink:
            # refuse this offer so the device moves on.
            return self._reject(request, systemft.REASON_SINK_FAILED)

        self.files[request.trans_id] = incoming
        self.accepted_total += 1
        if incoming.complete:
            # A zero-length file has no data frame to trigger finalization.
            self._seal_and_request_completion(incoming)
        return systemft.encode_setup_accept(request)

    def _admission_reason(self, request: systemft.SetupRequest) -> int | None:
        """Why this offer must be refused, or ``None`` to accept it."""
        channel = request.channel  # raises FileTransferError when not numeric
        if channel == CONTROL_CHANNEL:
            # The control channel carries JSON; file bytes there would collide
            # with the message stream.
            return systemft.REASON_BAD_CHANNEL
        declared = self.channels.data_channels
        if declared and channel not in declared:
            return systemft.REASON_BAD_CHANNEL
        if request.trans_id in self.files or request.trans_id in self.completing:
            return systemft.REASON_DUPLICATE
        if request.file_size < 0:
            return systemft.REASON_SINK_FAILED
        if (
            request.file_size > MAX_FILE_BYTES
            or len(self.files) + len(self.completing) >= MAX_INFLIGHT
        ):
            return systemft.REASON_POLICY
        return None

    def _reject(
        self, request: systemft.SetupRequest, reason: int, *, policy: bool = False
    ) -> bytes:
        self.result.reject(request.trans_id, reason, policy=policy)
        return systemft.encode_setup_reject(request, reason)

    def _reject_unparseable(self, payload: bytes) -> bytes | None:
        """Answer an offer that did not parse, when it still names a transaction.

        There is no :class:`systemft.SetupRequest` to build a reply from, so
        the transaction id and name are read defensively; without a usable id
        there is nothing to address and the frame is dropped.
        """
        try:
            obj = systemft._decode_json(payload)
        except systemft.FileTransferError:
            return None
        trans_id = obj.get("transId")
        if isinstance(trans_id, bool) or not isinstance(trans_id, int):
            return None
        file_name = obj.get("fileName")
        if not isinstance(file_name, str):
            file_name = ""
        else:
            try:
                file_name.encode("utf-8")
            except UnicodeEncodeError:
                file_name = ""
        self.result.reject(trans_id, systemft.REASON_SINK_FAILED)
        return systemft.encode_setup_reject_fields(
            trans_id, systemft.REASON_SINK_FAILED, file_name
        )

    # -- name reservation --------------------------------------------------

    def _candidates(self, name: str):
        """Every name a file may take, bounded by ``MAX_NAME_ATTEMPTS``."""
        yield self.output_dir / name
        stem, suffix = _split_rename(name)
        for index in range(2, MAX_NAME_ATTEMPTS + 1):
            yield self.output_dir / f"{stem}-{index}{suffix}"

    def _unique_path(
        self, name: str, skip: frozenset[Path] = frozenset()
    ) -> Path | None:
        """A name no file, directory or dangling symlink occupies.

        ``Path.exists`` follows links, so a dangling symlink looks free while a
        later ``open`` would create its target outside ``output_dir``.
        ``os.path.lexists`` counts the link itself. A staging file left by an
        interrupted run also blocks the name: the exclusive open would refuse
        it anyway. ``skip`` carries names a lost ``O_EXCL`` race already ruled
        out. ``None`` means every candidate is taken and the caller must reject
        the offer, not raise.
        """
        for candidate in self._candidates(name):
            if candidate in skip:
                continue
            if os.path.lexists(candidate):
                continue
            if os.path.lexists(systemft.part_path_for(candidate)):
                continue
            return candidate
        return None

    def _reserve_file(
        self, name: str, request: systemft.SetupRequest
    ) -> systemft.IncomingFile | None:
        """Claim a candidate name atomically, moving on when it is taken.

        ``_unique_path`` only proposes a name; ``IncomingFile.open`` claims it
        with ``O_EXCL``. Losing that claim (a racing writer) must try the next
        candidate rather than fail the transfer. ``skip`` guarantees a lost
        race moves forward even if the winner's entry has already vanished.
        ``None`` means the names are exhausted or the sink is unusable; the
        caller rejects the setup.
        """
        lost_races: frozenset[Path] = frozenset()
        for _attempt in range(MAX_NAME_ATTEMPTS):
            candidate = self._unique_path(name, lost_races)
            if candidate is None:
                return None
            incoming = systemft.IncomingFile(request=request, path=candidate)
            try:
                incoming.open()
            except FileExistsError:
                # Someone else claimed this name: try the next candidate, even
                # if their entry is already gone again.
                lost_races = lost_races | {candidate}
                continue
            except OSError:
                incoming.abandon()
                return None
            return incoming
        return None

    # -- data --------------------------------------------------------------

    def _owner_for_channel(self, channel: int) -> int | None:
        """The transaction currently receiving on ``channel``.

        A guess is safe only when exactly one file is in flight. With two, an
        unmatched channel is ambiguous, and attributing it to any single file
        corrupts that file, so the frame is dropped and counted as an anomaly.
        """
        # A sealed transaction is waiting for complete-rsp, not for more data.
        # Never let its late chunks fall through to the "one file in flight"
        # fallback and get appended to the next file on the same channel.
        if any(f.request.channel == channel for f in self.completing.values()):
            return None
        owners = [t for t, f in self.files.items() if f.request.channel == channel]
        if len(owners) == 1:
            return owners[0]
        if not owners and len(self.files) == 1:
            return next(iter(self.files))
        if self.files:
            self.result.anomalies += 1
        return None

    def _data(self, channel: int, body: bytes) -> bytes | None:
        if not body or body[0] != systemft.PLAIN_CHANNEL_FLAG:
            return None
        try:
            chunk = systemft.decode_chunk(body[1:])
        except systemft.FileTransferError:
            return None

        owner = self._owner_for_channel(channel)
        if owner is None:
            return None

        incoming = self.files[owner]
        try:
            incoming.write(chunk)
        except (systemft.FileTransferError, OSError) as exc:
            # ENOSPC/EIO included: abandoning closes the handle and removes the
            # staging bytes, so a failed write cannot leak either. The sender is
            # told, so it stops pushing a file that can never be published.
            self._fail_transaction(
                incoming, "receive_failed", systemft.REASON_SINK_FAILED,
                f"receiving {incoming.request.file_name}: {exc}",
                send_cancel=True,
            )
            return None
        self.result.bytes_received += len(chunk)

        if not incoming.complete:
            return None
        self._seal_and_request_completion(incoming)
        return None

    def _seal_and_request_completion(self, incoming: systemft.IncomingFile) -> None:
        """Verify a fully received file and ask the peer to confirm it.

        The staging file stays unpublished until _complete_response sees the
        matching result-0 response.
        """
        try:
            incoming.seal()
        except systemft.FileTransferError as exc:
            self._fail_transaction(
                incoming, "md5_mismatch" if "MD5" in str(exc) else "seal_failed",
                systemft.REASON_MD5_MISMATCH if "MD5" in str(exc)
                else systemft.REASON_SINK_FAILED,
                str(exc), send_cancel=True,
            )
            return
        except OSError as exc:
            self._fail_transaction(
                incoming, "seal_failed", systemft.REASON_SINK_FAILED,
                f"syncing {incoming.request.file_name}: {exc}", send_cancel=True,
            )
            return

        owner = incoming.request.trans_id
        self.files.pop(owner, None)
        self._forget_bindings(incoming.request.channel)
        self.completing[owner] = incoming
        self._reply_control(
            systemft.encode_complete_request(owner, incoming.request.file_name)
        )

        return None

    # -- teardown ---------------------------------------------------------

    def abandon(self) -> list[dict[str, Any]]:
        """Drop every unpublished transaction; return what was dropped.

        A sealed file still waiting for its complete-rsp is dropped too: without
        the peer's confirmation it is not a completed transfer. Published files
        are never touched.
        """
        dropped = []
        for state, table in (("receiving", self.files), ("awaiting_complete_rsp", self.completing)):
            for trans_id, incoming in table.items():
                dropped.append({
                    "transId": trans_id,
                    "state": state,
                    "receivedBytes": incoming.received,
                    "declaredBytes": incoming.request.file_size,
                })
                incoming.abandon()
            table.clear()
        self.session_channels.clear()
        return dropped

# --------------------------------------------------------------------------
# Range driver: one authenticated channel, one or more ranges
# --------------------------------------------------------------------------

# Explicit outcome states. Only RANGE_COMPLETED is a success; it covers an
# empty range too (a matching 06/08 with no offers is a real answer: the device
# holds nothing there).
RANGE_COMPLETED = "range_completed"
RANGE_COMPLETED_WITH_FAILURES = "range_completed_with_failures"
RANGE_COMPLETED_DRAIN_TIMEOUT = "range_completed_drain_timeout"
TRANSFER_FAILED = "transfer_failed"
WINDOW_ELAPSED_FILES_PUBLISHED_RANGE_UNVERIFIED = (
    "window_elapsed_files_published_range_unverified"
)
WINDOW_ELAPSED_PARTIAL_UNVERIFIED = "window_elapsed_partial_unverified"
WINDOW_ELAPSED_NO_FILES = "window_elapsed_no_files"
LINK_LOST = "link_lost"
RANGE_REQUEST_NOT_WRITTEN = "range_request_not_written"
NOT_STARTED = "not_started"

_RETRY_GUIDANCE = {
    RANGE_COMPLETED: "none needed",
    RANGE_COMPLETED_WITH_FAILURES: (
        "The device finished the range but at least one transaction was lost. "
        "Published files are complete and kept. Request the same range again on "
        "a NEW connection to re-fetch lost files whole; partial bytes are never "
        "resumed, and already-published names are kept as -2, -3 copies."
    ),
    RANGE_COMPLETED_DRAIN_TIMEOUT: (
        "The device reported the range end, but a transaction was still open at "
        "the host deadline. Re-run the same range on a new connection with a "
        "longer window."
    ),
    TRANSFER_FAILED: (
        "A transaction failed and the sequence stopped there. Fix the cause in "
        "the diagnostics (disk space, permissions), then request the same range "
        "on a new connection."
    ),
    WINDOW_ELAPSED_FILES_PUBLISHED_RANGE_UNVERIFIED: (
        "Every offered file was published, but no matching 06/08 arrived, so the "
        "range is not proven complete. Do not resend on this connection (the "
        "device may ignore a duplicate request). Re-run on a new connection; a "
        "range whose end is in the device's future only reports its end once "
        "the device clock passes it, so prefer a past end."
    ),
    WINDOW_ELAPSED_PARTIAL_UNVERIFIED: (
        "The window ended with a transfer unfinished or lost and no range end. "
        "Re-run the same range on a new connection with a longer window; "
        "partial bytes are discarded, never resumed."
    ),
    WINDOW_ELAPSED_NO_FILES: (
        "Nothing was offered and no range end arrived before the deadline. This "
        "is NOT proof the range is empty. Re-run once on a new connection with a "
        "past end and a longer window; do not loop."
    ),
    LINK_LOST: (
        "The link dropped. Published files are complete and kept; unfinished "
        "ones were discarded. Reconnect and request the same range once; it is "
        "re-sent as whole new transactions."
    ),
    RANGE_REQUEST_NOT_WRITTEN: (
        "The range request never reached the link, so nothing was asked of the "
        "device. It is safe to retry."
    ),
    NOT_STARTED: (
        "An earlier range in the sequence did not complete, so this one was not "
        "requested. Re-run the sequence from this range."
    ),
}


def retry_guidance(state: str) -> str:
    return _RETRY_GUIDANCE.get(state, "inspect diagnostics before retrying")


def window_outcome(
    *, eof_seen: bool, active: int, published: int, failed: bool
) -> str:
    """The state for a range that ran out of host time (Swift parity)."""
    if eof_seen:
        return RANGE_COMPLETED_DRAIN_TIMEOUT if active else (
            RANGE_COMPLETED_WITH_FAILURES if failed else RANGE_COMPLETED
        )
    if published and not failed and not active:
        return WINDOW_ELAPSED_FILES_PUBLISHED_RANGE_UNVERIFIED
    if published or failed or active:
        return WINDOW_ELAPSED_PARTIAL_UNVERIFIED
    return WINDOW_ELAPSED_NO_FILES


@dataclass
class RangeProgress:
    """What one range request observed, for the structured result."""

    start_ms: int
    end_ms: int
    request_written: bool = False
    echo_seen: bool = False
    eof_seen: bool = False
    eof_prewrite_ignored: int = 0
    eof_mismatched: int = 0
    eof_unauthenticated: int = 0
    eof_nonfinite: int = 0
    cycle_reports: int = 0
    other_business: int = 0
    rejected_frames: int = 0
    files_before: int = 0
    bytes_before: int = 0
    offers_before: int = 0
    rejected_before: int = 0
    failures_before: int = 0
    failures_recorded_before: int = 0
    started_at: float = field(default_factory=time.monotonic)


class RangeSyncDriver:
    """Drive ``06/00`` range requests over one connected channel.

    The channel is the :class:`connect.ConnectedChannel` a ``sync=True``
    connect returned: one authentication, one secure counter pair, one
    accepted ``system:filetransfer`` service. :meth:`run_range` may be called
    again for the next range on the same channel; the shared receiver keeps
    its declared channels, and the caller's overall deadline is respected.

    A range is complete only on an *authenticated* ``06/08`` carrying exactly
    the written range, read after the request was handed to the link, and
    only once every accepted transaction is published or abandoned.
    """

    def __init__(
        self,
        channel: Any,
        receiver: SyncReceiver,
        *,
        write: Callable[[int, bytes], None] | None = None,
        read_slice: float = 1.0,
    ) -> None:
        self.channel = channel
        self.receiver = receiver
        self._write_body = write or self._default_write
        self.read_slice = read_slice
        self.link_lost = False

    def _default_write(self, session_id: int, body: bytes) -> None:
        from .transport import BUSINESS_WRITE

        for frame in framing.split(session_id, body):
            self.channel.session.write(
                BUSINESS_WRITE, frame, self.channel.session.timeout
            )

    # -- message session -------------------------------------------------

    def _business(self, body: bytes, progress: RangeProgress) -> None:
        from .secure import SecureChannelError

        try:
            message = self.channel.decode_business(body)
        except SecureChannelError:
            progress.rejected_frames += 1
            return
        except XinliqiuError:
            progress.other_business += 1
            return
        if message is None:
            return
        header = (message.service, message.command)
        if header == commands.SYNC_RANGE_ECHO:
            echo = commands.parse_range_echo(message.payload)
            if echo == (progress.start_ms, progress.end_ms):
                progress.echo_seen = True  # an echo, never acceptance
            return
        if header == commands.SYNC_RANGE_END:
            eof = commands.parse_range_echo(message.payload)
            if eof != (progress.start_ms, progress.end_ms):
                progress.eof_mismatched += 1
            elif not message.authenticated:
                progress.eof_unauthenticated += 1
            elif not commands.is_finite_range(*eof):
                # 06/08 exists only for a finite end; Int64.max has no such
                # report in the reviewed implementation.
                progress.eof_nonfinite += 1
            elif not progress.request_written:
                progress.eof_prewrite_ignored += 1
            else:
                progress.eof_seen = True
            return
        if header == commands.SYNC_RANGE_CYCLE:
            progress.cycle_reports += 1
            return
        progress.other_business += 1

    # -- one range -------------------------------------------------------

    def run_range(
        self, start_ms: int, end_ms: int, *, deadline: float,
        output_dir: Path | None = None,
    ) -> dict[str, Any]:
        receiver = self.receiver
        if output_dir is not None:
            receiver.set_output_dir(output_dir)
        result = receiver.result
        progress = RangeProgress(
            start_ms=start_ms,
            end_ms=end_ms,
            files_before=len(result.files),
            bytes_before=result.bytes_published,
            offers_before=result.setup_seen,
            rejected_before=result.rejected_total,
            failures_before=result.failures_total,
            failures_recorded_before=len(result.failures),
        )
        failed_before = (
            result.failures_total, result.unplanned_rejections, result.service_failures
        )

        def failed_now() -> bool:
            return (
                result.failures_total, result.unplanned_rejections,
                result.service_failures,
            ) != failed_before

        payload = commands.sync_range_payload(start_ms, end_ms)
        if time.monotonic() >= deadline:
            # The shared budget is already gone; do not put another request on
            # the air just to report its timeout.
            return self._finish(
                progress, RANGE_REQUEST_NOT_WRITTEN,
                "the overall sync deadline was exhausted before the request",
            )
        # Message-session frames parked before this request was written (during
        # connect, or late reports of an earlier range) belong to an older job:
        # a matching 06/08 among them is counted as pre-write and never
        # completes this request.
        parked = getattr(self.channel, "pending_frames", None)
        if parked:
            mine = [b for sid, b in parked if sid == self.channel.session_id]
            parked[:] = [(sid, b) for sid, b in parked if sid != self.channel.session_id]
            for body in mine:
                self._business(body, progress)
        try:
            self.channel.send_only(
                commands.SERVICE_SYNC[0], commands.SERVICE_SYNC[1], payload
            )
        except LinkLost as exc:
            self.link_lost = True
            return self._finish(progress, LINK_LOST, str(exc))
        except TransportError as exc:
            return self._finish(progress, RANGE_REQUEST_NOT_WRITTEN, str(exc))
        progress.request_written = True

        state: str | None = None
        detail = ""
        while state is None:
            if progress.eof_seen and receiver.active_transactions == 0:
                state = RANGE_COMPLETED_WITH_FAILURES if failed_now() else RANGE_COMPLETED
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state = window_outcome(
                    eof_seen=progress.eof_seen,
                    active=receiver.active_transactions,
                    published=len(result.files) - progress.files_before,
                    failed=failed_now(),
                )
                break
            try:
                got = self.channel.read_raw(min(remaining, self.read_slice))
            except LinkLost as exc:
                self.link_lost = True
                state, detail = LINK_LOST, str(exc)
                break
            except TransportError as exc:
                # A non-idle transport failure is not a quiet stream. Surface
                # it as a failed operation rather than looping until timeout.
                if getattr(self.channel, "link_lost", False):
                    self.link_lost = True
                    state = LINK_LOST
                else:
                    state = TRANSFER_FAILED
                detail = str(exc)
                break
            if got is None:
                continue  # quiet is never completion; only the deadline ends a wait
            session_id, body = got
            if not body:
                continue
            if session_id == self.channel.session_id:
                self._business(body, progress)
                continue
            try:
                replies = receiver.feed_frames(session_id, body)
            except SyncError as exc:
                result.service_failures += 1
                if receiver.error is None:
                    receiver.error = str(exc)
                continue
            try:
                for reply_session, reply in replies:
                    self._write_body(reply_session, reply)
            except LinkLost as exc:
                self.link_lost = True
                state, detail = LINK_LOST, str(exc)
                break
            except TransportError as exc:
                # A control reply that cannot be written leaves the device
                # waiting on this host; the range cannot complete honestly.
                state, detail = TRANSFER_FAILED, f"writing a control reply: {exc}"
                break
        return self._finish(progress, state, detail)

    def _finish(self, progress: RangeProgress, state: str, detail: str = "") -> dict[str, Any]:
        receiver = self.receiver
        result = receiver.result
        dropped: list[dict[str, Any]] = []
        if state != RANGE_COMPLETED and receiver.active_transactions:
            # Nothing unconfirmed may linger under any name: abandon removes
            # staging files only, never a published one.
            dropped = receiver.abandon()
        new_files = result.files[progress.files_before:]
        new_published = result.published[progress.files_before:]
        failures = result.failures[progress.failures_recorded_before:]
        return {
            "state": state,
            "ok": state == RANGE_COMPLETED,
            "verified": state == RANGE_COMPLETED,
            "reason": state,
            "range_complete": state in (
                RANGE_COMPLETED, RANGE_COMPLETED_WITH_FAILURES,
                RANGE_COMPLETED_DRAIN_TIMEOUT,
            ),
            "start_ms": progress.start_ms,
            "end_ms": progress.end_ms,
            "files": [str(p) for p in new_files],
            "published": new_published,
            "count": len(new_files),
            "bytes": result.bytes_published - progress.bytes_before,
            "offers": result.setup_seen - progress.offers_before,
            "rejected": result.rejected_total - progress.rejected_before,
            "failures": failures,
            "abandoned": dropped,
            "retry": retry_guidance(state),
            "diagnostics": {
                "request_written": progress.request_written,
                "echo_seen": progress.echo_seen,
                "eof_seen": progress.eof_seen,
                "eof_mismatched": progress.eof_mismatched,
                "eof_unauthenticated": progress.eof_unauthenticated,
                "eof_nonfinite": progress.eof_nonfinite,
                "eof_prewrite_ignored": progress.eof_prewrite_ignored,
                "cycle_reports": progress.cycle_reports,
                "other_business": progress.other_business,
                "rejected_frames": progress.rejected_frames,
                "stale_complete_responses": result.stale_complete_responses,
                "service_failures": result.service_failures,
                "anomalies": result.anomalies,
                "active_transactions": receiver.active_transactions,
                "elapsed_s": round(time.monotonic() - progress.started_at, 3),
                "detail": detail or receiver.error or "",
            },
        }

    # -- several ranges --------------------------------------------------

    def run_ranges(
        self, ranges: list[tuple[int, int]], *, deadline: float,
        output_dirs: list[Path] | None = None,
    ) -> dict[str, Any]:
        """Run each range in order on this channel; stop at the first non-success.

        Every range after a failure is reported as :data:`NOT_STARTED`, so the
        caller can resume the sequence exactly there.
        """
        pairs = [(start, end) for start, end in ranges]
        if output_dirs is not None and len(output_dirs) != len(pairs):
            raise ValueError("output_dirs must have one directory per range")
        if len(set(pairs)) != len(pairs):
            raise ValueError("sync ranges must be distinct so a late EOF is attributable")
        results: list[dict[str, Any]] = []
        stopped_at: int | None = None
        for index, (start, end) in enumerate(pairs):
            if stopped_at is not None:
                results.append({
                    "state": NOT_STARTED, "ok": False, "verified": False,
                    "reason": NOT_STARTED, "range_complete": False,
                    "start_ms": start, "end_ms": end, "files": [], "count": 0,
                    "bytes": 0, "retry": retry_guidance(NOT_STARTED),
                })
                continue
            part = self.run_range(
                start, end, deadline=deadline,
                output_dir=output_dirs[index] if output_dirs else None,
            )
            results.append(part)
            if not part["ok"]:
                stopped_at = index
        files = [f for part in results for f in part.get("files", [])]
        state = results[stopped_at]["state"] if stopped_at is not None else RANGE_COMPLETED
        return {
            "state": state,
            "ok": stopped_at is None,
            "verified": stopped_at is None,
            "range_complete": stopped_at is None,
            "stopped_at": stopped_at,
            "ranges": results,
            "files": files,
            "count": len(files),
            "bytes": sum(part.get("bytes", 0) for part in results),
            "retry": retry_guidance(state),
        }


# --------------------------------------------------------------------------
# Voiceprint collection on the same connection
# --------------------------------------------------------------------------

VOICEPRINT_COLLECTED = "voiceprint_collected"
VOICEPRINT_START_NOT_WRITTEN = "voiceprint_start_not_written"
VOICEPRINT_NO_FILE = "voiceprint_no_file"
VOICEPRINT_TRANSFER_FAILED = "voiceprint_transfer_failed"
VOICEPRINT_LINK_LOST = "voiceprint_link_lost"

# The only voiceprint business notifications whose metadata is useful and
# reviewed for CLI diagnostics. Payload bytes are deliberately never exported.
_VOICEPRINT_DIAGNOSTIC_COMMANDS = frozenset({(0x02, 0x0A), (0x02, 0x0C)})

_VOICEPRINT_RETRY = {
    VOICEPRINT_COLLECTED: "none needed",
    VOICEPRINT_START_NOT_WRITTEN: (
        "START never reached the link; nothing was asked of the device. Safe to retry."
    ),
    VOICEPRINT_NO_FILE: (
        "START was written but no complete .vp.opus arrived in the window. One "
        "cleanup stop was attempted (see cleanup_stop). Ordinary-range re-read "
        "is unproven, so a retry is a NEW capture: run it again with a longer "
        "host window."
    ),
    VOICEPRINT_TRANSFER_FAILED: (
        "The voiceprint transfer failed (see failures). A retry is a NEW capture."
    ),
    VOICEPRINT_LINK_LOST: (
        "The link dropped before the file completed; the capture cannot be "
        "re-fetched. A retry is a NEW capture."
    ),
}


def collect_voiceprint(
    channel: Any,
    output_dir: Path,
    *,
    duration: int,
    deadline: float,
    read_slice: float = 1.0,
    cleanup_grace: float = 0.75,
) -> dict[str, Any]:
    """Send one ``07 02 <duration>`` START and receive exactly its file.

    Runs on an already-connected ``sync=True`` channel, so the file arrives on
    the same authenticated link. Only an offer named ``*.vp.opus`` (including
    ``.enc.vp.opus``) made after START was written is accepted, and only one;
    everything else is refused with a policy reason. No ``06/00`` is sent.

    If START was written but no file completes, exactly one ``07 02 00``
    cleanup stop is written while the link is still up; whether it was
    written is reported, never whether it took effect.
    """
    if isinstance(duration, bool) or not isinstance(duration, int) or not 1 <= duration <= 127:
        raise ValueError("voiceprint duration must be within 1..127 seconds")
    started = {"written": False}

    def accept(name: str) -> bool:
        return started["written"] and systemft.is_voiceprint_name(name)

    receiver = SyncReceiver(
        output_dir,
        control_session=getattr(channel, "system_session_id", None),
        message_session=channel.session_id,
        name_filter=accept,
        max_accepted=1,
    )
    driver = RangeSyncDriver(channel, receiver, read_slice=read_slice)
    notices: list[dict[str, Any]] = []
    start_attempted = False
    state: str | None = None
    detail = ""

    from .secure import SecureChannelError

    # read_reply() may have parked frames before this operation began. They are
    # pre-START by arrival order. Service negotiation must still be answered or
    # the current capture has no data channels. Complete file transactions from
    # an earlier capture are discarded instead of being offered to this receiver.
    pending = getattr(channel, "pending_frames", None)
    prestart_frames = list(pending) if pending else []
    if prestart_frames:
        pending.clear()
    prestart_discarded = 0
    prestart_service_processed = 0
    for session_id, body in prestart_frames:
        if session_id == channel.session_id:
            # Decode valid business frames to advance the authenticated stream
            # counter; dropping encrypted bytes without opening them would
            # desynchronise every subsequent reply.
            prestart_discarded += 1
            try:
                channel.decode_business(body)
            except (SecureChannelError, XinliqiuError):
                pass
            continue
        if session_id == 1 and body[:1] == bytes([SERVICE_REQUEST_TYPE]):
            try:
                replies = receiver.feed_frames(session_id, body)
                for reply_session, reply in replies:
                    driver._write_body(reply_session, reply)
                prestart_service_processed += 1
            except LinkLost as exc:
                state, detail = VOICEPRINT_LINK_LOST, str(exc)
                break
            except (TransportError, SyncError) as exc:
                state, detail = VOICEPRINT_TRANSFER_FAILED, str(exc)
                break
        else:
            # A setup offer, data chunk or completion from an older capture is
            # never allowed to satisfy this new START.
            prestart_discarded += 1

    t0 = time.monotonic()
    try:
        if state is None:
            start_attempted = True
            channel.send_only(
                commands.SERVICE_APPRECORD[0], commands.SERVICE_APPRECORD[1],
                bytes([duration]),
            )
            started["written"] = True
    except LinkLost as exc:
        state, detail = VOICEPRINT_LINK_LOST, str(exc)
    except TransportError as exc:
        state, detail = VOICEPRINT_START_NOT_WRITTEN, str(exc)

    while state is None:
        if receiver.result.files:
            state = VOICEPRINT_COLLECTED
            break
        if (
            receiver.result.failures_total
            or receiver.result.unplanned_rejections
            or receiver.result.service_failures
        ):
            state = VOICEPRINT_TRANSFER_FAILED
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            state = VOICEPRINT_NO_FILE
            break
        try:
            got = channel.read_raw(min(remaining, read_slice))
        except LinkLost as exc:
            state, detail = VOICEPRINT_LINK_LOST, str(exc)
            break
        except TransportError as exc:
            state = (
                VOICEPRINT_LINK_LOST if getattr(channel, "link_lost", False)
                else VOICEPRINT_TRANSFER_FAILED
            )
            detail = str(exc)
            break
        if got is None:
            continue
        session_id, body = got
        if not body:
            continue
        if session_id == channel.session_id:
            try:
                message = channel.decode_business(body)
            except (SecureChannelError, XinliqiuError):
                continue
            if (
                message is not None
                and message.authenticated
                and (message.service, message.command) in _VOICEPRINT_DIAGNOSTIC_COMMANDS
                and len(notices) < 32
            ):
                # 02/0A (app-record mode 1/0) and 02/0C are observations only;
                # neither proves the mode exited. Do not export arbitrary
                # business payloads into CLI JSON: service/command, auth and
                # timing are sufficient diagnostics and cannot leak notify data.
                notices.append({
                    "service": message.service, "command": message.command,
                    "authenticated": True,
                    "t_s": round(time.monotonic() - t0, 3),
                })
            continue
        try:
            replies = receiver.feed_frames(session_id, body)
        except SyncError as exc:
            receiver.result.service_failures += 1
            detail = str(exc)
            continue
        try:
            for reply_session, reply in replies:
                driver._write_body(reply_session, reply)
        except LinkLost as exc:
            state, detail = VOICEPRINT_LINK_LOST, str(exc)
            break
        except TransportError as exc:
            state, detail = VOICEPRINT_TRANSFER_FAILED, f"writing a control reply: {exc}"
            break

    dropped = receiver.abandon() if state != VOICEPRINT_COLLECTED else []
    cleanup = "not_needed"
    if state != VOICEPRINT_COLLECTED and start_attempted and state != VOICEPRINT_START_NOT_WRITTEN:
        if state == VOICEPRINT_LINK_LOST or getattr(channel, "link_lost", False):
            cleanup = "not_sent_link_lost"
        else:
            try:
                channel.send_only(
                    commands.SERVICE_APPRECORD[0], commands.SERVICE_APPRECORD[1], b"\x00"
                )
                cleanup = "write_attempted_unconfirmed"
                if cleanup_grace > 0:
                    time.sleep(cleanup_grace)  # let the write leave the host
            except TransportError as exc:
                cleanup = f"write_failed: {exc}"
    files = [str(p) for p in receiver.result.files]
    return {
        "state": state,
        "ok": state == VOICEPRINT_COLLECTED,
        "verified": state == VOICEPRINT_COLLECTED,
        "file_completed": bool(receiver.result.files),
        "start_write_attempted": start_attempted,
        "start_write_completed": started["written"],
        "seconds": duration,
        "start": (
            "written" if started["written"]
            else "write_attempted_failed" if start_attempted else "not_attempted"
        ),
        "file": files[0] if files else None,
        "files": files,
        "published": receiver.result.published,
        "bytes": receiver.result.bytes_published,
        "offers": receiver.result.setup_seen,
        "refused_offers": receiver.result.rejected_total,
        "failures": receiver.result.failures,
        "abandoned": dropped,
        "cleanup_stop": cleanup,
        "cleanup_stop_write_attempted": cleanup.startswith("write_attempted"),
        "notifications": notices,
        "retry": _VOICEPRINT_RETRY.get(state, ""),
        "diagnostics": {
            "detail": detail or receiver.error or "",
            "service_failures": receiver.result.service_failures,
            "stale_complete_responses": receiver.result.stale_complete_responses,
            "elapsed_s": round(time.monotonic() - t0, 3),
            "prestart_frames_discarded": prestart_discarded,
            "prestart_service_frames_processed": prestart_service_processed,
            "range_request_sent": False,
        },
    }
