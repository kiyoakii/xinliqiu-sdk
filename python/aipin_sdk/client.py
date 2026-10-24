# -*- coding: utf-8 -*-
"""The client object users interact with.

Everything here runs on this project's own protocol implementation over
``bleak``; there is no external binary to obtain. Each call opens a link, runs
the negotiation and authentication handshake, performs the request, and closes.

Covered: pairing, device status, storage totals, recording control, voiceprint
capture, and the SystemFT file stream that carries recordings off the device.

Every device operation that can end in more than one way returns a dictionary
with an explicit ``state``, an ``ok`` flag that is true only for a verified
success, ``retry`` guidance that is safe to follow, and ``diagnostics``. Use
:meth:`Xinliqiu.require_ok` to turn a non-success into an exception.
"""

from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from .errors import NotAuthenticated, OperationIncomplete, Unsupported, XinliqiuError
from .protocol import commands, connect as connect_proto, provision
from .protocol.auth import Pairing
from .protocol.transport import BUSINESS_NOTIFY, LinkLost, Session, TransportError
from .capabilities import CAPABILITIES, describe as describe_capabilities

if TYPE_CHECKING:
    from .protocol.init import Signer


def _business_payload(reply: bytes) -> bytes:
    """Strip the ``service || command`` envelope a business reply carries."""
    if len(reply) < 2:
        raise XinliqiuError(f"business reply is only {len(reply)} bytes")
    return reply[2:]


def scan_devices(name: str | None = None, seconds: float = 10.0):
    """Blocking scan; imported lazily so the SDK works without ``bleak``."""
    from .protocol.bleak_backend import scan as _scan

    return _scan(name, seconds)


# Retained for callers that imported them; the range driver no longer stops on
# quiet, and it never re-sends a range on the same connection (the device may
# treat a duplicate request in one session as already handled).
IDLE_SECONDS_AFTER_FILES = 25.0
RESEND_AFTER_SECONDS = 8.0

# Host windows (seconds). These bound how long the host waits; they are not
# device parameters.
MAX_WINDOW_SECONDS = 3600
DEFAULT_SYNC_SECONDS = 300
DEFAULT_SYNC_RANGES_SECONDS = 600
MAX_SYNC_RANGES = 16

# record-stop: one STOP, then at most this many status observations, one
# second apart. record-start observes the same way and never re-sends START.
STATUS_OBSERVATIONS = 3
STATUS_OBSERVATION_INTERVAL = 1.0
STATUS_REPLY_SECONDS = 8.0

CONNECT_FAILED = "connect_failed"


@dataclass(frozen=True)
class Credentials:
    """Everything needed to talk to one already-paired device.

    ``key_file`` is the JSON written by :func:`protocol.provision.pair`: the
    pairing key, the alias it was registered under, and both identifiers. The
    ``pair`` generates and persists this material; ``Credentials`` only reads
    the caller-selected files and never uploads their contents. Paths are
    expanded and made absolute on construction.
    """

    device_id: str
    peer_id_file: Path
    key_file: Path

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "peer_id_file", Path(self.peer_id_file).expanduser().absolute()
        )
        object.__setattr__(self, "key_file", Path(self.key_file).expanduser().absolute())

    def require_files(self) -> None:
        if not self.peer_id_file.exists():
            raise NotAuthenticated(f"peer id file not found: {self.peer_id_file}")
        if not self.key_file.exists():
            raise NotAuthenticated(f"pairing file not found: {self.key_file}")

    def pairing(self) -> Pairing:
        self.require_files()
        return provision.load_pairing(self.key_file)

    def peer_id(self) -> str:
        self.require_files()
        return provision.validate_peer_id(
            self.peer_id_file.read_text(encoding="utf-8").strip()
        )


@dataclass(frozen=True)
class RecordStatus:
    recording: bool
    battery_percent: int | None
    error_code: int | None
    device_timestamp_ms: int | None
    raw: dict[str, Any]
    #: The reply opened under the session key (always True: unauthenticated
    #: replies are refused).
    authenticated: bool = True


def _status_from(reply: bytes) -> RecordStatus:
    parsed = commands.DeviceStatus.parse(reply)
    return RecordStatus(
        recording=parsed.recording,
        battery_percent=parsed.battery_percent,
        error_code=parsed.error_byte,
        device_timestamp_ms=parsed.device_timestamp_ms,
        raw={
            "recordByte": parsed.record_byte,
            "chargeByte": parsed.charge_byte,
            "batteryByte": parsed.battery_percent,
            "errorByte": parsed.error_byte,
            "timestampMs": parsed.device_timestamp_ms,
        },
    )


def _check_ms(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer number of milliseconds")
    if not 0 <= value <= commands.INT64_MAX:
        raise ValueError(f"{label} must fit a non-negative signed 64-bit value")
    return value


def _check_range(start_ms: Any, end_ms: Any) -> tuple[int, int]:
    start = _check_ms(start_ms, "start_ms")
    end = _check_ms(end_ms, "end_ms")
    if end < start:
        raise ValueError("sync range must not end before it starts")
    return start, end


def _check_window(seconds: Any, label: str = "sync window") -> float:
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        raise ValueError(f"{label} must be a number of seconds")
    if not 1 <= seconds <= MAX_WINDOW_SECONDS:
        raise ValueError(f"{label} must be within 1..{MAX_WINDOW_SECONDS} seconds")
    return float(seconds)


@dataclass
class _Link:
    """An open authenticated channel and how to close it."""

    channel: Any
    close: Callable[[], None]
    info: dict[str, Any] = field(default_factory=dict)


class Xinliqiu:
    """Synchronous client for one device.

    ``agent_public_key`` is the package signing key as SPKI (DER, PEM or one
    line of base64). When set, the type-6 agent response carries
    ``00 01 || BE16(len) || SPKI`` exactly as the tested tool does, and the
    agent package defaults to :data:`connect.OFFICIAL_AGENT_PACKAGE`; without
    it the four-byte "no signature" fallback and the host's own package are
    used. The key is validated before any radio use.

    ``bind_start_delay_ms`` defaults to the tested profile's 1000 ms; it only
    delays the first business request after service acceptance.

    ``on_disconnect`` is called when the platform reports that the link
    dropped; every operation also reports it in its result.
    """

    def __init__(
        self,
        credentials: Credentials,
        *,
        agent_public_key: Path | None = None,
        owner_private_key: Path | None = None,
        timeout: float = 45.0,
        agent_package: str | None = None,
        agent_id: int = connect_proto.DEFAULT_AGENT_ID,
        bind_start_delay_ms: int | None = None,
        on_disconnect: Callable[[], None] | None = None,
    ) -> None:
        self.credentials = credentials
        self.agent_public_key = (
            Path(agent_public_key).expanduser().absolute() if agent_public_key else None
        )
        self.owner_private_key = (
            Path(owner_private_key).expanduser().absolute() if owner_private_key else None
        )
        self.timeout = timeout
        self.agent_package = agent_package
        self.agent_id = agent_id
        self.bind_start_delay_ms = (
            connect_proto.TESTED_BIND_START_DELAY_MS
            if bind_start_delay_ms is None
            else bind_start_delay_ms
        )
        self.on_disconnect = on_disconnect
        self._agent_der: bytes | None = None

    # -- plumbing --------------------------------------------------------

    def connect_options(self) -> dict[str, Any]:
        """Validated agent/bind settings for ``connect()``, before any radio use."""
        der = None
        if self.agent_public_key is not None:
            der = connect_proto.load_agent_public_key(self.agent_public_key)
        package = self.agent_package or (
            connect_proto.OFFICIAL_AGENT_PACKAGE if der is not None
            else connect_proto.DEFAULT_PACKAGE
        )
        delay = self.bind_start_delay_ms
        if (
            isinstance(delay, bool) or not isinstance(delay, int)
            or not 0 <= delay <= connect_proto.MAX_BIND_START_DELAY_MS
        ):
            raise ValueError("bind start delay must be an integer 0...2000 ms")
        if not package or "\x00" in package or len(package.encode("utf-8")) > 255:
            raise ValueError("agent package must be 1...255 non-NUL UTF-8 bytes")
        self._agent_der = der
        return {
            "agent_public_key": der,
            "package": package,
            "bind_start_delay_ms": delay,
            "agent_id": self.agent_id,
        }

    def _open_channel(self, *, sync: bool) -> _Link:
        """Connect, subscribe to AA16, run the handshake; return the channel.

        Tests and alternative transports override this one method.
        """
        from .protocol.bleak_backend import BleakBackend

        options = self.connect_options()  # validated before the radio
        pairing = self.credentials.pairing()
        peer_id = self.credentials.peer_id()
        backend = BleakBackend(on_disconnect=self.on_disconnect)
        session = Session(backend, self.credentials.device_id, timeout=self.timeout)
        try:
            session.open([BUSINESS_NOTIFY])
            channel = connect_proto.connect(
                session,
                pairing,
                peer_id,
                timeout=self.timeout,
                sync=sync,
                agent_id=options["agent_id"],
                package=options["package"],
                agent_public_key=options["agent_public_key"],
                bind_start_delay_ms=options["bind_start_delay_ms"],
            )
        except BaseException:
            session.close()
            raise
        return _Link(
            channel=channel,
            close=session.close,
            info={
                "agent_package": options["package"],
                "agent_auth": "spki" if options["agent_public_key"] else "unavailable",
                "bind_start_delay_ms": options["bind_start_delay_ms"],
            },
        )

    def _with_channel(self, worker, *, sync: bool = False):
        """Open a channel, run ``worker``, and always close the link.

        ``sync`` advertises the third local consumer the device requires before
        it will push recordings; ordinary control calls leave it off. Errors
        propagate unchanged: a dropped link raises :class:`transport.LinkLost`.
        """
        link = self._open_channel(sync=sync)
        try:
            return worker(link.channel)
        finally:
            link.close()

    @staticmethod
    def require_ok(result: dict[str, Any]) -> dict[str, Any]:
        """Return ``result`` if it is a verified success, else raise.

        Raises :class:`errors.OperationIncomplete` carrying the whole result,
        including its ``state`` and ``retry`` guidance.
        """
        if not result.get("ok"):
            raise OperationIncomplete(result)
        return result

    def _read_status(self, channel) -> RecordStatus:
        channel_timeout = getattr(
            getattr(channel, "session", None), "timeout", 45.0
        )
        reply = channel.send_command(
            commands.SERVICE_STATUS[0], commands.SERVICE_STATUS[1], b"\xFF",
            expect=commands.STATUS_REPLY_HEADER, require_authenticated=True,
            timeout=min(STATUS_REPLY_SECONDS, channel_timeout),
        )
        return _status_from(reply)

    # -- read-only -------------------------------------------------------

    def status(self) -> RecordStatus:
        """Recording state, battery and error byte from an authenticated reply."""
        return self._with_channel(self._read_status)

    def inventory_totals(
        self, start_ms: int = 0, end_ms: int | None = None
    ) -> dict[str, Any]:
        start_ms = _check_ms(start_ms, "start_ms")

        def worker(channel):
            end = end_ms
            if end is None:
                # Never substitute the host clock: read the authenticated
                # device timestamp on the same connection first.
                status = self._read_status(channel)
                end = status.device_timestamp_ms
                if end is None:
                    raise XinliqiuError(
                        "the device did not report a timestamp; pass an explicit "
                        "finite past end_ms"
                    )
            start, checked_end = _check_range(start_ms, end)
            if checked_end == start:
                raise ValueError("a storage query range must end after it starts")
            payload = commands.range_payload(start, checked_end)
            reply = channel.send_command(
                commands.SERVICE_STORAGE[0], commands.SERVICE_STORAGE[1], payload,
                expect=commands.STORAGE_REPLY_HEADER, require_authenticated=True,
            )
            return commands.StorageTotals.parse(
                reply, expected_range=(start, checked_end)
            )

        totals = self._with_channel(worker)
        return {
            "start_ms": totals.start_ms,
            "end_ms": totals.end_ms,
            "count": totals.item_count,
            "bytes": totals.used_bytes,
            "highlight_count": totals.highlight_count,
            "highlight_bytes": totals.highlight_bytes,
            "has_file_list": False,
            "has_cursor": False,
            "authenticated": True,
        }

    def storage_info(
        self, start_ms: int = 0, end_ms: int | None = None
    ) -> dict[str, Any]:
        """Usage with capacity and low-space thresholds explicitly unknown.

        The totals come from the authenticated device reply. Total/free capacity
        and numeric cleanup thresholds are not verified by this implementation.
        Without ``end_ms`` the device timestamp is read on the same connection.
        """
        totals = self.inventory_totals(start_ms, end_ms)
        return {
            "start_ms": totals["start_ms"],
            "end_ms": totals["end_ms"],
            "item_count": totals["count"],
            "used_bytes": totals["bytes"],
            "highlight_count": totals["highlight_count"],
            "highlight_bytes": totals["highlight_bytes"],
            "free_bytes": None,
            "total_bytes": None,
            "pressure": "unknown",
            "thresholds": {
                "almost_full_below_free_bytes": None,
                "delete_oldest_below_free_bytes": None,
                "create_refused_below_free_bytes": None,
                "status": "unverified",
            },
            "note": (
                "The device reports usage only; total and free capacity are not "
                "exposed. Low-space thresholds are unverified and no numeric "
                "limits are reported. Sync regularly and do not rely on a "
                "particular cleanup threshold preserving recordings."
            ),
        }

    # -- recording -------------------------------------------------------

    def _observe(self, channel, *, want_recording: bool, observations: int) -> tuple[list, RecordStatus | None, str]:
        """Up to ``observations`` status reads; stop at the wanted state."""
        seen: list[dict[str, Any]] = []
        last: RecordStatus | None = None
        problem = ""
        for index in range(observations):
            if index:
                time.sleep(STATUS_OBSERVATION_INTERVAL)
            try:
                last = self._read_status(channel)
            except LinkLost:
                raise
            except XinliqiuError as exc:
                problem = f"status read {index + 1}: {exc}"
                seen.append({"observation": index + 1, "error": str(exc)})
                # A missing reply cannot be told apart from a slow one; do
                # not keep asking on a connection that stopped answering.
                break
            seen.append({
                "observation": index + 1,
                "recording": last.recording,
                "recordByte": last.raw["recordByte"],
                "errorByte": last.raw["errorByte"],
            })
            if last.recording == want_recording:
                break
        return seen, last, problem

    def _record_toggle(self, enable: bool, observations: int) -> dict[str, Any]:
        action = "start" if enable else "stop"
        payload = b"\x01" if enable else b"\x00"
        out: dict[str, Any] = {
            "action": action,
            "write_attempted": False,
            "write_completed": False,
            "status_observations": [],
        }

        def worker(channel):
            try:
                channel.send_only(
                    commands.SERVICE_RECORD[0], commands.SERVICE_RECORD[1], payload
                )
            except LinkLost as exc:
                # The bytes may or may not have left the host.
                out["write_attempted"] = True
                out["detail"] = str(exc)
                return "link_lost_during_write"
            except TransportError as exc:
                out["detail"] = str(exc)
                return "write_failed"
            out["write_attempted"] = True
            out["write_completed"] = True
            if observations <= 0:
                return "write_attempted_unconfirmed"
            try:
                seen, last, problem = self._observe(
                    channel, want_recording=enable, observations=observations
                )
            except LinkLost as exc:
                out["detail"] = f"link dropped after the write: {exc}"
                return "write_attempted_link_lost"
            out["status_observations"] = seen
            if problem:
                out["detail"] = problem
            if last is not None:
                out["observed_recording"] = last.recording
                out["status"] = last.raw
            if last is not None and last.recording == enable:
                return "recording_observed" if enable else "stopped_observed"
            return "write_attempted_unconfirmed"

        try:
            state = self._with_channel(worker)
        except LinkLost as exc:
            state = "link_lost_before_write" if not out["write_attempted"] else "write_attempted_link_lost"
            out["detail"] = str(exc)
        except XinliqiuError as exc:
            if out["write_attempted"]:
                raise
            state = CONNECT_FAILED
            out["detail"] = str(exc)
        verified = "recording_observed" if enable else "stopped_observed"
        out["state"] = state
        out["ok"] = state == verified
        out["verified"] = out["ok"]
        out["observed"] = out["ok"]
        out["reason"] = f"record_{action}_{state}"
        out["sent"] = out["write_attempted"]  # older callers read "sent"
        if enable:
            out["note"] = "audio appears only when voice activity is detected"
        out["retry"] = {
            verified: "none needed",
            "write_attempted_unconfirmed": (
                f"{action.upper()} was written once but the new state was not "
                "observed. Do NOT resend it; read status() separately to learn "
                "the state."
            ),
            "write_attempted_link_lost": (
                f"{action.upper()} was written, then the link dropped. Read status() "
                "on a new connection before deciding anything; do not resend blindly."
            ),
            "link_lost_during_write": (
                "The link dropped during the write; it may or may not have landed. "
                "Read status() on a new connection first."
            ),
            "link_lost_before_write": "Nothing was written. Safe to retry.",
            "write_failed": "The write did not reach the link. Safe to retry.",
            CONNECT_FAILED: "Nothing was written. Safe to retry.",
        }.get(state, "read status() before retrying")
        return out

    def record_start(self, *, observations: int = STATUS_OBSERVATIONS) -> dict[str, Any]:
        """Write one ``07 00 01`` and observe the status, never resending START.

        ``state`` is ``recording_observed`` only when an authenticated status
        read shows a non-zero record byte after the write. Otherwise it is
        ``write_attempted_unconfirmed`` (or a link/connect state): the device
        has no application ACK for this command.
        """
        return self._record_toggle(True, observations)

    def record_stop(self, *, observations: int = STATUS_OBSERVATIONS) -> dict[str, Any]:
        """Write one ``07 00 00``, then up to three status reads 1 s apart.

        ``stopped_observed`` requires an authenticated status with record byte
        0 after the write. There is never a second STOP.
        """
        return self._record_toggle(False, observations)

    def collect_voiceprint(
        self,
        seconds: int = 6,
        output_dir: Path | None = None,
        *,
        window_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Capture one voiceprint sample and receive its file on the same link.

        Sends exactly one ``07 02 <seconds>`` (1..127) on a ``sync=True``
        channel and accepts exactly one ``*.vp.opus`` / ``*.enc.vp.opus`` file
        offered after START, published only after the device confirms its
        transaction. If no file completes, one ``07 02 00`` cleanup stop is
        written while the link is up. ``window_seconds`` is the host wait,
        default ``max(45, seconds + 39)``; it must exceed ``seconds``.

        Re-reading a voiceprint through an ordinary range is unproven; a retry
        is always a new capture.
        """
        from .protocol import sync as sync_mod

        if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= 127:
            raise ValueError("voiceprint duration must be within 1..127 seconds")
        window = _check_window(
            window_seconds if window_seconds is not None else max(45, seconds + 39),
            "voiceprint window",
        )
        if window <= seconds:
            raise ValueError("the host window must exceed the voiceprint duration")
        out = Path(output_dir).expanduser().absolute() if output_dir else Path(
            tempfile.mkdtemp(prefix="xinliqiu-voiceprint-")
        )
        out.mkdir(parents=True, exist_ok=True)

        def worker(channel):
            deadline = time.monotonic() + window
            return sync_mod.collect_voiceprint(
                channel, out, duration=seconds, deadline=deadline
            )

        try:
            result = self._with_channel(worker, sync=True)
        except LinkLost as exc:
            result = {
                "state": sync_mod.VOICEPRINT_LINK_LOST, "ok": False, "seconds": seconds,
                "start": "unknown", "files": [], "file": None,
                "retry": "The link dropped; reconnect and capture again.",
                "diagnostics": {"detail": str(exc)},
            }
        except XinliqiuError as exc:
            result = {
                "state": CONNECT_FAILED, "ok": False, "seconds": seconds,
                "start": "not_attempted", "files": [], "file": None,
                "retry": "Nothing was sent to the device. Safe to retry.",
                "diagnostics": {"detail": f"{type(exc).__name__}: {exc}"},
            }
        result["sent"] = result.get("start") == "written"
        result.setdefault("verified", bool(result.get("ok")))
        result.setdefault("file_completed", bool(result.get("files")))
        result.setdefault("start_write_attempted", result.get("start") != "not_attempted")
        result.setdefault("start_write_completed", result.get("start") == "written")
        result.setdefault("cleanup_stop_write_attempted", False)
        result["_output_dir"] = str(out)
        return result

    # -- file sync -------------------------------------------------------

    def sync_range(
        self,
        start_ms: int,
        end_ms: int,
        output_dir: Path | None = None,
        *,
        seconds: int = DEFAULT_SYNC_SECONDS,
    ) -> dict[str, Any]:
        """Fetch the recordings the device holds in a device-clock window.

        The device answers by opening a file service and offering files one at
        a time; each is accepted, streamed in plain chunks, MD5-checked when the
        sender supplied a digest, completed, and published only after the
        device's matching ``complete-rsp`` result 0.

        ``state`` is ``range_completed`` (``ok`` true, CLI exit 0) only after an
        authenticated ``06/08`` for exactly this range *and* every transaction
        drained without failure. That includes an empty range. A first file,
        quiet, the deadline, a disconnect or the ``06/01`` echo never complete
        a range. ``start_ms == end_ms`` (one time point) is allowed.
        """
        start_ms, end_ms = _check_range(start_ms, end_ms)
        window = _check_window(seconds)
        out = Path(output_dir).expanduser().absolute() if output_dir else Path(
            tempfile.mkdtemp(prefix="xinliqiu-sync-")
        )
        out.mkdir(parents=True, exist_ok=True)
        result = self._run_sync([(start_ms, end_ms)], [out], window)
        part = result["ranges"][0] if result.get("ranges") else result
        part = dict(part)
        part.setdefault("files", [])
        # Match sync_ranges: ``rejected`` is a count in both APIs, while the
        # actionable per-offer details live in ``rejected_pairs``.
        part["rejected"] = result.get("rejected_total", part.get("rejected", 0))
        part["rejected_pairs"] = list(result.get("rejected_pairs", []))
        part["rejected_total"] = result.get("rejected_total", 0)
        part["_output_dir"] = str(out)
        part["link"] = result.get("link", {})
        return part

    def sync_ranges(
        self, ranges, output_dir: Path | None = None, *,
        seconds: int = DEFAULT_SYNC_RANGES_SECONDS,
    ) -> dict[str, Any]:
        """Fetch several distinct ranges over ONE authenticated connection.

        Ranges run in order under one overall host deadline (``seconds``). The
        next range is requested only after the previous one completed with a
        matching ``06/08``, drained, and lost nothing; the first non-success
        stops the sequence and later ranges are reported ``not_started``.
        Each range writes into ``<output_dir>/range-<index>``.
        """
        pairs = [_check_range(start, end) for start, end in ranges]
        if not 1 <= len(pairs) <= MAX_SYNC_RANGES:
            raise ValueError(f"sync_ranges expects 1..{MAX_SYNC_RANGES} ranges")
        if len(set(pairs)) != len(pairs):
            # A late 06/08 must name exactly one request.
            raise ValueError("sync_ranges rejects duplicate ranges")
        window = _check_window(seconds)
        base = Path(output_dir).expanduser().absolute() if output_dir else Path(
            tempfile.mkdtemp(prefix="xinliqiu-sync-")
        )
        dirs = [base / f"range-{index}" for index in range(len(pairs))]
        result = self._run_sync(pairs, dirs, window)
        result["_output_dir"] = str(base)
        return result

    def _run_sync(self, pairs, dirs, window: float) -> dict[str, Any]:
        from .protocol import sync as sync_mod

        dirs[0].mkdir(parents=True, exist_ok=True)
        holder: dict[str, Any] = {}

        def worker(channel):
            receiver = sync_mod.SyncReceiver(
                dirs[0],
                control_session=channel.system_session_id,
                message_session=channel.session_id,
            )
            holder["receiver"] = receiver
            driver = sync_mod.RangeSyncDriver(channel, receiver)
            # One overall deadline for every range on this connection; it
            # starts once the authenticated channel is up.
            deadline = time.monotonic() + window
            try:
                return driver.run_ranges(pairs, deadline=deadline, output_dirs=dirs)
            finally:
                # Whatever happened, nothing unconfirmed stays on disk. abandon()
                # touches staging files only, never a published file.
                receiver.abandon()

        try:
            result = self._with_channel(worker, sync=True)
        except LinkLost as exc:
            state = sync_mod.LINK_LOST
            result = self._sync_failure(pairs, state, str(exc), holder)
        except XinliqiuError as exc:
            if "receiver" in holder:
                raise
            result = self._sync_failure(
                pairs, CONNECT_FAILED, f"{type(exc).__name__}: {exc}", holder
            )
        receiver = holder.get("receiver")
        if receiver is not None:
            result["rejected_pairs"] = list(receiver.result.rejected)
            result["rejected_total"] = receiver.result.rejected_total
            result["offers"] = receiver.result.setup_seen
        return result

    @staticmethod
    def _sync_failure(pairs, state: str, detail: str, holder) -> dict[str, Any]:
        from .protocol import sync as sync_mod

        retry = (
            "The authenticated link never came up, so no range was requested. "
            "Safe to retry." if state == CONNECT_FAILED else sync_mod.retry_guidance(state)
        )
        receiver = holder.get("receiver")
        files = [str(p) for p in receiver.result.files] if receiver else []
        ranges = [
            {
                "state": state if index == 0 else sync_mod.NOT_STARTED,
                "ok": False, "verified": False, "range_complete": False,
                "start_ms": start, "end_ms": end,
                "files": files if index == 0 else [], "count": len(files) if index == 0 else 0,
                "bytes": receiver.result.bytes_published if receiver and index == 0 else 0,
                "retry": retry if index == 0 else sync_mod.retry_guidance(sync_mod.NOT_STARTED),
                "diagnostics": {"detail": detail},
            }
            for index, (start, end) in enumerate(pairs)
        ]
        return {
            "state": state, "ok": False, "verified": False, "stopped_at": 0, "ranges": ranges,
            "files": files, "count": len(files),
            "bytes": receiver.result.bytes_published if receiver else 0,
            "retry": retry,
        }

    # -- owner key installation ------------------------------------------

    def init_device(
        self,
        *,
        owner_public_key: Path,
        signing_key: Path | None = None,
        account: str = "local-owner",
        public_key_version: int = 1,
        owner_private_key: Path | None = None,
        signer: Signer | None = None,
    ) -> dict[str, Any]:
        """Format the device and install an owner public key.

        This is the step that decides who can ever read the recordings: the
        device keeps one owner public key, and every recording is encrypted to
        it. It also rewrites the account record, so anything already on the
        device is gone.

        Supply exactly one signing identity: ``signer`` for a generic
        :class:`protocol.init.Signer` object, or ``signing_key`` for an external
        unencrypted P-256 PKCS#8 path. This implementation supports local INIT
        for slot 1 only; no signing material is shipped here.

        Before any radio use the owner *private* key (argument, or the client's
        ``owner_private_key``) must load, be private, and match
        ``owner_public_key``: installing a public key whose private half is not
        in hand would make every future recording unreadable. Relative paths
        are resolved against the current directory.

        ``state`` is ``init_verified`` (``ok`` true) only when the device
        accepted, echoed the account, and its key readback matches exactly.
        ``init_accepted_unverified`` means accepted without a readback; do not
        re-run INIT to obtain one - it erases the device again.
        """
        from .protocol import init as init_mod
        from .provision import owner_key_matches_public, verify_owner_key

        if (signer is None) == (signing_key is None):
            raise ValueError("init_device requires exactly one of signer or signing_key")
        if not 1 <= public_key_version <= 255:
            raise ValueError("public key version must be 1..255")
        if not 1 <= len(account.encode("utf-8")) <= 127:
            raise ValueError("account must be 1..127 UTF-8 bytes")

        public_path = Path(owner_public_key).expanduser().resolve()
        signer_path = (
            Path(signing_key).expanduser().resolve()
            if signing_key is not None
            else None
        )
        private_path = owner_private_key or self.owner_private_key
        if private_path is None:
            raise XinliqiuError(
                "init needs the owner PRIVATE key (owner_private_key / --owner-key) "
                "to prove it matches the public key being installed; without it "
                "every future recording could be unreadable"
            )
        private_path = Path(private_path).expanduser().resolve()
        verdict = verify_owner_key(private_path)
        if not verdict.get("ok"):
            raise XinliqiuError(
                f"owner private key {private_path} is not usable: {verdict.get('reason')}"
            )
        if not owner_key_matches_public(private_path, public_path):
            raise XinliqiuError(
                f"owner private key {private_path} does not match {public_path}; "
                "refusing to install a public key whose private half is not in hand"
            )

        owner = init_mod.OwnerPublicKey.from_file(public_path)
        active_signer = (
            signer if signer is not None else init_mod.Pkcs8Signer(signer_path)
        )
        out: dict[str, Any] = {
            "init_written": False,
            "account": account,
            "public_key_version": public_key_version,
            "fingerprint": owner.fingerprint,
        }

        def worker(channel):
            # send_command returns service || command || payload, so the first
            # two bytes are the envelope, not the challenge.
            challenge_raw = channel.send_command(
                init_mod.INIT_SERVICE, 0x0D, b"\x01",
                expect=(init_mod.INIT_SERVICE, 0x0D), require_authenticated=True,
            )
            received_at = time.monotonic()
            challenge = init_mod.parse_bind_challenge(_business_payload(challenge_raw))
            challenge.require_local_slot_one()
            out["device_id"] = challenge.device_id.hex()
            out["key_slot"] = challenge.key_slot

            now_ms = int(time.time() * 1000)
            expiry = init_mod.token_expiry_seconds(now_ms)
            token = init_mod.build_token(
                challenge,
                account=account,
                key_hash=owner.key_hash,
                public_key_version=public_key_version,
                signer=active_signer,
                expiry_seconds=expiry,
            )
            payload = init_mod.build_init_payload(
                timestamp_ms=now_ms,
                account=account,
                public_key_version=public_key_version,
                public_key=owner.utf8,
                token=token,
            )
            challenge.require_fresh(received_at)
            out["init_written"] = True  # from here on, never resend INIT
            try:
                response_raw = channel.send_command_large(
                    init_mod.INIT_SERVICE, init_mod.INIT_COMMAND, payload,
                    expect=(init_mod.INIT_SERVICE, init_mod.INIT_COMMAND),
                    require_authenticated=True,
                )
            except TransportError as exc:  # LinkLost included
                out["detail"] = f"link failed after INIT was written: {exc}"
                return "init_written_no_ack"
            except connect_proto.ReplyTimeout as exc:
                out["detail"] = str(exc)
                return "init_written_no_ack"
            try:
                response = init_mod.parse_init_response(
                    _business_payload(response_raw),
                    expected_account=account,
                    expected_public_key=owner.utf8,
                    expected_public_key_version=public_key_version,
                    framed=False,
                )
            except XinliqiuError as exc:
                out["detail"] = f"INIT answer could not be parsed: {exc}"
                return "init_ack_unparseable"
            out["device_status"] = response.status
            out["account_matched"] = response.account_matched
            out["public_key_readback"] = (
                "absent" if response.public_key_matched is None
                else "match" if response.public_key_matched else "mismatch"
            )
            if response.status != 1:
                return "init_rejected"
            if not response.account_matched:
                return "init_account_mismatch"
            if response.public_key_matched is True:
                return "init_verified"
            if response.public_key_matched is None:
                return "init_accepted_unverified"
            return "init_readback_mismatch"

        try:
            state = self._with_channel(worker)
        except XinliqiuError as exc:
            if not out["init_written"]:
                raise
            # Once INIT may have reached the device, every later failure is an
            # explicit unknown outcome, never an invitation to send it again.
            state = "init_written_no_ack"
            out["detail"] = f"{type(exc).__name__}: {exc}"
        out["state"] = state
        out["ok"] = state == "init_verified"
        out["verified"] = out["ok"]
        out["unverified"] = state in (
            "init_accepted_unverified", "init_written_no_ack", "init_ack_unparseable"
        )
        out["accepted"] = state in ("init_verified", "init_accepted_unverified")
        never_resend = (
            " Do NOT run INIT again to get a confirmation: every run erases the "
            "device. Verify instead by recording something new, syncing it, and "
            "decrypting it with the owner private key."
        )
        out["retry"] = {
            "init_verified": "none needed",
            "init_accepted_unverified": (
                "The device accepted INIT and echoed the account, but sent no key "
                "readback, so the installed key is not verified." + never_resend
            ),
            "init_written_no_ack": (
                "INIT was written but no authenticated answer arrived; the device "
                "may already be formatted with the new key." + never_resend
            ),
            "init_ack_unparseable": (
                "INIT was written and answered, but the answer was malformed; the "
                "outcome is unknown." + never_resend
            ),
            "init_rejected": (
                "The device refused INIT (see device_status). Check the signing "
                "key and the slot before trying again."
            ),
            "init_account_mismatch": (
                "The device answered for a different account. Stop and inspect; "
                "do not re-run INIT blindly."
            ),
            "init_readback_mismatch": (
                "The device reports a different installed key than the one sent. "
                "Stop: recordings may be encrypted to a key you do not hold."
            ),
        }.get(state, "inspect before retrying")
        return out

    # -- capability table ------------------------------------------------

    @staticmethod
    def capabilities() -> dict[str, Any]:
        return describe_capabilities()

    @staticmethod
    def require_capability(name: str) -> None:
        for bucket_name, bucket in describe_capabilities()["statuses"].items():
            for item in bucket:
                if item["name"] == name:
                    if bucket_name == "unavailable":
                        raise Unsupported(
                            f"{name} has no established SDK path on the tested setup: "
                            f"{item['note']}"
                        )
                    return
        raise XinliqiuError(f"unknown capability {name}")


def scan(name: str | None = None, seconds: int = 15) -> list[dict[str, Any]]:
    """Discover nearby devices."""
    return [
        {"id": d["id"], "name": d["name"], "rssi": d.get("rssi"), "connectable": True}
        for d in scan_devices(name, float(seconds))
    ]
