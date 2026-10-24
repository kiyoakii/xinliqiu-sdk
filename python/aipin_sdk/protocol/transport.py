# -*- coding: utf-8 -*-
"""Platform-neutral Bluetooth transport.

Everything above this layer speaks bytes. Everything below it knows how to
reach a device. Keeping the split hard is what lets the protocol run on macOS,
Linux, or a test harness without changing a line of protocol code.

A backend is anything that can:

* connect to a device and disclose the GATT services it offers;
* subscribe to notifications on a characteristic;
* write a characteristic and wait for the acknowledgement.

Nothing here knows what the bytes mean.
"""

from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol, Sequence, runtime_checkable

from ..errors import XinliqiuError


# The device exposes two service sets: one for the key exchange handshake and
# one for everything afterwards. These UUIDs are advertised publicly and are
# observable in any Bluetooth scanner.
PAIRING_SERVICE = "AFAF"
# The pairing exchange notifies on exactly these three characteristics: 0001
# (init acknowledgement), 1001 (UKEY2 replies) and 1004 (KSC confirmation).
# An earlier list named 0002/0003, which the device never notifies on, so a
# Session opened that way could not hear a single pairing reply.
PAIRING_CHARACTERISTICS = ("0001", "1001", "1004")

# On AA15 the device exposes exactly two characteristics: AA16 delivers
# notifications and accepts no writes, AA17 accepts writes and delivers no
# notifications. Writing to the wrong one produces silence, not an error.
BUSINESS_SERVICE = "AA15"
BUSINESS_NOTIFY = "AA16"
BUSINESS_WRITE = "AA17"


class TransportError(XinliqiuError):
    """A link-level failure: unreachable, disconnected, or timed out."""


class NotificationTimeout(TransportError):
    """No notification arrived within the timeout. Idle, not fatal.

    Read loops treat this (and, for older backends, a bare
    :class:`TransportError` from ``read_notification``) as an idle tick.
    """


class LinkLost(TransportError):
    """The link went away. Fatal for every operation on this connection.

    Raised by ``read_notification`` once the backend has seen the platform's
    disconnect callback and drained what arrived before it. Read loops must
    never treat it as an idle tick: a silent wait on a dead link is what used
    to turn a dropped connection into a plausible "nothing to send".
    """


#: Placed in a backend's notification queue when the platform reports that the
#: link dropped. Everything queued before it is still delivered first.
DISCONNECTED = object()
# Readable aliases for callers that prefer an explicit sentinel name.
DISCONNECT_SENTINEL = DISCONNECTED
DISCONNECTED_SENTINEL = DISCONNECTED


def is_fatal(exc: BaseException) -> bool:
    """True when ``exc`` must end the operation instead of counting as idle."""
    return isinstance(exc, LinkLost)


def is_idle_error(exc: BaseException) -> bool:
    """Whether a read failure is an empty/idle notification, not a dead link.

    Backends should raise :class:`NotificationTimeout`; the message fallback
    keeps older test/platform adapters compatible without swallowing a real
    failure such as "backend is closed" or "write failed".
    """
    if isinstance(exc, NotificationTimeout):
        return True
    if isinstance(exc, LinkLost) or not isinstance(exc, TransportError):
        return False
    text = str(exc).lower()
    return any(token in text for token in (
        "no notification", "idle", "timed out", "timeout", "timed-out",
    ))


@dataclass
class Notification:
    service: str
    characteristic: str
    payload: bytes
    at: float = field(default_factory=time.time)


@runtime_checkable
class Backend(Protocol):
    """What a platform adapter must provide.

    Implementations are expected to be single-use: connect once, use, close.
    The protocol assumes one link at a time.
    """

    def connect(self, device_id: str, timeout: float) -> None:
        """Open a link and wait until services are discovered."""

    def disconnect(self) -> None:
        """Close the link. Safe to call more than once."""

    def write(self, characteristic: str, payload: bytes, timeout: float) -> None:
        """Write and wait for the write acknowledgement."""

    def subscribe(self, characteristic: str) -> None:
        """Begin receiving notifications on a characteristic."""

    def read_notification(self, timeout: float) -> Notification:
        """Block until one notification arrives or the timeout expires."""


class Session:
    """A live link with notification buffering and reassembly helpers.

    The device fragments payloads across notifications. Callers that need one
    logical message call :meth:`read_message`; callers that want raw frames
    call :meth:`read`.
    """

    def __init__(self, backend: Backend, device_id: str, *, timeout: float = 45.0) -> None:
        self.backend = backend
        self.device_id = device_id
        self.timeout = timeout
        self._pending: queue.Queue[Notification] = queue.Queue()
        self._closed = False
        self._thread: threading.Thread | None = None
        #: The characteristics :meth:`open` actually subscribed to.
        self.subscribed: tuple[str, ...] = ()

    @property
    def link_lost(self) -> bool:
        """True once the backend has reported that the link dropped."""
        return bool(getattr(self.backend, "link_lost", False))

    @property
    def disconnected(self) -> bool:
        return self.link_lost

    def open(self, characteristics: Sequence[str] | None = None) -> "Session":
        """Connect and subscribe.

        ``characteristics`` defaults to the business notifier (AA16) plus the
        three pairing notifiers. Only the current mode's characteristics are
        subscribable, so a refusal on one of them is expected; refusal on every
        one of them means nothing could ever be heard, which is an error rather
        than a silent session.
        """
        self.backend.connect(self.device_id, self.timeout)
        wanted = (
            tuple(characteristics)
            if characteristics is not None
            else (BUSINESS_NOTIFY,) + PAIRING_CHARACTERISTICS
        )
        subscribed: list[str] = []
        failures: list[str] = []
        for uuid in wanted:
            try:
                self.backend.subscribe(uuid)
            except LinkLost:
                raise
            except TransportError as exc:
                failures.append(f"{uuid}: {exc}")
                continue
            subscribed.append(uuid)
        self.subscribed = tuple(subscribed)
        if wanted and not subscribed:
            self.close()
            raise TransportError(
                "no notification characteristic could be subscribed: "
                + "; ".join(failures)
            )
        return self

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.backend.disconnect()
        except Exception:  # noqa: BLE001 - closing must never raise
            pass

    def __enter__(self) -> "Session":
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def write(self, characteristic: str, payload: bytes, timeout: float | None = None) -> None:
        self.backend.write(
            characteristic, payload, self.timeout if timeout is None else timeout
        )

    def read(self, timeout: float | None = None) -> Notification:
        return self.backend.read_notification(
            self.timeout if timeout is None else timeout
        )

    def read_message(self, *, timeout: float | None = None, max_bytes: int = 1 << 20) -> bytes:
        """Read notifications until :class:`Framer` reports a complete frame."""
        from .framing import Framer

        framer = Framer()
        # Framer takes the limit as an attribute, not a constructor arg;
        # passing it here raised TypeError and made read_message unusable.
        framer.max_bytes = max_bytes
        deadline = time.monotonic() + (timeout or self.timeout)
        while time.monotonic() < deadline:
            try:
                note = self.read(max(0.1, deadline - time.monotonic()))
            except LinkLost:
                raise
            except TransportError as exc:
                if is_idle_error(exc):
                    continue  # idle tick; the deadline decides
                raise
            complete = framer.feed(note.payload)
            if complete is not None:
                return complete
        raise NotificationTimeout("timed out waiting for a complete frame")


class LoopbackBackend:
    """In-memory backend for tests.

    Feed it the notifications a real device would send, assert on what was
    written. This is what makes the protocol testable without hardware.
    """

    def __init__(
        self,
        *,
        responses: Sequence[bytes] | None = None,
        on_disconnect: Callable[[], None] | None = None,
    ) -> None:
        self.written: list[tuple[str, bytes]] = []
        self.connected = False
        self.link_lost = False
        self.on_disconnect = on_disconnect
        self._queue: queue.Queue[object] = queue.Queue()
        self._subscribed: set[str] = set()
        for payload in responses or ():
            self._queue.put(Notification("", "", payload))

    def connect(self, device_id: str, timeout: float) -> None:
        self.connected = True
        self.link_lost = False

    def disconnect(self) -> None:
        self.connected = False

    def write(self, characteristic: str, payload: bytes, timeout: float) -> None:
        if self.link_lost:
            raise LinkLost("write after the link dropped")
        if not self.connected:
            raise TransportError("write before connect")
        self.written.append((characteristic, payload))

    def subscribe(self, characteristic: str) -> None:
        self._subscribed.add(characteristic)

    def read_notification(self, timeout: float) -> Notification:
        try:
            item = self._queue.get(timeout=timeout)
        except queue.Empty:
            if self.link_lost:
                raise LinkLost("the link dropped") from None
            raise NotificationTimeout("no notification") from None
        if item is DISCONNECTED:
            # Keep reporting the loss to every later reader as well.
            self._queue.put(DISCONNECTED)
            raise LinkLost("the link dropped")
        return item  # type: ignore[return-value]

    def push(self, payload: bytes, characteristic: str = "") -> None:
        """Queue a notification a real device would have sent."""
        self._queue.put(Notification("", characteristic, payload))

    def simulate_disconnect(self) -> None:
        """Behave like the platform's disconnect callback.

        Notifications queued before the call are still delivered; every read
        after them raises :class:`LinkLost`, and writes fail the same way.
        """
        self.link_lost = True
        self.connected = False
        self._queue.put(DISCONNECTED)
        if self.on_disconnect is not None:
            self.on_disconnect()