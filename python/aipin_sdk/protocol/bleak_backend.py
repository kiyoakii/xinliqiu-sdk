# -*- coding: utf-8 -*-
"""Bluetooth backend built on ``bleak``.

``bleak`` covers macOS (CoreBluetooth), Linux (BlueZ) and Windows (WinRT), so
one adapter serves all three platforms. There is no platform-specific code in
this project as a result.

``bleak`` is asynchronous while the protocol layer is synchronous, so this
adapter owns a private event loop on a background thread and marshals every
call onto it. Notifications are handed back through a plain thread-safe queue,
deliberately not an ``asyncio.Queue``: those bind to a loop at construction and
cannot be created from another thread.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import queue
import threading
from typing import Any, Callable

from ..errors import XinliqiuError
from .transport import (
    BUSINESS_SERVICE,
    DISCONNECTED,
    LinkLost,
    Notification,
    NotificationTimeout,
    TransportError,
)

try:  # pragma: no cover - import guard
    from bleak import BleakClient, BleakScanner
except ImportError:  # pragma: no cover
    BleakClient = None  # type: ignore[assignment]
    BleakScanner = None  # type: ignore[assignment]


# Every call into the loop thread is bounded. A CoreBluetooth/BlueZ call that
# never resolves must surface as a TransportError, not hang the caller forever.
# The margins sit on top of the caller's own timeout so bleak's internal
# timeout fires first and keeps its more specific message.
CONNECT_MARGIN_SECONDS = 10.0
WRITE_MARGIN_SECONDS = 5.0
SUBSCRIBE_SECONDS = 15.0
DISCONNECT_SECONDS = 5.0


def _require_bleak() -> None:
    if BleakClient is None:
        raise XinliqiuError(
            "the bluetooth backend needs the bleak package: "
            'pip install "xinliqiu-sdk[ble]"'
        )


def _expand(uuid: str) -> str:
    """Accept the short 4-character form or a full 128-bit UUID."""
    text = uuid.strip()
    return text.lower() if len(text) > 8 else f"0000{text.lower()}-0000-1000-8000-00805f9b34fb"


class BleakBackend:
    """A synchronous facade over ``bleak``'s asynchronous client.

    ``on_disconnect`` is called (on the loop thread) when the platform reports
    that the link dropped. Independently of it, a :data:`transport.DISCONNECTED`
    sentinel is queued behind every notification that arrived first, so a
    reader sees all delivered data and then :class:`transport.LinkLost` - never
    an endless idle wait on a dead link.
    """

    def __init__(self, *, on_disconnect: Callable[[], None] | None = None) -> None:
        _require_bleak()
        self._inbox: queue.Queue[object] = queue.Queue()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name="xinliqiu-ble", daemon=True
        )
        self._thread.start()
        self._client: Any = None
        self._notify_uuid: str | None = None
        self._properties: dict[str, set[str]] = {}
        self._closed = False
        self._disconnecting = False
        self.link_lost = False
        self.on_disconnect = on_disconnect

    @property
    def disconnected(self) -> bool:
        return self.link_lost

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run(self, coro: Any, timeout: float) -> Any:
        """Run ``coro`` on the loop thread and wait at most ``timeout`` seconds."""
        if self._closed:
            coro.close()
            raise TransportError("backend is closed")
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=max(0.1, timeout))
        except concurrent.futures.TimeoutError:
            future.cancel()
            if self.link_lost:
                raise LinkLost("the link dropped while a call was pending") from None
            raise TransportError(
                f"bluetooth call did not finish within {timeout:.1f} s"
            ) from None

    # -- lifecycle -------------------------------------------------------

    def _handle_disconnect(self, _client: Any = None) -> None:
        # Runs on the loop thread. A disconnect we asked for is not a loss.
        if self._disconnecting or self.link_lost:
            return
        self.link_lost = True
        self._inbox.put(DISCONNECTED)
        callback = self.on_disconnect
        if callback is not None:
            try:
                callback()
            except Exception:  # noqa: BLE001 - a user callback must not kill the loop
                pass

    def connect(self, device_id: str, timeout: float) -> None:
        try:
            self._run(
                self._connect(device_id, timeout), timeout + CONNECT_MARGIN_SECONDS
            )
        except TransportError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface platform errors uniformly
            raise TransportError(f"cannot connect to {device_id}: {exc}") from exc

    async def _connect(self, device_id: str, timeout: float) -> None:
        client = BleakClient(
            device_id, timeout=timeout, disconnected_callback=self._handle_disconnect
        )
        await client.connect()
        self._client = client
        self.link_lost = False
        # Remember how each characteristic may be written. The device offers
        # AA17 as write-without-response only and the pairing characteristics as
        # write-with-response only, so a fixed choice fails on one of them with
        # "writing is not permitted".
        for service in client.services:
            for char in service.characteristics:
                self._properties[char.uuid.lower()] = set(char.properties or ())

    def disconnect(self) -> None:
        if self._closed:
            return
        self._disconnecting = True
        if self._client is not None:
            try:
                asyncio.run_coroutine_threadsafe(
                    self._client.disconnect(), self._loop
                ).result(timeout=DISCONNECT_SECONDS)
            except Exception:  # noqa: BLE001 - closing must not raise
                pass
            self._client = None
        self._closed = True
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=DISCONNECT_SECONDS)

    def __enter__(self) -> "BleakBackend":
        return self

    def __exit__(self, *exc: object) -> None:
        self.disconnect()

    # -- io --------------------------------------------------------------

    def write(self, characteristic: str, payload: bytes, timeout: float) -> None:
        if self.link_lost:
            raise LinkLost("write after the link dropped")
        if self._client is None:
            raise TransportError("write before connect")
        try:
            self._run(
                self._write(characteristic, payload, timeout),
                timeout + WRITE_MARGIN_SECONDS,
            )
        except TransportError:
            raise
        except Exception as exc:  # noqa: BLE001
            if self.link_lost:
                raise LinkLost(f"write failed after the link dropped: {exc}") from exc
            raise TransportError(f"write to {characteristic} failed: {exc}") from exc

    async def _write(self, characteristic: str, payload: bytes, timeout: float) -> None:
        target = _expand(characteristic)
        props = self._properties.get(target, set())
        # Prefer an acknowledged write when the characteristic allows one.
        if not props:
            response = True
        else:
            response = "write" in props
            if not response and "write-without-response" not in props:
                raise TransportError(
                    f"{characteristic} accepts no writes (properties: {sorted(props)})"
                )
        await asyncio.wait_for(
            self._client.write_gatt_char(target, payload, response=response),
            timeout,
        )

    def subscribe(self, characteristic: str) -> None:
        if self._client is None:
            raise TransportError("subscribe before connect")
        target = _expand(characteristic)

        def handler(_sender: Any, data: bytearray) -> None:
            # Runs on the loop thread; the queue is thread-safe by design. The
            # characteristic travels with the bytes, so a pairing reader can
            # tell a 1001 reply from a 1004 confirmation.
            self._inbox.put((target, bytes(data)))

        async def subscribe() -> None:
            await self._client.start_notify(target, handler)

        try:
            self._run(subscribe(), SUBSCRIBE_SECONDS)
            self._notify_uuid = target
        except LinkLost:
            raise
        except Exception as exc:  # noqa: BLE001
            raise TransportError(f"cannot subscribe to {characteristic}: {exc}") from exc

    def read_notification(self, timeout: float) -> Notification:
        try:
            item = self._inbox.get(timeout=timeout)
        except queue.Empty:
            if self.link_lost:
                raise LinkLost("the link dropped") from None
            raise NotificationTimeout("no notification within the timeout") from None
        if item is DISCONNECTED:
            self._inbox.put(DISCONNECTED)  # every later reader sees it too
            raise LinkLost("the link dropped")
        characteristic, payload = item  # type: ignore[misc]
        return Notification(BUSINESS_SERVICE, characteristic, payload)


async def discover(name: str | None = None, seconds: float = 10.0) -> list[dict[str, Any]]:
    """List nearby devices, optionally filtered by advertised name."""
    _require_bleak()
    found = await BleakScanner.discover(timeout=seconds)
    devices = []
    for device in found:
        label = getattr(device, "name", None) or ""
        if name and name.lower() not in label.lower():
            continue
        devices.append(
            {
                "id": getattr(device, "address", ""),
                "name": label,
                "rssi": getattr(device, "rssi", None),
            }
        )
    return devices


def scan(name: str | None = None, seconds: float = 10.0) -> list[dict[str, Any]]:
    """Blocking wrapper around :func:`discover`."""
    return asyncio.run(discover(name, seconds))