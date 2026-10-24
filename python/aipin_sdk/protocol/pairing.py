# -*- coding: utf-8 -*-
"""Pairing: turn a fresh device into one this host can talk to.

The exchange runs over the AFAF service, on characteristics that are only
reached during key establishment:

===== ==================================================================
0001  write: the 12-byte init frame; notify: its 16-byte acknowledgement
1001  write: handshake messages;        notify: the device's replies
1004  write: KSC generation;            notify: the confirmation
===== ==================================================================

Order matters. Sending before the device acknowledges the init frame leaves
the handshake unanswered; writing the handshake to 0001 instead of 1001 does
the same thing silently.

The result is a :class:`~.auth.Pairing`: a shared key, an alias identifying
this host, and both side identifiers. Persist it before the KSC request is
written - if the process dies between the two, the device has a binding for a
key that was never written down, and the slot is wasted until evicted.
:func:`pair` therefore calls ``stage(pairing)`` *before* the KSC write and
raises without writing if staging fails; the caller promotes the staged copy
only after the device's confirmation. When the confirmation is missing or
unreadable the outcome is unknown, and :class:`PairingUncertain` says so with
the staged material still in place.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from ..errors import XinliqiuError
from . import crypto, ukey2
from .auth import Pairing
from .transport import LinkLost, Session, TransportError, is_idle_error

CHAR_INIT = "00000001-0000-1000-8000-00805f9b34fb"
CHAR_HANDSHAKE = "00001001-0000-1000-8000-00805f9b34fb"
CHAR_KSC = "00001004-0000-1000-8000-00805f9b34fb"

# Fixed 12 bytes that put the device into pairing mode. The trailing ASCII is
# visible in this frame on the wire.
INIT_FRAME = bytes([0, 0, 0, 0, 0, 0, 5]) + b"WBOAF"

SUBSCRIBE_ORDER = (CHAR_INIT, CHAR_HANDSHAKE, CHAR_KSC)

INIT_ACK_BYTES = 16
PROVIDER_FINISH_BYTES = 38
KSC_CONFIRM_BYTES = 16

# SERVER_INIT is a protobuf ``Ukey2Message`` behind a 0x11 prefix; it may span
# several notifications. The whole message is at most 513 bytes (the UKEY2
# bound in the tested contract), which also bounds how much is buffered.
MAX_SERVER_INIT_BYTES = ukey2.MAX_MESSAGE


class PairingError(XinliqiuError):
    """Pairing failed or the device refused a step."""


class PairingUncertain(PairingError):
    """The KSC request was written, but its outcome was not observed.

    The device may or may not hold the new key. ``pairing`` is the material
    that was staged before the write; keep it. It may be usable, and deleting
    it would make a binding that did happen unrecoverable.
    """

    def __init__(self, message: str, pairing: Pairing) -> None:
        super().__init__(message)
        self.pairing = pairing


@dataclass
class PairStep:
    """Diagnostics for one step, useful when pairing fails."""

    name: str
    sent: int = 0
    received: int = 0


def _normalise(uuid: str) -> str:
    text = (uuid or "").strip().lower()
    return text if len(text) > 8 else f"0000{text}-0000-1000-8000-00805f9b34fb"


def server_init_expected_length(proto: bytes) -> int | None:
    """Total length of a SERVER_INIT ``Ukey2Message`` once enough has arrived.

    ``proto`` is everything after the 0x11 prefix. The message starts with
    field 1 (type, ``08 xx``) and then field 2 (``12`` + varint length). Returns
    ``None`` while the length varint is still incomplete.
    """
    if len(proto) < 4:
        return None
    if proto[0] != 0x08 or proto[2] != 0x12:
        raise PairingError("unexpected SERVER_INIT protobuf header")
    length = 0
    for i in range(5):
        index = 3 + i
        if index >= len(proto):
            return None
        length |= (proto[index] & 0x7F) << (7 * i)
        if not proto[index] & 0x80:
            if length > MAX_SERVER_INIT_BYTES - 1:
                raise PairingError("SERVER_INIT declares an oversized body")
            return index + 1 + length
    raise PairingError("SERVER_INIT length varint overflow")


def _read(session: Session, characteristic: str, deadline: float, what: str) -> bytes:
    """Next notification from ``characteristic`` before ``deadline``.

    A notification that carries a different characteristic is not this step's
    reply and is skipped; one that carries none (a test backend) is accepted.
    """
    wanted = _normalise(characteristic)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError(f"timed out waiting for {what}")
        try:
            note = session.read(max(0.1, remaining))
        except LinkLost:
            raise
        except TransportError as exc:
            if getattr(session, "link_lost", False):
                raise LinkLost(f"the link dropped waiting for {what}") from None
            if is_idle_error(exc):
                continue
            raise
        if note.characteristic and _normalise(note.characteristic) != wanted:
            continue
        return note.payload


def read_server_init(session: Session, deadline: float) -> bytes:
    """Accumulate a possibly fragmented SERVER_INIT; return it with its prefix."""
    buffer = bytearray()
    while True:
        chunk = _read(session, CHAR_HANDSHAKE, deadline, "the key exchange reply")
        if not chunk:
            continue
        buffer += chunk
        if buffer[0] != ukey2.FRAME_SERVER_INIT:
            raise PairingError("device did not answer the key exchange")
        if len(buffer) > MAX_SERVER_INIT_BYTES + 1:
            raise PairingError("SERVER_INIT exceeds the UKEY2 size bound")
        expected = server_init_expected_length(bytes(buffer[1:]))
        if expected is None or len(buffer) - 1 < expected:
            continue
        if len(buffer) - 1 != expected:
            raise PairingError("SERVER_INIT has trailing bytes")
        return bytes(buffer)


def pair(
    session: Session,
    *,
    alias: bytes | None = None,
    timeout: float = 40.0,
    on_step=None,
    stage: Callable[[Pairing], None] | None = None,
) -> tuple[Pairing, list[PairStep]]:
    """Run the full pairing exchange over an open session.

    ``timeout`` bounds the whole exchange. ``stage`` is called with the new
    material before the KSC request is written; if it raises, nothing is
    written and the error propagates. Returns the pairing material and a step
    log once the device confirmed the key. Raises :class:`PairingUncertain`
    when the KSC request was written but no readable confirmation arrived.
    """
    if alias is not None and len(alias) != 6:
        raise PairingError("alias must be 6 bytes")

    steps: list[PairStep] = []
    deadline = time.monotonic() + timeout

    def note(name: str, sent: int = 0, received: int = 0) -> None:
        step = PairStep(name, sent, received)
        steps.append(step)
        if on_step is not None:
            on_step(step)

    def left() -> float:
        return max(0.1, deadline - time.monotonic())

    # 1. Open the pairing window.
    session.write(CHAR_INIT, INIT_FRAME, left())
    ack = _read(session, CHAR_INIT, deadline, "the pairing init acknowledgement")
    if len(ack) != INIT_ACK_BYTES or ack[0] != 1 or ack[5] != 0:
        raise PairingError("device did not accept the pairing init frame")
    note("init_acknowledged", len(INIT_FRAME), len(ack))

    # 2. Key exchange. SERVER_INIT may arrive in several notifications.
    handshake = ukey2.Handshake()
    client_init = handshake.start()
    session.write(CHAR_HANDSHAKE, client_init, left())
    server_init = read_server_init(session, deadline)
    client_finish = handshake.accept_server_init(server_init)
    session.write(CHAR_HANDSHAKE, client_finish, left())
    note("handshake", len(client_init) + len(client_finish), len(server_init))

    # 3. The device proves it holds the same key and offers its identity.
    finish = _read(session, CHAR_HANDSHAKE, deadline, "the device finish frame")
    if len(finish) != PROVIDER_FINISH_BYTES:
        raise PairingError("device finish frame has an unexpected length")
    handshake.accept_server_finish(finish)
    provider_id = handshake.provider_id
    if provider_id is None:
        raise PairingError("device finished without an identity")
    note("device_finished", 0, len(finish))

    # 4. Generate the shared key, stage it durably, then register it.
    ksc = crypto.random_bytes(16)
    host_alias = alias if alias is not None else crypto.random_bytes(6)
    pairing = Pairing(
        ksc=ksc,
        alias=host_alias,
        seeker_id=handshake.seeker_id,
        provider_id=provider_id,
    )
    if stage is not None:
        stage(pairing)  # raising here means nothing was written
        note("ksc_staged", 0, 0)
    request = handshake.seal(bytes([0x0C, 0x20]) + ksc + host_alias)
    try:
        session.write(CHAR_KSC, request, left())
    except LinkLost as exc:
        raise PairingUncertain(
            f"the link dropped while the KSC request was being written: {exc}", pairing
        ) from exc
    except TransportError as exc:
        raise PairingUncertain(
            f"the KSC write did not complete cleanly: {exc}", pairing
        ) from exc
    note("ksc_sent", len(request), 0)

    # 5. Confirm. From here on, a failure is "outcome unknown" unless the device
    # explicitly refused.
    try:
        confirm = _read(session, CHAR_KSC, deadline, "the key confirmation")
    except TransportError as exc:
        raise PairingUncertain(f"no key confirmation: {exc}", pairing) from exc
    if len(confirm) != KSC_CONFIRM_BYTES:
        raise PairingUncertain("key confirmation has an unexpected length", pairing)
    try:
        plain = handshake.open(confirm)
    except Exception as exc:  # noqa: BLE001 - undecodable is "unknown", not "refused"
        raise PairingUncertain(f"key confirmation is unreadable: {exc}", pairing) from exc
    if len(plain) < 2 or plain[0] != 0x0D:
        raise PairingUncertain("key confirmation is not a 0x0D reply", pairing)
    if plain[1] != 0:
        raise PairingError(f"device rejected the key registration (status {plain[1]})")
    note("ksc_confirmed", 0, len(confirm))

    return pairing, steps
