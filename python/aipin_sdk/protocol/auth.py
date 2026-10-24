# -*- coding: utf-8 -*-
"""Session authentication over the business channel.

After the link is up, each side proves it holds the paired key. The key itself
never crosses the wire; only MACs over challenges do.

Frame shapes, all with a one-byte length prefix::

    request   : 10 01 | challenge(8) | time BE(8) | mac(8) | localID(6) | alias(6)
    response  : 11 01 00 | serverChallenge(8) | serverTime BE(8) | mac(8)
    confirm   : 12 01 00 | mac(8)

The MAC is over the little-endian forms of the timestamps while the timestamps
themselves travel big-endian. That asymmetry is the device's, not a choice made
here; getting it wrong yields a "wrong key" failure that looks like a bad
credential rather than a byte-order bug.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field, field

from ..errors import XinliqiuError
from . import crypto

TAG_BYTES = 8
REQUEST_TYPE = 0x10
RESPONSE_TYPE = 0x11
CONFIRM_TYPE = 0x12
PROTOCOL_VERSION = 1


class AuthError(XinliqiuError):
    """The device did not accept the credentials."""


@dataclass(frozen=True)
class Pairing:
    """The material a successful pairing produced.

    ``alias`` identifies this host on the device. Re-pairing with the same
    alias updates the slot this host already owns instead of evicting another
    host's - which is what keeps a phone's binding intact when the user
    upgrades or reinstall the SDK.
    """

    ksc: bytes = field(repr=False)
    alias: bytes
    seeker_id: bytes
    provider_id: bytes

    def __post_init__(self) -> None:
        for name, value, size in (
            ("ksc", self.ksc, 16),
            ("alias", self.alias, 6),
            ("seeker_id", self.seeker_id, 6),
            ("provider_id", self.provider_id, 6),
        ):
            if len(value) != size:
                raise ValueError(f"{name} must be {size} bytes, got {len(value)}")


def _mac(key: bytes, data: bytes) -> bytes:
    # HMAC-SHA512 truncated to 8 bytes. Using SHA256 here produces a tag the
    # device rejects, and the failure looks like a wrong credential.
    return crypto.hmac_sha512(key, data)[:TAG_BYTES]


def _time_be(value: int) -> bytes:
    return struct.pack(">Q", value)


def _time_le(value: int) -> bytes:
    return struct.pack("<Q", value)


@dataclass
class AuthState:
    """Tracks one authentication handshake."""

    pairing: Pairing
    local_id: bytes
    challenge: bytes = field(default_factory=lambda: crypto.random_bytes(8))
    client_time: int | None = None  # monotonic seconds, compared as-is
    server_challenge: bytes | None = None
    server_time: int | None = None
    verified: bool = False

    def request_payload(self, *, now: int | None = None) -> bytes:
        self.client_time = now if now is not None else int(time.monotonic())
        body = self.challenge + _time_be(self.client_time)
        return (
            bytes([REQUEST_TYPE, PROTOCOL_VERSION])
            + body
            + _mac(self.pairing.ksc, self.challenge + _time_le(self.client_time))
            + self.local_id
            + self.pairing.alias
        )

    def request(self, *, now: int | None = None) -> bytes:
        payload = self.request_payload(now=now)
        return bytes([len(payload)]) + payload

    def confirm_payload(self, response: bytes) -> bytes:
        """Verify the device's proof and build our confirmation."""
        if self.verified:
            raise AuthError("authentication already completed")
        if len(response) != 27:
            raise AuthError("authentication response must be 27 bytes")
        if response[0] != RESPONSE_TYPE or response[1] != PROTOCOL_VERSION or response[2] != 0:
            raise AuthError("device rejected authentication")

        if self.client_time is None:
            raise AuthError("request() must be sent before confirm()")

        server_challenge = response[3:11]
        server_time = int.from_bytes(response[11:19], "big")
        expected = _mac(
            self.pairing.ksc,
            self.challenge + server_challenge + _time_le(server_time),
        )
        if not crypto.hmac.compare_digest(response[19:27], expected):
            # Do not retain anything from a frame that failed to authenticate:
            # caller code that catches AuthError must not be able to build a
            # channel out of unverified bytes.
            raise AuthError(
                "device failed to prove possession of the pairing key; "
                "the stored credentials do not match this device"
            )

        self.server_challenge = server_challenge
        self.server_time = server_time
        self.verified = True
        return (
            bytes([CONFIRM_TYPE, PROTOCOL_VERSION, 0])
            + _mac(
                self.pairing.ksc,
                server_challenge + _time_le(self.client_time),
            )
        )

    def confirm(self, response: bytes) -> bytes:
        payload = self.confirm_payload(response)
        return bytes([len(payload)]) + payload

    @property
    def transcript(self) -> bytes:
        """Client challenge followed by the server challenge."""
        if self.server_challenge is None:
            raise AuthError("no server challenge yet")
        return self.challenge + self.server_challenge