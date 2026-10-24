# -*- coding: utf-8 -*-
"""Transport negotiation (EPI).

Before any business exchange, the host answers the device's offer with the
parameters it will use: how large a message may be, how large a BLE packet may
be, and what kind of client this is.

The offer carries a capability fingerprint. The answer below is built for the
one profile this project supports; if the offer does not match, the device
speaks something this code does not model and negotiation stops rather than
guessing.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import XinliqiuError

ANSWER_TYPE = 2
ANSWER_VERSION = 1

# Local limits this host advertises.
LOCAL_APDU_SIZE = 7680
LOCAL_SSDU_SIZE = 235

# Fields of the offer this host understands, with their byte widths.
_NUMBER_WIDTHS = {1: 4, 2: 2, 3: 2, 4: 2, 5: 2, 10: 1, 11: 1, 12: 1, 13: 1}
_STRING_KEYS = (6, 7, 8)

# The fingerprint the device must present for this host to answer.
EXPECTED = {
    1: 20480,
    2: 491,
    3: 47,
    4: 10000,
    5: 10,
    11: 2,
    13: 0,
}


class NegotiationError(XinliqiuError):
    """The device offered something this host cannot answer."""


@dataclass
class Offer:
    protocol_version: int
    peer_id: bytes
    mode: int
    numbers: dict[int, int]
    strings: dict[int, str]


def parse_offer(data: bytes) -> Offer:
    """Decode the device's offer frame."""
    view = memoryview(data)
    offset = 0

    def take(count: int) -> bytes:
        nonlocal offset
        if count < 0 or offset + count > len(view):
            raise NegotiationError("offer is truncated")
        chunk = bytes(view[offset : offset + count])
        offset += count
        return chunk

    def number(count: int) -> int:
        return int.from_bytes(take(count), "big")

    if number(1) != 1:
        raise NegotiationError("expected offer type 1")
    version = number(2)
    if version > 1:
        raise NegotiationError(f"device protocol version {version} is unsupported")
    peer_id = take(36)
    mode = number(1)
    count = number(1)

    numbers: dict[int, int] = {}
    strings: dict[int, str] = {}
    for index in range(count):
        key = number(1)
        if key in _NUMBER_WIDTHS:
            numbers[key] = number(_NUMBER_WIDTHS[key])
        elif key in _STRING_KEYS:
            size = number(1)
            try:
                strings[key] = take(size).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise NegotiationError(f"field {key} is not valid UTF-8") from exc
        elif key == 14:
            take(6)
        else:
            # An unknown trailing feature is tolerated; an unknown field in the
            # middle means the layout changed and the rest cannot be trusted.
            if index != count - 1:
                raise NegotiationError(f"unknown feature {key} before the last field")

    return Offer(version, peer_id, mode, numbers, strings)


def check_offer(offer: Offer) -> None:
    """Refuse offers that do not match the profile this host implements."""
    if offer.mode != 0x10:
        raise NegotiationError("offer mode is not the single-client mode")
    for key, expected_text in ((6, "oppo"), (7, "oppo"), (8, "Beluga")):
        if offer.strings.get(key) != expected_text:
            raise NegotiationError(
                f"offer field {key} is {offer.strings.get(key)!r}, expected {expected_text!r}"
            )
    for key, expected in EXPECTED.items():
        if offer.numbers.get(key) != expected:
            raise NegotiationError(
                f"offer field {key} is {offer.numbers.get(key)!r}, expected {expected!r}"
            )


def build_answer(peer_id: str, *, service_profiles: int = 0) -> bytes:
    """Build the answer frame for a verified offer."""
    if len(peer_id) != 36 or not peer_id.startswith("OAFP_"):
        raise NegotiationError("local peer id must be 36 ASCII bytes starting with OAFP_")
    if not peer_id.isascii() or not all(32 <= ord(c) < 127 for c in peer_id):
        raise NegotiationError("local peer id must be printable ASCII")
    if not 0 <= service_profiles <= 255:
        raise NegotiationError("service profile count must fit in one byte")

    payload = bytearray([ANSWER_TYPE, 0, ANSWER_VERSION])
    payload += peer_id.encode("ascii")
    payload += bytes([0, 8])  # mode, feature count
    payload += bytes([1, 0, 0, 0x1E, 0])  # APDU cap
    payload += bytes([2, 0, LOCAL_SSDU_SIZE])
    for key, value in ((6, "Mac"), (7, "Local"), (8, "MacProbe")):
        encoded = value.encode("ascii")
        payload += bytes([key, len(encoded)]) + encoded
    payload += bytes([10, 8, 12, service_profiles, 13, 0])

    if len(payload) > 255:
        raise NegotiationError("answer exceeds the single-byte length prefix")
    return bytes([len(payload)]) + bytes(payload)