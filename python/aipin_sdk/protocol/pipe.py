# -*- coding: utf-8 -*-
"""Pipe-message envelope.

Business bytes travel inside this frame on the secure channel::

    0xAA | length (7-bit groups, MSB-first, high bit = continuation) | body

    body = type | [transaction id LE32] | data

``type`` splits into a high nibble describing the frame class and a low nibble
describing whether a transaction id follows. Only the message class (high nibble
1) and the simple streamed form (exactly 0x30) are accepted here; anything else
means the peer is speaking something this code does not model, and stopping is
safer than guessing.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import XinliqiuError

MAGIC = 0xAA
MESSAGE_TYPE = 0x10
STREAM_TYPE = 0x30
MAX_BODY = 0x0FFF_FFFF


class PipeError(XinliqiuError):
    """A pipe message was malformed or of an unsupported kind."""


@dataclass(frozen=True)
class PipeMessage:
    type: int
    transaction_id: int | None
    data: bytes

    @property
    def is_stream(self) -> bool:
        return self.type == STREAM_TYPE


def _length_prefix(value: int) -> bytes:
    groups = []
    remaining = value
    while True:
        groups.append(remaining & 0x7F)
        remaining >>= 7
        if not remaining:
            break
    groups.reverse()
    return bytes(
        g | 0x80 if i < len(groups) - 1 else g for i, g in enumerate(groups)
    )


def encode(data: bytes, *, type: int = MESSAGE_TYPE, transaction_id: int | None = None) -> bytes:
    """Wrap ``data`` in a pipe message."""
    if type & 0xF0 != 0x10:
        raise PipeError(f"type 0x{type:02x} is not a message type")

    low = type & 0x0F
    if low == 0:
        if transaction_id is not None:
            raise PipeError("transaction id supplied for a type that has none")
    elif 1 <= low <= 4:
        if transaction_id is None:
            raise PipeError(f"type 0x{type:02x} requires a transaction id")
    else:
        raise PipeError(f"type low nibble {low} is not a supported message subtype")

    body = bytearray([type])
    if transaction_id is not None:
        body += transaction_id.to_bytes(4, "little")
    body += data

    if not body or len(body) > MAX_BODY:
        raise PipeError(f"body length {len(body)} is outside the 28-bit limit")
    return bytes([MAGIC]) + _length_prefix(len(body)) + bytes(body)


def decode(wire: bytes) -> PipeMessage:
    """Parse one complete pipe message."""
    if len(wire) < 2:
        raise PipeError("shorter than magic and length")
    if wire[0] != MAGIC:
        raise PipeError(f"missing 0xAA magic (first byte 0x{wire[0]:02x})")

    offset = 1
    length = 0
    groups = 0
    while True:
        if offset >= len(wire):
            raise PipeError("truncated length prefix")
        if groups >= 4:
            raise PipeError("length prefix longer than four groups")
        byte = wire[offset]
        offset += 1
        groups += 1
        length = (length << 7) | (byte & 0x7F)
        if not byte & 0x80:
            break

    if length <= 0:
        raise PipeError("zero-length body has no type byte")
    if length > MAX_BODY:
        raise PipeError(f"body length {length} exceeds the 28-bit limit")
    if len(wire) < offset + length:
        raise PipeError(
            f"truncated body: declared {length}, available {len(wire) - offset}"
        )
    if len(wire) > offset + length:
        trailing = len(wire) - offset - length
        if wire[offset + length] == MAGIC:
            raise PipeError(f"multiple AA frames in one plaintext (trailing {trailing} bytes)")
        raise PipeError(f"trailing {trailing} bytes after a complete body")

    body = wire[offset : offset + length]
    type_ = body[0]
    if type_ & 0xF0 != 0x10 and type_ != STREAM_TYPE:
        raise PipeError(f"type 0x{type_:02x} is not a supported business envelope")

    data_offset = 1
    transaction_id: int | None = None
    if type_ == STREAM_TYPE:
        pass  # no transaction id in the streamed form
    else:
        low = type_ & 0x0F
        if low == 0:
            pass
        elif 1 <= low <= 4:
            if length < 5:
                raise PipeError("transaction id is shorter than LE32")
            transaction_id = int.from_bytes(body[1:5], "little")
            data_offset = 5
        else:
            raise PipeError(f"type low nibble {low} is not a supported message subtype")

    return PipeMessage(type_, transaction_id, body[data_offset:])