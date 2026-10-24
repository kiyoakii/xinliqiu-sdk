# -*- coding: utf-8 -*-
"""Business commands: status, storage totals, recording control.

Every request is ``service, command, payload`` and every reply begins with the
same ``service, command`` pair. Fields after that differ per command, so each
parser below states what it reads rather than slicing a common struct.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import XinliqiuError

# Service/command pairs.
SERVICE_STATUS = (0x05, 0x02)
SERVICE_STORAGE = (0x05, 0x04)
SERVICE_RECORD = (0x07, 0x00)
SERVICE_APPRECORD = (0x07, 0x02)

SERVICE_SYNC = (0x06, 0x00)
# Device -> host range reports. 06/01 is an early echo of the written range and
# proves nothing; 06/08 is the only range-end report and exists only for a
# finite end. Both carry the original 16-byte range payload.
SYNC_RANGE_ECHO = (0x06, 0x01)
SYNC_RANGE_END = (0x06, 0x08)
# 06/09 is a periodic wake/cycle report, never a count or an end.
SYNC_RANGE_CYCLE = (0x06, 0x09)

INT64_MAX = (1 << 63) - 1

STATUS_REQUEST = bytes([0x05, 0x02, 0xFF])
RECORD_STOP = bytes([0x07, 0x00, 0x00])
VOICEPRINT_STOP = bytes([0x07, 0x02, 0x00])

# Requests and replies carry different headers. A status request is 05/02 but
# its reply begins 02/FF; a storage request is 05/04 while its reply begins
# 04/FF. Comparing a reply against the request pair rejects every valid answer.
STATUS_REPLY_HEADER = (0x02, 0xFF)
STORAGE_REPLY_HEADER = (0x04, 0xFF)

MIN_STATUS_PAYLOAD = 12


class ProtocolError(XinliqiuError):
    """A reply was malformed or of the wrong shape."""


@dataclass(frozen=True)
class DeviceStatus:
    recording: bool
    record_byte: int
    charge_byte: int
    battery_percent: int
    device_timestamp_ms: int
    error_byte: int
    in_case: int | None = None
    in_note: int | None = None

    @classmethod
    def parse(cls, reply: bytes) -> "DeviceStatus":
        if len(reply) < 2 + MIN_STATUS_PAYLOAD:
            raise ProtocolError("status reply is shorter than its header plus payload")
        if reply[0] != STATUS_REPLY_HEADER[0] or reply[1] != STATUS_REPLY_HEADER[1]:
            raise ProtocolError(
                f"status reply header is {reply[0]:02x}{reply[1]:02x}, expected 02ff"
            )

        payload = reply[2:]
        # The device treats the whole byte as state, not a bitfield: any non-zero
        # value means recording. Testing bit 0 would misread state 2 as stopped.
        record_byte = payload[0]
        return cls(
            recording=record_byte != 0,
            record_byte=record_byte,
            charge_byte=payload[1],
            battery_percent=payload[2],
            device_timestamp_ms=int.from_bytes(payload[3:11], "little"),
            error_byte=payload[11],
            in_case=payload[12] if len(payload) >= 16 else None,
            in_note=payload[13] if len(payload) >= 16 else None,
        )


@dataclass(frozen=True)
class StorageTotals:
    start_ms: int
    end_ms: int
    item_count: int
    used_bytes: int
    highlight_count: int
    highlight_bytes: int

    @classmethod
    def parse(
        cls, reply: bytes, *, expected_range: tuple[int, int] | None = None
    ) -> "StorageTotals":
        """Parse a ``04 FF`` aggregate reply.

        ``expected_range`` is the ``(start_ms, end_ms)`` that was requested. The
        reply echoes the range it answered; a reply for any other range belongs
        to some other request and is refused instead of being reported as the
        totals for this one.
        """
        # 2 header bytes + 32 payload bytes.
        if len(reply) < 34:
            raise ProtocolError("storage reply is shorter than 34 bytes")
        if reply[0] != STORAGE_REPLY_HEADER[0] or reply[1] != STORAGE_REPLY_HEADER[1]:
            raise ProtocolError(
                f"storage reply header is {reply[0]:02x}{reply[1]:02x}, expected 04ff"
            )

        payload = reply[2:]
        if expected_range is not None:
            echoed = (
                int.from_bytes(payload[0:8], "little"),
                int.from_bytes(payload[8:16], "little"),
            )
            if echoed != (int(expected_range[0]), int(expected_range[1])):
                raise ProtocolError(
                    f"storage reply answers range {echoed[0]}..{echoed[1]}, "
                    f"not the requested {expected_range[0]}..{expected_range[1]}"
                )
        return cls(
            start_ms=int.from_bytes(payload[0:8], "little"),
            end_ms=int.from_bytes(payload[8:16], "little"),
            item_count=int.from_bytes(payload[16:20], "little"),
            used_bytes=int.from_bytes(payload[20:24], "little"),
            highlight_count=int.from_bytes(payload[24:28], "little"),
            highlight_bytes=int.from_bytes(payload[28:32], "little"),
        )


def record_start_command() -> bytes:
    """The enable command for continuous recording.

    The device takes the payload byte as the new state; 1 enables, 0 disables.
    """
    return bytes([0x07, 0x00, 0x01])


def record_stop_command() -> bytes:
    return RECORD_STOP


def voiceprint_start_command(seconds: int) -> bytes:
    if not 1 <= seconds <= 127:
        raise ProtocolError("voiceprint duration must be 1..127 seconds")
    return bytes([0x07, 0x02, seconds])


def voiceprint_stop_command() -> bytes:
    return VOICEPRINT_STOP


def range_payload(start_ms: int, end_ms: int, *, allow_zero_width: bool = True) -> bytes:
    """The 16-byte payload shared by storage and sync requests.

    Two little-endian signed 64-bit values and nothing else - no offset, no
    resume token, no count, no flags.

    Zero-width (``start_ms == end_ms``) is admitted by default: it names one
    device time point, and a past zero-width sync range has been observed on
    hardware to complete with a matching 06/08. The storage command passes
    ``allow_zero_width=False`` to retain its strictly increasing contract.
    """
    if isinstance(start_ms, bool) or isinstance(end_ms, bool):
        raise ProtocolError("range bounds must be integers")
    if not isinstance(start_ms, int) or not isinstance(end_ms, int):
        raise ProtocolError("range bounds must be integers")
    if end_ms > INT64_MAX:
        raise ProtocolError("range end must fit a signed 64-bit value")
    if start_ms < 0 or end_ms < start_ms or (end_ms == start_ms and not allow_zero_width):
        raise ProtocolError(
            "range must be increasing and non-negative"
            + (" (zero-width allowed)" if allow_zero_width else "")
        )
    return start_ms.to_bytes(8, "little") + end_ms.to_bytes(8, "little")


def sync_range_payload(start_ms: int, end_ms: int) -> bytes:
    """The ``06/00`` range payload; a zero-width range is legal here."""
    return range_payload(start_ms, end_ms, allow_zero_width=True)


def is_finite_range(start_ms: int, end_ms: int) -> bool:
    """Only a finite end ever produces a 06/08 range-end report."""
    return end_ms != INT64_MAX


def storage_request(start_ms: int, end_ms: int) -> bytes:
    """Service 05 / command 04 with a range payload."""
    return bytes([SERVICE_STORAGE[0], SERVICE_STORAGE[1]]) + range_payload(start_ms, end_ms, allow_zero_width=False)


def sync_request(start_ms: int, end_ms: int) -> bytes:
    """Service 06 / command 00 with the same range payload."""
    return bytes([SERVICE_SYNC[0], SERVICE_SYNC[1]]) + sync_range_payload(start_ms, end_ms)


def parse_range_echo(payload: bytes) -> tuple[int, int] | None:
    """Decode a 16-byte range echo, or return None if it is not one."""
    if len(payload) != 16:
        return None
    return (
        int.from_bytes(payload[0:8], "little", signed=True),
        int.from_bytes(payload[8:16], "little", signed=True),
    )
