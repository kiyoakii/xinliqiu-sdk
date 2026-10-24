# -*- coding: utf-8 -*-
"""Minimal Ogg/Opus muxer for raw Opus packets (RFC 3533 + RFC 7845).

Produces a spec-compliant Ogg page stream so that any decoder (ffmpeg, libopus,
browsers) can consume it.  No external dependencies.

The parts that are easy to get wrong, and are therefore pinned here:

* Granule positions are always counted at 48 kHz, whatever the source rate.
  A 20 ms packet advances the granule by 960, never by 320.  The OpusHead
  "input sample rate" field is informational only.
* OpusHead with channel mapping family 0 is exactly 19 bytes; family 0 has no
  channel mapping table.
* OpusTags is magic, u32 vendor length, vendor string, u32 comment count and
  then each comment as u32 length + UTF-8 bytes.
* An Ogg page carries at most 255 lacing values.  A packet whose length is a
  multiple of 255 needs a terminating 0 lacing value, and a packet that does
  not fit is continued on the next page with the continuation flag set.
* OpusHead sits alone on the first (BOS) page, OpusTags finishes its own page,
  and audio starts on a fresh page.  Header pages carry granule 0.
"""

from __future__ import annotations

import struct
from typing import Iterable, Sequence

OPUS_HEAD_MAGIC = b"OpusHead"
OPUS_TAGS_MAGIC = b"OpusTags"
DEFAULT_SAMPLE_RATE = 16000
DEFAULT_PRE_SKIP = 0
DEFAULT_PACKET_MS = 20
DEFAULT_SERIAL = 0x48425401
DEFAULT_VENDOR = "aipin-sdk"

# Ogg/Opus granule positions always run at 48 kHz (RFC 7845 section 4).
GRANULE_RATE = 48000
SAMPLES_PER_MS_48K = GRANULE_RATE // 1000
PACKET_SAMPLES_48K = DEFAULT_PACKET_MS * SAMPLES_PER_MS_48K  # 960

# Whole-millisecond packet durations an Opus packet can have (RFC 6716: 10, 20,
# 40 and 60 ms frames, and multi-frame packets up to 120 ms).  2.5 and 5 ms
# frames are not representable in an integer-millisecond layout.
VALID_PACKET_MS = (10, 20, 40, 60, 80, 100, 120)

# Opus packet-size bound from the tested encode contract.
MAX_OPUS_PACKET = 1275
MAX_SEGMENTS = 255
MAX_PRE_SKIP = 0xFFFF
_GRANULE_NONE = 0xFFFFFFFFFFFFFFFF


def _make_crc_table() -> tuple[int, ...]:
    table = []
    for i in range(256):
        value = i << 24
        for _ in range(8):
            if value & 0x80000000:
                value = ((value << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                value = (value << 1) & 0xFFFFFFFF
        table.append(value)
    return tuple(table)


_CRC_TABLE = _make_crc_table()


def _crc32(data: bytes) -> int:
    """Ogg uses CRC-32 with polynomial 0x04C11DB7, no reflection, init 0."""
    crc = 0
    table = _CRC_TABLE
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ table[((crc >> 24) ^ byte) & 0xFF]
    return crc


def _require_int(name: str, value: object, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer; got {value!r}")
    if not low <= value <= high:
        raise ValueError(f"{name} must be {low}..{high}; got {value}")
    return value


def samples_per_packet(packet_ms: int = DEFAULT_PACKET_MS) -> int:
    """48 kHz granule advance for one packet of ``packet_ms`` milliseconds."""
    if isinstance(packet_ms, bool) or packet_ms not in VALID_PACKET_MS:
        raise ValueError(
            f"packet_ms must be one of {', '.join(map(str, VALID_PACKET_MS))}; got {packet_ms!r}"
        )
    return packet_ms * SAMPLES_PER_MS_48K


def _lacing(length: int) -> list[int]:
    values = [255] * (length // 255)
    values.append(length % 255)
    return values


def _page_bytes(lacing: list[int], body: bytes, *, serial: int, seq: int, granule: int, header_type: int) -> bytes:
    if not 1 <= len(lacing) <= MAX_SEGMENTS:
        raise ValueError(f"an Ogg page holds 1..{MAX_SEGMENTS} lacing values; got {len(lacing)}")
    header = struct.pack(
        "<4sBBQIIIB",
        b"OggS",
        0,
        header_type,
        granule & _GRANULE_NONE,
        serial & 0xFFFFFFFF,
        seq & 0xFFFFFFFF,
        0,
        len(lacing),
    )
    page = header + bytes(lacing) + body
    crc = _crc32(page)
    return page[:22] + struct.pack("<I", crc) + page[26:]


class _Paginator:
    """Lays packets into Ogg pages without ever exceeding 255 lacing values."""

    def __init__(self, serial: int) -> None:
        self.serial = serial
        self.seq = 0
        self.out = bytearray()
        self._lacing: list[int] = []
        self._body = bytearray()
        self._granule: int | None = None
        self._continued = False
        self._bos = True

    def _emit(self, *, eos: bool, continues: bool) -> None:
        header_type = 0
        if self._continued:
            header_type |= 0x01
        if self._bos:
            header_type |= 0x02
        if eos:
            header_type |= 0x04
        granule = _GRANULE_NONE if self._granule is None else self._granule
        self.out += _page_bytes(
            self._lacing, bytes(self._body),
            serial=self.serial, seq=self.seq, granule=granule, header_type=header_type,
        )
        self.seq += 1
        self._lacing = []
        self._body = bytearray()
        self._granule = None
        self._continued = continues
        self._bos = False

    def add(self, packet: bytes, granule: int) -> None:
        segments = _lacing(len(packet))
        # Start a whole packet on a fresh page when it would not fit here, so
        # ordinary audio packets are never split across pages.
        if self._lacing and len(self._lacing) + len(segments) > MAX_SEGMENTS:
            self._emit(eos=False, continues=False)
        offset = 0
        while len(self._lacing) + len(segments) > MAX_SEGMENTS:
            take = MAX_SEGMENTS - len(self._lacing)
            part, segments = segments[:take], segments[take:]
            size = sum(part)
            self._lacing += part
            self._body += packet[offset : offset + size]
            offset += size
            self._emit(eos=False, continues=True)
        self._lacing += segments
        self._body += packet[offset:]
        self._granule = granule

    def flush(self, *, eos: bool = False) -> None:
        if self._lacing:
            self._emit(eos=eos, continues=False)


def opus_head(
    *,
    channels: int = 1,
    pre_skip: int = DEFAULT_PRE_SKIP,
    input_sample_rate: int = DEFAULT_SAMPLE_RATE,
    output_gain: int = 0,
) -> bytes:
    """RFC 7845 identification header, channel mapping family 0 (19 bytes)."""
    _require_int("channels", channels, 1, 2)
    _require_int("pre_skip", pre_skip, 0, MAX_PRE_SKIP)
    _require_int("input_sample_rate", input_sample_rate, 0, 0xFFFFFFFF)
    _require_int("output_gain", output_gain, -0x8000, 0x7FFF)
    return struct.pack(
        "<8sBBHIhB",
        OPUS_HEAD_MAGIC,
        1,  # version
        channels,
        pre_skip,
        input_sample_rate,
        output_gain,
        0,  # mapping family 0: no channel mapping table follows
    )


def _validate_comment(comment: str) -> bytes:
    if not isinstance(comment, str):
        raise ValueError(f"OpusTags comments must be str; got {type(comment).__name__}")
    key, sep, _value = comment.partition("=")
    if not sep or not key or any(not (0x20 <= ord(ch) <= 0x7D) or ch == "=" for ch in key):
        raise ValueError(f"OpusTags comment must be KEY=value with a printable ASCII key; got {comment!r}")
    return comment.encode("utf-8")


def opus_tags(vendor: str = DEFAULT_VENDOR, comments: Iterable[str] = ()) -> bytes:
    """RFC 7845 comment header: vendor string plus a counted comment list."""
    if not isinstance(vendor, str):
        raise ValueError("vendor must be str")
    vendor_bytes = vendor.encode("utf-8")
    encoded = [_validate_comment(c) for c in comments]
    out = bytearray(OPUS_TAGS_MAGIC)
    out += struct.pack("<I", len(vendor_bytes)) + vendor_bytes
    out += struct.pack("<I", len(encoded))
    for item in encoded:
        out += struct.pack("<I", len(item)) + item
    return bytes(out)


def encode_packets(
    packets: Sequence[bytes],
    *,
    pre_skip: int = DEFAULT_PRE_SKIP,
    serial: int = DEFAULT_SERIAL,
    sample_rate: int = DEFAULT_SAMPLE_RATE,
    packet_ms: int = DEFAULT_PACKET_MS,
    channels: int = 1,
    output_gain: int = 0,
    vendor: str = DEFAULT_VENDOR,
    comments: Iterable[str] = (),
) -> bytes:
    """Mux already-split Opus packets, each ``packet_ms`` long, into Ogg/Opus.

    ``sample_rate`` is only the informational OpusHead input rate; granules are
    48 kHz (``packet_ms * 48`` per packet).  The caller declares the packet
    duration: this muxer never parses a TOC byte to guess it.
    """
    per_packet = samples_per_packet(packet_ms)
    _require_int("serial", serial, 0, 0xFFFFFFFF)
    packets = [bytes(p) for p in packets]
    if not packets:
        raise ValueError("empty payload")
    for index, packet in enumerate(packets):
        if not 1 <= len(packet) <= MAX_OPUS_PACKET:
            raise ValueError(
                f"Opus packet {index} length must be 1..{MAX_OPUS_PACKET}; got {len(packet)}"
            )
    total = len(packets) * per_packet
    _require_int("pre_skip", pre_skip, 0, MAX_PRE_SKIP)
    if pre_skip > total:
        raise ValueError(
            f"pre_skip {pre_skip} exceeds the total packet duration {total} at 48 kHz"
        )
    head = opus_head(
        channels=channels, pre_skip=pre_skip,
        input_sample_rate=sample_rate, output_gain=output_gain,
    )
    tags = opus_tags(vendor, comments)

    pager = _Paginator(serial)
    pager.add(head, 0)
    pager.flush()
    pager.add(tags, 0)
    pager.flush()
    granule = 0
    for packet in packets:
        granule += per_packet
        pager.add(packet, granule)
    pager.flush(eos=True)
    return bytes(pager.out)


def encode(
    payload: bytes,
    *,
    packet_bytes: int = 40,
    pre_skip: int = DEFAULT_PRE_SKIP,
    serial: int = DEFAULT_SERIAL,
    sample_rate: int = DEFAULT_SAMPLE_RATE,
    packet_ms: int = DEFAULT_PACKET_MS,
    channels: int = 1,
    output_gain: int = 0,
    vendor: str = DEFAULT_VENDOR,
    comments: Iterable[str] = (),
) -> bytes:
    """Mux fixed-size Opus packets into an Ogg stream (mono by default)."""
    if isinstance(packet_bytes, bool) or not isinstance(packet_bytes, int) or packet_bytes <= 0:
        raise ValueError("packet_bytes must be positive")
    if packet_bytes > MAX_OPUS_PACKET:
        raise ValueError(f"packet_bytes must be 1..{MAX_OPUS_PACKET}; got {packet_bytes}")
    if len(payload) % packet_bytes:
        raise ValueError(f"payload {len(payload)} not a multiple of {packet_bytes}")
    packets = [payload[i : i + packet_bytes] for i in range(0, len(payload), packet_bytes)]
    if not packets:
        raise ValueError("empty payload")
    return encode_packets(
        packets,
        pre_skip=pre_skip,
        serial=serial,
        sample_rate=sample_rate,
        packet_ms=packet_ms,
        channels=channels,
        output_gain=output_gain,
        vendor=vendor,
        comments=comments,
    )
