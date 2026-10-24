# -*- coding: utf-8 -*-
"""Frame format for the business channel.

One frame is::

    length   u8      body length + 2
    header   u16 BE  (session_id << 2) | fragmentation
    body     bytes

There is no address, no MEX header and no sequence field: the transport
profile in use sets frameProcedure 0, so the two-byte header sits directly
against the body.

A body larger than one frame is split into fragments marked first / middle /
last. The receiver concatenates them in order.

The numbers below are not tunable knobs. ``MAX_FRAME_BYTES`` is what the host
advertises during negotiation; changing it without renegotiating produces
frames the device drops.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import XinliqiuError

MAX_FRAME_BYTES = 235
MAX_BODY_CHUNK = MAX_FRAME_BYTES - 3

# The device's own fragments arrive at up to 238 bytes; the receiver accepts
# what the host advertised rather than assuming the device's exact split.
MAX_RECEIVED_FRAME_BYTES = 238
MAX_RECEIVED_BODY_CHUNK = MAX_RECEIVED_FRAME_BYTES - 3

MAX_TOTAL_BODY_BYTES = 1 << 20

FRAGMENT_NONE = 0
FRAGMENT_FIRST = 1
FRAGMENT_MIDDLE = 2
FRAGMENT_LAST = 3


class FrameError(XinliqiuError):
    """A frame was malformed or arrived out of order."""


@dataclass(frozen=True)
class Frame:
    session_id: int
    fragmentation: int
    body: bytes


def encode(session_id: int, body: bytes, fragmentation: int = FRAGMENT_NONE) -> bytes:
    if not 0 <= session_id < 1024:
        raise FrameError("session id must fit in 10 bits")
    if not body or len(body) > MAX_BODY_CHUNK:
        raise FrameError("frame body is empty or too large")
    if not 0 <= fragmentation <= 3:
        raise FrameError("fragmentation flag out of range")
    header = (session_id << 2) | fragmentation
    return bytes([len(body) + 2, (header >> 8) & 0xFF, header & 0xFF]) + body


def split(session_id: int, body: bytes) -> list[bytes]:
    """Encode ``body`` as one or more frames."""
    if not body or len(body) > MAX_TOTAL_BODY_BYTES:
        raise FrameError("body is empty or too large")

    if len(body) <= MAX_BODY_CHUNK:
        return [encode(session_id, body, FRAGMENT_NONE)]

    chunks = [body[i : i + MAX_BODY_CHUNK] for i in range(0, len(body), MAX_BODY_CHUNK)]
    if len(chunks) < 2:
        raise FrameError("fragmentation produced a single chunk")

    frames = []
    for index, chunk in enumerate(chunks):
        if index == 0:
            flag = FRAGMENT_FIRST
        elif index == len(chunks) - 1:
            flag = FRAGMENT_LAST
        else:
            flag = FRAGMENT_MIDDLE
        frames.append(encode(session_id, chunk, flag))
    return frames


def decode(payload: bytes) -> Frame:
    if len(payload) < 3:
        raise FrameError("frame shorter than its header")
    length = payload[0]
    if length != len(payload) - 1:
        raise FrameError("frame length byte disagrees with its size")
    header = (payload[1] << 8) | payload[2]
    return Frame(
        session_id=(header >> 2) & 0x3FF,
        fragmentation=header & 0x3,
        body=payload[3:],
    )


class Framer:
    """Reassembles one logical message from a notification stream.

    Feed it whatever arrives; it returns the message body once complete, or
    ``None`` while more is needed.
    """

    def __init__(self, *, session_id: int | None = None) -> None:
        # ``session_id`` filters frames belonging to other sessions. Leaving it
        # ``None`` accepts any session, which is only appropriate for a single
        # link that never carries more than one session.
        self.session_id = session_id
        # The 1 MiB ceiling is a protocol bound, not a tuning knob.
        self.max_bytes = MAX_TOTAL_BODY_BYTES
        self._buffer = bytearray()
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    def reset(self) -> None:
        self._buffer.clear()
        self._active = False

    def feed(self, payload: bytes) -> bytes | None:
        """Accept one notification; return the message body once complete.

        A protocol error resets the reassembly state before propagating. Without
        that, a single malformed or oversized fragment would leave the framer
        stuck mid-sequence and every later frame would be rejected, turning one
        bad packet into a dead channel.
        """
        try:
            return self._feed(payload)
        except FrameError:
            self.reset()
            raise

    def _feed(self, payload: bytes) -> bytes | None:
        frame = decode(payload)
        if self.session_id is not None and frame.session_id != self.session_id:
            raise FrameError("frame belongs to another session")
        if len(frame.body) > MAX_RECEIVED_BODY_CHUNK:
            raise FrameError("received fragment is larger than advertised")

        if frame.fragmentation == FRAGMENT_NONE:
            if self._active:
                raise FrameError("unfragmented frame during a fragmented sequence")
            if not frame.body:
                raise FrameError("empty unfragmented body")
            return frame.body

        if frame.fragmentation == FRAGMENT_FIRST:
            if self._active:
                raise FrameError("nested first fragment")
            if not frame.body:
                raise FrameError("empty first fragment")
            self._active = True
            self._buffer = bytearray(frame.body)
            return None

        if frame.fragmentation == FRAGMENT_MIDDLE:
            if not self._active:
                raise FrameError("middle fragment without a first")
            self._append(frame.body)
            return None

        # FRAGMENT_LAST
        if not self._active:
            raise FrameError("last fragment without a first")
        self._append(frame.body)
        complete = bytes(self._buffer)
        self.reset()
        # A fragmented sequence is by construction larger than one chunk. A
        # shorter one would mean the peer fragmented below the frame size, which
        # the transport never does; reject it rather than guess.
        if len(complete) <= MAX_BODY_CHUNK:
            raise FrameError("fragmented sequence did not exceed one chunk")
        return complete

    def _append(self, body: bytes) -> None:
        if not body:
            raise FrameError("empty continuation fragment")
        if len(self._buffer) + len(body) > self.max_bytes:
            raise FrameError("reassembled body exceeds the limit")
        self._buffer += body
