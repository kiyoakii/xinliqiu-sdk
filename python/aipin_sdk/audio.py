# -*- coding: utf-8 -*-
"""Opus packet handling and WAV export.

Recordings are stored as fixed-size raw Opus packets, 20 ms each, mono, 16 kHz
source bandwidth.  The container does not carry a native sample count, so the
decoded duration is always ``packet_count * 20 ms``; that is a packet-count
duration, not the original microphone duration.

Ogg granules are always 48 kHz: one 20 ms packet advances the granule by 960.
``sample_rate`` is the source rate written into OpusHead and the WAV output
rate; it never changes the granule arithmetic.

WAV export runs ffmpeg in strict mode (``-xerror``): one undecodable packet
fails the whole export instead of being silently concealed, so a WAV that comes
back is a complete decode of every declared packet.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import oggopus
from .errors import ContainerError

DEFAULT_PACKET_BYTES = 40
DEFAULT_PACKET_MS = 20
DEFAULT_SAMPLE_RATE = 16000
DEFAULT_FFMPEG_TIMEOUT = 120.0
VALID_PACKET_MS = oggopus.VALID_PACKET_MS
MAX_PACKET_BYTES = oggopus.MAX_OPUS_PACKET
MIN_SAMPLE_RATE = 8000
MAX_SAMPLE_RATE = 192000
_WAV_HEADER_BYTES = 44


class AudioExportError(ContainerError):
    """ffmpeg-backed export failed.  ``code`` says which way, for callers.

    Codes: ``E_DECODER_UNAVAILABLE`` (no ffmpeg), ``E_DECODER_TIMEOUT``,
    ``E_DECODER`` (ffmpeg ran and failed, including a corrupt packet under
    ``-xerror``) and ``E_DECODER_OUTPUT`` (ffmpeg claimed success but left no
    usable WAV).  Subclasses ContainerError so existing handlers still catch it.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _check_int(name: str, value: object, low: int, high: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ContainerError(f"{name} must be an integer {low}..{high}; got {value!r}")


@dataclass(frozen=True)
class OpusLayout:
    packet_bytes: int = DEFAULT_PACKET_BYTES
    packet_ms: int = DEFAULT_PACKET_MS
    sample_rate: int = DEFAULT_SAMPLE_RATE

    def __post_init__(self) -> None:
        _check_int("packet_bytes", self.packet_bytes, 1, MAX_PACKET_BYTES)
        if isinstance(self.packet_ms, bool) or self.packet_ms not in VALID_PACKET_MS:
            raise ContainerError(
                f"packet_ms must be one of {', '.join(map(str, VALID_PACKET_MS))}; "
                f"got {self.packet_ms!r}"
            )
        _check_int("sample_rate", self.sample_rate, MIN_SAMPLE_RATE, MAX_SAMPLE_RATE)

    @property
    def samples_per_packet_48k(self) -> int:
        """Ogg granule advance per packet (960 for 20 ms)."""
        return self.packet_ms * oggopus.SAMPLES_PER_MS_48K

    def packet_count(self, payload: bytes) -> int:
        if len(payload) % self.packet_bytes:
            raise ContainerError(
                f"payload {len(payload)} bytes is not a multiple of {self.packet_bytes}"
            )
        return len(payload) // self.packet_bytes

    def duration_seconds(self, payload: bytes) -> float:
        return self.packet_count(payload) * self.packet_ms / 1000.0

    def final_granule(self, payload: bytes) -> int:
        """48 kHz granule of the last page: ``packet_count * packet_ms * 48``."""
        return self.packet_count(payload) * self.samples_per_packet_48k


def _require_ffmpeg() -> str:
    exe = shutil.which("ffmpeg")
    if not exe:
        raise AudioExportError(
            "E_DECODER_UNAVAILABLE",
            "ffmpeg is required for Opus decoding; to_ogg() works without it",
        )
    return exe


def to_ogg(payload: bytes, layout: OpusLayout | None = None, *, pre_skip: int = 0) -> bytes:
    """Wrap raw Opus packets into an Ogg/Opus stream.

    ``pre_skip`` is written verbatim into OpusHead (48 kHz samples) and must not
    exceed the total packet duration.  0 keeps every decoded sample.
    """
    layout = layout or OpusLayout()
    if layout.packet_count(payload) == 0:  # also validates alignment
        raise ContainerError("raw Opus payload is empty")
    try:
        return oggopus.encode(
            payload,
            packet_bytes=layout.packet_bytes,
            pre_skip=pre_skip,
            sample_rate=layout.sample_rate,
            packet_ms=layout.packet_ms,
        )
    except ValueError as exc:
        raise ContainerError(str(exc)) from exc


def _stderr_tail(raw: bytes | None) -> str:
    text = (raw or b"").decode("utf-8", "replace").strip()
    return " | ".join(text.splitlines()[-3:])[:1200]


def to_wav(
    payload: bytes,
    layout: OpusLayout | None = None,
    *,
    pre_skip: int = 0,
    timeout: float = DEFAULT_FFMPEG_TIMEOUT,
) -> bytes:
    """Decode raw Opus packets to a 16-bit mono WAV and return its bytes.

    ffmpeg runs with ``-nostdin -xerror`` in a private (0700) temporary
    directory that is always removed.  Every failure raises AudioExportError
    with a ``code``; nothing partial is returned.
    """
    layout = layout or OpusLayout()
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not timeout > 0:
        raise ContainerError(f"timeout must be a positive number of seconds; got {timeout!r}")
    ogg = to_ogg(payload, layout, pre_skip=pre_skip)
    ffmpeg = _require_ffmpeg()
    with tempfile.TemporaryDirectory(prefix="aipin-audio-") as tmp:
        workdir = Path(tmp)
        os.chmod(workdir, 0o700)
        src = workdir / "in.ogg"
        out = workdir / "out.wav"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(src, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(ogg)
        command = [
            ffmpeg, "-hide_banner", "-nostdin", "-nostats", "-loglevel", "error",
            "-xerror", "-n",
            "-i", str(src),
            "-map_metadata", "-1", "-vn",
            "-c:a", "pcm_s16le", "-ar", str(layout.sample_rate), "-ac", "1",
            "-f", "wav",
            str(out),
        ]
        try:
            proc = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AudioExportError(
                "E_DECODER_TIMEOUT", f"ffmpeg WAV decode exceeded {timeout} s and was stopped"
            ) from exc
        except FileNotFoundError as exc:
            raise AudioExportError(
                "E_DECODER_UNAVAILABLE", "ffmpeg disappeared before it could run"
            ) from exc
        except OSError as exc:
            raise AudioExportError(
                "E_DECODER", f"ffmpeg could not be executed: {exc.strerror or exc}"
            ) from exc
        if proc.returncode != 0:
            detail = _stderr_tail(proc.stderr)
            raise AudioExportError(
                "E_DECODER",
                f"ffmpeg WAV decode failed with status {proc.returncode}"
                + (f": {detail}" if detail else ""),
            )
        if out.is_symlink() or not out.is_file():
            raise AudioExportError("E_DECODER_OUTPUT", "ffmpeg reported success but wrote no WAV")
        data = out.read_bytes()
        if len(data) < _WAV_HEADER_BYTES or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
            raise AudioExportError(
                "E_DECODER_OUTPUT", f"ffmpeg output is not a WAV file ({len(data)} bytes)"
            )
        return data
