# -*- coding: utf-8 -*-
"""Offline regressions for the audio, Ogg, CMPT/enpt and SecureChannel fixes.

No device, no network, no real keys or recordings: every key is generated in
memory and every Opus stream is synthesised by a local ffmpeg (tests that need
ffmpeg skip when it is absent).

    python3 -m unittest tests.test_fixes_audio      (from xinliqiu-sdk/)
    python3 tests/test_fixes_audio.py
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

import aipin_sdk as hb  # noqa: E402
from aipin_sdk import audio, container, oggopus  # noqa: E402

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTO = False

FFMPEG = shutil.which("ffmpeg")


# --- helpers ----------------------------------------------------------------


def parse_ogg(data: bytes) -> tuple[list[dict], list[bytes]]:
    """Independent Ogg page/packet reader used only by these tests."""
    pages: list[dict] = []
    packets: list[bytes] = []
    partial = b""
    offset = 0
    while offset < len(data):
        assert data[offset : offset + 4] == b"OggS", f"no OggS at {offset}"
        header_type = data[offset + 5]
        (granule,) = struct.unpack_from("<Q", data, offset + 6)
        serial, seq, crc = struct.unpack_from("<III", data, offset + 14)
        count = data[offset + 26]
        lacing = data[offset + 27 : offset + 27 + count]
        cursor = offset + 27 + count
        for value in lacing:
            partial += data[cursor : cursor + value]
            cursor += value
            if value < 255:
                packets.append(partial)
                partial = b""
        page = data[offset:cursor]
        pages.append(
            {
                "type": header_type,
                "granule": granule,
                "serial": serial,
                "seq": seq,
                "crc": crc,
                "segments": count,
                "bytes": page,
                "ends_open": bool(lacing) and lacing[-1] == 255,
            }
        )
        offset = cursor
    assert partial == b"", "unterminated packet"
    return pages, packets


def bitwise_crc(page: bytes) -> int:
    page = page[:22] + b"\x00\x00\x00\x00" + page[26:]
    crc = 0
    for byte in page:
        crc ^= byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 else (crc << 1) & 0xFFFFFFFF
    return crc


def make_cmpt(entries: list[tuple[str, bytes]], *, trailing: bytes = b"") -> bytes:
    table = bytearray()
    for name, payload in entries:
        table += name.encode("utf-8")[:64].ljust(64, b"\x00") + struct.pack("<I", len(payload))
    offset = 12 + len(table)
    body = b"".join(p for _, p in entries) + trailing
    declared = offset + len(body)
    return b"CMPT" + struct.pack("<HHI", len(entries), offset, declared) + bytes(table) + body


def make_enpt(plaintext: bytes, public_key, *, aes_key: bytes | None = None, version: int = 3) -> bytes:
    aes_key = os.urandom(32) if aes_key is None else aes_key
    nonce = os.urandom(12)
    wrapped = public_key.encrypt(aes_key, padding.PKCS1v15())
    sealed = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    head = b"enpt" + struct.pack("<HH", len(wrapped), 12) + wrapped + nonce
    head += struct.pack("<H", 0x118) + bytes([version, 0])
    return head + ciphertext + tag + struct.pack("<HH", 16, 24) + b"enpt"


def pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


_REFERENCE: list[bytes] | None = None


def reference_packets() -> list[bytes]:
    """Ten 40-byte CBR Opus packets from a synthetic 440 Hz tone."""
    global _REFERENCE
    if _REFERENCE is None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "ref.ogg"
            subprocess.run(
                [
                    FFMPEG, "-hide_banner", "-nostdin", "-loglevel", "error",
                    "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=16000:duration=0.2",
                    "-ac", "1", "-c:a", "libopus", "-b:a", "16k", "-frame_duration", "20",
                    "-application", "audio", "-vbr", "off", "-y", str(out),
                ],
                check=True,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=60,
            )
            _pages, packets = parse_ogg(out.read_bytes())
        audio_packets = [p for p in packets[2:] if len(p) == 40]
        assert len(audio_packets) >= 10, [len(p) for p in packets]
        _REFERENCE = audio_packets[:10]
    return list(_REFERENCE)


# --- Ogg/Opus muxer ----------------------------------------------------------


class OggGranuleAndHeaderTests(unittest.TestCase):
    def test_granules_are_48k_960_per_20ms_packet(self):
        ogg = oggopus.encode(b"\x08" * 40 * 3, packet_bytes=40)
        pages, packets = parse_ogg(ogg)
        self.assertEqual([p["granule"] for p in pages], [0, 0, 2880])
        self.assertEqual(len(packets), 2 + 3)
        # Source rate never enters the granule arithmetic.
        for rate in (8000, 16000, 48000):
            pages, _ = parse_ogg(oggopus.encode(b"\x08" * 40 * 5, packet_bytes=40, sample_rate=rate))
            self.assertEqual(pages[-1]["granule"], 5 * 960, rate)

    def test_granule_per_page_is_last_completed_packet(self):
        # 300 packets of 40 B: page boundaries at 255 lacing values.
        ogg = oggopus.encode(b"\x08" * 40 * 300, packet_bytes=40)
        pages, packets = parse_ogg(ogg)
        audio_pages = pages[2:]
        self.assertEqual([p["segments"] for p in audio_pages], [255, 45])
        self.assertEqual([p["granule"] for p in audio_pages], [255 * 960, 300 * 960])
        self.assertEqual(len(packets) - 2, 300)

    def test_other_packet_durations_scale_granules(self):
        layout = hb.OpusLayout(packet_ms=60)
        ogg = hb.to_ogg(b"\x08" * 40 * 4, layout)
        pages, _ = parse_ogg(ogg)
        self.assertEqual(pages[-1]["granule"], 4 * 2880)
        self.assertEqual(layout.final_granule(b"\x08" * 160), 4 * 2880)

    def test_opus_head_is_spec_correct(self):
        ogg = oggopus.encode(b"\x08" * 40 * 20, packet_bytes=40, pre_skip=312, sample_rate=16000)
        pages, packets = parse_ogg(ogg)
        head = packets[0]
        self.assertEqual(len(head), 19, "family 0 OpusHead has no mapping table")
        magic, version, channels, pre_skip, rate, gain, family = struct.unpack("<8sBBHIhB", head)
        self.assertEqual(
            (magic, version, channels, pre_skip, rate, gain, family),
            (b"OpusHead", 1, 1, 312, 16000, 0, 0),
        )
        self.assertEqual(pages[0]["type"], 0x02, "OpusHead page is BOS only")
        self.assertEqual(pages[0]["segments"], 1, "OpusHead is alone on its page")
        self.assertEqual(pages[-1]["type"] & 0x04, 0x04, "last page is EOS")
        self.assertTrue(all(p["type"] & 0x04 == 0 for p in pages[:-1]))
        self.assertEqual(len({p["serial"] for p in pages}), 1)
        self.assertEqual([p["seq"] for p in pages], list(range(len(pages))))

    def test_opus_tags_is_spec_correct(self):
        ogg = oggopus.encode(
            b"\x08" * 40, packet_bytes=40, vendor="vénd", comments=["TITLE=tëst", "X=1"]
        )
        pages, packets = parse_ogg(ogg)
        tags = packets[1]
        self.assertEqual(tags[:8], b"OpusTags")
        (vlen,) = struct.unpack_from("<I", tags, 8)
        self.assertEqual(tags[12 : 12 + vlen].decode("utf-8"), "vénd")
        cursor = 12 + vlen
        (count,) = struct.unpack_from("<I", tags, cursor)
        cursor += 4
        seen = []
        for _ in range(count):
            (n,) = struct.unpack_from("<I", tags, cursor)
            seen.append(tags[cursor + 4 : cursor + 4 + n].decode("utf-8"))
            cursor += 4 + n
        self.assertEqual(cursor, len(tags), "no bytes after the comment list")
        self.assertEqual(seen, ["TITLE=tëst", "X=1"])
        self.assertEqual(pages[1]["granule"], 0)
        self.assertEqual(pages[1]["segments"], len(oggopus._lacing(len(tags))))
        # Default tags: non-empty vendor, zero comments.
        _p, default_packets = parse_ogg(oggopus.encode(b"\x08" * 40, packet_bytes=40))
        default = default_packets[1]
        (vlen,) = struct.unpack_from("<I", default, 8)
        self.assertGreater(vlen, 0)
        self.assertEqual(struct.unpack_from("<I", default, 12 + vlen)[0], 0)
        self.assertEqual(len(default), 16 + vlen)
        for bad in ("novalue", "=x", "KéY=1", 5):
            with self.assertRaises(ValueError, msg=repr(bad)):
                oggopus.opus_tags(comments=[bad])

    def test_crc_matches_bitwise_reference(self):
        ogg = oggopus.encode(os.urandom(40 * 7), packet_bytes=40, pre_skip=100)
        pages, _ = parse_ogg(ogg)
        for page in pages:
            self.assertEqual(page["crc"], bitwise_crc(page["bytes"]))

    def test_page_segment_limit_with_255_multiple_packets(self):
        # 255-byte packets need [255, 0] lacing: 127 packets per 255-value page.
        ogg = oggopus.encode(b"\x08" * 255 * 300, packet_bytes=255)
        pages, packets = parse_ogg(ogg)
        self.assertTrue(all(p["segments"] <= 255 for p in pages))
        self.assertEqual(len(packets) - 2, 300)
        self.assertTrue(all(len(p) == 255 for p in packets[2:]))
        self.assertTrue(all(not p["ends_open"] for p in pages), "packets are never split")
        self.assertEqual(pages[-1]["granule"], 300 * 960)
        # Every packet up to the Opus maximum is accepted and round-trips.
        ogg = oggopus.encode(b"\x08" * 1275 * 60, packet_bytes=1275)
        pages, packets = parse_ogg(ogg)
        self.assertTrue(all(p["segments"] <= 255 for p in pages))
        self.assertEqual([len(p) for p in packets[2:]], [1275] * 60)

    def test_long_header_packet_continues_across_pages(self):
        long_comment = "C=" + "x" * (255 * 300)
        ogg = oggopus.encode(b"\x08" * 40 * 2, packet_bytes=40, comments=[long_comment])
        pages, packets = parse_ogg(ogg)
        self.assertTrue(all(p["segments"] <= 255 for p in pages))
        self.assertIn(long_comment.encode(), packets[1])
        tag_pages = [p for p in pages if p["granule"] in (0, 0xFFFFFFFFFFFFFFFF)][1:]
        self.assertGreater(len(tag_pages), 1)
        self.assertTrue(tag_pages[1]["type"] & 0x01, "continuation flag set")
        self.assertEqual(tag_pages[0]["granule"], 0xFFFFFFFFFFFFFFFF, "no packet ends there")
        self.assertEqual(packets[2:], [b"\x08" * 40] * 2)

    def test_muxer_rejects_bad_inputs(self):
        for kwargs in (
            {"packet_bytes": 0},
            {"packet_bytes": 1276},
            {"packet_bytes": True},
            {"pre_skip": -1},
            {"pre_skip": 65536},
            {"pre_skip": 961},  # exceeds one packet's 960 samples
            {"packet_ms": 25},
            {"channels": 3},
        ):
            args = {"packet_bytes": 40, **kwargs}
            size = args["packet_bytes"]
            # An aligned payload where possible, so the rejection is the field under test.
            payload = b"\x08" * (size if type(size) is int and size > 0 else 40)
            with self.assertRaises(ValueError, msg=repr(kwargs)):
                oggopus.encode(payload, **args)
        with self.assertRaises(ValueError):
            oggopus.encode(b"", packet_bytes=40)
        with self.assertRaises(ValueError):
            oggopus.encode_packets([b"\x08" * 40, b""])


class LayoutValidationTests(unittest.TestCase):
    def test_custom_layouts_are_validated(self):
        for kwargs in (
            {"packet_bytes": 0},
            {"packet_bytes": -40},
            {"packet_bytes": 1276},
            {"packet_bytes": 40.0},
            {"packet_ms": 0},
            {"packet_ms": 25},
            {"packet_ms": True},
            {"sample_rate": 0},
            {"sample_rate": 7999},
            {"sample_rate": 192001},
        ):
            with self.assertRaises(hb.ContainerError, msg=repr(kwargs)):
                hb.OpusLayout(**kwargs)
        layout = hb.OpusLayout(packet_bytes=80, packet_ms=40, sample_rate=48000)
        self.assertEqual(layout.samples_per_packet_48k, 1920)
        self.assertEqual(hb.OpusLayout().samples_per_packet_48k, 960)

    def test_to_ogg_maps_errors_to_container_error(self):
        with self.assertRaises(hb.ContainerError):
            hb.to_ogg(b"")
        with self.assertRaises(hb.ContainerError):
            hb.to_ogg(b"\x08" * 41)
        with self.assertRaises(hb.ContainerError):
            hb.to_ogg(b"\x08" * 40, pre_skip=961)
        self.assertTrue(hb.to_ogg(b"\x08" * 40, pre_skip=960).startswith(b"OggS"))


# --- ffmpeg WAV export ---------------------------------------------------------


class WavExportControlTests(unittest.TestCase):
    """Command shape and error mapping, without depending on ffmpeg."""

    def _run_with(self, fake_run):
        with mock.patch.object(audio, "_require_ffmpeg", return_value="/usr/bin/ffmpeg"), \
                mock.patch.object(audio.subprocess, "run", side_effect=fake_run):
            return hb.to_wav(b"\x08" * 40 * 3)

    def test_command_is_strict_and_noninteractive(self):
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            src = Path(cmd[cmd.index("-i") + 1])
            seen["src_mode"] = src.stat().st_mode & 0o777
            seen["dir_mode"] = src.parent.stat().st_mode & 0o777
            seen["dir"] = src.parent
            Path(cmd[-1]).write_bytes(b"RIFF" + b"\x00" * 4 + b"WAVE" + b"\x00" * 32)
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        wav = self._run_with(fake_run)
        cmd = seen["cmd"]
        for flag in ("-nostdin", "-xerror", "-n"):
            self.assertIn(flag, cmd)
        self.assertLess(cmd.index("-xerror"), cmd.index("-i"), "-xerror is a global option")
        self.assertNotIn("-y", cmd)
        self.assertEqual(seen["kwargs"]["stdin"], subprocess.DEVNULL)
        self.assertGreater(seen["kwargs"]["timeout"], 0)
        self.assertEqual(seen["src_mode"], 0o600)
        self.assertEqual(seen["dir_mode"], 0o700)
        self.assertFalse(seen["dir"].exists(), "temporary directory is removed")
        self.assertTrue(wav.startswith(b"RIFF"))

    def test_timeout_is_controlled(self):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

        with self.assertRaises(audio.AudioExportError) as ctx:
            self._run_with(fake_run)
        self.assertEqual(ctx.exception.code, "E_DECODER_TIMEOUT")
        self.assertIsInstance(ctx.exception, hb.ContainerError)

    def test_missing_or_bogus_output_is_controlled(self):
        def no_output(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        def bogus_output(cmd, **kwargs):
            Path(cmd[-1]).write_bytes(b"not a wav")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        for fake in (no_output, bogus_output):
            with self.assertRaises(audio.AudioExportError) as ctx:
                self._run_with(fake)
            self.assertEqual(ctx.exception.code, "E_DECODER_OUTPUT", fake.__name__)

    def test_nonzero_exit_reports_stderr_tail(self):
        def failing(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 183, b"", b"line1\nline2\nInvalid data\n")

        with self.assertRaises(audio.AudioExportError) as ctx:
            self._run_with(failing)
        self.assertEqual(ctx.exception.code, "E_DECODER")
        self.assertIn("183", str(ctx.exception))
        self.assertIn("Invalid data", str(ctx.exception))

    def test_missing_ffmpeg_is_controlled(self):
        with mock.patch.object(audio.shutil, "which", return_value=None):
            with self.assertRaises(audio.AudioExportError) as ctx:
                hb.to_wav(b"\x08" * 40)
        self.assertEqual(ctx.exception.code, "E_DECODER_UNAVAILABLE")
        # Ogg export never needs ffmpeg.
        with mock.patch.object(audio.shutil, "which", return_value=None):
            self.assertTrue(hb.to_ogg(b"\x08" * 40).startswith(b"OggS"))

    def test_invalid_timeout_rejected(self):
        for bad in (0, -1, True, "5"):
            with self.assertRaises(hb.ContainerError, msg=repr(bad)):
                hb.to_wav(b"\x08" * 40, timeout=bad)


@unittest.skipUnless(FFMPEG, "ffmpeg not installed")
class WavExportFfmpegTests(unittest.TestCase):
    def test_valid_stream_decodes_to_full_packet_duration(self):
        payload = b"".join(reference_packets())
        wav = hb.to_wav(payload)
        self.assertEqual(wav[:4], b"RIFF")
        data_at = wav.index(b"data")
        (size,) = struct.unpack_from("<I", wav, data_at + 4)
        # 10 packets * 20 ms * 16 kHz * 2 bytes, pre-skip 0.
        self.assertEqual(size, 10 * 320 * 2)

    def test_mixed_stream_with_one_corrupt_packet_fails(self):
        packets = reference_packets()
        bad = bytearray(packets[4])
        bad[0] = (bad[0] & 0xFC) | 0x03  # code 3 ...
        bad[1] = 0x00  # ... with zero frames: undecodable
        packets[4] = bytes(bad)
        payload = b"".join(packets)
        self.assertTrue(hb.to_ogg(payload).startswith(b"OggS"), "muxing never inspects packets")
        with self.assertRaises(audio.AudioExportError) as ctx:
            hb.to_wav(payload)
        self.assertEqual(ctx.exception.code, "E_DECODER")


# --- CMPT ---------------------------------------------------------------------


class CmptTests(unittest.TestCase):
    def test_trailing_undeclared_bytes_rejected(self):
        base = [("1000-2000.enc.opus", b"a" * 40)]
        hb.parse_cmpt(make_cmpt(base))
        for extra in (b"\x00", b"\x00" * 24, b"junk"):
            with self.assertRaisesRegex(hb.ContainerError, "trailing bytes", msg=repr(extra)):
                hb.parse_cmpt(make_cmpt(base, trailing=extra))

    def test_entry_count_bounds(self):
        with self.assertRaises(hb.ContainerError):
            hb.parse_cmpt(b"CMPT" + struct.pack("<HHI", 0, 12, 12))

    def test_masked_lengths_match_source(self):
        data = bytearray(make_cmpt([("1-2.enc.opus", b"q" * 40)]))
        struct.pack_into("<I", data, 8, len(data) | 0x80000000)
        struct.pack_into("<I", data, 12 + 64, 40 | 0x80000000)
        parsed = hb.parse_cmpt(bytes(data))
        self.assertEqual(parsed.entries[0].size, 40)
        self.assertEqual(parsed.declared_length, len(data))

    def test_tested_kinds_are_ported(self):
        cases = {
            "1-2.enc.opus": ("audio", "audio", "plain"),
            "1-2.opus": ("audio", "audio", "plain"),
            "1-2.enc.note.opus": ("audio", "note-audio", "note"),
            "1-2.note.opus": ("audio", "note-audio", "note"),
            "1-2.enc.noise.opus": ("audio", "audio", "noise"),
            "1-2.noise.opus": ("audio", "audio", "noise"),
            "1-2.enc.vp.opus": ("audio", "audio", "vp"),
            "1-2.VP.OPUS": ("audio", "audio", "vp"),
            "1-2.end.enc.opus": ("end-marker", "end-marker", None),
            "1-2.end.opus": ("end-marker", "end-marker", None),
            "1792593674787.mark": ("mark", "mark", None),
            "1-2.tp": ("tp", "trace-point", None),
            "1-2.compat.tp": ("compat-tp", "trace-point", None),
            "readme.txt": ("unknown", "unknown", None),
        }
        names = list(cases)
        parsed = hb.parse_cmpt(make_cmpt([(n, b"x" * (i + 1)) for i, n in enumerate(names)]))
        for entry in parsed.entries:
            cmpt_kind, kind, variant = cases[entry.name]
            self.assertEqual(entry.cmpt_kind, cmpt_kind, entry.name)
            self.assertEqual(entry.kind, kind, entry.name)
            self.assertIn(entry.kind, container.STORAGE_KINDS)
            self.assertEqual(entry.audio_variant, variant, entry.name)
            self.assertEqual(entry.is_marker, cmpt_kind in ("end-marker", "mark"), entry.name)
        self.assertEqual(len(parsed.by_kind("audio")), 8, "every audio variant")
        self.assertEqual(len(parsed.by_kind("note-audio")), 2)
        self.assertEqual(len(parsed.by_kind("mark")), 1)
        self.assertEqual(len(parsed.by_kind("trace-point")), 2)
        self.assertEqual(len(parsed.by_kind("compat-tp")), 1)

    def test_generated_output_name_never_trusts_entry_name(self):
        hostile = [
            "../../etc/passwd.enc.opus",
            "/abs/1-2.mark",
            "..\\..\\win.tp",
            ".hidden.end.enc.opus",
            "a/b/1-2.compat.tp",
            "",
        ]
        parsed = hb.parse_cmpt(make_cmpt([(n, b"z") for n in hostile]))
        names = []
        for entry in parsed.entries:
            out = entry.output_name()
            names.append(out)
            self.assertEqual(Path(out).name, out)
            self.assertNotIn("..", out)
            self.assertFalse(out.startswith("."))
            self.assertRegex(out, r"^cmpt-\d{3}-[a-z-]+\.bin$")
        self.assertEqual(
            names,
            [
                "cmpt-000-audio.bin",
                "cmpt-001-mark.bin",
                "cmpt-002-tp.bin",
                "cmpt-003-end-marker.bin",
                "cmpt-004-compat-tp.bin",
                "cmpt-005-unknown.bin",
            ],
        )
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual([e.name_is_safe for e in parsed.entries], [False, False, False, True, True, False])
        entry = parsed.entries[0]
        self.assertEqual(container.generated_output_name(entry, ".enpt", prefix="c7"), "c7-000-audio.enpt")
        for prefix in ("../x", "", ".a", "a/b", "x" * 65):
            with self.assertRaises(hb.ContainerError, msg=prefix):
                entry.output_name(prefix=prefix)
        for suffix in ("/x", ".", "bin", "../.bin", ".a.b.c.d"):
            with self.assertRaises(hb.ContainerError, msg=suffix):
                entry.output_name(suffix)


class MarkerTests(unittest.TestCase):
    def test_marker_rules(self):
        good = struct.pack("<Q", 1792593674787) + b"\x00" * 32
        self.assertEqual(container.parse_marker(good), 1792593674787)
        with self.assertRaisesRegex(hb.ContainerError, "nonzero"):
            container.parse_marker(b"\x00" * 40)
        with self.assertRaises(hb.ContainerError):
            container.parse_marker(good[:39])
        with self.assertRaises(hb.ContainerError):
            container.parse_marker(good[:8] + b"\x01" + b"\x00" * 31)


# --- enpt ---------------------------------------------------------------------


def _synthetic_enpt(payload: bytes = b"p" * 40) -> bytes:
    head = b"enpt" + struct.pack("<HH", 256, 12) + b"\x00" * 268
    head += struct.pack("<H", 0x118) + bytes([1, 0])
    return head + payload + b"\x00" * 16 + struct.pack("<HH", 16, 24) + b"enpt"


class EnptStructureTests(unittest.TestCase):
    def test_header_length_field_validated(self):
        base = bytearray(_synthetic_enpt())
        self.assertEqual(hb.parse_enpt(bytes(base)).header_length, 0x118)
        for value in (0, 0x117, 0x119, 0xFFFF):
            data = bytearray(base)
            struct.pack_into("<H", data, 276, value)
            with self.assertRaisesRegex(hb.ContainerError, "header length", msg=hex(value)):
                hb.parse_enpt(bytes(data))

    def test_trailer_length_fields_validated(self):
        base = _synthetic_enpt()
        info = hb.parse_enpt(base)
        self.assertEqual((info.tag_length, info.trailer_length), (16, 24))
        for offset, value, label in ((-8, 15, "tag length"), (-8, 0, "tag length"),
                                     (-6, 23, "trailer length"), (-6, 48, "trailer length")):
            data = bytearray(base)
            struct.pack_into("<H", data, len(data) + offset, value)
            with self.assertRaisesRegex(hb.ContainerError, label):
                hb.parse_enpt(bytes(data))
        # Extra bytes after a complete envelope shift the trailer and are caught.
        with self.assertRaises(hb.ContainerError):
            hb.parse_enpt(base + b"\x00" * 24)

    def test_tag_and_magic_positions(self):
        data = bytearray(_synthetic_enpt())
        data[-24:-8] = bytes(range(16))
        info = hb.parse_enpt(bytes(data))
        self.assertEqual(info.tag, bytes(range(16)))
        self.assertEqual(info.plaintext_length, 40)
        data[-1:] = b"X"
        with self.assertRaisesRegex(hb.ContainerError, "magic"):
            hb.parse_enpt(bytes(data))


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class EnptKeyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def test_roundtrip_with_rsa2048_and_32_byte_key(self):
        data = make_enpt(b"plain" * 8, self.key.public_key(), version=9)
        self.assertEqual(hb.parse_enpt(data).public_key_version, 9)
        self.assertEqual(hb.decrypt_enpt(data, pem(self.key)), b"plain" * 8)
        self.assertEqual(hb.decrypt_enpt(data, pem(self.key).decode()), b"plain" * 8)

    def test_non_2048_rsa_key_rejected(self):
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        data = make_enpt(b"x" * 40, self.key.public_key())
        with self.assertRaisesRegex(hb.DecryptError, "RSA-1024"):
            hb.decrypt_enpt(data, pem(small))

    def test_non_rsa_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        data = make_enpt(b"x" * 40, self.key.public_key())
        with self.assertRaisesRegex(hb.DecryptError, "RSA private key"):
            hb.decrypt_enpt(data, pem(ec.generate_private_key(ec.SECP256R1())))

    def test_wrapped_key_must_be_32_bytes(self):
        # AES-128 is a valid AESGCM key, so without the contract check this
        # would authenticate and be accepted.
        data = make_enpt(b"x" * 40, self.key.public_key(), aes_key=os.urandom(16))
        with self.assertRaisesRegex(hb.DecryptError, "32-byte"):
            hb.decrypt_enpt(data, pem(self.key))

    def test_wrong_key_and_tampered_tag(self):
        data = make_enpt(b"x" * 40, self.key.public_key())
        with self.assertRaises(hb.DecryptError):
            hb.decrypt_enpt(data, pem(self.other))
        tampered = bytearray(data)
        tampered[-24] ^= 1
        with self.assertRaisesRegex(hb.DecryptError, "authentication"):
            hb.decrypt_enpt(bytes(tampered), pem(self.key))

    def test_marker_through_cmpt_and_enpt(self):
        marker = struct.pack("<Q", 1700000000123) + b"\x00" * 32
        blob = make_cmpt([
            ("1700000000123-1700000000124.end.enc.opus", make_enpt(marker, self.key.public_key())),
            ("1700000000123.mark", make_enpt(marker, self.key.public_key())),
        ])
        for entry in hb.parse_cmpt(blob).entries:
            self.assertTrue(entry.is_marker)
            plain = hb.decrypt_enpt(entry.payload, pem(self.key))
            self.assertEqual(container.parse_marker(plain), 1700000000123)


# --- SecureChannel ------------------------------------------------------------


@unittest.skipUnless(_HAVE_CRYPTO, "cryptography not installed")
class SecureChannelNonceTests(unittest.TestCase):
    def setUp(self):
        from aipin_sdk.protocol import crypto

        self.crypto = crypto
        self.key = bytes(range(32))

    def test_forged_frame_does_not_burn_the_nonce(self):
        sender = self.crypto.SecureChannel(self.key, initial_nonce=5)
        receiver = self.crypto.SecureChannel(self.key)
        genuine = sender.seal(b"real")
        forged = genuine[:12] + b"\x00" * (len(genuine) - 12)
        with self.assertRaisesRegex(self.crypto.CryptoError, "authentication"):
            receiver.open(forged)
        self.assertEqual(receiver.open(genuine), b"real")
        with self.assertRaisesRegex(self.crypto.CryptoError, "nonce reuse"):
            receiver.open(genuine)

    def test_wrong_aad_then_right_aad(self):
        sender = self.crypto.SecureChannel(self.key)
        receiver = self.crypto.SecureChannel(self.key)
        message = sender.seal(b"x", aad=b"hdr")
        with self.assertRaises(self.crypto.CryptoError):
            receiver.open(message, aad=b"other")
        self.assertEqual(receiver.open(message, aad=b"hdr"), b"x")


if __name__ == "__main__":
    unittest.main(verbosity=2)
