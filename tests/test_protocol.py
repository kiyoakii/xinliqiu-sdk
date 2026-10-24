# -*- coding: utf-8 -*-
"""Unit tests for ``aipin_sdk.protocol`` (framing, crypto, auth, ukey2).

Standard-library ``unittest`` only, so this file is runnable directly::

    python3 tests/test_protocol.py

and it is equally picked up by pytest if that is what CI uses.

The suite needs the ``cryptography`` package.  If it is missing every test
raised ``unittest.SkipTest`` with an install hint instead of crashing at
import time.

Nothing here touches a device, a network or Bluetooth: the only "peer" is
this file acting as a fake server built from the same primitives.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python"))

try:
    import cryptography  # noqa: F401  (probe import only)
except ImportError as _crypto_import_error:  # pragma: no cover - env dependent
    _HAVE_CRYPTO = False
    _CRYPTO_HINT = (
        "the protocol tests need the 'cryptography' package "
        f"(import failed: {_crypto_import_error!r}); "
        'install it with: pip install "cryptography>=42" '
        '(or pip install -e "python[dev]" from the repo root)'
    )
else:
    _HAVE_CRYPTO = True
    _CRYPTO_HINT = ""


# -- helpers shared by several test classes --------------------------------


def protobuf_varint(value: int) -> bytes:
    """Reference LEB128 encoder, independent of ``ukey2._varint``."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def protobuf_key(number: int, wire_type: int) -> bytes:
    return protobuf_varint((number << 3) | wire_type)


# ==========================================================================
# framing
# ==========================================================================


class _ProtocolTestBase(unittest.TestCase):
    """Auto-fixture that skips the class cleanly when crypto is unavailable."""

    @classmethod
    def setUpClass(cls) -> None:
        if not _HAVE_CRYPTO:
            raise unittest.SkipTest(_CRYPTO_HINT)

    def assert_raises(self, exc_type, message: str, context: str):
        """``assertRaises(exc_type)`` whose failure says *what* broke.

        A helper rather than ``assertRaises(..., msg=...)`` because the latter
        silently ignores ``msg`` on Python 3.9 and ``assertRaisesRegex`` has no
        message parameter on that version either.
        """
        return _RaisedAs(self, exc_type, message, context)


class _RaisedAs:
    def __init__(self, testcase, exc_type, message, context):
        self._case = testcase
        self._expected = exc_type
        self._message = message
        self._context = context

    def __enter__(self):
        self._manager = self._case.assertRaises(self._expected)
        return self._manager.__enter__()

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None and issubclass(exc_type, self._expected):
            self._case.assertIn(
                self._message,
                str(exc),
                f"{self._context}: the error should mention {self._message!r}, got {exc}",
            )
        return self._manager.__exit__(exc_type, exc, tb)


class FramingTests(_ProtocolTestBase):
    """Frame encode/decode round trips, fragmentation and rejection rules."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import framing

        self.f = framing

    # -- single frame ---------------------------------------------------

    def test_single_frame_roundtrip_preserves_session_and_body(self):
        frame = self.f.encode(42, b"hello device")

        self.assertEqual(
            frame[0],
            len(b"hello device") + 2,
            "length byte must be body length + 2 (the u16 header)",
        )
        decoded = self.f.decode(frame)
        self.assertEqual(
            (decoded.session_id, decoded.fragmentation, decoded.body),
            (42, self.f.FRAGMENT_NONE, b"hello device"),
            "decoded frame must match the encoded session / flag / body",
        )

    def test_unfragmented_frame_from_split_is_accepted_by_framer(self):
        framer = self.f.Framer(session_id=7)
        frames = self.f.split(7, b"short message")

        self.assertEqual(len(frames), 1, "a body under one chunk must stay a single frame")
        self.assertEqual(
            framer.feed(frames[0]),
            b"short message",
            "Framer.feed must return the whole body for an unfragmented frame",
        )
        self.assertFalse(framer.active, "framer must be idle after a complete message")

    # -- multiple frames ------------------------------------------------

    def test_split_of_over_700_bytes_yields_first_middle_last_in_order(self):
        body = bytes(random.Random(1).getrandbits(8) for _ in range(700))
        frames = self.f.split(3, body)

        self.assertGreaterEqual(len(frames), 4, "700 bytes needs at least first+2 middle+last")
        flags = [self.f.decode(raw).fragmentation for raw in frames]
        self.assertEqual(flags[0], self.f.FRAGMENT_FIRST, "first frame must be marked FIRST")
        self.assertEqual(flags[-1], self.f.FRAGMENT_LAST, "last frame must be marked LAST")
        self.assertEqual(
            flags[1:-1],
            [self.f.FRAGMENT_MIDDLE] * (len(frames) - 2),
            "every frame between first and last must be marked MIDDLE",
        )
        for index, raw in enumerate(frames):
            self.assertLessEqual(
                len(self.f.decode(raw).body),
                self.f.MAX_BODY_CHUNK,
                f"fragment {index} of {len(frames)} exceeds MAX_BODY_CHUNK",
            )

    def test_framer_reassembles_over_700_bytes_in_order(self):
        body = bytes(random.Random(2).getrandbits(8) for _ in range(700))
        framer = self.f.Framer(session_id=3)
        frames = self.f.split(3, body)

        results = [framer.feed(raw) for raw in frames[:-1]]
        self.assertEqual(
            results, [None] * (len(frames) - 1),
            "Framer must return None for every non-final fragment",
        )
        self.assertTrue(framer.active, "framer must be mid-sequence before the LAST frame")
        self.assertEqual(
            framer.feed(frames[-1]), body,
            "reassembled body must be byte-identical to the original 700-byte body",
        )
        self.assertFalse(framer.active, "framer must reset after completing a message")

    # -- illegal lengths ------------------------------------------------

    def test_encode_rejects_empty_body(self):
        with self.assertRaises(self.f.FrameError):
            self.f.encode(1, b"")

    def test_encode_rejects_body_larger_than_one_chunk(self):
        oversized = b"x" * (self.f.MAX_BODY_CHUNK + 1)
        with self.assertRaises(self.f.FrameError):
            self.f.encode(1, oversized)

    def test_encode_rejects_session_id_outside_ten_bits(self):
        for bad in (-1, 1024):
            with self.subTest(session_id=bad):
                with self.subTest(expect=f"session_id={bad} must be refused (10-bit field)"):
                    with self.assertRaises(self.f.FrameError):
                        self.f.encode(bad, b"x")

    def test_encode_rejects_fragmentation_out_of_range(self):
        for bad in (-1, 4):
            with self.subTest(flag=bad):
                with self.subTest(expect=f"fragmentation={bad} is not a 2-bit flag"):
                    with self.assertRaises(self.f.FrameError):
                        self.f.encode(1, b"x", bad)

    def test_frame_shorter_than_header_is_rejected(self):
        for payload in (b"", b"\x02", b"\x02\x00"):
            with self.subTest(payload=payload.hex()):
                with self.subTest(expect=f"frame {payload.hex()!r} shorter than its 3-byte header must be refused"):
                    with self.assertRaises(self.f.FrameError):
                        self.f.decode(payload)

    def test_length_byte_disagreeing_with_size_is_rejected(self):
        frame = self.f.encode(1, b"abcd")
        truncated = frame[:-1]
        extended = frame + b"x"
        for label, payload in (("truncated", truncated), ("extended", extended)):
            with self.subTest(case=label):
                with self.subTest(expect=f"{label} frame must fail the length byte / size cross-check"):
                    with self.assertRaises(self.f.FrameError):
                        self.f.decode(payload)

    def test_zero_length_byte_is_rejected(self):
        # length == 0 would imply a -1 byte body; only the size check catches it.
        with self.subTest(expect="a zero length byte cannot describe a real frame"):
            with self.assertRaises(self.f.FrameError):
                self.f.decode(b"\x00\x00\x00")

    def test_split_rejects_empty_and_oversized_bodies(self):
        with self.subTest(expect="split(b'') must be refused"):
            with self.assertRaises(self.f.FrameError):
                self.f.split(1, b"")
        with self.subTest(expect=f"split of MAX_TOTAL_BODY_BYTES+1 ({self.f.MAX_TOTAL_BODY_BYTES + 1}) must be refused"):
            with self.assertRaises(self.f.FrameError):
                self.f.split(1, b"x" * (self.f.MAX_TOTAL_BODY_BYTES + 1))

    # -- fragmentation ordering -----------------------------------------

    def _frame(self, body: bytes, flag: int) -> bytes:
        return self.f.encode(0, body, flag)

    def test_middle_without_first_is_rejected(self):
        framer = self.f.Framer()
        with self.assert_raises(self.f.FrameError, "without a first", "MIDDLE frame before any FIRST"):
            framer.feed(self._frame(b"payload", self.f.FRAGMENT_MIDDLE))

    def test_last_without_first_is_rejected(self):
        framer = self.f.Framer()
        with self.assert_raises(self.f.FrameError, "without a first", "LAST frame before any FIRST"):
            framer.feed(self._frame(b"payload", self.f.FRAGMENT_LAST))

    def test_nested_first_is_rejected(self):
        framer = self.f.Framer()
        self.assertIsNone(
            framer.feed(self._frame(b"a" * 100, self.f.FRAGMENT_FIRST)),
            "the first FIRST fragment must be accepted",
        )
        with self.assert_raises(self.f.FrameError, "nested first", "a second FIRST inside one sequence"):
            framer.feed(self._frame(b"b" * 100, self.f.FRAGMENT_FIRST))

    def test_fragmented_sequence_that_fits_one_chunk_is_rejected(self):
        # INTENTIONAL, mirrors the reference implementation - do not "fix" it:
        # a body of at most MAX_BODY_CHUNK travels as a single unfragmented
        # frame, so FIRST+LAST totalling less than one chunk is a protocol
        # violation rather than something to silently reassemble.
        framer = self.f.Framer()
        framer.feed(self._frame(b"abc", self.f.FRAGMENT_FIRST))
        with self.assert_raises(
            self.f.FrameError, "did not exceed one chunk", "a fragmented sequence shorter than one chunk"
        ):
            framer.feed(self._frame(b"de", self.f.FRAGMENT_LAST))


    def test_empty_continuation_and_empty_first_are_rejected(self):
        # encode() refuses an empty body outright, so an empty fragment can only
        # be built by hand: a length byte of 2 with no body behind it.
        def raw(flag: int) -> bytes:
            header = (0 << 2) | flag
            return bytes([2, (header >> 8) & 0xFF, header & 0xFF])

        framer = self.f.Framer()
        with self.assert_raises(
            self.f.FrameError, "empty first fragment", "a FIRST frame with an empty body"
        ):
            framer.feed(raw(self.f.FRAGMENT_FIRST))

        self.assertIsNone(
            framer.feed(self._frame(b"x" * 200, self.f.FRAGMENT_FIRST)),
            "test setup: a non-empty FIRST must be accepted",
        )
        with self.assert_raises(
            self.f.FrameError,
            "empty continuation fragment",
            "an empty MIDDLE fragment inside a sequence",
        ):
            framer.feed(raw(self.f.FRAGMENT_MIDDLE))

    def test_empty_unfragmented_body_is_rejected(self):
        def raw(flag: int) -> bytes:
            header = (0 << 2) | flag
            return bytes([2, (header >> 8) & 0xFF, header & 0xFF])

        with self.assert_raises(
            self.f.FrameError, "empty unfragmented body", "a NONE frame with an empty body"
        ):
            self.f.Framer().feed(raw(self.f.FRAGMENT_NONE))

    def test_unfragmented_frame_during_sequence_is_rejected(self):
        framer = self.f.Framer()
        framer.feed(self._frame(b"x" * 200, self.f.FRAGMENT_FIRST))
        with self.assert_raises(
            self.f.FrameError, "during a fragmented sequence", "unfragmented frame interleaved into a sequence"
        ):
            framer.feed(self._frame(b"y", self.f.FRAGMENT_NONE))

    def test_framer_rejects_frame_from_another_session(self):
        framer = self.f.Framer(session_id=5)
        with self.assert_raises(
            self.f.FrameError, "another session", "a frame from session 6 reaching a session-5 framer"
        ):
            framer.feed(self.f.encode(6, b"x"))

    # -- size limits ----------------------------------------------------

    def test_framer_rejects_received_fragment_larger_than_device_maximum(self):
        too_big_body = b"z" * (self.f.MAX_RECEIVED_BODY_CHUNK + 1)
        # encode() only produces host-sized frames, so hand-build the oversized
        # inbound one: length byte, header (session 0, NONE), then the body.
        raw = bytes([len(too_big_body) + 2, 0, self.f.FRAGMENT_NONE]) + too_big_body
        self.assertGreater(
            len(self.f.decode(raw).body),
            self.f.MAX_RECEIVED_BODY_CHUNK,
            "test setup: body must exceed MAX_RECEIVED_BODY_CHUNK",
        )
        with self.assert_raises(
            self.f.FrameError, "larger than advertised", "an inbound frame above MAX_RECEIVED_BODY_CHUNK"
        ):
            self.f.Framer().feed(raw)


    def test_framer_constructor_takes_no_max_bytes_parameter(self):
        # The 1 MiB ceiling is a protocol bound, not a tuning knob, so the
        # constructor deliberately does not accept it.
        with self.assertRaises(TypeError):
            self.f.Framer(max_bytes=250)
        self.assertEqual(
            self.f.Framer().max_bytes,
            self.f.MAX_TOTAL_BODY_BYTES,
            "the framer's reassembly ceiling must be the 1 MiB protocol bound",
        )

    def test_framer_rejects_reassembled_body_over_max_bytes(self):
        # max_bytes follows the 1 MiB protocol bound; a test lowers the
        # attribute directly so the case does not allocate a megabyte.
        framer = self.f.Framer()
        framer.max_bytes = 250
        self.assertIsNone(
            framer.feed(self._frame(b"a" * 200, self.f.FRAGMENT_FIRST)),
            "200-byte FIRST fits under max_bytes=250 and must be accepted",
        )
        with self.assert_raises(
            self.f.FrameError, "exceeds the limit", "200 + 100 bytes against max_bytes=250"
        ):
            framer.feed(self._frame(b"b" * 100, self.f.FRAGMENT_LAST))

    def test_framer_recovers_after_an_over_limit_error(self):
        # Feed() must clear its own state before re-raising: an error inside
        # _append used to leave the framer active with a stale buffer, so every
        # later frame was rejected until someone called reset() by hand.
        framer = self.f.Framer()
        framer.max_bytes = 250
        framer.feed(self._frame(b"a" * 200, self.f.FRAGMENT_FIRST))
        with self.assert_raises(self.f.FrameError, "exceeds the limit", "oversized reassembly"):
            framer.feed(self._frame(b"b" * 100, self.f.FRAGMENT_LAST))

        self.assertFalse(framer.active, "an error must leave the framer idle, not mid-sequence")
        self.assertEqual(
            framer.feed(self._frame(b"ok", self.f.FRAGMENT_NONE)),
            b"ok",
            "a well-formed frame after an over-limit error must be accepted without reset()",
        )

    def test_framer_recovers_after_every_kind_of_error(self):
        cases = {
            "middle without first": ([], self._frame(b"m", self.f.FRAGMENT_MIDDLE), None),
            "last without first": ([], self._frame(b"l", self.f.FRAGMENT_LAST), None),
            "nested first": ([self._frame(b"a" * 100, self.f.FRAGMENT_FIRST)], self._frame(b"b", self.f.FRAGMENT_FIRST), None),
            "unfragmented during sequence": (
                [self._frame(b"a" * 100, self.f.FRAGMENT_FIRST)],
                self._frame(b"z", self.f.FRAGMENT_NONE),
                None,
            ),
            "short fragmented sequence": (
                [self._frame(b"abc", self.f.FRAGMENT_FIRST)],
                self._frame(b"de", self.f.FRAGMENT_LAST),
                None,
            ),
            "frame from another session": ([], self.f.encode(9, b"q"), 0),
        }
        for label, (setup, bad, session_id) in cases.items():
            with self.subTest(case=label):
                framer = self.f.Framer(session_id=session_id) if session_id is not None else self.f.Framer()
                for frame in setup:
                    framer.feed(frame)
                with self.assertRaises(self.f.FrameError):
                    framer.feed(bad)
                self.assertFalse(framer.active, f"after '{label}' the framer must be idle again")
                self.assertEqual(
                    framer.feed(self.f.encode(0, b"ok")),
                    b"ok",
                    f"after '{label}' the next well-formed frame must reassemble",
                )

# ==========================================================================
# crypto
# ==========================================================================


class EphemeralKeyTests(_ProtocolTestBase):
    """ECDH agreement and input validation."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import crypto

        self.crypto = crypto

    def test_public_point_is_uncompressed_p256(self):
        point = self.crypto.EphemeralKey.generate().public_point
        self.assertEqual(len(point), 65, "an uncompressed P-256 point is 65 bytes")
        self.assertEqual(point[0], 0x04, "uncompressed points start with the 0x04 tag")

    def test_ecdh_agrees_in_both_directions(self):
        alice = self.crypto.EphemeralKey.generate()
        bob = self.crypto.EphemeralKey.generate()

        alice_secret = alice.agree(bob.public_point)
        bob_secret = bob.agree(alice.public_point)

        self.assertEqual(
            alice_secret,
            bob_secret,
            "both sides of the ECDH exchange must derive the same shared secret",
        )
        self.assertEqual(len(alice_secret), 32, "the P-256 x-coordinate secret is 32 bytes")
        self.assertNotEqual(alice.public_point, bob.public_point, "test setup: keys must differ")

    def test_ecdh_secret_differs_per_peer(self):
        alice = self.crypto.EphemeralKey.generate()
        bob = self.crypto.EphemeralKey.generate()
        mallory = self.crypto.EphemeralKey.generate()

        self.assertNotEqual(
            alice.agree(bob.public_point),
            alice.agree(mallory.public_point),
            "the secret must be bound to the peer key actually used",
        )

    def test_agree_rejects_non_uncompressed_point(self):
        key = self.crypto.EphemeralKey.generate()
        for label, point in (
            ("empty", b""),
            ("compressed (0x02 tag)", b"\x02" + bytes(32)),
            ("hybrid-ish (0x06 tag)", b"\x06" + bytes(64)),
        ):
            with self.subTest(case=label):
                with self.subTest(expect=f"agree() must refuse a {label} peer point"):
                    with self.assertRaises(self.crypto.CryptoError):
                        key.agree(point)

    def test_agree_rejects_point_not_on_curve(self):
        key = self.crypto.EphemeralKey.generate()
        for label, point in (
            ("all-zero coordinates", b"\x04" + bytes(64)),
            ("all-0xff coordinates", b"\x04" + b"\xff" * 64),
            ("truncated", b"\x04" + bytes(10)),
        ):
            with self.subTest(case=label):
                with self.subTest(expect=f"agree() must refuse an off-curve point ({label})"):
                    with self.assertRaises(self.crypto.CryptoError):
                        key.agree(point)


class KeyDerivationTests(_ProtocolTestBase):
    """HKDF behaviour."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import crypto

        self.crypto = crypto

    def test_derive_key_is_deterministic_for_same_inputs(self):
        secret, salt, info = b"secret" * 4, b"salt" * 4, b"info"
        first = self.crypto.derive_key(secret, salt, info)
        second = self.crypto.derive_key(secret, salt, info)

        self.assertEqual(first, second, "HKDF must be deterministic for identical inputs")
        self.assertEqual(len(first), 32, "default HKDF length must be 32 bytes")

    def test_derive_key_matches_rfc5869_test_case_1(self):
        # RFC 5869, Appendix A.1: HKDF-SHA256(0x0b*22, 0x000102..0c, 0xf0f1..f9, 42)
        ikm = b"\x0b" * 22
        salt = bytes(range(13))
        info = bytes(range(0xF0, 0xFA))
        expected = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        self.assertEqual(
            self.crypto.derive_key(ikm, salt, info, length=42),
            expected,
            "derive_key must be plain HKDF-SHA256, as RFC 5869 case 1 defines it",
        )

    def test_derive_key_changes_with_salt_and_info(self):
        secret = b"s" * 32
        base = self.crypto.derive_key(secret, b"a", b"info")
        other_salt = self.crypto.derive_key(secret, b"b", b"info")
        other_info = self.crypto.derive_key(secret, b"a", b"other")

        self.assertNotEqual(base, other_salt, "changing the salt must change the key")
        self.assertNotEqual(base, other_info, "changing the info label must change the key")

    def test_derived_key_shorter_length_is_a_prefix_of_a_longer_one(self):
        # HKDF expands from a single P_hash stream, so a shorter request IS the
        # prefix of a longer one.  (ukey2.py's comment claims the opposite; this
        # test pins the real behaviour so nobody re-derives a key on that belief.)
        secret = b"s" * 32
        long_key = self.crypto.derive_key(secret, b"", b"", length=32)
        short_key = self.crypto.derive_key(secret, b"", b"", length=16)
        self.assertEqual(
            short_key,
            long_key[:16],
            "HKDF-SHA256 output is prefix-stable: the 16-byte key is the first 16 bytes of the 32-byte key",
        )


class AesTests(_ProtocolTestBase):
    """AES-CBC, ECB and packet_transform."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import crypto

        self.crypto = crypto
        self.key = bytes(range(32))
        self.iv = bytes(range(16, 32))

    def test_cbc_roundtrip_for_multiple_whole_blocks(self):
        for blocks in (1, 2, 4):
            with self.subTest(blocks=blocks):
                plaintext = bytes((i * 7) & 0xFF for i in range(16 * blocks))
                ciphertext = self.crypto.aes_cbc_encrypt(self.key, self.iv, plaintext)
                self.assertEqual(
                    len(ciphertext), len(plaintext),
                    f"CBC wrapper must not pad: {blocks} block(s) in, {blocks} block(s) out",
                )
                self.assertNotEqual(ciphertext, plaintext, "ciphertext must differ from plaintext")
                self.assertEqual(
                    self.crypto.aes_cbc_decrypt(self.key, self.iv, ciphertext),
                    plaintext,
                    f"CBC decrypt must recover the {blocks}-block plaintext",
                )

    def test_cbc_encrypt_matches_nist_sp800_38a_vector(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
        self.assertEqual(
            self.crypto.aes_cbc_encrypt(key, iv, plain),
            expected,
            "CBC block 1 must match NIST SP 800-38A F.2.1",
        )

    def test_cbc_encrypt_rejects_partial_block(self):
        for size in (1, 15, 17, 31):
            with self.subTest(size=size):
                with self.subTest(expect=("whole number of AES blocks", f"a {size}-byte payload is not a whole number of AES blocks and must be refused")):
                    with self.assertRaises(self.crypto.CryptoError):
                        self.crypto.aes_cbc_encrypt(self.key, self.iv, b"x" * size)

    def test_cbc_decrypt_rejects_empty_and_partial_block(self):
        for size in (0, 1, 15, 17):
            with self.subTest(size=size):
                with self.subTest(expect=("whole number of AES blocks", f"a {size}-byte ciphertext is not a whole number of AES blocks and must be refused")):
                    with self.assertRaises(self.crypto.CryptoError):
                        self.crypto.aes_cbc_decrypt(self.key, self.iv, b"x" * size)

    def test_cbc_roundtrip_accepts_empty_plaintext(self):
        # 0 blocks is a legal multiple of 16; the wrapper leaves it alone.
        self.assertEqual(
            self.crypto.aes_cbc_encrypt(self.key, self.iv, b""),
            b"",
            "an empty plaintext is 0 whole blocks and must encrypt to nothing",
        )

    def test_cbc_depends_on_iv(self):
        plain = b"A" * 16
        other_iv = bytes(range(16))
        self.assertNotEqual(
            self.crypto.aes_cbc_encrypt(self.key, self.iv, plain),
            self.crypto.aes_cbc_encrypt(self.key, other_iv, plain),
            "CBC output must depend on the IV",
        )

    def test_ecb_block_matches_nist_vector_and_requires_16_bytes(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        block = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        self.assertEqual(
            self.crypto.aes_ecb_block(key, block),
            bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97"),
            "aes_ecb_block must match NIST SP 800-38A F.1.1",
        )
        for size in (0, 15, 17):
            with self.subTest(size=size):
                with self.subTest(expect=("must be 16 bytes", f"aes_ecb_block must accept exactly 16 bytes, not {size}")):
                    with self.assertRaises(self.crypto.CryptoError):
                        self.crypto.aes_ecb_block(key, b"x" * size)

    def test_ecb_is_stateless_across_calls(self):
        key = bytes(range(16))
        block = b"\x00" * 16
        self.assertEqual(
            self.crypto.aes_ecb_block(key, block),
            self.crypto.aes_ecb_block(key, block),
            "each ECB call must encrypt one independent block",
        )

    def test_packet_transform_is_symmetric_for_a_given_nonce(self):
        # The docstring says encryption and decryption are the same call.  That
        # holds only when the same nonce is supplied both ways: the nonce is
        # XORed into output bytes 8..15 of every block.
        plaintext = bytes(range(10))
        ciphertext = self.crypto.packet_transform(plaintext, self.key, self.iv, b"\x11" * 8)
        self.assertNotEqual(ciphertext, plaintext, "the transform must actually change the data")
        self.assertEqual(
            self.crypto.packet_transform(ciphertext, self.key, self.iv, b"\x11" * 8),
            plaintext,
            "applying packet_transform twice with the SAME nonce must restore the plaintext",
        )

    def test_packet_transform_double_apply_with_same_nonce_is_identity_everywhere(self):
        data = bytes(range(64))
        for nonce in (bytes(8), b"\x01\x02\x03\x04\x05\x06\x07\x08", b"\xff" * 8):
            with self.subTest(nonce=nonce.hex()):
                twice = self.crypto.packet_transform(
                    self.crypto.packet_transform(data, self.key, self.iv, nonce),
                    self.key,
                    self.iv,
                    nonce,
                )
                self.assertEqual(
                    twice, data,
                    "double-apply with the same nonce must be the identity (8 fixed nonce bytes per block do not cancel)",
                )

    def test_packet_transform_lanes_cannot_be_undone_with_a_different_nonce(self):
        # Non-obvious consequence of the design: decryption MUST reuse the
        # sender's nonce.  This pins the counter layout so a change is caught.
        plaintext = bytes(range(16))
        nonce = b"\xa5" * 8
        ciphertext = self.crypto.packet_transform(plaintext, self.key, self.iv, nonce)
        result = self.crypto.packet_transform(ciphertext, self.key, self.iv, bytes(8))
        self.assertEqual(
            result[:8], plaintext[:8], "lanes 0..7 carry no nonce, so they recover with any nonce"
        )
        self.assertEqual(
            result[8:], bytes(a ^ b for a, b in zip(plaintext[8:], nonce)),
            "lanes 8..15 XOR both nonces: decrypting with a different nonce leaves plaintext ^ nonce ^ other_nonce",
        )

    def test_packet_transform_first_byte_carries_block_index(self):
        plaintext = bytes(48)
        zero_nonce = bytes(8)
        ciphertext = self.crypto.packet_transform(plaintext, self.key, self.iv, zero_nonce)
        mask_first = self.crypto.aes_ecb_block(self.key, self.iv)[0]
        for block_index in range(3):
            with self.subTest(block=block_index):
                self.assertEqual(
                    ciphertext[block_index * 16],
                    mask_first ^ (block_index & 0xFF),
                    f"byte 0 of block {block_index} must be mask^0 deselected by the block index counter",
                )

    def test_packet_transform_requires_eight_byte_nonce(self):
        for size in (0, 7, 9, 16):
            with self.subTest(size=size):
                with self.subTest(expect=("8 bytes", f"packet_transform must require an 8-byte nonce, got {size}")):
                    with self.assertRaises(self.crypto.CryptoError):
                        self.crypto.packet_transform(b"\x00" * 16, self.key, self.iv, b"n" * size)

    def test_packet_transform_is_a_bijection_on_empty_input(self):
        self.assertEqual(
            self.crypto.packet_transform(b"", self.key, self.iv, bytes(8)),
            b"",
            "an empty payload must transform to an empty payload",
        )


class GcmAndSecureChannelTests(_ProtocolTestBase):
    """AES-GCM helpers and the replay-checking business channel."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import crypto

        self.crypto = crypto
        self.key = bytes(range(32))

    def test_gcm_roundtrip_and_aad_binding(self):
        nonce = bytes(range(12))
        sealed = self.crypto.aes_gcm_encrypt(self.key, nonce, b"payload", b"aad")
        self.assertEqual(
            self.crypto.aes_gcm_decrypt(self.key, nonce, sealed, b"aad"),
            b"payload",
            "GCM decrypt with the correct AAD must recover the plaintext",
        )
        with self.assert_raises(
            self.crypto.CryptoError, "authentication failed", "GCM decrypted with a different AAD"
        ):
            self.crypto.aes_gcm_decrypt(self.key, nonce, sealed, b"other")

    def test_secure_channel_constructor_requires_32_byte_key(self):
        for size in (0, 16, 31, 33):
            with self.subTest(size=size):
                with self.assert_raises(
                    self.crypto.CryptoError, "32 bytes", f"SecureChannel key of {size} bytes"
                ):
                    self.crypto.SecureChannel(b"k" * size)

    def test_secure_channel_roundtrip_and_nonce_advances(self):
        channel = self.crypto.SecureChannel(self.key, initial_nonce=41)
        first = channel.seal(b"one")
        second = channel.seal(b"two")

        self.assertEqual(first[:12], (41).to_bytes(12, "big"), "first nonce must be initial_nonce")
        self.assertEqual(
            second[:12], (42).to_bytes(12, "big"), "the nonce counter must advance per message"
        )
        self.assertEqual(channel.open(first), b"one", "the first message must open")
        self.assertEqual(channel.open(second), b"two", "the second message must open")

    def test_secure_channel_rejects_replayed_message(self):
        channel = self.crypto.SecureChannel(self.key)
        message = channel.seal(b"once")
        self.assertEqual(channel.open(message), b"once")
        with self.subTest(expect=("nonce reuse", "replaying an already-opened message must be refused by the nonce check")):
            with self.assertRaises(self.crypto.CryptoError):
                channel.open(message)

    def test_secure_channel_tracks_replay_per_instance(self):
        # The replay memory is a per-instance set of nonces already opened, so a
        # long-lived receiver catches a replay while a brand-new instance has
        # seen nothing and cannot - which is why the receiver must be kept for
        # the life of the link rather than rebuilt per message.
        sender = self.crypto.SecureChannel(self.key)
        message = sender.seal(b"hello")
        receiver = self.crypto.SecureChannel(self.key)
        self.assertEqual(receiver.open(message), b"hello", "the first delivery must open")
        with self.assert_raises(
            self.crypto.CryptoError, "nonce reuse", "replaying a message on the receiver that already opened it"
        ):
            receiver.open(message)
        self.assertEqual(
            self.crypto.SecureChannel(self.key).open(message),
            b"hello",
            "a fresh receiver instance has no replay memory: the GCM tag still authenticates, "
            "so rejecting replays is the receiver's bookkeeping, not the cipher's",
        )

    def test_channels_sharing_an_initial_nonce_collide(self):
        # Documented contract: callers must pass a DISTINCT initial_nonce per
        # connection. Two connections starting at the same value repeat the
        # nonce on their first message, and the receiver refuses the second.
        receiver = self.crypto.SecureChannel(self.key, initial_nonce=7)
        receiver.open(self.crypto.SecureChannel(self.key, initial_nonce=7).seal(b"a"))
        with self.assert_raises(
            self.crypto.CryptoError,
            "nonce reuse",
            "a second connection reusing another connection's first nonce",
        ):
            receiver.open(self.crypto.SecureChannel(self.key, initial_nonce=7).seal(b"b"))

    def test_channels_with_distinct_initial_nonces_do_not_collide(self):
        receiver = self.crypto.SecureChannel(self.key, initial_nonce=500)
        for start in (100, 200, 300):
            with self.subTest(initial_nonce=start):
                message = self.crypto.SecureChannel(self.key, initial_nonce=start).seal(b"payload")
                self.assertEqual(
                    receiver.open(message), b"payload",
                    f"a message from a connection starting at nonce {start} must open",
                )

    def test_secure_channel_rejects_tampered_ciphertext(self):
        channel = self.crypto.SecureChannel(self.key)
        message = bytearray(channel.seal(b"important"))
        message[-1] ^= 0x01
        with self.assert_raises(
            self.crypto.CryptoError, "authentication failed", "a flipped ciphertext bit"
        ):
            channel.open(bytes(message))

    def test_secure_channel_rejects_wrong_aad(self):
        sender = self.crypto.SecureChannel(self.key)
        message = sender.seal(b"x", aad=b"header")
        with self.assert_raises(
            self.crypto.CryptoError, "authentication failed", "opening with a different AAD"
        ):
            self.crypto.SecureChannel(self.key).open(message, aad=b"wrong")
        self.assertEqual(
            self.crypto.SecureChannel(self.key).open(message, aad=b"header"), b"x",
            "opening with the sender's AAD must succeed",
        )

    def test_secure_channel_rejects_message_shorter_than_nonce(self):
        channel = self.crypto.SecureChannel(self.key)
        for payload in (b"", b"\x00" * 12):
            with self.subTest(length=len(payload)):
                with self.assert_raises(
                    self.crypto.CryptoError, "too short", f"a {len(payload)}-byte sealed message"
                ):
                    channel.open(payload)

# ==========================================================================

# auth
# ==========================================================================


class AuthTests(_ProtocolTestBase):
    """HMAC session authentication (``auth.AuthState``).

    Frame shapes, all with a one-byte length prefix::

        request   : 10 01 | challenge(8) | time BE(8) | mac(8) | localID(6) | alias(6)
        response  : 11 01 00 | serverChallenge(8) | serverTime BE(8) | mac(8)
        confirm   : 12 01 00 | mac(8)

    The MAC is HMAC-SHA512 truncated to 8 bytes, taken over the *little-endian*
    timestamp even though the timestamp travels big-endian on the wire. The
    response does not repeat our client challenge; the MAC covers it, though,
    which is what binds the answer to this request.
    """

    def setUp(self) -> None:
        from aipin_sdk.protocol import auth, crypto

        self.auth = auth
        self.crypto = crypto
        self.pairing = auth.Pairing(
            ksc=bytes(range(16)),
            alias=b"ALIAS1",
            seeker_id=b"\x01" * 6,
            provider_id=b"\x02" * 6,
        )
        self.state = auth.AuthState(
            pairing=self.pairing, local_id=b"\x03" * 6, challenge=b"\x04" * 8
        )
        # The real flow always sends the request before it can confirm, and
        # confirm() refuses to sign without the client time it transmitted.
        self.state.request(now=11)

    # -- helpers --------------------------------------------------------

    def _tag(self, key: bytes, data: bytes) -> bytes:
        """Reference tag: HMAC-SHA512 truncated to TAG_BYTES."""
        return hmac.new(key, data, hashlib.sha512).digest()[: self.auth.TAG_BYTES]

    def _state(self):
        """A fresh AuthState with the request already sent.

        The real flow always calls request() before confirm(); confirm() now
        refuses to sign a confirmation without the client time it sent.
        """
        state = self.auth.AuthState(
            self.pairing, b"\x03" * 6, challenge=b"\x04" * 8
        )
        state.request(now=11)
        return state

    def _server_response(self, key: bytes, server_challenge: bytes, server_time: int = 7) -> bytes:
        """Build the 27-byte response the device would send."""
        body = server_challenge + server_time.to_bytes(8, "big")
        tag = self._tag(
            key,
            self.state.challenge + server_challenge + server_time.to_bytes(8, "little"),
        )
        return bytes([self.auth.RESPONSE_TYPE, self.auth.PROTOCOL_VERSION, 0]) + body + tag

    # -- request --------------------------------------------------------

    def test_request_layout(self):
        now = 0x0102030405060708
        frame = self.state.request(now=now)
        payload = frame[1:]

        self.assertEqual(
            frame[0], len(payload),
            "the request carries a one-byte length prefix over everything after it",
        )
        self.assertEqual(
            payload,
            bytes([self.auth.REQUEST_TYPE, self.auth.PROTOCOL_VERSION])
            + b"\x04" * 8
            + b"\x01\x02\x03\x04\x05\x06\x07\x08"
            + self._tag(self.pairing.ksc, b"\x04" * 8 + b"\x08\x07\x06\x05\x04\x03\x02\x01")
            + b"\x03" * 6
            + b"ALIAS1",
            "request must be type 0x10, version 1, challenge, BE timestamp, MAC, local id, alias",
        )

    def test_request_payload_has_no_length_prefix_and_tracks_time(self):
        framed = self.state.request(now=1000)
        self.assertEqual(
            self.state.request_payload(now=1000), framed[1:],
            "request_payload() is request() without the one-byte length prefix",
        )
        self.assertEqual(
            self.state.client_time, 1000, "request() must record the timestamp it signed"
        )
        self.assertNotEqual(
            self.state.request_payload(now=1001)[:18],
            self.state.request_payload(now=1000)[:18],
            "a different timestamp must change the signed bytes",
        )

    def test_timestamp_is_seconds_not_milliseconds(self):
        import time as _time

        before = int(_time.monotonic())
        payload = self.state.request_payload()
        after = int(_time.monotonic())
        stamp = int.from_bytes(payload[10:18], "big")
        self.assertGreaterEqual(stamp, before, "default timestamp must be monotonic seconds")
        self.assertLessEqual(
            stamp, after, "default timestamp must be monotonic seconds, not milliseconds"
        )

    def test_mac_is_hmac_sha512_truncated_to_eight_bytes(self):
        now = 1234
        payload = self.state.request_payload(now=now)
        challenge, timestamp = payload[2:10], payload[10:18]
        tag = payload[18:26]

        self.assertEqual(len(tag), self.auth.TAG_BYTES, "the tag is TAG_BYTES long")
        self.assertEqual(
            tag,
            hmac.new(self.pairing.ksc, challenge + timestamp[::-1], hashlib.sha512).digest()[:8],
            "request MAC = HMAC-SHA512(ksc, challenge || LE timestamp)[:8]",
        )
        self.assertNotEqual(
            tag,
            hmac.new(self.pairing.ksc, challenge + timestamp[::-1], hashlib.sha256).digest()[:8],
            "HMAC-SHA256 would produce a tag the device rejects",
        )

    def test_request_changes_with_timestamp_and_challenge(self):
        first = self.state.request(now=1)
        second = self.state.request(now=2)
        self.assertNotEqual(
            first, second, "a different timestamp must produce a different MAC"
        )
        other = self.auth.AuthState(self.pairing, b"\x03" * 6, challenge=b"\x09" * 8)
        self.assertEqual(
            other.request(now=1)[3:11], b"\x09" * 8,
            "the challenge must be carried verbatim into the request",
        )
        self.assertNotEqual(
            first[19:27], other.request(now=1)[19:27],
            "a different challenge must produce a different MAC",
        )

    # -- verification ---------------------------------------------------

    def test_valid_server_response_is_accepted(self):
        response = self._server_response(self.pairing.ksc, b"\x07" * 8, server_time=99)
        confirm = self.state.confirm(response)

        self.assertTrue(self.state.verified, "a correct MAC must mark the handshake verified")
        self.assertEqual(
            self.state.server_challenge, b"\x07" * 8,
            "response bytes 3..11 become the server challenge",
        )
        self.assertEqual(self.state.server_time, 99, "response bytes 11..19 are the server time, BE")
        payload = confirm[1:]
        self.assertEqual(confirm[0], len(payload), "confirm() carries a one-byte length prefix")
        self.assertEqual(
            payload[:3], bytes([self.auth.CONFIRM_TYPE, self.auth.PROTOCOL_VERSION, 0]),
            "confirm payload starts with 12 01 00",
        )
        self.assertEqual(
            self.state.client_time, 11,
            "client_time is what request() transmitted, and the MAC must use it",
        )
        self.assertEqual(
            payload[3:],
            self._tag(self.pairing.ksc, b"\x07" * 8 + (11).to_bytes(8, "little")),
            "confirm MAC = HMAC-SHA512(ksc, serverChallenge || LE clientTime)[:8]",
        )

    def test_confirm_depends_on_the_client_timestamp_sent(self):
        response = self._server_response(self.pairing.ksc, b"\x07" * 8)
        self.state.request(now=424242)
        confirm = self.state.confirm(response)
        self.assertEqual(
            self.state.client_time, 424242,
            "confirm() must sign the same client timestamp the request carried",
        )
        self.assertEqual(
            confirm[4:],
            self._tag(self.pairing.ksc, b"\x07" * 8 + (424242).to_bytes(8, "little")),
            "the confirmation must be bound to the timestamp actually sent",
        )

    def test_confirmation_requires_an_exact_27_byte_response(self):
        good = self._server_response(self.pairing.ksc, b"\x07" * 8)
        self.assertEqual(len(good), 27, "test setup: the real response is 27 bytes")
        for label, response in (
            ("one byte short", good[:-1]),
            ("one byte long", good + b"\x00"),
            ("empty", b""),
        ):
            with self.subTest(case=label):
                with self.assert_raises(
                    self.auth.AuthError,
                    "must be 27 bytes",
                    f"a server response that is {label}",
                ):
                    self._state().confirm(response)

    def test_response_with_wrong_header_is_rejected(self):
        good = self._server_response(self.pairing.ksc, b"\x07" * 8)
        for label, index, value in (
            ("response type 0x10 instead of 0x11", 0, self.auth.REQUEST_TYPE),
            ("protocol version 2", 1, 2),
            ("status byte 1", 2, 1),
        ):
            with self.subTest(case=label):
                mutated = bytearray(good)
                mutated[index] = value
                with self.assert_raises(
                    self.auth.AuthError, "device rejected authentication", label
                ):
                    self._state().confirm(bytes(mutated))

    def test_forged_mac_is_rejected_and_state_untouched(self):
        good = self._server_response(self.pairing.ksc, b"\x07" * 8)
        forged = good[:-1] + bytes([good[-1] ^ 0xFF])
        with self.assert_raises(
            self.auth.AuthError,
            "failed to prove possession",
            "a MAC that does not match the pairing key",
        ):
            self.state.confirm(forged)
        self.assertFalse(
            self.state.verified, "a rejected response must not mark the handshake verified"
        )

    def test_valid_mac_for_wrong_key_is_rejected(self):
        response = self._server_response(b"\x99" * 16, b"\x07" * 8)
        with self.assert_raises(
            self.auth.AuthError, "failed to prove possession", "a well-formed MAC under a different key"
        ):
            self._state().confirm(response)

    def test_mac_must_cover_the_whole_payload(self):
        for offset, label in (
            (3, "server challenge"),
            (11, "server time high byte"),
            (18, "server time low byte"),
        ):
            response = bytearray(self._server_response(self.pairing.ksc, b"\x07" * 8))
            response[offset] ^= 0x01
            with self.subTest(field=label):
                with self.assert_raises(
                    self.auth.AuthError,
                    "failed to prove possession",
                    f"altering the {label} under a valid MAC",
                ):
                    self._state().confirm(bytes(response))

    def test_server_time_is_included_in_the_mac(self):
        # The tag covers challenge || server challenge || LE server time, not
        # just the challenges, so swapping the time under a valid tag fails.
        response = bytearray(self._server_response(self.pairing.ksc, b"\x07" * 8, server_time=7))
        response[11:19] = (8).to_bytes(8, "big")
        with self.assert_raises(
            self.auth.AuthError,
            "failed to prove possession",
            "server time swapped under a valid tag",
        ):
            self._state().confirm(bytes(response))

    def test_confirmation_twice_is_rejected(self):
        response = self._server_response(self.pairing.ksc, b"\x07" * 8)
        self.state.confirm(response)
        with self.assert_raises(
            self.auth.AuthError, "already completed", "a second confirm() on the same AuthState"
        ):
            self.state.confirm(response)

    def test_transcript_is_client_then_server_challenge(self):
        with self.assert_raises(
            self.auth.AuthError, "no server challenge", "transcript before confirm()"
        ):
            self.state.transcript
        self.state.confirm(self._server_response(self.pairing.ksc, b"\x07" * 8))
        self.assertEqual(
            self.state.transcript, b"\x04" * 8 + b"\x07" * 8,
            "the transcript is the client challenge followed by the server challenge",
        )

    # -- construction rules --------------------------------------------

    def test_pairing_enforces_field_sizes(self):
        good = dict(ksc=bytes(16), alias=bytes(6), seeker_id=bytes(6), provider_id=bytes(6))
        field_to_size = {"ksc": 16, "alias": 6, "seeker_id": 6, "provider_id": 6}
        for field, size in field_to_size.items():
            for bad_size in (0, size - 1, size + 1):
                with self.subTest(field=field, size=bad_size):
                    values = dict(good)
                    values[field] = bytes(bad_size)
                    with self.subTest(
                        expect=f"Pairing must require {field} to be exactly {size} bytes, got {bad_size}"
                    ):
                        with self.assertRaises(ValueError):
                            self.auth.Pairing(**values)

    def test_pairing_is_immutable(self):
        pairing = self.auth.Pairing(
            ksc=bytes(16), alias=b"ALIAS1", seeker_id=b"\x01" * 6, provider_id=b"\x02" * 6
        )
        with self.assertRaises(Exception):
            pairing.ksc = bytes(15)


# ==========================================================================
# ukey2
# ==========================================================================


class ProtobufCodecTests(_ProtocolTestBase):
    """The purpose-built protobuf subset in ukey2."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import ukey2

        self.u = ukey2

    # -- varint ---------------------------------------------------------

    def test_varint_matches_reference_encoding(self):
        values = [0, 1, 127, 128, 300, 2**31 - 1, 2**32, 2**63 - 1, 2**64 - 1]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(
                    self.u._varint(value),
                    protobuf_varint(value),
                    f"varint({value}) must match the canonical LEB128 encoding",
                )

    def test_varint_roundtrip_for_large_numbers(self):
        for value in (0, 127, 128, 16384, 2**32 + 5, 2**64 - 1):
            with self.subTest(value=value):
                raw = self.u._varint(value)
                decoded, end = self.u._read_varint(raw, 0)
                self.assertEqual(decoded, value, f"varint({value}) must decode back to itself")
                self.assertEqual(end, len(raw), f"varint({value}) decoder must consume exactly its bytes")

    def test_varint_known_encodings(self):
        self.assertEqual(self.u._varint(0), b"\x00", "0 encodes as one zero byte")
        self.assertEqual(self.u._varint(127), b"\x7f", "127 is the largest one-byte varint")
        self.assertEqual(self.u._varint(128), b"\x80\x01", "128 needs a continuation byte")
        self.assertEqual(self.u._varint(300), b"\xac\x02", "300 is the protobuf doc example")

    def test_read_varint_rejects_truncated_and_overlong(self):
        with self.assert_raises(self.u.Ukey2Error, "truncated varint", "a lone continuation byte"):
            self.u._read_varint(b"\x80", 0)
        with self.assert_raises(self.u.Ukey2Error, "overflows 64 bits", "11 continuation bytes"):
            self.u._read_varint(b"\x80" * 10 + b"\x01", 0)
        with self.assert_raises(self.u.Ukey2Error, "overflows 64 bits", "a 10th byte greater than 1"):
            self.u._read_varint(b"\xff" * 9 + b"\x02", 0)
        self.assertEqual(
            self.u._read_varint(self.u._varint(2**64 - 1), 0),
            (2**64 - 1, 10),
            "the largest legal uint64 must still decode",
        )

    # -- field helpers --------------------------------------------------

    def test_field_varint_layout(self):
        self.assertEqual(
            self.u.field_varint(1, 1), b"\x08\x01", "field 1 varint 1 is key=0x08, value=0x01"
        )
        self.assertEqual(
            self.u.field_varint(3, 100),
            b"\x18\x64",
            "field 3 varint 100 (the cipher-commitment value) is key=0x18, value=0x64",
        )

    def test_field_bytes_layout(self):
        self.assertEqual(
            self.u.field_bytes(2, b"abc"),
            b"\x12\x03abc",
            "field 2 bytes is key=0x12, length, payload",
        )
        self.assertEqual(self.u.field_bytes(4, b""), b"\x22\x00", "an empty bytes field is legal")

    # -- parse ----------------------------------------------------------

    def test_parse_roundtrip_mixed_varint_and_bytes(self):
        data = (
            self.u.field_varint(1, 2)
            + self.u.field_bytes(2, b"\x00\xffpayload")
            + self.u.field_varint(3, 2**64 - 1)
        )
        parsed = self.u.parse(data)
        self.assertEqual(parsed[1], [2], "field 1 varint must come back as an int")
        self.assertEqual(parsed[2], [b"\x00\xffpayload"], "field 2 must come back byte-exact")
        self.assertEqual(parsed[3], [2**64 - 1], "a 64-bit varint must survive the round trip")
        self.assertIsInstance(parsed[1][0], int, "ints and bytes must stay distinct")
        self.assertIsInstance(parsed[2][0], bytes, "ints and bytes must stay distinct")

    def test_parse_rejects_duplicate_field_numbers(self):
        # parse() is strict: every message in this protocol carries each field
        # once, so a repeat means a malformed or crafted frame. This is what
        # keeps accept_server_init from reading a different field 2 than the
        # byte length suggests.
        data = self.u.field_bytes(5, b"one") + self.u.field_bytes(5, b"two")
        with self.assert_raises(self.u.Ukey2Error, "appears twice", "repeated field 5"):
            self.u.parse(data)

    def test_parse_rejects_field_number_zero(self):
        with self.assert_raises(self.u.Ukey2Error, "field number zero", "key 0x02"):
            self.u.parse(b"\x02\x01")

    def test_parse_rejects_message_larger_than_max_message(self):
        oversized = self.u.field_bytes(2, bytes(self.u.MAX_MESSAGE))
        self.assertGreater(len(oversized), self.u.MAX_MESSAGE, "test setup: payload beyond the cap")
        with self.assert_raises(self.u.Ukey2Error, "size limit", "a message above MAX_MESSAGE"):
            self.u.parse(oversized)

    def test_parse_nested_message_and_long_bytes(self):
        inner = self.u.field_varint(1, 1) + self.u.field_bytes(2, os.urandom(200))
        parsed = self.u.parse(self.u.field_bytes(2, inner))
        nested = self.u.parse(parsed[2][0])
        self.assertEqual(nested[1], [1])
        self.assertEqual(len(nested[2][0]), 200, "a 200-byte length-delimited field must survive")

    def test_parse_empty_input_is_empty_dict(self):
        self.assertEqual(self.u.parse(b""), {}, "an empty message has no fields")

    def test_parse_rejects_unsupported_wire_types(self):
        for wire, label in ((5, "fixed32"), (1, "fixed64"), (3, "start-group"), (4, "end-group")):
            with self.subTest(wire=wire):
                data = protobuf_key(1, wire) + b"\x00" * 8
                with self.subTest(expect=("unsupported wire type", f"wire type {wire} ({label}) is outside the codec's subset and must be refused")):
                    with self.assertRaises(self.u.Ukey2Error):
                        self.u.parse(data)

    def test_parse_rejects_truncated_length_delimited_field(self):
        data = self.u.field_bytes(2, b"abcdef")
        with self.subTest(expect=("truncated length-delimited field", "a field claiming more bytes than remain must be refused")):
            with self.assertRaises(self.u.Ukey2Error):
                self.u.parse(data[:-1])

    # -- coordinates ----------------------------------------------------

    def test_coord_left_pads_to_32_bytes(self):
        self.assertEqual(
            self.u._coord(b"\x07"),
            b"\x00" * 31 + b"\x07",
            "a short coordinate must be left-padded to 32 bytes",
        )
        full = bytes(range(32))
        self.assertEqual(self.u._coord(full), full, "a full-width coordinate is unchanged")

    def test_coord_trims_leading_zeros_before_padding(self):
        # _coord strips leading zeros, then right-justifies into 32 bytes.
        oversized_but_narrow = b"\x00\x00\x00" + b"\x01" * 32
        self.assertEqual(
            self.u._coord(oversized_but_narrow),
            b"\x01" * 32,
            "leading zeros are stripped before the 32-byte padding, so a 35-byte input with 32 significant bytes is valid",
        )
        self.assertEqual(
            self.u._coord(b"\x00\x01"),
            b"\x00" * 31 + b"\x01",
            "trimming must be followed by re-padding to the full 32-byte width",
        )

    def test_coord_rejects_empty_and_overlong(self):
        for label, value in (("empty", b""), ("all zero", b"\x00" * 8), ("33 significant bytes", b"\x01" * 33)):
            with self.subTest(case=label):
                with self.subTest(expect=("invalid curve coordinate", f"_coord must reject a {label} coordinate")):
                    with self.assertRaises(self.u.Ukey2Error):
                        self.u._coord(value)


class ClientInitTests(_ProtocolTestBase):
    """Structure and commitment of CLIENT_INIT."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import ukey2

        self.u = ukey2
        self.handshake = ukey2.Handshake()
        self.wire = self.handshake.start()
        self.outer = ukey2.parse(self.wire[1:])
        self.inner = ukey2.parse(self.outer[2][0])

    def test_start_is_prefixed_with_client_init_byte(self):
        self.assertEqual(self.wire[0], 0x10, "CLIENT_INIT is transported behind 0x10")
        self.assertEqual(self.wire[0], self.u.FRAME_CLIENT_INIT)

    def test_outer_envelope_is_ukey2_message_type_client_init(self):
        self.assertEqual(
            self.outer[1], [2], "outer Ukey2Message.type must be 2 (CLIENT_INIT)"
        )
        self.assertEqual(list(self.outer), [1, 2], "the envelope must carry exactly type + data")
        self.assertIsInstance(self.outer[2][0], bytes, "outer field 2 must be length-delimited")

    def test_inner_body_carries_version_random_cipher_and_suite(self):
        self.assertEqual(self.inner[1], [1], "CLIENT_INIT.version must be 1")
        self.assertEqual(len(self.inner[2][0]), 32, "CLIENT_INIT.random must be 32 bytes")
        self.assertIsInstance(
            self.inner[3][0], bytes,
            "field 3 must be the length-delimited Ukey2CipherCommitment message, not a bare varint",
        )
        self.assertEqual(
            self.inner[4], [b"AES_256_CBC-HMAC_SHA256"],
            "CLIENT_INIT.next_protocol must be the AES_256_CBC-HMAC_SHA256 suite string",
        )

    def test_cipher_commitment_uses_cipher_type_100(self):
        commitment = self.u.parse(self.inner[3][0])
        self.assertEqual(
            commitment[1], [self.u.CIPHER_COMMITMENT],
            "the cipher commitment's handshake_cipher type must be 100",
        )
        self.assertEqual(self.u.CIPHER_COMMITMENT, 100)
        self.assertEqual(len(commitment[2][0]), 64, "the commitment is a SHA-512 digest (64 bytes)")

    def test_commitment_equals_sha512_of_client_finish(self):
        commitment = self.u.parse(self.inner[3][0])[2][0]
        finish = self.handshake._client_finish
        self.assertTrue(finish, "test setup: CLIENT_FINISH must have been built by start()")
        self.assertEqual(
            commitment,
            hashlib.sha512(finish).digest(),
            "the commitment must be sha512 over the *complete* ClientFinish message (type + data)",
        )

    def test_commitment_does_not_cover_only_the_finish_data(self):
        # A plausible misreading is to hash the inner data without the type
        # field.  Assert we are not doing that, so the transcript binding is real.
        commitment = self.u.parse(self.inner[3][0])[2][0]
        data_only = hashlib.sha512(self.handshake._finish_data).digest()
        self.assertNotEqual(
            commitment,
            data_only,
            "the commitment must include the ClientFinish message type, not only its data",
        )

    def test_client_finish_message_is_well_formed(self):
        finish = self.u.parse(self.handshake._client_finish)
        self.assertEqual(finish[1], [4], "ClientFinish.type must be 4")
        data = self.u.parse(finish[2][0])
        self.assertEqual(sorted(data), [1, 2], "ClientFinish.data must be public_key + iv")
        self.assertEqual(len(data[2]), 1, "ClientFinish.data.iv must be present")
        self.assertEqual(len(data[2][0]), 16, "the AES-CBC IV is 16 bytes")
        generic = self.u.parse(data[1][0])
        self.assertEqual(generic[1], [1], "the public key must be a generic P-256 key (type 1)")
        xy = self.u.parse(generic[2][0])
        self.assertEqual(len(xy[1][0]), 32, "the X coordinate must be padded to 32 bytes")
        self.assertEqual(len(xy[2][0]), 32, "the Y coordinate must be padded to 32 bytes")

    def test_client_finish_public_key_is_our_ephemeral_point(self):
        data = self.u.parse(self.u.parse(self.handshake._client_finish)[2][0])
        xy = self.u.parse(self.u.parse(data[1][0])[2][0])
        tag, coords = self.handshake.ephemeral.public_point[0], self.handshake.ephemeral.public_point[1:]
        self.assertEqual(tag, 0x04, "test setup: an uncompressed point")
        self.assertEqual(xy[1][0], coords[:32], "X in CLIENT_FINISH must be the ephemeral key's X")
        self.assertEqual(xy[2][0], coords[32:], "Y in CLIENT_FINISH must be the ephemeral key's Y")

    def test_calling_start_twice_is_not_idempotent(self):
        # start() rebuilds CLIENT_INIT with a *fresh* 32-byte random every call
        # while the commitment still covers the ClientFinish built in the same
        # call, so two calls describe two different, valid handshakes.  It is
        # a re-entrancy trap (the second CLIENT_INIT invalidates the first
        # commitment a peer may already have stored) but not a wire bug.
        first = self.handshake.start()
        second = self.handshake.start()
        self.assertNotEqual(
            first, second,
            "start() must not be called twice: it re-randomises CLIENT_INIT.random",
        )
        self.assertEqual(
            self.handshake._client_init, second[1:],
            "the handshake must keep the CLIENT_INIT from its most recent start() call",
        )


class HandshakeFlowTests(_ProtocolTestBase):
    """accept_server_init / accept_server_finish behaviour against a fake peer."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import ukey2

        self.u = ukey2

    def _server_init(self, server_key) -> bytes:
        point = server_key.public_point[1:]
        generic = self.u.field_varint(1, 1) + self.u.field_bytes(
            2,
            self.u.field_bytes(1, self.u._coord(point[:32]))
            + self.u.field_bytes(2, self.u._coord(point[32:])),
        )
        # Field 2 goes last: parse() collapses repeated numbers, and the
        # production code reads exactly one server random.
        body = (
            self.u.field_varint(1, 1)
            + self.u.field_varint(3, self.u.CIPHER_COMMITMENT)
            + self.u.field_bytes(4, generic)
            + self.u.field_bytes(2, os.urandom(32))
        )
        return bytes([self.u.FRAME_SERVER_INIT]) + self.u.field_varint(1, 3) + self.u.field_bytes(2, body)

    def _run_handshake(self):
        from aipin_sdk.protocol import crypto

        handshake = self.u.Handshake()
        client_init = handshake.start()
        server_key = crypto.EphemeralKey.generate()
        server_init = self._server_init(server_key)
        finish = handshake.accept_server_init(server_init)
        return handshake, server_key, client_init, server_init, finish

    def test_accept_server_init_derives_a_16_byte_key_matching_the_peer(self):
        handshake, server_key, _, _, _ = self._run_handshake()

        self.assertEqual(len(handshake.session_key), 16, "the session key is the first 16 bytes of an HKDF output")
        self.assertEqual(
            server_key.agree(handshake.ephemeral.public_point),
            handshake.ephemeral.agree(server_key.public_point),
            "test setup: both sides must agree on the ECDH secret",
        )

    def test_accept_server_init_key_matches_transcript_derivation(self):
        from aipin_sdk.protocol import crypto

        handshake, server_key, client_init, server_init, _ = self._run_handshake()
        shared = server_key.agree(handshake.ephemeral.public_point)
        handshake_key = crypto.derive_key(
            hashlib.sha256(shared).digest(),
            self.u.INFO_HANDSHAKE,
            client_init[1:] + server_init[1:],
            length=32,
        )
        expected = crypto.derive_key(handshake_key, self.u.SESSION_SALT, self.u.INFO_CLIENT_KEY, length=32)[:16]
        self.assertEqual(
            handshake.session_key, expected,
            "key = HKDF(sha256(ECDH), 'UKEY2 v1 next', CLIENT_INIT||SERVER_INIT) then 'client' sliced to 16",
        )

    def test_client_finish_frame_appends_the_committed_message_verbatim(self):
        handshake, _, _, _, finish = self._run_handshake()
        self.assertEqual(finish[0], self.u.FRAME_CLIENT_FINISH, "CLIENT_FINISH is transported behind 0x12")
        self.assertEqual(
            finish[17:], handshake._client_finish,
            "CLIENT_FINISH must append the exact bytes the commitment covers (1 byte IV prefix + 16-byte CBC block)",
        )
        self.assertEqual(len(finish[1:17]), 16, "the encrypted identity is one 16-byte AES-CBC block")

    def test_accept_server_init_rejects_wrong_transport_prefix(self):
        with self.assert_raises(self.u.Ukey2Error, "expected SERVER_INIT", "a 0x10-prefixed message"):
            self.u.Handshake().accept_server_init(b"\x10" + bytes(4))

    def test_accept_server_init_rejects_empty_and_oversized_messages(self):
        with self.assert_raises(self.u.Ukey2Error, "expected SERVER_INIT", "an empty message"):
            self.u.Handshake().accept_server_init(b"")
        with self.assert_raises(self.u.Ukey2Error, "too large", f"a body over MAX_MESSAGE={self.u.MAX_MESSAGE}"):
            self.u.Handshake().accept_server_init(b"\x11" + bytes(self.u.MAX_MESSAGE + 1))

    def test_accept_server_init_rejects_wrong_outer_type(self):
        message = b"\x11" + self.u.field_varint(1, 2) + self.u.field_bytes(2, b"x")
        with self.assert_raises(
            self.u.Ukey2Error, "not a SERVER_INIT", "outer type 2 (client init) on the server path"
        ):
            self.u.Handshake().accept_server_init(message)

    def test_accept_server_init_rejects_unsupported_cipher(self):
        body = self.u.field_varint(1, 1) + self.u.field_varint(3, 200) + self.u.field_bytes(4, b"")
        message = b"\x11" + self.u.field_varint(1, 3) + self.u.field_bytes(2, body)
        with self.assert_raises(
            self.u.Ukey2Error, "unsupported protocol or cipher", "cipher type 200 instead of 100"
        ):
            self.u.Handshake().accept_server_init(message)

    def test_session_key_is_unavailable_before_accept_server_init(self):
        handshake = self.u.Handshake()
        handshake.start()
        with self.assert_raises(self.u.Ukey2Error, "no session key", "session_key read before SERVER_INIT"):
            handshake.session_key

    def test_accept_server_finish_requires_an_established_key(self):
        with self.assert_raises(
            self.u.Ukey2Error, "not far enough along", "accept_server_finish before accept_server_init"
        ):
            self.u.Handshake().accept_server_finish(bytes(8) + bytes(8) + bytes(22))

    KEY = bytes(range(16))
    IV = bytes(range(16, 32))
    NONCE = bytes(range(8))
    CONFIRMATION = bytes([0x13]) + bytes(8) + b"\xde\xad\xbe\xef\x00\x01" + bytes([1]) + bytes(6)

    def _handshake_with_key(self):
        handshake = self.u.Handshake()
        handshake.start()
        handshake._aes_key = self.KEY
        handshake.iv = self.IV
        return handshake

    def _server_finish(self, plain: bytes, *, key: bytes = None, mac_key: bytes = None) -> bytes:
        from aipin_sdk.protocol import crypto

        key = key or self.KEY
        cipher = crypto.packet_transform(plain, key, self.IV, self.NONCE)
        mac = crypto.hmac_sha256(mac_key or self.KEY, self.NONCE + cipher)[:8]
        return mac + self.NONCE + cipher

    def test_accept_server_finish_rejects_wrong_length_messages(self):
        handshake = self._handshake_with_key()
        for size in (0, 15, 16, 37, 39, 64):
            with self.subTest(size=size):
                with self.assert_raises(
                    self.u.Ukey2Error,
                    "must be 38 bytes",
                    f"a {size}-byte SERVER_FINISH (the frame is exactly 38)",
                ):
                    handshake.accept_server_finish(bytes(size))

    def test_accept_server_finish_accepts_authenticated_confirmation(self):
        handshake = self._handshake_with_key()
        message = self._server_finish(self.CONFIRMATION)
        self.assertEqual(len(message), self.u.SERVER_FINISH_BYTES, "test setup: a complete frame")

        self.assertEqual(
            handshake.accept_server_finish(message),
            self.CONFIRMATION,
            "an authenticated SERVER_FINISH must be accepted and returned as plaintext",
        )
        self.assertEqual(
            handshake.provider_id, b"\xde\xad\xbe\xef\x00\x01", "provider id is plaintext bytes 9..15"
        )

    def test_accept_server_finish_rejects_forged_mac(self):
        handshake = self._handshake_with_key()
        for label, mac_key in (
            ("MAC all zeros", b"\x00" * 16),
            ("MAC under a different key", b"\x99" * 16),
        ):
            with self.subTest(case=label):
                message = self._server_finish(self.CONFIRMATION, mac_key=mac_key)
                with self.assert_raises(
                    self.u.Ukey2Error, "failed authentication", f"a SERVER_FINISH with {label}"
                ):
                    handshake.accept_server_finish(message)
        self.assertIsNone(handshake.provider_id, "a rejected frame must not set provider_id")

    def test_accept_server_finish_rejects_correctly_maced_but_wrong_payload(self):
        # Passes the MAC but decrypts to something that is not a confirmation:
        # the structural check (0x13 at 0, 1 at 15) must still refuse it.
        handshake = self._handshake_with_key()
        cases = {
            "random 22 bytes": os.urandom(22),
            "wrong magic": b"\x00" + self.CONFIRMATION[1:],
            "wrong status byte": self.CONFIRMATION[:15] + b"\x02" + self.CONFIRMATION[16:],
            "transformed with the wrong key": self._server_finish(self.CONFIRMATION, key=b"\x11" * 16),
        }
        for label, message in cases.items():
            if len(message) != self.u.SERVER_FINISH_BYTES:
                message = self._server_finish(message)
            with self.subTest(case=label):
                with self.assert_raises(
                    self.u.Ukey2Error, "device rejected the pairing", f"a frame with {label}"
                ):
                    self._handshake_with_key().accept_server_finish(message)

    def test_seal_envelope_layout_and_mac(self):
        from aipin_sdk.protocol import crypto

        handshake = self._handshake_with_key()
        sealed = handshake.seal(b"K" * 24, nonce=b"\x01" * 8)

        self.assertEqual(len(sealed), 40, "seal(24 bytes) is mac(8) || nonce(8) || transform(24) = 40 bytes")
        self.assertEqual(sealed[8:16], b"\x01" * 8, "an explicit nonce must be used as-is")
        self.assertEqual(
            sealed[:8],
            crypto.hmac_sha256(self.KEY, sealed[8:])[:8],
            "the leading MAC must be HMAC-SHA256(session key, nonce || cipher)[:8]",
        )
        self.assertEqual(
            crypto.packet_transform(sealed[16:], self.KEY, self.IV, sealed[8:16]),
            b"K" * 24,
            "the ciphertext must transform back to the plaintext under the same nonce",
        )

    def test_seal_uses_a_fresh_random_nonce_by_default(self):
        handshake = self._handshake_with_key()
        first, second = handshake.seal(b"K" * 24), handshake.seal(b"K" * 24)
        self.assertNotEqual(
            first[8:16], second[8:16], "without an explicit nonce, seal() must draw a fresh 8-byte nonce"
        )

    def test_open_decrypts_one_aes_cbc_block(self):
        from aipin_sdk.protocol import crypto

        handshake = self._handshake_with_key()
        block = crypto.aes_cbc_encrypt(self.KEY, self.IV, b"confirmation-16!")
        self.assertEqual(handshake.open(block), b"confirmation-16!", "open() decrypts one AES-CBC block")


# ==========================================================================
# epi (transport negotiation)
# ==========================================================================


class OfferBuilder:
    """Builds a device offer frame in the layout ``epi.parse_offer`` reads.

    wire::

        type u8(=1) | version u16 | peer_id(36) | mode u8 | count u8
        count x field:  key u8, then the value at that key's width

    Records are written in the order they are supplied so tests can also build
    deliberately odd offers (unknown keys mid-list, bad UTF-8, truncation).
    """

    #: (key, value) pairs of the profile this host accepts.
    NUMBERS = ((1, 20480), (2, 491), (3, 47), (4, 10000), (5, 10), (10, 1), (11, 2), (12, 3), (13, 0))
    STRINGS = ((6, "oppo"), (7, "oppo"), (8, "Beluga"))

    @classmethod
    def default_fields(cls):
        return list(cls.NUMBERS) + list(cls.STRINGS)

    @staticmethod
    def _encode(key, value):
        if isinstance(value, str):
            raw = value.encode("utf-8")
            return bytes([key, len(raw)]) + raw
        width = {1: 4, 2: 2, 3: 2, 4: 2, 5: 2, 10: 1, 11: 1, 12: 1, 13: 1}[key]
        return bytes([key]) + int(value).to_bytes(width, "big")

    @classmethod
    def build(cls, fields=None, *, type_=1, version=1, peer_id=b"OAFP_" + b"0" * 31, mode=0x10):
        fields = cls.default_fields() if fields is None else fields
        data = bytearray([type_])
        data += int(version).to_bytes(2, "big")
        data += peer_id
        data += bytes([mode])
        data.append(len(fields))
        for key, value in fields:
            if isinstance(value, bytes) and value.startswith(b"RAW:"):
                # The raw bytes follow the key byte, so a test can control the
                # length or payload exactly (bad UTF-8, a short field 14, ...).
                data.append(key)
                data += value[4:]
            else:
                data += cls._encode(key, value)
        return bytes(data)


class EpiTests(_ProtocolTestBase):
    """Offer parsing, profile checking and answer construction."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import epi

        self.epi = epi

    # -- constants ------------------------------------------------------

    def test_answer_constants(self):
        self.assertEqual(self.epi.ANSWER_TYPE, 2, "the host answers with message type 2")
        self.assertEqual(self.epi.ANSWER_VERSION, 1, "the answer carries protocol version 1")
        self.assertEqual(self.epi.LOCAL_APDU_SIZE, 7680, "the APDU ceiling advertised is 7680 bytes")
        self.assertEqual(
            self.epi.LOCAL_SSDU_SIZE, 235, "the SSDU ceiling advertised matches the frame size"
        )

    # -- parse_offer ----------------------------------------------------

    def test_parse_offer_reads_header_peer_id_and_mode(self):
        peer = b"OAFP_" + bytes(range(0x30, 0x30 + 31))  # OAFP_ + 31 = 36 bytes
        self.assertEqual(len(peer), 36, "test setup: an offer peer id is 36 bytes")
        offer = self.epi.parse_offer(OfferBuilder.build(peer_id=peer))

        self.assertEqual(offer.protocol_version, 1, "version field is 1")
        self.assertEqual(
            offer.peer_id, peer,
            "the 36-byte peer id must be taken verbatim",
        )
        self.assertEqual(offer.mode, 0x10, "mode byte is read after the peer id")

    def test_parse_offer_collects_numbers_and_strings(self):
        offer = self.epi.parse_offer(OfferBuilder.build())

        self.assertEqual(
            offer.numbers,
            dict(OfferBuilder.NUMBERS),
            "every numeric field must be decoded at its own width",
        )
        self.assertEqual(
            offer.strings,
            dict(OfferBuilder.STRINGS),
            "fields 6/7/8 decode as UTF-8 strings",
        )
        self.assertIsInstance(offer, self.epi.Offer, "parse_offer returns an Offer")

    def test_parse_offer_rejects_only_versions_above_one(self):
        offer = self.epi.parse_offer(OfferBuilder.build(version=0))
        self.assertEqual(offer.protocol_version, 0, "version 0 is not rejected: only >1 is")
        with self.assert_raises(
            self.epi.NegotiationError, "unsupported", "a device announcing protocol version 2"
        ):
            self.epi.parse_offer(OfferBuilder.build(version=2))

    def test_parse_offer_rejects_a_non_offer_type(self):
        with self.assert_raises(self.epi.NegotiationError, "expected offer type 1", "type byte 2"):
            self.epi.parse_offer(OfferBuilder.build(type_=2))

    def test_parse_offer_rejects_truncated_frames(self):
        full = OfferBuilder.build()
        for cut in (0, 1, 2, 3, 8, 39, 41, 60, len(full) - 1):
            with self.subTest(cut=cut):
                with self.assert_raises(
                    self.epi.NegotiationError, "offer is truncated", f"an offer cut to {cut} bytes"
                ):
                    self.epi.parse_offer(full[:cut])

    def test_parse_offer_rejects_invalid_utf8_in_a_string_field(self):
        # The invalid bytes must be the FIRST field 8: a later duplicate key
        # shifts the layout and is caught as truncation before UTF-8 decoding.
        fields = []
        placed = False
        for key, value in OfferBuilder.default_fields():
            if key == 8 and not placed:
                fields.append((8, b"RAW:\x04\xff\xfe\xfd\xfc"))
                placed = True
            elif key != 8:
                fields.append((key, value))
        with self.assert_raises(
            self.epi.NegotiationError, "not valid UTF-8", "a Beluga field holding invalid UTF-8"
        ):
            self.epi.parse_offer(OfferBuilder.build(fields))

    def test_parse_offer_tolerates_an_unknown_trailing_feature(self):
        fields = OfferBuilder.default_fields() + [(200, b"RAW:\xab")]
        offer = self.epi.parse_offer(OfferBuilder.build(fields))
        self.assertEqual(
            offer.strings, dict(OfferBuilder.STRINGS),
            "an unknown trailing feature must not disturb the fields already read",
        )
        self.epi.check_offer(offer)  # and it must still be an acceptable offer

    def test_parse_offer_rejects_an_unknown_feature_in_the_middle(self):
        fields = OfferBuilder.default_fields()
        fields.insert(2, (200, b"RAW:\xab"))
        with self.assert_raises(
            self.epi.NegotiationError, "unknown feature 200", "an unknown key before the last field"
        ):
            self.epi.parse_offer(OfferBuilder.build(fields))

    def test_parse_offer_skips_field_14_which_carries_six_bytes(self):
        fields = OfferBuilder.default_fields() + [(14, b"RAW:\x01\x02\x03\x04\x05\x06")]
        offer = self.epi.parse_offer(OfferBuilder.build(fields))
        self.assertEqual(offer.strings, dict(OfferBuilder.STRINGS))
        fields[-1] = (14, b"RAW:\x01\x02\x03")
        with self.assert_raises(
            self.epi.NegotiationError, "offer is truncated", "field 14 with only three bytes"
        ):
            self.epi.parse_offer(OfferBuilder.build(fields))

    # -- check_offer ----------------------------------------------------

    def test_check_offer_accepts_the_supported_profile(self):
        self.assertIsNone(self.epi.check_offer(self.epi.parse_offer(OfferBuilder.build())))

    def test_check_offer_requires_single_client_mode(self):
        for mode in (0x00, 0x01, 0xFF):
            with self.subTest(mode=mode):
                with self.assert_raises(
                    self.epi.NegotiationError, "single-client mode", f"offer mode 0x{mode:02x}"
                ):
                    self.epi.check_offer(self.epi.parse_offer(OfferBuilder.build(mode=mode)))

    def test_check_offer_requires_the_oppo_and_beluga_strings(self):
        for key, good, bad, label in (
            (6, "oppo", "Oppo", "vendor field 6"),
            (7, "oppo", "local", "vendor field 7"),
            (8, "Beluga", "beluga", "product field 8"),
        ):
            with self.subTest(field=key):
                fields = [(k, bad if k == key else v) for k, v in OfferBuilder.default_fields()]
                offer = self.epi.parse_offer(OfferBuilder.build(fields))
                self.assertEqual(offer.strings[key], bad, "test setup: the field was replaced")
                with self.assert_raises(
                    self.epi.NegotiationError,
                    f"offer field {key} is",
                    f"{label} set to {bad!r} instead of {good!r}",
                ):
                    self.epi.check_offer(offer)

    def test_check_offer_requires_every_fingerprint_number(self):
        for key, expected in sorted(self.epi.EXPECTED.items()):
            with self.subTest(field=key):
                # field 13 is legitimately 0, so perturb each field by +1.
                fields = [(k, expected + 1 if k == key else v) for k, v in OfferBuilder.default_fields()]
                offer = self.epi.parse_offer(OfferBuilder.build(fields))
                self.assertEqual(offer.numbers[key], expected + 1)
                with self.assert_raises(
                    self.epi.NegotiationError,
                    f"offer field {key} is",
                    f"fingerprint field {key} changed from {expected} to {expected + 1}",
                ):
                    self.epi.check_offer(offer)

    def test_check_offer_rejects_a_missing_fingerprint_field(self):
        fields = [(k, v) for k, v in OfferBuilder.default_fields() if k != 3]
        offer = self.epi.parse_offer(OfferBuilder.build(fields))
        with self.assert_raises(
            self.epi.NegotiationError, "offer field 3 is", "an offer missing fingerprint field 3"
        ):
            self.epi.check_offer(offer)

    def test_check_offer_ignores_fields_that_are_not_part_of_the_fingerprint(self):
        fields = [(k, 9 if k == 10 else v) for k, v in OfferBuilder.default_fields()]
        self.assertIsNone(
            self.epi.check_offer(self.epi.parse_offer(OfferBuilder.build(fields))),
            "field 10 is not in EXPECTED, so its value must not matter",
        )
        self.assertNotIn(10, self.epi.EXPECTED)

    # -- build_answer ---------------------------------------------------

    def test_build_answer_layout(self):
        peer = "OAFP_" + "a" * 31
        answer = self.epi.build_answer(peer)

        self.assertEqual(answer[0], len(answer) - 1, "the answer carries a one-byte length prefix")
        payload = answer[1:]
        self.assertEqual(payload[0], self.epi.ANSWER_TYPE, "answer type byte is 2")
        self.assertEqual(payload[1], 0, "answer second byte is 0")
        self.assertEqual(payload[2], self.epi.ANSWER_VERSION, "answer version byte is 1")
        self.assertEqual(payload[3:39], peer.encode("ascii"), "the local peer id is echoed")
        self.assertEqual(payload[39], 0, "answer mode is 0")
        self.assertEqual(payload[40], 8, "the answer advertises eight features")
        self.assertEqual(
            payload[41:],
            b"\x01\x00\x00\x1e\x00"
            b"\x02\x00" + bytes([self.epi.LOCAL_SSDU_SIZE]) + b""
            b"\x06\x03Mac\x07\x05Local\x08\x08MacProbe"
            b"\x0a\x08\x0c\x00\x0d\x00",
            "APDU cap, SSDU cap, the three strings, then fields 10..13",
        )

    def test_build_answer_carries_the_service_profile_count(self):
        for count in (0, 1, 127, 255):
            with self.subTest(count=count):
                answer = self.epi.build_answer("OAFP_" + "a" * 31, service_profiles=count)
                self.assertIn(
                    bytes([12, count]),
                    answer,
                    "the service profile count must appear as field 12",
                )
        with self.assert_raises(
            self.epi.NegotiationError, "one byte", "a service profile count of 256"
        ):
            self.epi.build_answer("OAFP_" + "a" * 31, service_profiles=256)

    def test_build_answer_rejects_bad_peer_ids(self):
        for label, peer in (
            ("too short", "OAFP_" + "a" * 30),
            ("too long", "OAFP_" + "a" * 32),
            ("wrong prefix", "OAFP" + "a" * 32),
            ("non-ASCII", "OAFP_" + "é" * 31),
            ("control character", "OAFP_" + "\x00" * 31),
        ):
            with self.subTest(case=label):
                with self.assert_raises(
                    self.epi.NegotiationError, "peer id", f"a local peer id that is {label}"
                ):
                    self.epi.build_answer(peer)

    def test_build_answer_fits_its_single_byte_length_prefix(self):
        answer = self.epi.build_answer("OAFP_" + "a" * 31, service_profiles=255)
        self.assertLessEqual(answer[0], 255, "the answer must fit the u8 length prefix")
        self.assertEqual(len(answer), answer[0] + 1)


# ==========================================================================
# connect (sync-recordings admission)
# ==========================================================================


class ConnectSyncTests(_ProtocolTestBase):
    """The third consumer sync-recordings needs, and the raw reader it uses."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import connect, framing
        from aipin_sdk.protocol.transport import LoopbackBackend, Session, TransportError

        self.connect = connect
        self.f = framing
        self.LoopbackBackend = LoopbackBackend
        self.Session = Session
        self.TransportError = TransportError

    def _runner(self, *, sync: bool, agent_id: int = 42):
        """A runner with a connected fake link that has nothing to read."""
        TransportError = self.TransportError

        class SilentBackend(self.LoopbackBackend):
            def read_notification(self, timeout):
                raise TransportError("no notification")

        backend = SilentBackend()
        backend.connect("test-device", 1.0)
        runner = self.connect._Runner(
            session=self.Session(backend, "test-device", timeout=0.05),
            pairing=None,
            local_peer_id="OAFP_" + "a" * 31,
            agent_id=agent_id,
            package="local.insico.test",
            name="Test",
            agent_auth_payload=self.connect.AGENT_AUTH_UNAVAILABLE,
            deadline=float("inf"),
            sync=sync,
        )
        return runner, backend

    def _query_profiles(self, backend) -> tuple[str, ...]:
        frame = self.f.decode(backend.written[0][1])
        self.assertEqual(
            frame.session_id, self.connect.SESSION_CAPEX, "the query is on session 2"
        )
        return self.connect.CapabilityQuery.parse(frame.body).profiles

    def test_sync_capex_query_asks_the_device_for_the_system_profile(self):
        runner, backend = self._runner(sync=True)
        with self.assertRaises(self.TransportError):
            runner._exchange_capabilities()
        self.assertEqual(
            self._query_profiles(backend),
            ("jg.pipe.message", "jg.pipe.file", "system:filetransfer"),
            "sync must ask the device for the provider its type-1 will target",
        )

        runner, backend = self._runner(sync=False)
        with self.assertRaises(self.TransportError):
            runner._exchange_capabilities()
        self.assertEqual(
            self._query_profiles(backend),
            ("jg.pipe.message", "jg.pipe.file"),
            "sync=False keeps the original two-profile query byte for byte",
        )

    def test_sync_derives_a_distinct_system_consumer_at_message_plus_two(self):
        runner, _ = self._runner(sync=True, agent_id=42)
        self.assertEqual(
            runner.system_agent_id, 44, "the protocol derives message + 2"
        )
        runner, _ = self._runner(sync=False, agent_id=42)
        self.assertIsNone(runner.system_agent_id, "sync=False advertises no third consumer")

        query = self.connect.CapabilityQuery(
            3, 0, ("jg.pipe.message", "jg.pipe.file", "system:filetransfer")
        )
        from unittest import mock

        with mock.patch.object(
            self.connect,
            "capex_response_body_from",
            wraps=self.connect.capex_response_body_from,
        ) as encoder:
            body, _checksum = self.connect.capex_response_body(
                query,
                local_agent_id=42,
                local_file_agent_id=43,
                local_system_agent_id=44,
                package="local.insico.test",
                name="Test",
            )
        self.assertEqual(
            encoder.call_args.kwargs.get("local_system_agent_id"),
            44,
            "capex_response_body must pass the system consumer to the encoder",
        )
        parsed = self.connect.CapabilityResponse.parse(body)
        system = [
            agent
            for application in parsed.applications
            for agent in application.agents
            if agent.profile == "system:filetransfer"
        ]
        self.assertEqual(
            [agent.id for agent in system], [44], "the system record carries message + 2"
        )
        self.assertEqual(system[0].connection_timeout, 30, "the official XML timeout is 30")
        self.assertEqual(system[0].role_flags, 0x09, "consumer + socket, no wake claim")

        with self.assert_raises(
            self.connect.ConnectError,
            "system consumer",
            "a message agent of 0xFEFE would derive the FF00 unsupported marker",
        ):
            self.connect.connect(
                None, None, "OAFP_" + "a" * 31, sync=True, agent_id=0xFEFE
            )

    def test_sync_answers_a_device_capex_query_with_the_system_agent(self):
        requested = (
            "system:filetransfer",
            "jg.pipe.wake",
            "jg.pipe.message",
            "jg.pipe.file",
        )
        device_query = self.f.encode(2, self.connect.capex_query_body(requested, 0))
        TransportError = self.TransportError

        class DrainBackend(self.LoopbackBackend):
            """Serve queued frames, then fail the read at once instead of idling."""

            def read_notification(self, timeout):
                if self._queue.empty():
                    raise TransportError("no notification")
                return super().read_notification(timeout)

        backend = DrainBackend(responses=[device_query])
        backend.connect("test-device", 1.0)
        runner = self.connect._Runner(
            session=self.Session(backend, "test-device", timeout=0.05),
            pairing=None,
            local_peer_id="OAFP_" + "a" * 31,
            agent_id=42,
            package="local.insico.test",
            name="Test",
            agent_auth_payload=self.connect.AGENT_AUTH_UNAVAILABLE,
            deadline=float("inf"),
            sync=True,
        )
        with self.assertRaises(self.TransportError):
            runner._exchange_capabilities()

        frames = [self.f.decode(payload) for _characteristic, payload in backend.written]
        self.assertGreaterEqual(len(frames), 2, "the query and its answer are both written")
        answer = self.connect.CapabilityResponse.parse(frames[1].body)
        agents = [agent for application in answer.applications for agent in application.agents]
        self.assertIn(
            (44, self.connect.PROFILE_SYSTEM, 30),
            [(agent.id, agent.profile, agent.connection_timeout) for agent in agents],
            "the device query is answered with local_system_agent_id = message + 2",
        )
        self.assertIn(
            (0xFF00, "jg.pipe.wake"),
            [(agent.id, agent.profile) for agent in agents],
            "an unimplemented requested profile is still the FF00 dummy",
        )

    def test_sync_opens_the_system_service_one_session_past_the_file_service(self):
        app = self.connect.CapabilityApplication(
            "local.insico.test",
            "Test",
            (
                self.connect.CapabilityAgent(4, self.connect.PROFILE_MESSAGE, 0x0100, 0, 10),
                self.connect.CapabilityAgent(5, self.connect.PROFILE_FILE, 0x0100, 0, 10),
                self.connect.CapabilityAgent(6, self.connect.PROFILE_SYSTEM, 0x0100, 0, 30),
            ),
        )

        def challenge(first: int, second: int, profile: str) -> bytes:
            return (
                bytes([5])
                + first.to_bytes(2, "big")
                + second.to_bytes(2, "big")
                + profile.encode("utf-8")
                + b";"
                + self.connect.AGENT_AUTH_UNAVAILABLE
            )

        def accept(initiator: int, acceptor: int, profile: str, sessions):
            return self.connect.service_connection_response_body(
                initiator_agent_id=initiator,
                acceptor_agent_id=acceptor,
                profile=profile,
                status=0,
                session_ids=sessions,
            )

        responses = [
            self.f.encode(
                self.connect.SESSION_CAPEX,
                self.connect.capex_response_body_from([app], 0),
            ),
            self.f.encode(
                self.connect.SESSION_SERVICE,
                challenge(42, 4, self.connect.PROFILE_MESSAGE),
            ),
            self.f.encode(
                self.connect.SESSION_SERVICE,
                accept(42, 4, self.connect.PROFILE_MESSAGE, (32, 33)),
            ),
            self.f.encode(
                self.connect.SESSION_SERVICE,
                challenge(43, 5, self.connect.PROFILE_FILE),
            ),
            self.f.encode(
                self.connect.SESSION_SERVICE,
                accept(5, 43, self.connect.PROFILE_FILE, (34,)),
            ),
            self.f.encode(
                self.connect.SESSION_SERVICE,
                accept(6, 44, self.connect.PROFILE_SYSTEM, (35,)),
            ),
        ]
        backend = self.LoopbackBackend(responses=responses)
        backend.connect("test-device", 1.0)
        runner = self.connect._Runner(
            session=self.Session(backend, "test-device", timeout=0.1),
            pairing=None,
            local_peer_id="OAFP_" + "a" * 31,
            agent_id=42,
            package="local.insico.test",
            name="Test",
            agent_auth_payload=self.connect.AGENT_AUTH_UNAVAILABLE,
            deadline=float("inf"),
            sync=True,
        )
        runner._exchange_capabilities()

        self.assertEqual(runner._next_system_session, 35, "file session 34 + 1")
        self.assertEqual(runner.system_provider_id, 6, "provider learned from capex")
        self.assertEqual(runner.system_session_id, 35, "the accepted system session")
        self.assertEqual(runner.file_channels, {35: 100}, "the proposed control channel")
        self.assertIn(
            "system_service_accepted",
            [step.name for step in runner.steps],
            "the device's type-2 was accepted, not ignored",
        )

        system_requests = []
        for _characteristic, payload in backend.written:
            frame = self.f.decode(payload)
            if frame.session_id == self.connect.SESSION_SERVICE and frame.body[:1] == b"\x01":
                request = self.connect.ServiceConnectionRequest.parse(frame.body)
                if request.profile == self.connect.PROFILE_SYSTEM:
                    system_requests.append(request)
        self.assertEqual(len(system_requests), 1, "one host-initiated system offer")
        request = system_requests[0]
        self.assertEqual(request.profile, self.connect.PROFILE_SYSTEM)
        self.assertEqual(request.local_agent_id, 44, "the system consumer is message + 2")
        self.assertEqual(request.remote_agent_id, 6, "the device provider from capex")
        self.assertEqual(
            [channel.session_id for channel in request.channels],
            [35],
            "one session, one past the file service",
        )
        self.assertEqual(
            [channel.channel_id for channel in request.channels],
            [100],
            "the control channel is what the host proposes",
        )

    def test_device_system_service_request_is_parked_and_declared(self):
        runner, backend = self._runner(sync=True)
        runner._file_accepted = True
        runner._pending_service = "system"
        proposal = self.connect.service_connection_request_body(
            local_agent_id=5,
            remote_agent_id=44,
            profile=self.connect.PROFILE_SYSTEM,
            channels=(
                self.connect.ChannelProposal(34, 100, 4, 3, 0),
                self.connect.ChannelProposal(35, 101, 4, 0, 0),
                self.connect.ChannelProposal(36, 102, 4, 0, 0),
            ),
        )
        runner._handle_service(proposal)

        self.assertEqual(
            runner._pending_service,
            "system_accepted",
            "the device opened the service itself",
        )
        self.assertEqual(
            runner.raw_frames,
            [(self.connect.SESSION_SERVICE, proposal)],
            "the type-1 is parked verbatim, never swallowed",
        )
        self.assertEqual(runner.system_session_id, 34, "channel 100 is the control session")
        self.assertEqual(
            runner.file_channels,
            {34: 100, 35: 101, 36: 102},
            "the device's declaration is kept as session -> channel",
        )
        self.assertEqual(
            backend.written, [], "connect() leaves the type-2 accept to the sync layer"
        )

        channel = self.connect.ConnectedChannel(
            session=runner.session,
            secure=None,
            session_id=32,
            channel_id=104,
            message_provider_id=4,
            file_provider_id=5,
            device_info=None,
            bind_payload=b"",
            pending_frames=runner.raw_frames,
        )
        self.assertEqual(
            channel.read_raw(0.01),
            (self.connect.SESSION_SERVICE, proposal),
            "read_raw returns exactly what the sync layer must answer",
        )

    def test_bind_loop_parks_a_device_type_1_instead_of_failing(self):
        proposal = self.connect.service_connection_request_body(
            local_agent_id=5,
            remote_agent_id=44,
            profile=self.connect.PROFILE_SYSTEM,
            channels=(self.connect.ChannelProposal(34, 100, 4, 3, 0),),
        )
        backend = self.LoopbackBackend(responses=[self.f.encode(1, proposal)])
        backend.connect("test-device", 1.0)
        runner = self.connect._Runner(
            session=self.Session(backend, "test-device", timeout=0.05),
            pairing=None,
            local_peer_id="OAFP_" + "a" * 31,
            agent_id=42,
            package="local.insico.test",
            name="Test",
            agent_auth_payload=self.connect.AGENT_AUTH_UNAVAILABLE,
            deadline=float("inf"),
            sync=True,
        )
        runner.secure = object()  # the parked path never opens an envelope

        with self.assertRaises(self.TransportError):
            runner._read_business(0.2)
        self.assertEqual(
            runner.raw_frames, [(1, proposal)], "the bind loop parked it, not failed"
        )
        self.assertEqual(
            runner.file_channels,
            {34: 100},
            "parking still records the declared session -> channel map",
        )

    def test_sync_tolerates_a_device_that_ignores_the_host_system_offer(self):
        runner, _ = self._runner(sync=True)
        runner.system_provider_id = 6
        runner._next_system_session = 35
        runner._file_accepted = True
        runner._pending_service = "system"
        runner._exchange_capabilities()

        self.assertEqual(
            runner._pending_service,
            "system_accepted",
            "no reply must not abort connect; the device opens the service later",
        )
        self.assertIn(
            "system_service_no_reply",
            [step.name for step in runner.steps],
            "the timeout is recorded rather than hidden",
        )

    def test_read_raw_returns_the_frame_without_decrypting_or_routing_it(self):
        backend = self.LoopbackBackend()
        backend.connect("test-device", 1.0)
        channel = self.connect.ConnectedChannel(
            session=self.Session(backend, "test-device", timeout=0.2),
            secure=None,
            session_id=32,
            channel_id=104,
            message_provider_id=4,
            file_provider_id=5,
            device_info=None,
            bind_payload=b"",
        )
        request_body = self.connect.service_connection_request_body(
            local_agent_id=5,
            remote_agent_id=44,
            profile=self.connect.PROFILE_SYSTEM,
            channels=(
                self.connect.ChannelProposal(34, 100, 4, 3, 0),
                self.connect.ChannelProposal(35, 101, 4, 0, 0),
            ),
        )
        backend.push(self.f.encode(1, request_body))
        self.assertEqual(
            channel.read_raw(1.0),
            (1, request_body),
            "a reserved-session type-1 comes back verbatim, session and body",
        )

        long_body = request_body + bytes(400)
        for frame in self.f.split(1, long_body):
            backend.push(frame)
        self.assertEqual(
            channel.read_raw(1.0), (1, long_body), "fragments are reassembled per session"
        )

        frames = self.f.split(1, long_body)
        backend.push(frames[0])
        self.assertIsNone(
            channel.read_raw(0.1),
            "an incomplete fragment sequence is not a frame yet",
        )
        backend.push(frames[1])
        self.assertEqual(
            channel.read_raw(0.5),
            (1, long_body),
            "reassembly state survives between read_raw calls",
        )
        self.assertIsNone(channel.read_raw(0.05), "an idle link returns None, not a raise")

        parked = self.connect.ConnectedChannel(
            session=self.Session(backend, "test-device", timeout=0.2),
            secure=None,
            session_id=32,
            channel_id=104,
            message_provider_id=4,
            file_provider_id=5,
            device_info=None,
            bind_payload=b"",
            pending_frames=[(1, request_body)],
        )
        self.assertEqual(
            parked.read_raw(0.01),
            (1, request_body),
            "a frame parked during connect() is returned before any read",
        )


    def test_services_done_names_the_terminal_stage(self):
        runner, _ = self._runner(sync=True)
        self.assertEqual(
            runner._services_done,
            "system_accepted",
            "sync is only done after the system stage",
        )
        runner, _ = self._runner(sync=False)
        self.assertEqual(
            runner._services_done,
            "file_accepted",
            "a plain link is done after the file stage",
        )

    def test_capex_response_range_checks_the_system_consumer(self):
        query = self.connect.CapabilityQuery(
            3, 0, ("jg.pipe.message", "jg.pipe.file", "system:filetransfer")
        )
        for system_id, label in (
            (0, "zero"),
            (0xFF00, "the FF00 unsupported marker"),
            (0x10000, "a value wider than the field"),
        ):
            with self.subTest(case=label):
                with self.assert_raises(
                    self.connect.StageError,
                    "system consumer",
                    f"a direct capex_response_body call with system id {system_id}",
                ):
                    self.connect.capex_response_body(
                        query,
                        local_agent_id=42,
                        local_file_agent_id=43,
                        local_system_agent_id=system_id,
                        package="local.insico.test",
                        name="Test",
                    )

    def test_read_raw_survives_a_single_idle_tick(self):
        TransportError = self.TransportError
        body = b"\x2a\x00"
        payload = self.f.encode(1, body)

        class OneIdleBackend(self.LoopbackBackend):
            def __init__(self):
                super().__init__()
                self.idle = True

            def read_notification(self, timeout):
                if self.idle:
                    self.idle = False
                    raise TransportError("idle tick")
                return super().read_notification(timeout)

        backend = OneIdleBackend()
        backend.connect("test-device", 1.0)
        backend.push(payload)
        channel = self.connect.ConnectedChannel(
            session=self.Session(backend, "test-device", timeout=0.2),
            secure=None,
            session_id=32,
            channel_id=104,
            message_provider_id=4,
            file_provider_id=5,
            device_info=None,
            bind_payload=b"",
        )
        self.assertEqual(
            channel.read_raw(1.0),
            (1, body),
            "one empty notification is not the end of the wait",
        )



# ==========================================================================
# commands (business commands)
# ==========================================================================


class CommandsTests(_ProtocolTestBase):
    """Status and storage parsing, and the request builders."""

    def setUp(self) -> None:
        from aipin_sdk.protocol import commands

        self.c = commands

    # -- constants ------------------------------------------------------

    def test_service_and_command_constants(self):
        self.assertEqual(self.c.SERVICE_STATUS, (0x05, 0x02))
        self.assertEqual(self.c.SERVICE_STORAGE, (0x05, 0x04))
        self.assertEqual(self.c.SERVICE_RECORD, (0x07, 0x00))
        self.assertEqual(self.c.SERVICE_APPRECORD, (0x07, 0x02))
        self.assertEqual(self.c.STATUS_REQUEST, bytes([0x05, 0x02, 0xFF]))
        self.assertEqual(self.c.MIN_STATUS_PAYLOAD, 12)
        self.assertEqual(self.c.STATUS_REPLY_HEADER, (0x02, 0xFF))
        self.assertEqual(self.c.STORAGE_REPLY_HEADER, (0x04, 0xFF))
        self.assertNotEqual(
            self.c.STATUS_REPLY_HEADER, self.c.SERVICE_STATUS,
            "a status reply is 02/FF even though the request is 05/02",
        )
        self.assertNotEqual(
            self.c.STORAGE_REPLY_HEADER, self.c.SERVICE_STORAGE,
            "a storage reply is 04/FF even though the request is 05/04",
        )

    # -- status ---------------------------------------------------------

    def _status_reply(self, payload: bytes, header=None) -> bytes:
        """A status reply is reply-header + payload; the default is 02/FF."""
        return bytes(self.c.STATUS_REPLY_HEADER if header is None else header) + payload

    def test_status_parse_reads_every_field(self):
        timestamp = 0x0102030405060708
        payload = (
            bytes([0x02, 0x05, 87])
            + timestamp.to_bytes(8, "little")
            + bytes([0x09, 0x00, 0x01, 0x00, 0x00, 0x00])  # error, in_case, in_note, padding
        )
        self.assertGreaterEqual(
            len(payload), 16, "test setup: the case/note bytes need a 16-byte payload"
        )
        status = self.c.DeviceStatus.parse(self._status_reply(payload))

        self.assertTrue(status.recording, "a non-zero record byte means recording")
        self.assertEqual(status.record_byte, 0x02, "the raw record byte is kept")
        self.assertEqual(status.charge_byte, 0x05, "charge byte is payload 1")
        self.assertEqual(status.battery_percent, 87, "battery is payload 2")
        self.assertEqual(
            status.device_timestamp_ms, timestamp,
            "the device clock is a little-endian 8-byte millisecond counter",
        )
        self.assertEqual(status.error_byte, 0x09, "error byte is payload 11")
        self.assertEqual((status.in_case, status.in_note), (0, 1), "case/note bytes need payload >= 16")

    def test_status_recording_is_any_non_zero_byte(self):
        # The device treats the whole byte as state: testing bit 0 would read
        # state 2 as "stopped".
        for value, expected in ((0, False), (1, True), (2, True), (0x80, True), (0xFF, True)):
            with self.subTest(record_byte=value):
                payload = bytes([value, 0, 50]) + bytes(8) + bytes([0])
                status = self.c.DeviceStatus.parse(self._status_reply(payload))
                self.assertEqual(status.recording, expected, f"record byte {value} must read as {expected}")

    def test_status_extra_bytes_are_optional(self):
        payload = bytes([0x00, 0x00, 40]) + (12345).to_bytes(8, "little") + bytes([0])
        status = self.c.DeviceStatus.parse(self._status_reply(payload))
        self.assertEqual(len(payload), self.c.MIN_STATUS_PAYLOAD, "test setup: the short payload")
        self.assertIsNone(status.in_case, "in_case requires a payload of at least 16 bytes")
        self.assertIsNone(status.in_note, "in_note requires a payload of at least 16 bytes")

    def test_status_parse_rejects_short_and_wrong_header_replies(self):
        with self.assert_raises(
            self.c.ProtocolError, "shorter than its header", "a status reply of 13 bytes"
        ):
            self.c.DeviceStatus.parse(bytes([0x02, 0xFF]) + bytes(11))
        with self.assert_raises(
            self.c.ProtocolError, "status reply header is 0504", "a storage header on the status path"
        ):
            self.c.DeviceStatus.parse(bytes([0x05, 0x04]) + bytes(self.c.MIN_STATUS_PAYLOAD))

    def test_status_parse_of_synthetic_reply(self):
        # Synthetic reply with the same field layout: request 05 02 FF, response
        # header 02 FF, then record/charge/battery, clock, error and extra bytes.
        timestamp = 1792763288558
        payload = bytearray(24)
        payload[2] = 20
        payload[3:11] = timestamp.to_bytes(8, "little")
        payload[11] = 2
        reply = bytes(self.c.STATUS_REPLY_HEADER) + bytes(payload)
        status = self.c.DeviceStatus.parse(reply)

        self.assertFalse(status.recording, "record byte 0 in the synthetic reply means stopped")
        self.assertEqual(status.record_byte, 0)
        self.assertEqual(status.battery_percent, 20, "battery is payload 2; the synthetic value is 0x14")
        self.assertEqual(status.error_byte, 2, "error is payload 11; the synthetic value is 0x02")
        self.assertEqual(
            status.device_timestamp_ms, timestamp,
            "the device clock is a little-endian 8-byte millisecond counter",
        )

    def test_request_header_is_not_a_reply_header(self):
        # The device answers the 05/02 status request with an 02/FF reply, so a
        # parser that compared a reply against the request pair would reject
        # every valid answer.  Pin that the request pair is refused.
        self.assertEqual(self.c.STATUS_REQUEST[:2], bytes(self.c.SERVICE_STATUS))
        self.assertNotEqual(bytes(self.c.SERVICE_STATUS), bytes(self.c.STATUS_REPLY_HEADER))
        self.assertNotEqual(bytes(self.c.SERVICE_STORAGE), bytes(self.c.STORAGE_REPLY_HEADER))

        with self.assert_raises(
            self.c.ProtocolError,
            "status reply header is 0502",
            "a 05 02 request header used where an 02 FF status reply belongs",
        ):
            self.c.DeviceStatus.parse(bytes(self.c.SERVICE_STATUS) + bytes(self.c.MIN_STATUS_PAYLOAD))

        with self.assert_raises(
            self.c.ProtocolError,
            "storage reply header is 0504",
            "a 05 04 request header used where an 04 FF storage reply belongs",
        ):
            self.c.StorageTotals.parse(bytes(self.c.SERVICE_STORAGE) + bytes(32))

    # -- storage --------------------------------------------------------

    def test_storage_parse_reads_every_field(self):
        payload = (
            (1000).to_bytes(8, "little")
            + (2000).to_bytes(8, "little")
            + (17).to_bytes(4, "little")
            + (4_000_000).to_bytes(4, "little")
            + (3).to_bytes(4, "little")
            + (120_000).to_bytes(4, "little")
        )
        totals = self.c.StorageTotals.parse(bytes([0x04, 0xFF]) + payload)

        self.assertEqual((totals.start_ms, totals.end_ms), (1000, 2000), "the window is two LE u64s")
        self.assertEqual(totals.item_count, 17, "item count is a LE u32")
        self.assertEqual(totals.used_bytes, 4_000_000, "used bytes is a LE u32")
        self.assertEqual(totals.highlight_count, 3, "highlight count is a LE u32")
        self.assertEqual(totals.highlight_bytes, 120_000, "highlight bytes is a LE u32")

    def test_storage_parse_rejects_short_and_wrong_header_replies(self):
        with self.assert_raises(
            self.c.ProtocolError, "shorter than 34 bytes", "a 33-byte storage reply"
        ):
            self.c.StorageTotals.parse(bytes([0x04, 0xFF]) + bytes(31))
        with self.assert_raises(
            self.c.ProtocolError, "storage reply header is 0502", "a status header on the storage path"
        ):
            self.c.StorageTotals.parse(bytes([0x05, 0x02]) + bytes(32))

    # -- request builders -----------------------------------------------

    def test_record_commands(self):
        self.assertEqual(
            self.c.record_start_command(), bytes([0x07, 0x00, 0x01]), "record start enables (state 1)"
        )
        self.assertEqual(
            self.c.record_stop_command(), bytes([0x07, 0x00, 0x00]), "record stop disables (state 0)"
        )
        self.assertEqual(self.c.record_stop_command(), self.c.RECORD_STOP)

    def test_voiceprint_commands(self):
        for seconds in (1, 30, 127):
            with self.subTest(seconds=seconds):
                self.assertEqual(
                    self.c.voiceprint_start_command(seconds),
                    bytes([0x07, 0x02, seconds]),
                    "the voiceprint duration is one byte",
                )
        for bad in (0, -1, 128, 1000):
            with self.subTest(seconds=bad):
                with self.assert_raises(
                    self.c.ProtocolError, "1..127", f"a voiceprint duration of {bad}"
                ):
                    self.c.voiceprint_start_command(bad)
        self.assertEqual(self.c.voiceprint_stop_command(), bytes([0x07, 0x02, 0x00]))
        self.assertEqual(self.c.voiceprint_stop_command(), self.c.VOICEPRINT_STOP)

    def test_storage_request_layout(self):
        request = self.c.storage_request(1000, 2000)
        self.assertEqual(
            request,
            bytes([0x05, 0x04]) + (1000).to_bytes(8, "little") + (2000).to_bytes(8, "little"),
            "a storage query is service, command, start, end in little-endian",
        )

    def test_sync_request_allows_a_zero_width_range(self):
        # A past zero-width 06/00 completed with a matching authenticated 06/08
        # on the tested device. That observation does not relax 05/04, which remains
        # strictly increasing (covered by the rejection test below).
        request = self.c.sync_request(1000, 1000)
        self.assertEqual(
            request,
            bytes(self.c.SERVICE_SYNC) + (1000).to_bytes(8, "little") * 2,
        )
        self.assertEqual(self.c.sync_range_payload(1000, 1000), request[2:])

    def test_storage_request_rejects_an_empty_or_inverted_range(self):
        for label, start, end in (
            ("negative start", -1, 10),
            ("reversed range", 2000, 1000),
            ("equal bounds", 1000, 1000),
        ):
            with self.subTest(case=label):
                with self.assert_raises(
                    self.c.ProtocolError, "increasing and non-negative", f"a storage range that is {label}"
                ):
                    self.c.storage_request(start, end)

    def test_status_and_storage_replies_are_plain_dataclasses(self):
        payload = bytes([0x00, 0x00, 40]) + bytes(8) + bytes([0])
        status = self.c.DeviceStatus.parse(bytes(self.c.STATUS_REPLY_HEADER) + payload)
        with self.assertRaises(Exception):
            status.battery_percent = 1
        totals = self.c.StorageTotals.parse(bytes(self.c.STORAGE_REPLY_HEADER) + bytes(32))
        with self.assertRaises(Exception):
            totals.item_count = 1


class SecureChannelTests(unittest.TestCase):
    """The 0x04 business envelope. This module had no direct tests at all."""

    KSC = bytes(range(16))
    QCQS = bytes(range(16, 32))

    def _pair(self):
        from aipin_sdk.protocol import secure

        return (
            secure,
            secure.SecureChannel(self.KSC, self.QCQS),
            secure.SecureChannel(self.KSC, self.QCQS),
        )

    def test_round_trip(self):
        secure, host_tx, host_rx = self._pair()
        sealed = host_tx.seal(b"hello device")
        self.assertEqual(sealed[0], secure.FLAG_ENCRYPTED, "envelope starts with the 0x04 flag")
        self.assertEqual(host_rx.open(sealed), b"hello device")
        print("ok secure round trip")

    def test_counter_is_strictly_increasing_and_replay_fails_closed(self):
        secure, host_tx, host_rx = self._pair()
        sealed = host_tx.seal(b"one")
        self.assertEqual(host_rx.open(sealed), b"one")
        with self.assertRaises(secure.SecureChannelError):
            host_rx.open(sealed)
        later = host_tx.seal(b"two")
        self.assertEqual(host_rx.open(later), b"two")
        with self.assertRaises(secure.SecureChannelError):
            host_rx.open(sealed)  # an old frame can never be replayed
        print("ok secure counter is strictly increasing")

    def test_counters_only_advance_after_authentication(self):
        secure, host_tx, host_rx = self._pair()
        sealed = host_tx.seal(b"payload")
        tampered = sealed[:-1] + bytes([sealed[-1] ^ 0x01])
        before = host_rx.receive_counter
        with self.assertRaises(secure.SecureChannelError):
            host_rx.open(tampered)
        self.assertEqual(
            host_rx.receive_counter, before,
            "a forged frame must not consume the counter it named",
        )
        self.assertEqual(host_rx.open(sealed), b"payload")
        print("ok secure ignores forged frames without consuming the counter")

    def test_host_and_device_ranges_never_collide(self):
        """Both directions derive (key, nonce) from the same counter value.

        If a host frame and a device frame ever shared a counter they would
        encrypt different plaintexts under one GCM nonce. The host therefore
        starts above HOST_COUNTER_BASE, and the device's own counters stay low.
        """
        secure, host_tx, host_rx = self._pair()
        self.assertGreaterEqual(
            host_tx.send_counter + 1, secure.HOST_COUNTER_BASE,
            "the first host frame must already sit above the device's range",
        )
        first = host_tx.send_counter + 1
        self.assertGreater(
            first, 0xFFFF_FFFF,
            "an overlapping low counter is exactly the nonce reuse we must avoid",
        )
        # a device frame numbered 1 must still be accepted
        self.assertEqual(host_rx.receive_counter, 0)
        print("ok host counters are disjoint from the device range")

    def test_wrong_key_cannot_open(self):
        from aipin_sdk.protocol import secure

        sender = secure.SecureChannel(self.KSC, self.QCQS)
        receiver = secure.SecureChannel(b"\xff" * 16, self.QCQS)
        sealed = sender.seal(b"secret")
        with self.assertRaises(secure.SecureChannelError):
            receiver.open(sealed)
        print("ok secure rejects a frame sealed under another key")

    def test_rejects_bad_construction(self):
        from aipin_sdk.protocol import secure

        with self.assertRaises(secure.SecureChannelError):
            secure.SecureChannel(b"short", self.QCQS)
        with self.assertRaises(secure.SecureChannelError):
            secure.SecureChannel(self.KSC, b"short")

    def test_counter_exhaustion_is_refused(self):
        from aipin_sdk.protocol import secure

        channel = secure.SecureChannel(self.KSC, self.QCQS)
        channel.send_counter = 0xFFFF_FFFF_FFFF_FFFF - 1
        channel.seal(b"last")
        with self.assertRaises(secure.SecureChannelError):
            channel.seal(b"overflow")
        print("ok secure refuses to wrap the counter")

    def test_key_never_appears_in_repr(self):
        from aipin_sdk.protocol import auth, secure

        text = repr(secure.SecureChannel(b"\xab" * 16, self.QCQS))
        self.assertNotIn("abab", text.lower(), f"pairing key leaked in {text}")
        pairing = auth.Pairing(
            ksc=b"\xab" * 16, alias=b"A" * 6, seeker_id=b"B" * 6, provider_id=b"C" * 6
        )
        self.assertNotIn("abab", repr(pairing).lower(), "pairing key leaked in a repr")
        print("ok the pairing key stays out of reprs")


if __name__ == "__main__":
    if not _HAVE_CRYPTO:
        print(_CRYPTO_HINT, file=sys.stderr)
        print("\nAll protocol tests are being skipped.\n", file=sys.stderr)
    unittest.main(verbosity=2)
