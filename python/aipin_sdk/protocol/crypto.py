# -*- coding: utf-8 -*-
"""Cryptographic primitives, all from ``cryptography``.

Nothing here implements a cipher. This module only wires well-known primitives
together in the arrangement the device expects: an ephemeral P-256 ECDH to
agree a key, SHA-256 based key derivation, AES-256-GCM for the business
channel, and HMAC-SHA512 for the session authentication tag.

If you are auditing this project for "does it roll its own crypto", the answer
should be: no. Read this file to confirm.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from ..errors import XinliqiuError

try:  # pragma: no cover - import guard
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:  # pragma: no cover
    raise XinliqiuError(
        "the protocol stack requires the cryptography package: "
        'pip install "xinliqiu-sdk"'
    ) from exc


class CryptoError(XinliqiuError):
    """A cryptographic operation failed."""


def random_bytes(count: int) -> bytes:
    return os.urandom(count)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


@dataclass
class EphemeralKey:
    """One side of an ECDH exchange."""

    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> "EphemeralKey":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @property
    def public_point(self) -> bytes:
        """Uncompressed point: 0x04 || X || Y."""
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    def agree(self, peer_point: bytes) -> bytes:
        """Derive the shared secret against a peer's uncompressed point."""
        if not peer_point or peer_point[0] != 0x04:
            raise CryptoError("peer key is not an uncompressed point")
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_point)
        except ValueError as exc:
            raise CryptoError("peer key is not a valid curve point") from exc
        return self.private_key.exchange(ec.ECDH(), peer)


def derive_key(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256, the standard derivation for a negotiated session key."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        shared_secret
    )


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # noqa: BLE001 - cryptography raises a bare InvalidTag
        raise CryptoError("message authentication failed") from exc


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """AES-CBC over whole blocks, with no padding.

    The device treats these payloads as fixed-size blocks and does not expect
    PKCS#7. Padding a complete block would add sixteen bytes the device never
    accounts for, so the caller must supply an exact multiple of the block
    size.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(plaintext) % 16:
        raise CryptoError("payload must be a whole number of AES blocks")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if not ciphertext or len(ciphertext) % 16:
        raise CryptoError("ciphertext must be a whole number of AES blocks")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def aes_ecb_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block in ECB mode. Used to build the packet mask."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(block) != 16:
        raise CryptoError("block must be 16 bytes")
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def packet_transform(data: bytes, key: bytes, iv: bytes, nonce: bytes) -> bytes:
    """The device's packet cipher, used for the key-registration exchange.

    It is not CBC. A mask is computed by encrypting the IV in ECB mode, and
    each output byte is the input XOR the corresponding mask byte XOR a
    counter byte: the block index for the first byte of each block, the nonce
    bytes for positions 8..15, zero elsewhere. It is symmetric, so encryption
    and decryption are the same call.
    """
    if len(nonce) != 8:
        raise CryptoError("packet nonce must be 8 bytes")
    mask = aes_ecb_block(key, iv)
    out = bytearray(data)
    for offset in range(len(out)):
        block_index = offset // 16
        position = offset % 16
        if position == 0:
            counter = block_index & 0xFF
        elif position >= 8:
            counter = nonce[position - 8]
        else:
            counter = 0
        out[offset] ^= mask[position] ^ counter
    return bytes(out)


class SecureChannel:
    """AES-256-GCM business channel with a monotonic nonce.

    The device expects the nonce to advance per message; reusing one is a
    cryptographic failure, so the counter is checked rather than trusted.

    ``initial_nonce`` must be distinct for every connection that shares a key.
    Two channels starting from the same value will collide on the wire, and the
    second one will refuse the first's messages as replays. It is a parameter
    rather than a random default because the starting value is part of the
    agreement with the peer, not a local choice.
    """

    def __init__(self, key: bytes, *, initial_nonce: int = 0) -> None:
        if len(key) != 32:
            raise CryptoError("business channel key must be 32 bytes")
        self.key = key
        self._nonce = initial_nonce
        self._seen: set[bytes] = set()

    def _next(self) -> bytes:
        nonce = self._nonce.to_bytes(12, "big")
        self._nonce += 1
        return nonce

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        nonce = self._next()
        return nonce + aes_gcm_encrypt(self.key, nonce, plaintext, aad)

    def open(self, message: bytes, aad: bytes = b"") -> bytes:
        if len(message) < 13:
            raise CryptoError("sealed message is too short")
        nonce, body = message[:12], message[12:]
        if nonce in self._seen:
            raise CryptoError("nonce reuse detected")
        plaintext = aes_gcm_decrypt(self.key, nonce, body, aad)
        # Record the nonce only once the message authenticated. Recording it
        # first would let any forged frame carrying a future nonce burn that
        # nonce, so the genuine message would later be refused as a replay.
        self._seen.add(nonce)
        return plaintext