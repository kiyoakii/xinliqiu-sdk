# -*- coding: utf-8 -*-
"""The business channel's confidentiality layer.

Every frame is keyed from the pairing secret and the two authentication
challenges, so no session key is ever transmitted::

    frame = 0x04 | counter:u64 big-endian | ciphertext | tag(16)

    digest = HMAC-SHA512(KSC, qc || qs || counter:u64 big-endian)
    aes key = digest[0:16]      (AES-128)
    nonce   = digest[16:28]
    aad     = digest[28:48]

Both directions derive from the same material but keep independent counters.
The receive counter must strictly increase; a frame that does not is rejected
rather than decrypted, which is what makes replay impossible.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import XinliqiuError
from . import crypto

FLAG_ENCRYPTED = 0x04
TAG_BYTES = 16
COUNTER_BYTES = 8
CHALLENGE_BYTES = 16

# The device derives the AES-GCM key, nonce and AAD from (ksc, qcqs, counter)
# with no direction input, so a host frame and a device frame carrying the same
# counter would encrypt different plaintexts under one GCM nonce. That is the
# one failure mode AES-GCM does not survive. The device accepts any strictly
# increasing counter, so the host keeps its whole range above this base and the
# two directions can never collide. Verified against hardware: a first frame
# at 2**63 is accepted and answered normally.
HOST_COUNTER_BASE = 1 << 63


class SecureChannelError(XinliqiuError):
    """A secure frame could not be sealed or opened."""


@dataclass
class SecureChannel:
    """AES-128-GCM channel derived from the pairing key.

    ``qcqs`` is the client challenge followed by the server challenge, 16 bytes
    in total. Both sides must agree on it; using a different value produces
    frames the peer cannot open, which surfaces as an authentication failure
    rather than a decryption error.
    """

    ksc: bytes = field(repr=False)
    qcqs: bytes
    send_counter: int = HOST_COUNTER_BASE - 1
    receive_counter: int = 0

    def __post_init__(self) -> None:
        if len(self.ksc) != 16:
            raise SecureChannelError("the pairing key must be 16 bytes")
        if len(self.qcqs) != CHALLENGE_BYTES:
            raise SecureChannelError("the challenge transcript must be 16 bytes")

    def _material(self, counter: int) -> bytes:
        return crypto.hmac_sha512(
            self.ksc, self.qcqs + counter.to_bytes(COUNTER_BYTES, "big")
        )

    def seal(self, plaintext: bytes) -> bytes:
        """Encrypt one payload, advancing the send counter."""
        if self.send_counter >= 0xFFFF_FFFF_FFFF_FFFF:
            raise SecureChannelError("send counter exhausted")
        self.send_counter += 1
        digest = self._material(self.send_counter)
        sealed = crypto.aes_gcm_encrypt(
            digest[0:16], digest[16:28], plaintext, aad=digest[28:48]
        )
        # aes_gcm_encrypt returns ciphertext || tag.
        return (
            bytes([FLAG_ENCRYPTED])
            + self.send_counter.to_bytes(COUNTER_BYTES, "big")
            + sealed
        )

    def open(self, payload: bytes) -> bytes:
        """Decrypt one payload, enforcing a strictly increasing counter."""
        if not payload:
            raise SecureChannelError("empty secure frame")
        if payload[0] != FLAG_ENCRYPTED:
            raise SecureChannelError(
                f"expected flag 0x04, got 0x{payload[0]:02x}"
            )
        if len(payload) < 1 + COUNTER_BYTES + TAG_BYTES:
            raise SecureChannelError("frame is shorter than flag, counter and tag")

        counter = int.from_bytes(payload[1 : 1 + COUNTER_BYTES], "big")
        if counter <= self.receive_counter:
            raise SecureChannelError(
                f"counter {counter} does not exceed the last seen {self.receive_counter}"
            )

        body = payload[1 + COUNTER_BYTES :]
        digest = self._material(counter)
        try:
            plaintext = crypto.aes_gcm_decrypt(
                digest[0:16], digest[16:28], body, aad=digest[28:48]
            )
        except crypto.CryptoError as exc:
            raise SecureChannelError(
                "frame failed authentication; the pairing or transcript is wrong"
            ) from exc

        self.receive_counter = counter
        return plaintext