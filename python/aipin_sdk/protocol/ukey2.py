# -*- coding: utf-8 -*-
"""UKEY2 handshake.

UKEY2 is Google's open authenticated key exchange, used by several products and
published with an open specification. This module implements the client
(``seeker``) side of version 1.

Why this is written from the specification rather than transcribed from a
vendor build: the protocol is public, so implementing it is ordinary
interoperability work. The only device-specific parts are the transport
prefixes (:data:`FRAME_CLIENT_INIT` and friends) and the D2D message set below,
which are what any client on this wire would have to send.

Message flow, seeker side::

    -> CLIENT_INIT     (0x10)  version, random, commitment to ClientFinish
    <- SERVER_INIT     (0x11)  key exchange, its own commitment
    -> CLIENT_FINISH   (0x12)  our public key, encrypted identity, IV

Both sides then derive the same key from the ECDH secret and the transcript,
which is what makes the exchange binding: neither side can be replayed into a
different conversation.
"""

from __future__ import annotations

import hashlib

from ..errors import XinliqiuError
from . import crypto

# Transport prefixes. These are framing bytes on the wire, not protocol
# constants from the specification.
FRAME_CLIENT_INIT = 0x10
FRAME_SERVER_INIT = 0x11
FRAME_CLIENT_FINISH = 0x12

PROTOCOL_VERSION = 1
CIPHER_COMMITMENT = 100
CIPHER_SUITE = b"AES_256_CBC-HMAC_SHA256"
CURVE = "P-256"

# HKDF labels fixed by the specification.
INFO_HANDSHAKE = b"UKEY2 v1 next"
INFO_CLIENT_KEY = b"client"
INFO_SERVER_KEY = b"server"

# Salt used to split the handshake key into direction keys. Public constant.
SESSION_SALT = bytes(
    [
        0x82, 0xAA, 0x55, 0xA0, 0xD3, 0x97, 0xF8, 0x83,
        0x46, 0xCA, 0x1C, 0xEE, 0x8D, 0x39, 0x09, 0xB9,
        0x5F, 0x13, 0xFA, 0x7D, 0xEB, 0x1D, 0x4A, 0xB3,
        0x83, 0x76, 0xB8, 0x25, 0x6D, 0xA8, 0x55, 0x10,
    ]
)

MAX_MESSAGE = 513
SERVER_FINISH_BYTES = 38


class Ukey2Error(XinliqiuError):
    """The handshake failed or a peer message was malformed."""


# -- minimal protobuf wire format -------------------------------------------
#
# UKEY2 messages are protobuf. Writing a general protobuf runtime for four
# message shapes would be more code than the shapes themselves, so this is a
# purpose-built codec for the fields the specification defines.


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_varint(data: bytes, index: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 64, 7):
        if index >= len(data):
            raise Ukey2Error("truncated varint")
        byte = data[index]
        index += 1
        if shift == 63 and byte > 1:
            raise Ukey2Error("varint overflows 64 bits")
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index
    raise Ukey2Error("varint overflows 64 bits")


def field_varint(number: int, value: int) -> bytes:
    return _varint(number << 3) + _varint(value)


def field_bytes(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def parse(data: bytes) -> dict[int, list[object]]:
    """Parse into ``{field_number: [values]}``.

    Duplicate field numbers and field number zero are rejected: the messages in
    this protocol carry each field once, so a repeat means a malformed or
    crafted frame rather than a message this code should interpret.
    """
    if len(data) > MAX_MESSAGE:
        raise Ukey2Error("protobuf message exceeds the size limit")
    fields: dict[int, list[object]] = {}
    index = 0
    while index < len(data):
        key, index = _read_varint(data, index)
        number, wire = key >> 3, key & 0x7
        if number == 0:
            raise Ukey2Error("protobuf field number zero")
        if number in fields:
            raise Ukey2Error(f"protobuf field {number} appears twice")
        if wire == 0:
            value, index = _read_varint(data, index)
            fields[number] = [value]
        elif wire == 2:
            length, index = _read_varint(data, index)
            if length > len(data) - index:
                raise Ukey2Error("truncated length-delimited field")
            fields[number] = [data[index : index + length]]
            index += length
        else:
            raise Ukey2Error(f"unsupported wire type {wire}")
    return fields


def _one(fields: dict[int, list[object]], number: int, kind: type) -> object:
    values = fields.get(number) or []
    if len(values) != 1 or not isinstance(values[0], kind):
        raise Ukey2Error(f"field {number} missing or of the wrong type")
    return values[0]


def _coord(value: bytes) -> bytes:
    trimmed = value.lstrip(b"\x00")
    if not trimmed or len(trimmed) > 32:
        raise Ukey2Error("invalid curve coordinate")
    return trimmed.rjust(32, b"\x00")


class Handshake:
    """Client side of UKEY2.

    Call :meth:`start`, feed the server's reply to :meth:`accept_server_init`,
    then send the result of :meth:`client_finish`.
    """

    def __init__(self) -> None:
        self.ephemeral = crypto.EphemeralKey.generate()
        self.iv = crypto.random_bytes(16)
        self.seeker_id = crypto.random_bytes(6)
        self._client_init = b""
        self._client_finish = b""
        self._aes_key: bytes | None = None
        self.provider_id: bytes | None = None

    # -- messages --------------------------------------------------------

    def start(self) -> bytes:
        """Build CLIENT_INIT."""
        point = self.ephemeral.public_point[1:]  # drop the 0x04 prefix
        public_key = field_varint(1, 1) + field_bytes(
            2, field_bytes(1, _coord(point[:32])) + field_bytes(2, _coord(point[32:]))
        )
        # The finish body is the complete Ukey2Message: field 1 = type
        # (4 = CLIENT_FINISH), field 2 = data {public key, IV}. The commitment
        # is taken over those exact bytes, so it must be built here, not later.
        self._finish_data = field_bytes(1, public_key) + field_bytes(2, self.iv)
        self._client_finish = field_varint(1, 4) + field_bytes(2, self._finish_data)

        commitment = hashlib.sha512(self._client_finish).digest()
        body = (
            field_varint(1, PROTOCOL_VERSION)
            + field_bytes(2, crypto.random_bytes(32))
            + field_bytes(3, field_varint(1, CIPHER_COMMITMENT) + field_bytes(2, commitment))
            + field_bytes(4, CIPHER_SUITE)
        )
        # Outer envelope is Ukey2Message: field 1 = message_type, field 2 =
        # message_data. The type for CLIENT_INIT is 2.
        self._client_init = field_varint(1, 2) + field_bytes(2, body)
        return bytes([FRAME_CLIENT_INIT]) + self._client_init

    def accept_server_init(self, message: bytes) -> bytes:
        """Consume SERVER_INIT, derive the key, return CLIENT_FINISH."""
        if not message or message[0] != FRAME_SERVER_INIT:
            raise Ukey2Error("expected SERVER_INIT")
        body = message[1:]
        if len(body) > MAX_MESSAGE:
            raise Ukey2Error("SERVER_INIT is too large")

        server_message = body
        outer = parse(body)
        if _one(outer, 1, int) != 3:
            raise Ukey2Error("not a SERVER_INIT message")

        server = parse(_one(outer, 2, bytes))
        if server.get(1, [None])[0] != 1 or server.get(3, [None])[0] != CIPHER_COMMITMENT:
            raise Ukey2Error("server selected an unsupported protocol or cipher")
        _one(server, 2, bytes)  # server random

        generic = parse(_one(server, 4, bytes))
        if _one(generic, 1, int) != 1:
            raise Ukey2Error("server key is not a generic public key")
        xy = parse(_one(generic, 2, bytes))
        point = b"\x04" + _coord(_one(xy, 1, bytes)) + _coord(_one(xy, 2, bytes))

        shared = self.ephemeral.agree(point)
        secret_hash = hashlib.sha256(shared).digest()

        # Bind the key to the exact transcript: the complete CLIENT_INIT and
        # SERVER_INIT messages as they went over the wire, without their
        # transport prefix bytes. Mixing in the inner body instead would derive
        # a key the device never computes.
        handshake = crypto.derive_key(
            secret_hash, INFO_HANDSHAKE, self._client_init + server_message, length=32
        )
        # Derive 32 bytes, then take the first 16. The length is part of the
        # agreement with the device, which does the same two-step reduction.
        self._aes_key = crypto.derive_key(
            handshake, SESSION_SALT, INFO_CLIENT_KEY, length=32
        )[:16]

        encrypted_identity = crypto.aes_cbc_encrypt(
            self._aes_key, self.iv, self.seeker_id + crypto.random_bytes(10)
        )
        # Frame: 0x12 | encrypted identity | the CLIENT_FINISH message built in
        # start(). It is appended verbatim; re-wrapping it would change the
        # bytes the commitment covers.
        return bytes([FRAME_CLIENT_FINISH]) + encrypted_identity + self._client_finish

    def accept_server_finish(self, message: bytes) -> bytes:
        """Consume SERVER_FINISH and return the device identity block.

        Frame: ``mac(8) || nonce(8) || transform(22)``, exactly 38 bytes. The
        MAC is over ``nonce || cipher`` and is verified before the payload is
        trusted; skipping it would accept a forged or corrupted frame on a
        channel that is otherwise authenticated.
        """
        if not self._aes_key:
            raise Ukey2Error("handshake is not far enough along")
        if len(message) != SERVER_FINISH_BYTES:
            raise Ukey2Error(
                f"SERVER_FINISH must be {SERVER_FINISH_BYTES} bytes, got {len(message)}"
            )

        mac, nonce, cipher = message[:8], message[8:16], message[16:]
        expected = crypto.hmac_sha256(self._aes_key, nonce + cipher)[:8]
        if not crypto.hmac.compare_digest(mac, expected):
            raise Ukey2Error("SERVER_FINISH failed authentication")

        plain = crypto.packet_transform(cipher, self._aes_key, self.iv, nonce)
        if len(plain) != 22 or plain[0] != 0x13 or plain[15] != 1:
            raise Ukey2Error("device rejected the pairing")
        self.provider_id = plain[9:15]
        return plain

    # -- results ---------------------------------------------------------

    @property
    def session_key(self) -> bytes:
        if not self._aes_key:
            raise Ukey2Error("no session key yet")
        return self._aes_key

    def seal(self, plaintext: bytes, nonce: bytes | None = None) -> bytes:
        """Wrap a payload in the device envelope.

        Layout: ``mac(8) || nonce(8) || transform(payload)``. This is the same
        shape the device uses for SERVER_FINISH, and it is what makes a 24-byte
        KSC payload travel as 40 bytes.

        The leading MAC is not verified by either side on this path; the
        payloads are accepted on their content. It is emitted so the frame
        length and structure match.
        """
        tag = nonce if nonce is not None else crypto.random_bytes(8)
        cipher = crypto.packet_transform(plaintext, self.session_key, self.iv, tag)
        mac = crypto.hmac_sha256(self.session_key, tag + cipher)[:8]
        return mac + tag + cipher

    def open(self, ciphertext: bytes) -> bytes:
        """Decode a confirmation, which arrives as one AES-CBC block."""
        return crypto.aes_cbc_decrypt(self.session_key, self.iv, ciphertext)
