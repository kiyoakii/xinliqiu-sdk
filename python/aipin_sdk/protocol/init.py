# -*- coding: utf-8 -*-
"""Local on-device INIT: format and install an owner public key.

This module builds the slot-1 INIT supported by this implementation after the
device advertises a bind challenge. It is pure formatting plus a signature seam:
no Bluetooth, no network, no file writes, and no credential store. The PKCS#8
signer reads an external path supplied by the caller; no key material is embedded
here.

Wire shapes (the tested slot-1 INIT contract)::

    bind challenge, payload after 02 0d
        version=1 | nonce[16] | deviceId[12] | ttl:u32 LE | keySlot:u8

    token TBS
        01 | keySlot | op=01 | deviceId[12] | nonce[16] | expiry:i64 LE
           | accountLen:u8 | accountUtf8 | publicKeyVersion:u8 | keyHash[32]

    token
        TBS || raw P-256 r||s (64 bytes)

    INIT type 1, payload after 02 08
        01 | timestampMs:i64 LE | accountLen:u8 | accountUtf8
           | publicKeyVersion:u8 | publicKeyLen:u16 LE | publicKeyUtf8
           | tokenLen:u16 LE | token

    INIT success response, payload after 02 08
        status=1 | rtcMs:i64 LE | accountLen:u8 | accountUtf8
                 [| publicKeyVersion:u8 | publicKeyLen:u16 LE | publicKeyUtf8]

Two details are easy to get wrong and follow the tested INIT contract:

* ``keyHash`` is SHA-256 of the exact owner-public-key **text** (canonical
  base64 UTF-8), not SHA-256 of the SPKI DER bytes. The tested contract and
  its self-check both say so; a DER digest produces a token the device rejects.
* This implementation supports local INIT only for ``keySlot=1``. Other slots
  are rejected rather than approximated locally.

The response parser follows the reviewed builder: a success status is accepted
on an exact account match, and a key readback shorter than three bytes is
treated as absent. A mismatched optional key readback is reported through
``public_key_matched`` but does not by itself flip ``accepted``.

RSA key validation is implemented here rather than delegated so a malformed
owner SPKI is refused with a specific reason.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import stat as stat_module
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..errors import XinliqiuError

try:  # pragma: no cover - import guard, exercised only without the extra
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
except ImportError as _crypto_import_error:
    _CRYPTO_IMPORT_ERROR: Exception | None = _crypto_import_error
    UnsupportedAlgorithm = None  # type: ignore[assignment]
    hashes = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]
    ec = None  # type: ignore[assignment]
    decode_dss_signature = None  # type: ignore[assignment]
else:
    _CRYPTO_IMPORT_ERROR = None


# -- wire constants ---------------------------------------------------------

BIND_CHALLENGE_BYTES = 34
INIT_SERVICE = 0x02
INIT_COMMAND = 0x08
INIT_TYPE = 1
TOKEN_VERSION = 1
BIND_OPERATION = 1
LOCAL_KEY_SLOT = 1
TOKEN_SIGNATURE_BYTES = 64
TOKEN_EXPIRY_SECONDS = 300
MAX_ACCOUNT_BYTES = 127
MAX_PUBLIC_KEY_BYTES = 0xFFFF
MAX_TOKEN_BYTES = 0xFFFF
MAX_OWNER_KEY_TEXT_BYTES = 493
MAX_SIGNER_FILE_BYTES = 1024 * 1024

_RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")
_I64_MAX = (1 << 63) - 1
_U32_MAX = (1 << 32) - 1


class InitError(XinliqiuError):
    """A local INIT challenge, payload, response or signer was rejected."""


# -- 02/0d challenge --------------------------------------------------------


@dataclass(frozen=True)
class BindChallenge:
    """The fixed part of a ``02 0d`` bind challenge.

    ``trailing`` keeps any bytes the device sent after the reviewed 34-byte
    payload so the caller can log or ignore them without silently losing
    framing information.
    """

    version: int
    nonce: bytes
    device_id: bytes
    ttl_ms: int
    key_slot: int
    trailing: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.nonce, (bytes, bytearray, memoryview)):
            raise InitError("bind challenge nonce must be bytes")
        if not isinstance(self.device_id, (bytes, bytearray, memoryview)):
            raise InitError("bind challenge device id must be bytes")
        if not isinstance(self.trailing, (bytes, bytearray, memoryview)):
            raise InitError("bind challenge trailing bytes must be bytes")
        object.__setattr__(self, "nonce", bytes(self.nonce))
        object.__setattr__(self, "device_id", bytes(self.device_id))
        object.__setattr__(self, "trailing", bytes(self.trailing))
        if len(self.nonce) != 16 or len(self.device_id) != 12:
            raise InitError("bind challenge fixed-field length mismatch")
        if not 0 <= self.version <= 0xFF or not 0 <= self.key_slot <= 0xFF:
            raise InitError("bind challenge version/keySlot must be one byte")
        if not 0 < self.ttl_ms <= _U32_MAX:
            raise InitError("bind challenge TTL must be 1...4294967295 ms")

    def require_local_slot_one(self) -> None:
        """Reject slots other than the slot-1 INIT this implementation supports."""
        if self.key_slot != LOCAL_KEY_SLOT:
            raise InitError(
                f"bind challenge keySlot={self.key_slot}; this implementation "
                "supports local INIT only for keySlot=1"
            )

    def require_fresh(self, received_at: float, now: float | None = None) -> None:
        """Reject a challenge outside its own advertised TTL.

        Both values are seconds from the same clock (``time.monotonic()`` is a
        good choice). They are not wall-clock timestamps: the device's TTL is a
        duration, and a wall clock jump must not extend or shorten it.
        """
        current = time.monotonic() if now is None else now
        age_ms = (current - received_at) * 1000.0
        if age_ms < 0 or age_ms >= self.ttl_ms:
            raise InitError("bind challenge is outside its advertised TTL")


def parse_bind_challenge(payload: bytes) -> BindChallenge:
    """Parse the payload that follows ``02 0d`` on the bind channel.

    The parser performs the tested validation (version 1, at least 34
    bytes, non-zero TTL) and then enforces this implementation's local-signing
    branch: only ``keySlot=1`` is accepted. Other slots raise :class:`InitError`
    instead of being approximated locally.
    """
    raw = _as_bytes(payload, "bind challenge payload")
    if len(raw) < BIND_CHALLENGE_BYTES:
        raise InitError(
            f"bind challenge is shorter than {BIND_CHALLENGE_BYTES} bytes "
            f"(got {len(raw)})"
        )
    if raw[0] != 1:
        raise InitError(f"bind challenge version is not 1 (got {raw[0]})")
    challenge = BindChallenge(
        version=raw[0],
        nonce=raw[1:17],
        device_id=raw[17:29],
        ttl_ms=int.from_bytes(raw[29:33], "little"),
        key_slot=raw[33],
        trailing=raw[BIND_CHALLENGE_BYTES:],
    )
    challenge.require_local_slot_one()
    return challenge


# -- owner public key -------------------------------------------------------


@dataclass(frozen=True)
class OwnerPublicKey:
    """A validated canonical-base64 RSA-2048 SPKI owner public key.

    ``key_hash`` is SHA-256 of ``text.encode("utf-8")``. That is the value the
    v9.d TBS carries: the exact text bytes, not the DER bytes. ``spki_der`` is
    retained because callers often also need to show or pin the key itself.
    """

    text: str
    utf8: bytes = field(init=False)
    spki_der: bytes = field(init=False)
    key_hash: bytes = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise InitError("owner public key text must be a string")
        der = _decode_canonical_spki_text(self.text)
        object.__setattr__(self, "utf8", self.text.encode("utf-8"))
        object.__setattr__(self, "spki_der", der)
        object.__setattr__(self, "key_hash", hashlib.sha256(self.utf8).digest())

    @classmethod
    def from_file(cls, path: str | Path) -> "OwnerPublicKey":
        """Read the exact single-line base64 text from an absolute path."""
        raw = _read_absolute_file(
            path, max_bytes=MAX_OWNER_KEY_TEXT_BYTES, label="owner public key"
        )
        if b"\n" in raw or b"\r" in raw or b" " in raw:
            raise InitError(
                "owner public key file must be exact UTF-8 without whitespace"
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InitError("owner public key file must be UTF-8") from exc
        return cls(text)

    @property
    def fingerprint(self) -> str:
        """Lower-case hex of the v9.d key hash (over the text bytes)."""
        return self.key_hash.hex()


def owner_key_hash(text: str) -> bytes:
    """Return the 32-byte v9.d key hash for canonical owner-key text.

    The tested contract hashes the exact UTF-8 text (canonical base64 SPKI), not the
    decoded SPKI DER. This helper makes that explicit at the call site instead
    of leaving a caller to guess which of the two digests the TBS wants.
    """
    if not isinstance(text, str):
        raise InitError("owner public key text must be a string")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InitError("owner public key text is not UTF-8") from exc
    return hashlib.sha256(encoded).digest()


def _decode_canonical_spki_text(text: str) -> bytes:
    if not text:
        raise InitError("owner public key text is empty")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - str always encodes
        raise InitError("owner public key text is not UTF-8") from exc
    if len(encoded) > MAX_OWNER_KEY_TEXT_BYTES:
        raise InitError(
            f"owner public key text is longer than {MAX_OWNER_KEY_TEXT_BYTES} bytes"
        )
    if any(byte >= 0x80 for byte in encoded):
        raise InitError("owner public key must be canonical single-line base64")
    if len(text) % 4 != 0 or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) is None:
        raise InitError("owner public key must be canonical single-line base64")
    try:
        der = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InitError("owner public key base64 is not canonical") from exc
    if base64.b64encode(der).decode("ascii") != text:
        raise InitError("owner public key base64 is not canonical")
    _require_rsa2048_spki(der)
    return der


def _der_read(data: bytes, offset: int) -> tuple[int, int, int]:
    """Read one DER TLV, returning ``(tag, content_offset, end_offset)``."""
    if offset + 2 > len(data):
        raise InitError("owner key DER is truncated")
    tag = data[offset]
    first = data[offset + 1]
    length = first
    cursor = offset + 2
    if first & 0x80:
        count = first & 0x7F
        if count < 1 or count > 3 or cursor + count > len(data):
            raise InitError("owner key DER has an invalid length")
        length = 0
        for _ in range(count):
            length = (length << 8) | data[cursor]
            cursor += 1
    if cursor + length > len(data):
        raise InitError("owner key DER value exceeds the buffer")
    return tag, cursor, cursor + length


def _require_rsa2048_spki(der: bytes) -> None:
    """Require one RSA-2048 SubjectPublicKeyInfo, matching the tested contract."""
    outer = _der_read(der, 0)
    if outer[0] != 0x30 or outer[2] != len(der):
        raise InitError("owner key is not one DER SEQUENCE")

    algorithm = _der_read(der, outer[1])
    if algorithm[0] != 0x30 or algorithm[1] >= algorithm[2]:
        raise InitError("owner key algorithm is not a SEQUENCE")

    oid = _der_read(der, algorithm[1])
    if oid[0] != 0x06 or der[oid[1]:oid[2]] != _RSA_ENCRYPTION_OID or oid[2] > algorithm[2]:
        raise InitError("owner key is not RSA SPKI")

    bit_string = _der_read(der, algorithm[2])
    if (
        bit_string[0] != 0x03
        or bit_string[1] >= bit_string[2]
        or der[bit_string[1]] != 0
        or bit_string[2] != outer[2]
    ):
        raise InitError("owner RSA SPKI BIT STRING is malformed")

    rsa = _der_read(der, bit_string[1] + 1)
    if rsa[0] != 0x30 or rsa[2] != bit_string[2]:
        raise InitError("owner RSAPublicKey is not one SEQUENCE")

    modulus = _der_read(der, rsa[1])
    if modulus[0] != 0x02 or modulus[1] >= modulus[2]:
        raise InitError("owner RSA modulus is missing")
    n = bytearray(der[modulus[1]:modulus[2]])
    while len(n) > 1 and n[0] == 0:
        del n[0]
    if len(n) != 256 or n[0] & 0x80 == 0:
        raise InitError("owner RSA modulus is not 2048 bits")

    exponent = _der_read(der, modulus[2])
    if (
        exponent[0] != 0x02
        or exponent[2] != rsa[2]
        or exponent[1] >= exponent[2]
        or der[exponent[1]] & 0x80
    ):
        raise InitError("owner RSA exponent is malformed")
    e = 0
    for byte in der[exponent[1]:exponent[2]]:
        e = (e << 8) | byte
        if e > 0x7FFF_FFFF:
            raise InitError("owner RSA exponent is too large")
    if e < 3 or (e & 1) == 0:
        raise InitError("owner RSA exponent is not odd")


# -- signing seam -----------------------------------------------------------


@runtime_checkable
class Signer(Protocol):
    """The caller-supplied P-256 signing identity for the TBS.

    ``sign`` returns the raw 64-byte ``r || s`` form, not DER. ``public_key_sha256_hex``
    is the tested public fingerprint: lower-case SHA-256 of the 65-byte
    uncompressed point ``04 || X || Y``, not the owner key hash.
    """

    public_key_sha256_hex: str

    def sign(self, tbs: bytes) -> bytes:
        """Return a raw 64-byte P-256 signature over ``tbs``."""


class Pkcs8Signer:
    """Sign with a P-256 private key loaded from an external PKCS#8 file.

    The file may be PEM (``-----BEGIN PRIVATE KEY-----``) or DER. It must be
    unencrypted: there is deliberately no password parameter, so a caller
    cannot accidentally pass a secret through this API. The path must be
    absolute and is read once; nothing is written.
    """

    def __init__(self, path: str | Path) -> None:
        _require_crypto()
        raw = _read_absolute_file(
            path, max_bytes=MAX_SIGNER_FILE_BYTES, label="signing key"
        )
        try:
            if raw.lstrip().startswith(b"-----BEGIN"):
                key = serialization.load_pem_private_key(raw, password=None)
            else:
                key = serialization.load_der_private_key(raw, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise InitError(
                "signing key is not an unencrypted P-256 PKCS#8 key"
            ) from exc
        self._key = _require_p256_private_key(key)
        self.public_key_sha256_hex = _p256_public_fingerprint(self._key.public_key())

    def sign(self, tbs: bytes) -> bytes:
        return _p256_raw_signature(self._key, _as_bytes(tbs, "TBS"))

    def __repr__(self) -> str:
        return f"Pkcs8Signer(public_key_sha256_hex={self.public_key_sha256_hex!r})"


def _require_crypto() -> None:
    if _CRYPTO_IMPORT_ERROR is not None:
        raise InitError(
            "INIT signing requires the cryptography package: "
            'pip install "xinliqiu-sdk"'
        ) from _CRYPTO_IMPORT_ERROR


def _require_p256_private_key(key, label: str = "signing key"):
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise InitError(f"{label} is not a P-256 PKCS#8 key")
    return key


def _p256_public_fingerprint(public_key) -> str:
    point = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return hashlib.sha256(point).hexdigest()


def _p256_raw_signature(private_key, tbs: bytes) -> bytes:
    der = private_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    if len(raw) != TOKEN_SIGNATURE_BYTES:  # pragma: no cover - fixed-size curve
        raise InitError("P-256 signature is not raw 64 bytes")
    return raw


# -- token and INIT builders ------------------------------------------------


def token_expiry_seconds(timestamp_ms: int) -> int:
    """The tested token expiry: ``timestamp_ms / 1000 + 300`` seconds."""
    _check_i64(timestamp_ms, "timestamp")
    expiry = timestamp_ms // 1000 + TOKEN_EXPIRY_SECONDS
    _check_i64(expiry, "token expiry")
    return expiry


def build_tbs(
    challenge: BindChallenge,
    *,
    account: str | bytes,
    key_hash: bytes,
    public_key_version: int,
    expiry_seconds: int,
) -> bytes:
    """Build the exact bytes the P-256 signer signs.

    ``key_hash`` must be the 32-byte :func:`owner_key_hash` value (SHA-256 of
    the owner-key text), not a DER digest.
    """
    challenge.require_local_slot_one()
    account_bytes = _account_bytes(account)
    key_hash_bytes = _key_hash_bytes(key_hash)
    _check_u8(public_key_version, "public key version")
    _check_i64(expiry_seconds, "token expiry")

    tbs = bytearray()
    tbs.append(TOKEN_VERSION)
    tbs.append(challenge.key_slot)
    tbs.append(BIND_OPERATION)
    tbs += challenge.device_id
    tbs += challenge.nonce
    tbs += expiry_seconds.to_bytes(8, "little", signed=False)
    tbs.append(len(account_bytes))
    tbs += account_bytes
    tbs.append(public_key_version)
    tbs += key_hash_bytes
    return bytes(tbs)


def build_token(
    challenge: BindChallenge,
    *,
    account: str | bytes,
    key_hash: bytes,
    public_key_version: int,
    signer: Signer,
    expiry_seconds: int,
) -> bytes:
    """Build ``TBS || raw P-256 r||s`` with a caller-supplied signer."""
    tbs = build_tbs(
        challenge,
        account=account,
        key_hash=key_hash,
        public_key_version=public_key_version,
        expiry_seconds=expiry_seconds,
    )
    signature = _as_bytes(signer.sign(tbs), "P-256 signature")
    if len(signature) != TOKEN_SIGNATURE_BYTES:
        raise InitError(
            f"P-256 signature is not raw {TOKEN_SIGNATURE_BYTES} bytes "
            f"(got {len(signature)})"
        )
    token = tbs + signature
    if len(token) > MAX_TOKEN_BYTES:
        raise InitError("token exceeds the u16 length")
    return token


def build_init_payload(
    *,
    timestamp_ms: int,
    account: str | bytes,
    public_key_version: int,
    public_key: str | bytes,
    token: bytes,
) -> bytes:
    """Build the INIT type-1 payload that follows ``02 08``.

    The caller wraps the result in the business frame; this function never
    emits the header itself.
    """
    _check_i64(timestamp_ms, "timestamp")
    account_bytes = _account_bytes(account)
    _check_u8(public_key_version, "public key version")
    key_bytes = _public_key_bytes(public_key)
    token_bytes = _as_bytes(token, "token")
    if not 1 <= len(token_bytes) <= MAX_TOKEN_BYTES:
        raise InitError(f"token length must be 1...{MAX_TOKEN_BYTES}")

    payload = bytearray()
    payload.append(INIT_TYPE)
    payload += timestamp_ms.to_bytes(8, "little", signed=False)
    payload.append(len(account_bytes))
    payload += account_bytes
    payload.append(public_key_version)
    payload += len(key_bytes).to_bytes(2, "little")
    payload += key_bytes
    payload += len(token_bytes).to_bytes(2, "little")
    payload += token_bytes
    return bytes(payload)


# -- 02/08 response ---------------------------------------------------------


@dataclass(frozen=True)
class InitResponse:
    """A parsed INIT ack, including the optional public-key readback."""

    status: int
    timestamp_ms: int | None
    account: bytes | None
    account_matched: bool
    public_key_version: int | None
    public_key_matched: bool | None
    trailing_bytes: int

    @property
    def accepted(self) -> bool:
        """The reviewed rule: status 1 and an exact account match.

        The optional key readback is diagnostic. The tested contract does not flip
        acceptance on it, so neither does this property; callers that require a
        readback should also check ``public_key_matched is True``.
        """
        return self.status == 1 and self.account_matched


def parse_init_response(
    response: bytes,
    *,
    expected_account: str | bytes,
    expected_public_key: str | bytes | None = None,
    expected_public_key_version: int | None = None,
    framed: bool = True,
) -> InitResponse:
    """Parse an INIT ``02 08`` response.

    With ``framed=True`` (the tested shape) ``response`` starts with
    ``02 08``. Pass ``framed=False`` when the caller already stripped the
    service/command bytes and holds only the payload.

    ``expected_public_key`` is the owner-key text the device was asked to
    install. If it (or the expected version) is omitted, a present readback is
    reported with ``public_key_matched=None`` instead of being guessed.
    """
    raw = _as_bytes(response, "INIT response")
    account_expected = _account_bytes(expected_account)
    key_expected: bytes | None = None
    if expected_public_key is not None:
        key_expected = _public_key_bytes(expected_public_key)
    if expected_public_key_version is not None:
        _check_u8(expected_public_key_version, "expected public key version")

    if framed:
        if len(raw) < 3:
            raise InitError(
                "INIT response is shorter than service/command/status"
            )
        if raw[0] != INIT_SERVICE or raw[1] != INIT_COMMAND:
            raise InitError("INIT response header is not 02 08")
        payload = raw[2:]
    else:
        if len(raw) < 1:
            raise InitError("INIT response payload is empty")
        payload = raw

    status = payload[0]
    if status != 1:
        return InitResponse(
            status=status,
            timestamp_ms=None,
            account=None,
            account_matched=False,
            public_key_version=None,
            public_key_matched=None,
            trailing_bytes=len(payload) - 1,
        )

    if len(payload) < 10:
        raise InitError(
            "INIT success response is shorter than timestamp/account"
        )
    timestamp = int.from_bytes(payload[1:9], "little")
    account_length = payload[9]
    if not 1 <= account_length <= MAX_ACCOUNT_BYTES or len(payload) < 10 + account_length:
        raise InitError("INIT response account length is invalid")
    account = payload[10:10 + account_length]
    try:
        account.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InitError("INIT response account is not UTF-8") from exc
    account_matched = account == account_expected

    offset = 10 + account_length
    if offset == len(payload):
        return InitResponse(
            status=1,
            timestamp_ms=timestamp,
            account=account,
            account_matched=account_matched,
            public_key_version=None,
            public_key_matched=None,
            trailing_bytes=0,
        )
    # The reviewed parser treats fewer than three remaining bytes as an absent
    # optional key block; the device still accepts on the exact account.
    if len(payload) - offset < 3:
        return InitResponse(
            status=1,
            timestamp_ms=timestamp,
            account=account,
            account_matched=account_matched,
            public_key_version=None,
            public_key_matched=None,
            trailing_bytes=len(payload) - offset,
        )

    version = payload[offset]
    offset += 1
    key_length = int.from_bytes(payload[offset:offset + 2], "little")
    offset += 2
    if len(payload) < offset + key_length:
        raise InitError("INIT response public-key length is invalid")
    returned_key = payload[offset:offset + key_length]
    matched: bool | None
    if key_expected is None or expected_public_key_version is None:
        matched = None
    else:
        matched = (
            key_length > 0
            and returned_key == key_expected
            and version == expected_public_key_version
        )
    return InitResponse(
        status=1,
        timestamp_ms=timestamp,
        account=account,
        account_matched=account_matched,
        public_key_version=version,
        public_key_matched=matched,
        trailing_bytes=len(payload) - offset - key_length,
    )


# -- shared validation ------------------------------------------------------


def _as_bytes(value, label: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise InitError(f"{label} must be bytes")


def _account_bytes(account: str | bytes) -> bytes:
    if isinstance(account, str):
        try:
            raw = account.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise InitError("account label is not UTF-8") from exc
    else:
        raw = _as_bytes(account, "account label")
    if not 1 <= len(raw) <= MAX_ACCOUNT_BYTES:
        raise InitError(
            f"account label must be 1...{MAX_ACCOUNT_BYTES} UTF-8 bytes "
            f"(got {len(raw)})"
        )
    if b"\x00" in raw:
        raise InitError("account label must not contain a NUL byte")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InitError("account label is not UTF-8") from exc
    return raw


def _public_key_bytes(public_key: str | bytes) -> bytes:
    if isinstance(public_key, str):
        try:
            raw = public_key.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise InitError("owner public key is not UTF-8") from exc
    else:
        raw = _as_bytes(public_key, "owner public key")
    if not 1 <= len(raw) <= MAX_PUBLIC_KEY_BYTES:
        raise InitError(
            f"owner public key length must be 1...{MAX_PUBLIC_KEY_BYTES} bytes"
        )
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InitError("owner public key is not UTF-8") from exc
    return raw


def _key_hash_bytes(key_hash: bytes) -> bytes:
    raw = _as_bytes(key_hash, "key hash")
    if len(raw) != 32:
        raise InitError(f"key hash must be 32 bytes (got {len(raw)})")
    return raw


def _check_u8(value: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFF:
        raise InitError(f"{label} must be 0...255")


def _check_i64(value: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _I64_MAX:
        raise InitError(f"{label} must fit a non-negative signed 64-bit integer")


def _read_absolute_file(
    path: str | Path, *, max_bytes: int, label: str
) -> bytes:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise InitError(f"{label} path must be absolute")
    try:
        info = candidate.stat()
    except OSError as exc:
        raise InitError(f"cannot stat {label}") from exc
    if not stat_module.S_ISREG(info.st_mode):
        raise InitError(f"{label} must be a regular file")
    if not 1 <= info.st_size <= max_bytes:
        raise InitError(f"{label} file must be 1...{max_bytes} bytes")
    try:
        return candidate.read_bytes()
    except OSError as exc:
        raise InitError(f"cannot read {label}") from exc


__all__ = [
    "BIND_CHALLENGE_BYTES",
    "BIND_OPERATION",
    "BindChallenge",
    "INIT_TYPE",
    "InitError",
    "InitResponse",
    "LOCAL_KEY_SLOT",
    "MAX_ACCOUNT_BYTES",
    "MAX_OWNER_KEY_TEXT_BYTES",
    "MAX_PUBLIC_KEY_BYTES",
    "MAX_TOKEN_BYTES",
    "OwnerPublicKey",
    "Pkcs8Signer",
    "TOKEN_EXPIRY_SECONDS",
    "TOKEN_SIGNATURE_BYTES",
    "Signer",
    "build_init_payload",
    "build_tbs",
    "build_token",
    "owner_key_hash",
    "parse_bind_challenge",
    "parse_init_response",
    "token_expiry_seconds",
]
