# -*- coding: utf-8 -*-
"""CMPT container parsing and enpt payload decryption.

CMPT layout (little-endian):

    0x00  "CMPT"
    0x04  u16 entry_count           (1..1000; not a type tag)
    0x06  u16 data_offset
    0x08  u32 declared_length       (top bit masked, as the source does)
    0x0C  entry table, entry_count records of 68 bytes:
              64 bytes NUL-padded UTF-8 name, then u32 payload_length
              (payload_length also has its top bit masked)

Entry payloads follow the table (after an optional gap up to data_offset)
contiguously in table order, and the last one ends exactly at
declared_length.  Bytes after the last entry that no entry declares are
rejected rather than silently ignored.

enpt envelope:

    0x000  "enpt"
    0x004  u16 wrapped_key_length   (256 for RSA-2048)
    0x006  u16 nonce_length         (12)
    0x008  RSA-2048 PKCS#1 v1.5 wrapped 32-byte AES key
    0x108  12-byte GCM nonce
    0x114  u16 header_length        (0x0118)
    0x116  u8  public key version
    0x117  u8  reserved
    0x118  ciphertext ...
    end-24 16-byte GCM tag | u16 tag_length 16 | u16 trailer_length 24 | "enpt"

Entry names come from the device and are metadata, never a path.  To write an
entry to disk use :func:`generated_output_name`, which derives a fixed-shape
name from the entry index and classified kind only.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

from .errors import ContainerError, DecryptError

CMPT_MAGIC = b"CMPT"
ENPT_MAGIC = b"enpt"
CMPT_HEADER = 12
ENTRY_RECORD = 68
ENTRY_NAME_BYTES = 64
MAX_ENTRY_COUNT = 1000
LENGTH_MASK = 0x7FFFFFFF
ENPT_HEADER = 0x118
ENPT_TRAILER = 24
ENPT_WRAPPED_KEY = 256
ENPT_NONCE = 12
ENPT_TAG = 16
ENPT_RSA_BITS = 2048
ENPT_AES_KEY = 32

# Authenticated .mark / end-marker plaintext: LE64 device timestamp (ms) then
# 32 zero bytes.  It is not Opus and must never be fed to the packet framer.
MARKER_BYTES = 40
MARKER_TIMESTAMP_BYTES = 8

# Classification follows the tested container contract. Order matters:
# longest suffix first.
END_MARKER_EXTENSIONS = (".end.enc.opus", ".end.opus")
_AUDIO_EXTENSIONS = {
    ".enc.note.opus": "note",
    ".note.opus": "note",
    ".enc.noise.opus": "noise",
    ".noise.opus": "noise",
    ".enc.vp.opus": "vp",
    ".vp.opus": "vp",
    ".enc.opus": "plain",
    ".opus": "plain",
}
AUDIO_EXTENSIONS = tuple(_AUDIO_EXTENSIONS)
KNOWN_EXTENSIONS = END_MARKER_EXTENSIONS + AUDIO_EXTENSIONS + (".compat.tp", ".mark", ".tp")

# Tested CMPT kinds (cmpt_kind) and the storage vocabulary (kind).  The storage
# vocabulary is shared by LocalStorage and the Cloudflare Worker.  Plaintext
# trace-point/unknown entries stay local; enpt audio/note-audio/end-marker/mark
# entries and explicitly encrypted diagnostics are uploadable.
CMPT_KINDS = ("audio", "end-marker", "mark", "tp", "compat-tp", "unknown")
STORAGE_KINDS = (
    "audio", "end-marker", "note-audio", "mark", "trace-point", "unknown", "diagnostic",
)

_NAME_TRIM = b"\x00 \t\n\r"
_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SUFFIX_RE = re.compile(r"^(\.[A-Za-z0-9]{1,16}){1,3}$")


def extension_of(name: str) -> str:
    """The known CMPT suffix of ``name`` (lower-cased), or ``""``."""
    lowered = name.lower()
    for ext in KNOWN_EXTENSIONS:
        if lowered.endswith(ext):
            return ext
    return ""


def cmpt_kind_of(name: str) -> str:
    """Tested CMPT kind: audio, end-marker, mark, tp, compat-tp or unknown."""
    ext = extension_of(name)
    if ext in END_MARKER_EXTENSIONS:
        return "end-marker"
    if ext in _AUDIO_EXTENSIONS:
        return "audio"
    if ext == ".mark":
        return "mark"
    if ext == ".tp":
        return "tp"
    if ext == ".compat.tp":
        return "compat-tp"
    return "unknown"


def audio_variant_of(name: str) -> str | None:
    """plain, note, noise or vp for audio entries; None otherwise."""
    return _AUDIO_EXTENSIONS.get(extension_of(name))


def _storage_kind(name: str) -> str:
    kind = cmpt_kind_of(name)
    if kind == "audio":
        return "note-audio" if audio_variant_of(name) == "note" else "audio"
    if kind == "end-marker":
        return "end-marker"
    if kind == "mark":
        return "mark"
    if kind in ("tp", "compat-tp"):
        return "trace-point"
    return "unknown"


def name_is_safe(name: str) -> bool:
    """True when ``name`` has no empty, ``.`` or ``..`` component and no controls.

    Safe does not mean "use as a path": even a safe name may contain ``/``.
    Use :func:`generated_output_name` for anything written to disk.
    """
    if not name or any(ord(ch) < 0x20 or ch == "\x7f" for ch in name):
        return False
    parts = name.replace("\\", "/").split("/")
    return all(part not in ("", ".", "..") for part in parts)


@dataclass(frozen=True)
class Entry:
    index: int
    name: str
    size: int
    payload: bytes
    raw_name: bytes = b""

    @property
    def kind(self) -> str:
        """Storage vocabulary shared with the Worker and LocalStorage.

        ``.tp`` and ``.compat.tp`` are both trace-point; ``.mark`` is mark.
        Use :attr:`cmpt_kind` for the full tested classification.
        """
        return _storage_kind(self.name)

    @property
    def cmpt_kind(self) -> str:
        """Tested CMPT kind: audio, end-marker, mark, tp, compat-tp or unknown."""
        return cmpt_kind_of(self.name)

    @property
    def extension(self) -> str:
        return extension_of(self.name)

    @property
    def audio_variant(self) -> str | None:
        """plain, note, noise or vp for audio entries; None otherwise."""
        return audio_variant_of(self.name)

    @property
    def is_audio(self) -> bool:
        """Encrypted 40-byte/20 ms Opus packet stream (every audio variant)."""
        return self.cmpt_kind == "audio"

    @property
    def is_marker(self) -> bool:
        """Decrypts to a 40-byte timestamp marker (see :func:`parse_marker`)."""
        return self.cmpt_kind in ("end-marker", "mark")

    @property
    def name_is_safe(self) -> bool:
        return name_is_safe(self.name)

    def output_name(self, suffix: str = ".bin", *, prefix: str = "cmpt") -> str:
        """Generated file name for this entry; see :func:`generated_output_name`."""
        return generated_output_name(self, suffix, prefix=prefix)


def generated_output_name(entry: Entry, suffix: str = ".bin", *, prefix: str = "cmpt") -> str:
    """Derive ``<prefix>-NNN-<cmpt_kind><suffix>`` without trusting entry.name.

    Matches the tested extractor's ``cmpt-NNN-<kind>.bin`` shape.  The result
    is a single path component built only from the index, the classified kind
    and validated caller strings, so a hostile device name cannot traverse,
    collide with a dotfile or smuggle separators.  Pass a distinct ``prefix``
    (e.g. the container's own sequence) when extracting several containers into
    one directory.
    """
    if isinstance(entry.index, bool) or not isinstance(entry.index, int) or entry.index < 0:
        raise ContainerError(f"entry index must be a non-negative integer; got {entry.index!r}")
    if not isinstance(prefix, str) or not _PREFIX_RE.match(prefix):
        raise ContainerError("prefix must be 1..64 of [A-Za-z0-9_-], starting alphanumeric")
    if not isinstance(suffix, str) or not _SUFFIX_RE.match(suffix):
        raise ContainerError("suffix must look like .ext (up to three alphanumeric parts)")
    return f"{prefix}-{entry.index:03d}-{entry.cmpt_kind}{suffix}"


@dataclass(frozen=True)
class Container:
    path: Path | None
    declared_length: int
    entries: list[Entry]

    def by_kind(self, kind: str) -> list[Entry]:
        """Entries whose storage ``kind`` or tested ``cmpt_kind`` equals ``kind``.

        ``by_kind("audio")`` therefore returns every audio variant (plain,
        note, noise, vp); ``by_kind("note-audio")`` only note audio;
        ``by_kind("mark")`` the highlight markers.
        """
        return [e for e in self.entries if e.kind == kind or e.cmpt_kind == kind]


@dataclass(frozen=True)
class EnptInfo:
    wrapped_key_length: int
    nonce_length: int
    public_key_version: int
    ciphertext: bytes
    tag: bytes
    nonce: bytes
    wrapped_key: bytes
    header_length: int = ENPT_HEADER
    reserved: int = 0
    tag_length: int = ENPT_TAG
    trailer_length: int = ENPT_TRAILER

    @property
    def plaintext_length(self) -> int:
        return len(self.ciphertext)


def _decode_name(raw: bytes) -> str:
    return raw.rstrip(_NAME_TRIM).decode("utf-8", "replace").replace("\x00", "").strip()


def parse_cmpt(data: bytes, path: Path | None = None) -> Container:
    if len(data) < CMPT_HEADER or data[:4] != CMPT_MAGIC:
        raise ContainerError(f"not a CMPT container: {path or '<bytes>'}")
    count, data_off, raw_declared = struct.unpack_from("<HHI", data, 4)
    declared = raw_declared & LENGTH_MASK
    if declared != len(data):
        masked = f" (raw field {raw_declared})" if raw_declared != declared else ""
        raise ContainerError(
            f"declared length {declared}{masked} does not match actual length {len(data)}"
        )
    if not 1 <= count <= MAX_ENTRY_COUNT:
        raise ContainerError(f"entry count {count} outside 1..{MAX_ENTRY_COUNT}")
    table_end = CMPT_HEADER + count * ENTRY_RECORD
    if table_end > len(data):
        raise ContainerError("entry table exceeds buffer")
    if not table_end <= data_off <= len(data):
        raise ContainerError(
            f"data_offset {data_off} outside valid range {table_end}..{len(data)}"
        )
    entries: list[Entry] = []
    offset = data_off
    for i in range(count):
        rec = CMPT_HEADER + i * ENTRY_RECORD
        raw_name = bytes(data[rec : rec + ENTRY_NAME_BYTES])
        name = _decode_name(raw_name)
        (raw_size,) = struct.unpack_from("<I", data, rec + ENTRY_NAME_BYTES)
        size = raw_size & LENGTH_MASK
        if offset + size > len(data):
            raise ContainerError(
                f"entry {i} truncated: want {size}, got {max(0, len(data) - offset)}"
            )
        payload = bytes(data[offset : offset + size])
        entries.append(Entry(index=i, name=name, size=size, payload=payload, raw_name=raw_name))
        offset += size
    if offset != len(data):
        raise ContainerError(
            f"{len(data) - offset} trailing bytes after the last entry "
            f"(entries end at {offset}, declared length {declared})"
        )
    return Container(path=path, declared_length=declared, entries=entries)


def parse_cmpt_file(path: Path) -> Container:
    return parse_cmpt(Path(path).read_bytes(), Path(path))


def parse_marker(plaintext: bytes) -> int:
    """Decode an authenticated ``.mark``/end-marker plaintext to its timestamp.

    Returns the device timestamp in milliseconds.  Rejects a wrong length,
    nonzero padding and a zero timestamp, so an invalid marker is never
    reported as a highlight or segment end.
    """
    if len(plaintext) != MARKER_BYTES:
        raise ContainerError(f"marker plaintext must be {MARKER_BYTES} bytes; got {len(plaintext)}")
    for offset in range(MARKER_TIMESTAMP_BYTES, MARKER_BYTES):
        if plaintext[offset]:
            raise ContainerError(f"marker padding byte at offset {offset} is nonzero")
    timestamp = int.from_bytes(plaintext[:MARKER_TIMESTAMP_BYTES], "little")
    if timestamp == 0:
        raise ContainerError("marker timestamp must be nonzero")
    return timestamp


def parse_enpt(data: bytes) -> EnptInfo:
    if len(data) < 4 or data[:4] != ENPT_MAGIC:
        raise ContainerError("not an enpt payload")
    if len(data) < ENPT_HEADER + ENPT_TRAILER:
        raise ContainerError(
            f"enpt payload too short: {len(data)} bytes, need at least "
            f"{ENPT_HEADER + ENPT_TRAILER} for header and trailer"
        )
    key_len, nonce_len = struct.unpack_from("<HH", data, 4)
    if key_len != ENPT_WRAPPED_KEY or nonce_len != ENPT_NONCE:
        raise ContainerError(
            f"unexpected enpt wrapped key/nonce length {key_len}/{nonce_len} "
            f"(expected {ENPT_WRAPPED_KEY}/{ENPT_NONCE})"
        )
    cursor = 8
    wrapped = bytes(data[cursor : cursor + key_len])
    cursor += key_len
    nonce = bytes(data[cursor : cursor + nonce_len])
    cursor += nonce_len
    (header_len,) = struct.unpack_from("<H", data, cursor)
    if header_len != ENPT_HEADER:
        raise ContainerError(
            f"unexpected enpt header length field {header_len:#x} (expected {ENPT_HEADER:#x})"
        )
    cursor += 2
    version = data[cursor]
    reserved = data[cursor + 1]
    cursor += 2  # version + reserved
    if cursor != ENPT_HEADER:  # pragma: no cover - fixed by the constants above
        raise ContainerError(f"unexpected enpt header length {cursor}")
    trailer = data[-ENPT_TRAILER:]
    tag_len, trailer_len = struct.unpack_from("<HH", trailer, ENPT_TAG)
    if tag_len != ENPT_TAG:
        raise ContainerError(f"unexpected enpt tag length {tag_len} (expected {ENPT_TAG})")
    if trailer_len != ENPT_TRAILER:
        raise ContainerError(
            f"unexpected enpt trailer length {trailer_len} (expected {ENPT_TRAILER})"
        )
    if trailer[20:24] != ENPT_MAGIC:
        raise ContainerError("enpt trailer magic mismatch")
    tag = bytes(trailer[:ENPT_TAG])
    ciphertext = bytes(data[ENPT_HEADER:-ENPT_TRAILER])
    return EnptInfo(
        wrapped_key_length=key_len,
        nonce_length=nonce_len,
        public_key_version=version,
        ciphertext=ciphertext,
        tag=tag,
        nonce=nonce,
        wrapped_key=wrapped,
        header_length=header_len,
        reserved=reserved,
        tag_length=tag_len,
        trailer_length=trailer_len,
    )


def decrypt_enpt(data: bytes, private_key_pem: bytes | Path | str) -> bytes:
    """Unwrap the AES key with RSA-OAEP-less PKCS#1 v1.5 and verify GCM.

    The key must be an RSA-2048 private key and must unwrap exactly 32 bytes
    (AES-256).  Raises ContainerError for a malformed enpt envelope and
    DecryptError when the key cannot be loaded, is not RSA-2048, does not
    match, or the tag fails.  Nothing is returned unless GCM authenticates.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except ImportError as exc:  # pragma: no cover
        raise ContainerError(
            "decryption requires the 'cryptography' package: pip install xinliqiu-sdk"
        ) from exc

    info = parse_enpt(data)
    try:
        pem = private_key_pem
        if isinstance(pem, Path):
            pem = pem.read_bytes()
        elif isinstance(pem, str):
            pem = pem.encode("utf-8")
        key = load_pem_private_key(pem, password=None)
    except Exception as exc:  # noqa: BLE001 - a bad/unsupported key is a decrypt failure
        raise DecryptError(
            "could not load the owner private key; expected an unencrypted PEM key"
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise DecryptError("owner key must be an RSA private key")
    if key.key_size != ENPT_RSA_BITS:
        raise DecryptError(
            f"owner key is RSA-{key.key_size}; enpt wraps its AES key with RSA-{ENPT_RSA_BITS}"
        )
    try:
        aes_key = key.decrypt(info.wrapped_key, padding.PKCS1v15())
    except Exception as exc:  # noqa: BLE001 - surface any RSA failure uniformly
        raise DecryptError("RSA unwrap failed: private key does not match this payload") from exc
    if len(aes_key) != ENPT_AES_KEY:
        raise DecryptError(
            "RSA unwrap did not yield a 32-byte AES key: private key does not match this payload"
        )
    try:
        return AESGCM(aes_key).decrypt(info.nonce, info.ciphertext + info.tag, None)
    except Exception as exc:  # noqa: BLE001
        raise DecryptError("AES-GCM authentication failed") from exc
