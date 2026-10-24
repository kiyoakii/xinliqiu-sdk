# -*- coding: utf-8 -*-
"""Pluggable storage for synced containers.

Hard rule enforced across every backend in this module: **only ciphertext is
stored**.  Entries carry their original enpt payload; nothing here decrypts.
Device credentials never pass through a Storage implementation.

Three layers are deliberately separate:

* outer-file classification (:func:`classify_outer_file`) - a synced file may
  be a CMPT container, a direct ``enpt`` payload or a plain JSONL diagnostic;
* entry classification (:func:`storage_kind`) - follows the tested container
  contract, including ``.mark`` and end markers;
* the backends, which only accept ciphertext kinds and verify the enpt
  envelope structure before storing a byte.

Diagnostics and unknown entries are never dropped: they stay on the local
disk and are reported in ``not_uploaded`` unless the caller passes an explicit
:class:`EncryptedDiagnosticPolicy`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Protocol

from .container import Container, Entry
from .errors import ContainerError, XinliqiuError

try:  # POSIX file locking; Windows falls back to the in-process lock only.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None


DIGEST_VERSION = "xinliqiu-storage-digest/v1"
DEVICE_KEY_PREFIX = "d1-"
MAX_SAFE_MS = 2**53 - 1  # the Worker is a JS number implementation
DEFAULT_START_MS = 0
DEFAULT_END_MS = MAX_SAFE_MS
MAX_PAGE_LIMIT = 1000
DEFAULT_LIST_LIMIT = 200
DEFAULT_CHANGES_LIMIT = 500
MAX_OBJECT_BYTES = 2 * 1024 * 1024

ENPT_HEADER = 0x118
ENPT_TRAILER = 24
ENPT_MIN_BYTES = ENPT_HEADER + ENPT_TRAILER

# Kinds that are enpt ciphertext on the device and therefore uploadable.
CIPHERTEXT_KINDS = frozenset({"audio", "note-audio", "end-marker", "mark"})
# Diagnostics/unknown stay local unless an encrypted diagnostic policy exists.
DIAGNOSTIC_KIND = "diagnostic"

_END_SUFFIXES = (".end.enc.opus", ".end.opus")
_NOTE_SUFFIXES = (".enc.note.opus", ".note.opus")
_AUDIO_SUFFIXES = (
    ".enc.noise.opus", ".noise.opus", ".enc.vp.opus", ".vp.opus",
    ".enc.opus", ".opus",
)
_DIAG_SUFFIXES = (".tp", ".compat.tp", ".jsonl", ".json", ".log", ".txt")

# Name suffixes stripped before parsing device timestamps.
_FILENAME_SUFFIXES = (
    ".end.enc.opus", ".end.opus",
    ".enc.note.opus", ".note.opus",
    ".enc.noise.opus", ".noise.opus",
    ".enc.vp.opus", ".vp.opus",
    ".compat", ".mark", ".enc.opus", ".opus",
)
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


def storage_kind(name: str) -> str:
    """Classify an entry name using the tested source-extension rules."""
    n = name.lower()
    if n.endswith(_END_SUFFIXES):
        return "end-marker"
    if n.endswith(_NOTE_SUFFIXES):
        return "note-audio"
    if n.endswith(".mark"):
        return "mark"
    if n.endswith(_AUDIO_SUFFIXES):
        return "audio"
    if n.endswith(_DIAG_SUFFIXES):
        return DIAGNOSTIC_KIND
    return "unknown"


def _signed_long(text: str) -> int | None:
    body = text[1:] if text[:1] == "+" else text
    if not body or not body.isdigit() or not body.isascii():
        return None
    value = int(body)
    if value < _INT64_MIN or value > _INT64_MAX:
        return None
    return value


def entry_times(name: str) -> tuple[int | None, int | None]:
    """Device start/end ms from an entry or outer-file name.

    Mirrors the source parser: strip a known suffix, split on ``_`` then ``-``;
    a single ``.mark`` value ``n`` means ``(n, n + 1)``.  Values outside the
    JavaScript safe-integer range are dropped so both backends agree.
    """
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    lowered = base.lower()
    suffix = ""
    for candidate in _FILENAME_SUFFIXES:
        if lowered.endswith(candidate):
            suffix = candidate
            break
    stem = base[: len(base) - len(suffix)] if suffix else base
    parts = stem.split("_")
    if suffix == ".mark":
        if len(parts) != 2:
            if len(parts) != 1:
                return None, None
            parts = stem.split("-")
            if len(parts) >= 3:
                return None, None
        if len(parts) == 1:
            n = _signed_long(parts[0])
            if n is None or n <= 0 or n >= _INT64_MAX:
                return None, None
            if n + 1 > MAX_SAFE_MS:
                return None, None
            return n, n + 1
        start, end = _signed_long(parts[0]), _signed_long(parts[1])
        if start is None or end is None or start <= 0 or end <= 0 or end <= start:
            return None, None
        if start > MAX_SAFE_MS or end > MAX_SAFE_MS:
            return None, None
        return start, end
    if len(parts) != 2:
        parts = stem.split("-")
    if len(parts) != 2:
        return None, None
    start, end = _signed_long(parts[0]), _signed_long(parts[1])
    if start is None or end is None or start <= 0 or end <= 0:
        return None, None
    if start > MAX_SAFE_MS or end > MAX_SAFE_MS:
        return None, None
    return start, end


def _name_times(name: str) -> tuple[int | None, int | None]:
    """Backward-compatible alias for :func:`entry_times`."""
    return entry_times(name)


def validate_enpt(data: bytes) -> None:
    """Structural check of a complete enpt envelope; raises ContainerError.

    Checks the fields of the tested enpt contract
    checks, including the header length and both trailer length words.  This
    never authenticates or decrypts; it only proves the bytes have the shape
    of ciphertext rather than plaintext audio or JSON.
    """
    if len(data) < ENPT_MIN_BYTES:
        raise ContainerError(f"enpt payload too short: {len(data)} bytes")
    if data[:4] != b"enpt":
        raise ContainerError("not an enpt payload")
    key_len, nonce_len = struct.unpack_from("<HH", data, 4)
    if key_len != 256 or nonce_len != 12:
        raise ContainerError(
            f"unexpected enpt wrapped key/nonce length {key_len}/{nonce_len}"
        )
    (header_len,) = struct.unpack_from("<H", data, 276)
    if header_len != ENPT_HEADER:
        raise ContainerError(f"enpt header length must be {ENPT_HEADER}, got {header_len}")
    trailer = data[-ENPT_TRAILER:]
    tag_len, trailer_len = struct.unpack_from("<HH", trailer, 16)
    if tag_len != 16:
        raise ContainerError(f"enpt GCM tag length must be 16, got {tag_len}")
    if trailer_len != ENPT_TRAILER:
        raise ContainerError(f"enpt trailer length must be 24, got {trailer_len}")
    if trailer[20:24] != b"enpt":
        raise ContainerError("enpt trailer magic mismatch")


def canonical_device_key(device_id: str) -> str:
    """Collision-free, path-safe canonical encoding of a raw device identity.

    Lowercase hex of the UTF-8 bytes: injective, identical on case-insensitive
    filesystems, and computable in SQL (``lower(hex(...))``) for backfills.
    Unlike the old ``safeSegment`` sanitiser, two distinct raw identities can
    never map to one key.
    """
    validate_device_id(device_id)
    return DEVICE_KEY_PREFIX + device_id.encode("utf-8").hex()


def validate_device_id(device_id: str) -> str:
    if not isinstance(device_id, str) or not device_id:
        raise ValueError("device identity must be a non-empty string")
    encoded = device_id.encode("utf-8")
    if len(encoded) > 256:
        raise ValueError("device identity must be at most 256 UTF-8 bytes")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in device_id):
        raise ValueError("device identity must not contain control characters")
    if device_id != device_id.strip():
        raise ValueError("device identity must not have surrounding whitespace")
    return device_id


def object_key_for(device_id: str, sha256: str) -> str:
    return f"{canonical_device_key(device_id)}/{sha256}"


# --------------------------------------------------------------------------
# Stable storage device identity (separate from the BLE UUID)
# --------------------------------------------------------------------------

STORAGE_DEVICE_ENV = "XINLIQIU_STORAGE_DEVICE_ID"
STORAGE_CONFIG_KEY = "storage_device_id"
IDENTITY_DERIVATION_LABEL = "xinliqiu-storage-device/v1:"


@dataclass(frozen=True)
class StorageIdentity:
    """The identity used for storage keys, and where it came from."""

    device_id: str
    source: str  # explicit | environment | config | pairing-derived | ble-uuid
    stable: bool

    def as_dict(self) -> dict:
        return {"device_id": self.device_id, "source": self.source, "stable": self.stable}


def derive_storage_device_id(provider_device_id_hex: str) -> str:
    """Derive a stable storage identity from the pairing's provider device id.

    The provider device id is a device-side identifier, unlike the host BLE
    UUID which changes between computers.  Only a keyed-by-label hash is used
    as the storage key, so the raw identifier is never sent to a store.
    """
    cleaned = provider_device_id_hex.strip().lower()
    if not cleaned or len(cleaned) % 2 or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("provider device id must be non-empty hex")
    digest = hashlib.sha256((IDENTITY_DERIVATION_LABEL + cleaned).encode("ascii")).hexdigest()
    return f"pd-{digest[:32]}"


def _read_config(config_path: Path | None = None) -> dict:
    if config_path is None:
        from .userconfig import config_path as default_config_path

        config_path = default_config_path()
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_storage_device_id(device_id: str, config_path: Path | None = None) -> Path:
    """Persist the storage identity in the user config (0600, atomic).

    Other config keys are preserved; this only adds ``storage_device_id``.
    """
    validate_device_id(device_id)
    if config_path is None:
        from .userconfig import config_path as default_config_path

        config_path = default_config_path()
    path = Path(config_path)
    data = _read_config(path)
    data[STORAGE_CONFIG_KEY] = device_id
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    return path


def resolve_storage_identity(
    explicit: str | None = None,
    *,
    credentials=None,
    ble_device_id: str | None = None,
    config_path: Path | None = None,
    environ: dict | None = None,
    allow_pairing_derivation: bool = True,
) -> StorageIdentity:
    """Resolve the storage identity; never silently confuse it with BLE UUID.

    Precedence: explicit argument > ``XINLIQIU_STORAGE_DEVICE_ID`` > saved
    ``storage_device_id`` config > identity derived from the pairing's
    provider device id > the BLE UUID (reported as unstable).
    """
    env = os.environ if environ is None else environ
    if explicit:
        return StorageIdentity(validate_device_id(explicit), "explicit", True)
    from_env = env.get(STORAGE_DEVICE_ENV)
    if from_env:
        return StorageIdentity(validate_device_id(from_env), "environment", True)
    from_config = _read_config(config_path).get(STORAGE_CONFIG_KEY)
    if isinstance(from_config, str) and from_config:
        return StorageIdentity(validate_device_id(from_config), "config", True)
    if allow_pairing_derivation and credentials is not None:
        try:
            pairing_data = json.loads(Path(credentials.key_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, AttributeError):
            pairing_data = {}
        if isinstance(pairing_data, dict):
            provider = pairing_data.get("providerDeviceIdHex") or pairing_data.get("providerIdHex")
            if isinstance(provider, str) and provider:
                return StorageIdentity(
                    derive_storage_device_id(provider), "pairing-derived", True
                )
    fallback = ble_device_id or getattr(credentials, "device_id", None)
    if fallback:
        # A BLE UUID is host-specific: usable, but two computers will not
        # converge on one store until a stable identity is configured.
        return StorageIdentity(validate_device_id(fallback), "ble-uuid", False)
    raise XinliqiuError(
        "no storage device identity: pass storage_device_id, set "
        f"{STORAGE_DEVICE_ENV}, or save one with save_storage_device_id()"
    )


# --------------------------------------------------------------------------
# Records and shared query semantics
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class StoredObject:
    object_key: str
    entry_name: str
    kind: str
    size_bytes: int
    sha256: str
    start_ms: int | None
    end_ms: int | None
    seq: int | None = None
    device_id: str | None = None
    encryption: str | None = None


@dataclass(frozen=True)
class StorageItem:
    """One upload unit: ciphertext bytes plus explicit classification."""

    name: str
    payload: bytes
    kind: str
    encryption: str | None = None
    index: int = 0

    @property
    def size(self) -> int:
        return len(self.payload)


def item_times(item) -> tuple[int | None, int | None]:
    return entry_times(item.name)


def range_bounds(start_ms: int | None, end_ms: int | None) -> tuple[int | None, int | None]:
    """Inclusive [lo, hi] interval; None when the object has no device time."""
    if start_ms is None and end_ms is None:
        return None, None
    if start_ms is None:
        return end_ms, end_ms
    if end_ms is None:
        return start_ms, start_ms
    return (start_ms, end_ms) if start_ms <= end_ms else (end_ms, start_ms)


def validate_range(start_ms: int, end_ms: int) -> tuple[int, int]:
    for label, value in (("start_ms", start_ms), ("end_ms", end_ms)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{label} must be an integer")
        if not 0 <= value <= MAX_SAFE_MS:
            raise ValueError(f"{label} must be within 0..{MAX_SAFE_MS}")
    if end_ms < start_ms:
        raise ValueError("end_ms must be >= start_ms")
    return start_ms, end_ms


def validate_limit(limit: int, *, maximum: int = MAX_PAGE_LIMIT) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer")
    if not 1 <= limit <= maximum:
        raise ValueError(f"limit must be within 1..{maximum}")
    return limit


def validate_since(since: int) -> int:
    if isinstance(since, bool) or not isinstance(since, int) or since < 0:
        raise ValueError("since must be a non-negative integer")
    return since


def overlaps(lo: int | None, hi: int | None, start_ms: int, end_ms: int) -> bool:
    """Inclusive interval overlap: [lo,hi] x [start,end] is non-empty."""
    if lo is None or hi is None:
        return False
    return lo <= end_ms and hi >= start_ms


def encode_cursor(bucket: int, sort_ms: int | None, seq: int) -> str:
    payload = json.dumps(
        {"v": 1, "b": bucket, "t": sort_ms, "s": seq}, separators=(",", ":")
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[int, int | None, int]:
    if not isinstance(cursor, str) or not cursor or len(cursor) > 256:
        raise ValueError("invalid cursor")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except Exception as exc:  # noqa: BLE001 - any decode failure is one error
        raise ValueError("invalid cursor") from exc
    if not isinstance(data, dict) or data.get("v") != 1:
        raise ValueError("unsupported cursor version")
    bucket, sort_ms, seq = data.get("b"), data.get("t"), data.get("s")
    if bucket not in (0, 1):
        raise ValueError("invalid cursor bucket")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("invalid cursor sequence")
    if bucket == 0:
        if isinstance(sort_ms, bool) or not isinstance(sort_ms, int) or sort_ms < 0:
            raise ValueError("invalid cursor timestamp")
    elif sort_ms is not None:
        raise ValueError("untimed cursor must not carry a timestamp")
    # Same shape as the (bucket, sort_ms, seq) sort keys; untimed sorts by 0.
    return bucket, (sort_ms if bucket == 0 else 0), seq


def digest_material(
    device_id: str,
    start_ms: int,
    end_ms: int,
    include_untimed: bool,
    rows: Iterable[tuple[str, int]],
) -> bytes:
    """Versioned, backend-independent digest material.

    Only content hashes and sizes participate, never object keys, entry names
    or storage timestamps, so a local store and the Worker agree byte for byte.
    ``rows`` must be sorted by (sha256, size_bytes).
    """
    lines = [
        DIGEST_VERSION,
        f"device={canonical_device_key(device_id)}",
        f"range={start_ms}:{end_ms}",
        f"untimed={1 if include_untimed else 0}",
        "objects=",
    ]
    lines.extend(f"{sha256}:{size_bytes}" for sha256, size_bytes in rows)
    return "\n".join(lines).encode("utf-8")


def compute_digest(
    device_id: str,
    start_ms: int,
    end_ms: int,
    include_untimed: bool,
    rows: Iterable[tuple[str, int]],
) -> str:
    return hashlib.sha256(
        digest_material(device_id, start_ms, end_ms, include_untimed, rows)
    ).hexdigest()


class Storage(Protocol):
    def put_entry(self, device_id: str, entry: Entry) -> dict: ...
    def list(self, device_id: str, start_ms: int, end_ms: int) -> list[StoredObject]: ...
    def get(self, object_key: str) -> bytes: ...


def prepare_upload(device_id: str, entry) -> StorageItem:
    """Classify and structurally verify one entry before any backend write.

    ``entry`` may be a container :class:`Entry` or a :class:`StorageItem`.
    Plaintext is refused, never silently stored: an uploadable name whose
    payload is not enpt raises ContainerError, as does a malformed envelope.
    """
    validate_device_id(device_id)
    payload = entry.payload
    if not isinstance(payload, (bytes, bytearray)):
        raise ContainerError("entry payload must be bytes")
    payload = bytes(payload)
    kind = entry.kind if isinstance(entry, StorageItem) else storage_kind(entry.name)
    if kind == DIAGNOSTIC_KIND:
        encryption = getattr(entry, "encryption", None)
        if not encryption:
            raise ContainerError(
                "diagnostic uploads require an explicit encrypted diagnostic policy"
            )
        if not isinstance(encryption, str) or len(encryption) > 128:
            raise ContainerError("diagnostic encryption scheme must be a short string")
    elif kind in CIPHERTEXT_KINDS:
        validate_enpt(payload)
    else:
        raise ContainerError(f"kind {kind!r} is not uploadable ciphertext")
    if not payload:
        raise ContainerError("refusing to store an empty payload")
    if len(payload) > MAX_OBJECT_BYTES:
        raise ContainerError(f"payload exceeds {MAX_OBJECT_BYTES} bytes")
    return StorageItem(
        name=entry.name,
        payload=payload,
        kind=kind,
        encryption=getattr(entry, "encryption", None),
        index=getattr(entry, "index", 0),
    )


# --------------------------------------------------------------------------
# Local filesystem backend
# --------------------------------------------------------------------------


def _safe_component(value: str) -> bool:
    return (
        bool(value)
        and value not in (".", "..")
        and "/" not in value
        and "\\" not in value
        and "\x00" not in value
    )


class LocalStorage:
    """Filesystem store: one directory per device, one file per ciphertext blob.

    The index is an append-only JSONL log guarded by an flock plus an
    in-process lock.  Torn trailing lines and duplicate records are repaired
    atomically (temp file + rename) instead of being silently ignored.
    """

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / "index.jsonl"
        self.lock_path = self.root / ".lock"
        self._thread_lock = threading.RLock()
        self.last_repair: dict = {"repaired": 0, "dropped_lines": 0, "duplicates": 0}

    @contextmanager
    def _locked(self):
        with self._thread_lock:
            fd = os.open(str(self.lock_path), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    @staticmethod
    def _digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _blob_path(self, device_id: str, object_key: str) -> Path:
        sha = object_key.rsplit("/", 1)[-1]
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise XinliqiuError(f"invalid object key: {object_key}")
        component = object_key.split("/", 1)[0]
        if component == canonical_device_key(device_id):
            pass  # canonical hex directory
        elif component == device_id and _safe_component(component):
            pass  # legacy keys used the raw device id as the directory name
        else:
            raise XinliqiuError(f"unsafe or mismatched object key: {object_key}")
        path = (self.root / component / f"{sha}.bin").resolve()
        if self.root.resolve() not in path.parents:
            raise XinliqiuError(f"object path escapes the store root: {object_key}")
        return path

    def _read_records(self) -> tuple[list[dict], int]:
        """Return (records, invalid_line_count); preserve stored seqs."""
        if not self.index_path.exists():
            return [], 0
        raw = self.index_path.read_bytes()
        records: list[dict] = []
        invalid = 0
        next_seq = 1
        for line in raw.split(b"\n"):
            if not line.strip():
                continue
            try:
                record = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                invalid += 1
                continue
            if not isinstance(record, dict) or not self._valid_record(record):
                invalid += 1
                continue
            seq = record.get("seq")
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
                seq = next_seq
            record["seq"] = seq
            next_seq = max(next_seq, seq + 1)
            records.append(record)
        return records, invalid

    @staticmethod
    def _valid_record(record: dict) -> bool:
        try:
            return (
                isinstance(record.get("object_key"), str)
                and isinstance(record.get("device_id"), str)
                and isinstance(record.get("entry_name"), str)
                and isinstance(record.get("kind"), str)
                and isinstance(record.get("size_bytes"), int)
                and isinstance(record.get("sha256"), str)
                and len(record["sha256"]) == 64
                and "/" in record["object_key"]
            )
        except (KeyError, TypeError):
            return False

    def _snapshot(self) -> list[dict]:
        """Records plus atomic repair of torn/duplicate index lines."""
        records, invalid = self._read_records()
        seen: dict[tuple[str, str], dict] = {}
        deduped: list[dict] = []
        duplicates = 0
        for record in records:
            key = (record["device_id"], record["sha256"])
            if key in seen:
                duplicates += 1
                continue
            seen[key] = record
            deduped.append(record)
        # A stale or hand-edited index can repeat a seq. Keep the stored values
        # but make them unique and monotonic so a cursor cannot skip an entry.
        used_seqs: set[int] = set()
        next_seq = max((record["seq"] for record in deduped), default=0) + 1
        renumbered = 0
        for record in deduped:
            if record["seq"] in used_seqs:
                record["seq"] = next_seq
                next_seq += 1
                renumbered += 1
            used_seqs.add(record["seq"])
        self.last_repair = {
            "repaired": 1 if (invalid or duplicates or renumbered) else 0,
            "dropped_lines": invalid,
            "duplicates": duplicates,
            "renumbered": renumbered,
        }
        if invalid or duplicates or renumbered:
            self._write_index(deduped)
        return deduped

    def _write_index(self, records: list[dict]) -> None:
        tmp = self.index_path.with_name(self.index_path.name + f".{os.getpid()}.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for record in records:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.index_path)
        finally:
            if tmp.exists():
                tmp.unlink()

    def _append_index(self, record: dict) -> None:
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        fd = os.open(str(self.index_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        start: int | None = None
        try:
            start = os.lseek(fd, 0, os.SEEK_END)
            written = 0
            while written < len(line):
                count = os.write(fd, line[written:])
                if count <= 0:
                    raise OSError("short write while appending the index")
                written += count
            os.fsync(fd)
        except BaseException:
            if start is not None:
                try:
                    os.ftruncate(fd, start)
                except OSError:
                    pass
            raise
        finally:
            os.close(fd)

    def _write_blob(self, path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if self._digest(path.read_bytes()) == self._digest(payload):
                return
        tmp = path.with_name(path.name + f".{os.getpid()}.{threading.get_ident()}.part")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()

    def put_entry(self, device_id: str, entry) -> dict:
        item = prepare_upload(device_id, entry)
        sha = self._digest(item.payload)
        start, end = entry_times(item.name)
        with self._locked():
            records = self._snapshot()
            for record in records:
                if record["device_id"] == device_id and record["sha256"] == sha:
                    return self._duplicate_response(record, device_id)
            object_key = object_key_for(device_id, sha)
            path = self._blob_path(device_id, object_key)
            self._write_blob(path, item.payload)
            record = {
                "object_key": object_key,
                "device_id": device_id,
                "device_key": canonical_device_key(device_id),
                "entry_name": item.name,
                "kind": item.kind,
                "size_bytes": len(item.payload),
                "sha256": sha,
                "device_start_ms": start,
                "device_end_ms": end,
                "synced_at": int(time.time() * 1000),
                "seq": max((r.get("seq", 0) for r in records), default=0) + 1,
            }
            if item.encryption:
                record["encryption"] = item.encryption
            self._append_index(record)
            return {
                "status": "stored",
                "object_key": object_key,
                "sha256": sha,
                "size": len(item.payload),
                "seq": record["seq"],
            }

    @staticmethod
    def _duplicate_response(record: dict, device_id: str) -> dict:
        # Raw identity check: a canonical-key collision must never merge two
        # different devices into one object.
        if record.get("device_id") != device_id:
            raise XinliqiuError("object identity conflict")
        return {
            "status": "duplicate",
            "object_key": record["object_key"],
            "sha256": record["sha256"],
            "size": record["size_bytes"],
            "seq": record.get("seq"),
        }

    def repair(self) -> dict:
        """Force an index repair pass and verify every referenced blob."""
        with self._locked():
            records = self._snapshot()
            missing = []
            corrupt = []
            for record in records:
                path = self._blob_path(record["device_id"], record["object_key"])
                if not path.exists():
                    missing.append(record["object_key"])
                elif self._digest(path.read_bytes()) != record["sha256"]:
                    corrupt.append(record["object_key"])
            return {**self.last_repair, "objects": len(records), "missing": missing, "corrupt": corrupt}

    def _records_for(self, device_id: str) -> list[dict]:
        with self._locked():
            return [r for r in self._snapshot() if r["device_id"] == device_id]

    @staticmethod
    def _to_object(record: dict) -> StoredObject:
        return StoredObject(
            object_key=record["object_key"],
            entry_name=record["entry_name"],
            kind=record["kind"],
            size_bytes=record["size_bytes"],
            sha256=record["sha256"],
            start_ms=record.get("device_start_ms"),
            end_ms=record.get("device_end_ms"),
            seq=record.get("seq"),
            device_id=record.get("device_id"),
            encryption=record.get("encryption"),
        )

    @staticmethod
    def _sort_key(record: dict) -> tuple[int, int, int]:
        lo, _ = range_bounds(record.get("device_start_ms"), record.get("device_end_ms"))
        return (1, 0, record["seq"]) if lo is None else (0, lo, record["seq"])

    def list_page(
        self,
        device_id: str,
        start_ms: int = DEFAULT_START_MS,
        end_ms: int = DEFAULT_END_MS,
        *,
        kind: str | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
        cursor: str | None = None,
        include_untimed: bool = True,
    ) -> dict:
        validate_device_id(device_id)
        validate_range(start_ms, end_ms)
        validate_limit(limit)
        position = decode_cursor(cursor) if cursor else None
        rows = []
        for record in self._records_for(device_id):
            if kind and record["kind"] != kind:
                continue
            lo, hi = range_bounds(record.get("device_start_ms"), record.get("device_end_ms"))
            if lo is None:
                if not include_untimed:
                    continue
            elif not overlaps(lo, hi, start_ms, end_ms):
                continue
            if position and self._sort_key(record) <= position:
                continue
            rows.append(record)
        rows.sort(key=self._sort_key)
        page, has_more = rows[:limit], len(rows) > limit
        next_cursor = (
            encode_cursor(*self._sort_key(page[-1])) if has_more and page else None
        )
        return {
            "objects": [self._to_object(r) for r in page],
            "count": len(page),
            "next_cursor": next_cursor,
            "has_more": has_more,
        }

    def list(
        self,
        device_id: str,
        start_ms: int = DEFAULT_START_MS,
        end_ms: int = DEFAULT_END_MS,
        *,
        kind: str | None = None,
        include_untimed: bool = True,
    ) -> list[StoredObject]:
        """All matching objects, following pagination until exhausted."""
        out: list[StoredObject] = []
        cursor = None
        while True:
            page = self.list_page(
                device_id, start_ms, end_ms, kind=kind, limit=MAX_PAGE_LIMIT,
                cursor=cursor, include_untimed=include_untimed,
            )
            out.extend(page["objects"])
            if not page["has_more"]:
                return out
            cursor = page["next_cursor"]

    def changes(self, device_id: str, since: int = 0, limit: int = DEFAULT_CHANGES_LIMIT) -> dict:
        """Incremental pull; the cursor is the storage sequence of the last row."""
        validate_device_id(device_id)
        validate_since(since)
        validate_limit(limit)
        rows = [r for r in self._records_for(device_id) if r["seq"] > since]
        rows.sort(key=lambda r: r["seq"])
        page, has_more = rows[:limit], len(rows) > limit
        cursor = page[-1]["seq"] if page else since
        return {
            "objects": [self._to_object(r) for r in page],
            "cursor": cursor,
            "has_more": has_more,
            "latest_seq": max((r["seq"] for r in self._records_for(device_id)), default=0),
        }

    def digest(
        self,
        device_id: str,
        start_ms: int = DEFAULT_START_MS,
        end_ms: int = DEFAULT_END_MS,
        *,
        include_untimed: bool = True,
    ) -> dict:
        """Same digest definition as the Cloudflare backend, one snapshot."""
        validate_device_id(device_id)
        validate_range(start_ms, end_ms)
        with self._locked():
            records = [r for r in self._snapshot() if r["device_id"] == device_id]
            rows: list[tuple[str, int]] = []
            for record in records:
                lo, hi = range_bounds(record.get("device_start_ms"), record.get("device_end_ms"))
                if lo is None:
                    if not include_untimed:
                        continue
                elif not overlaps(lo, hi, start_ms, end_ms):
                    continue
                rows.append((record["sha256"], record["size_bytes"]))
            latest_seq = max((r["seq"] for r in records), default=0)
        rows.sort()
        return {
            "digest_version": DIGEST_VERSION,
            "device": device_id,
            "device_key": canonical_device_key(device_id),
            "start_ms": start_ms,
            "end_ms": end_ms,
            "include_untimed": include_untimed,
            "count": len(rows),
            "total_bytes": sum(size for _, size in rows),
            "digest": compute_digest(device_id, start_ms, end_ms, include_untimed, rows),
            "latest_seq": latest_seq,
        }

    def get(self, object_key: str) -> bytes:
        with self._locked():
            for record in self._snapshot():
                if record["object_key"] == object_key:
                    path = self._blob_path(record["device_id"], object_key)
                    break
            else:
                raise XinliqiuError(f"object not found: {object_key}")
        if not path.exists():
            raise XinliqiuError(f"object not found: {object_key}")
        return path.read_bytes()

    def inventory(self, device_id: str | None = None) -> dict:
        with self._locked():
            records = self._snapshot()
        grouped: dict[str, list[dict]] = {}
        for record in records:
            if device_id and record["device_id"] != device_id:
                continue
            grouped.setdefault(record["device_id"], []).append(record)
        rows = [
            {
                "device_id": dev,
                "object_count": len(items),
                "total_bytes": sum(r["size_bytes"] for r in items),
                "latest_seq": max(r["seq"] for r in items),
            }
            for dev, items in sorted(grouped.items())
        ]
        return {"inventory": rows[0] if device_id and rows else (None if device_id else rows)}


# --------------------------------------------------------------------------
# Cloudflare Worker backend
# --------------------------------------------------------------------------


class CloudflareStorage:
    """Remote store backed by the `cloudflare/` Worker in this repository."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(
        self, method: str, path: str, *, body: bytes | None = None, headers: dict | None = None
    ) -> tuple[int, bytes, dict]:
        req = urllib.request.Request(self.base_url + path, data=body, method=method)
        req.add_header("authorization", f"Bearer {self.token}")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read(), dict(resp.headers.items())
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers.items()) if exc.headers else {}
        except urllib.error.URLError as exc:
            raise XinliqiuError(f"cloudflare request failed: {exc.reason}") from exc

    @staticmethod
    def _error(status: int, payload: bytes, operation: str) -> XinliqiuError:
        detail = payload[:400].decode("utf-8", "replace")
        return XinliqiuError(f"cloudflare {operation} failed ({status}): {detail}")

    @staticmethod
    def _json(payload: bytes, operation: str) -> dict:
        try:
            body = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise XinliqiuError(f"cloudflare {operation} returned invalid JSON") from exc
        if not isinstance(body, dict):
            raise XinliqiuError(f"cloudflare {operation} returned a non-object body")
        return body

    @staticmethod
    def _object(row: dict) -> StoredObject:
        return StoredObject(
            object_key=row["object_key"],
            entry_name=row["entry_name"],
            kind=row["kind"],
            size_bytes=row["size_bytes"],
            sha256=row["sha256"],
            start_ms=row.get("device_start_ms"),
            end_ms=row.get("device_end_ms"),
            seq=row.get("seq"),
            device_id=row.get("device_id"),
            encryption=row.get("encryption"),
        )

    def put_entry(self, device_id: str, entry) -> dict:
        item = prepare_upload(device_id, entry)
        sha = hashlib.sha256(item.payload).hexdigest()
        start, end = entry_times(item.name)
        # Header values are ASCII: raw identities and names are percent-encoded
        # and the Worker decodes them, so non-ASCII identities survive.
        headers = {
            "content-type": "application/octet-stream",
            "x-xinliqiu-device": urllib.parse.quote(device_id, safe=""),
            "x-xinliqiu-device-encoding": "percent",
            "x-xinliqiu-name": urllib.parse.quote(item.name, safe=""),
            "x-xinliqiu-name-encoding": "percent",
            "x-xinliqiu-kind": item.kind,
            "x-xinliqiu-sha256": sha,
        }
        if start is not None:
            headers["x-xinliqiu-start-ms"] = str(start)
        if end is not None:
            headers["x-xinliqiu-end-ms"] = str(end)
        if item.encryption:
            headers["x-xinliqiu-encryption"] = item.encryption
        status, payload, _ = self._request("POST", "/objects", body=item.payload, headers=headers)
        if status not in (200, 201):
            raise self._error(status, payload, "put")
        body = self._json(payload, "put")
        if body.get("object_key", "").rsplit("/", 1)[-1] != sha:
            raise XinliqiuError("cloudflare put returned a key for different content")
        return body

    def list_page(
        self,
        device_id: str,
        start_ms: int = DEFAULT_START_MS,
        end_ms: int = DEFAULT_END_MS,
        *,
        kind: str | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
        cursor: str | None = None,
        include_untimed: bool = True,
    ) -> dict:
        validate_device_id(device_id)
        validate_range(start_ms, end_ms)
        validate_limit(limit)
        if cursor:
            decode_cursor(cursor)
        query = {
            "device": device_id,
            "start_ms": start_ms,
            "end_ms": end_ms,
            "limit": limit,
            "include_untimed": "1" if include_untimed else "0",
        }
        if kind:
            query["kind"] = kind
        if cursor:
            query["cursor"] = cursor
        status, payload, _ = self._request("GET", "/objects?" + urllib.parse.urlencode(query))
        if status != 200:
            raise self._error(status, payload, "list")
        body = self._json(payload, "list")
        return {
            "objects": [self._object(o) for o in body.get("objects", [])],
            "count": int(body.get("count", 0)),
            "next_cursor": body.get("next_cursor"),
            "has_more": bool(body.get("has_more")),
        }

    def list(
        self,
        device_id: str,
        start_ms: int = DEFAULT_START_MS,
        end_ms: int = DEFAULT_END_MS,
        *,
        kind: str | None = None,
        include_untimed: bool = True,
    ) -> list[StoredObject]:
        out: list[StoredObject] = []
        cursor = None
        while True:
            page = self.list_page(
                device_id, start_ms, end_ms, kind=kind, limit=MAX_PAGE_LIMIT,
                cursor=cursor, include_untimed=include_untimed,
            )
            out.extend(page["objects"])
            if not page["has_more"]:
                return out
            if not page["next_cursor"] or page["next_cursor"] == cursor:
                raise XinliqiuError("cloudflare list did not advance its cursor")
            cursor = page["next_cursor"]

    def get(self, object_key: str) -> bytes:
        status, payload, _ = self._request(
            "GET", "/objects/" + urllib.parse.quote(object_key, safe="")
        )
        if status != 200:
            raise self._error(status, payload, "get")
        return payload

    def changes(self, device_id: str, since: int = 0, limit: int = DEFAULT_CHANGES_LIMIT) -> dict:
        """Incremental pull by storage cursor.

        Returns ``{"objects": [...], "cursor": int, "has_more": bool}``.
        Cursor is the storage-side sequence, not a device timestamp.
        """
        validate_device_id(device_id)
        validate_since(since)
        validate_limit(limit)
        query = urllib.parse.urlencode({"device": device_id, "since": since, "limit": limit})
        status, payload, _ = self._request("GET", f"/objects/changes?{query}")
        if status != 200:
            raise self._error(status, payload, "changes")
        body = self._json(payload, "changes")
        cursor = int(body.get("cursor") or 0)
        if body.get("objects") and cursor <= since:
            raise XinliqiuError("cloudflare changes returned a non-advancing cursor")
        return {
            "objects": [self._object(o) for o in body.get("objects", [])],
            "cursor": cursor if body.get("objects") else since,
            "has_more": bool(body.get("has_more")),
            "latest_seq": body.get("latest_seq"),
        }

    def digest(
        self,
        device_id: str,
        start_ms: int = DEFAULT_START_MS,
        end_ms: int = DEFAULT_END_MS,
        *,
        include_untimed: bool = True,
    ) -> dict:
        """Content digest for a device range; compare two clients cheaply."""
        validate_device_id(device_id)
        validate_range(start_ms, end_ms)
        query = urllib.parse.urlencode({
            "device": device_id, "start_ms": start_ms, "end_ms": end_ms,
            "include_untimed": "1" if include_untimed else "0",
        })
        status, payload, _ = self._request("GET", f"/digest?{query}")
        if status != 200:
            raise self._error(status, payload, "digest")
        body = self._json(payload, "digest")
        if body.get("digest_version") != DIGEST_VERSION:
            raise XinliqiuError(
                f"store digest version {body.get('digest_version')!r} does not match "
                f"this client ({DIGEST_VERSION}); upgrade the Worker"
            )
        if body.get("device") != device_id:
            raise XinliqiuError("cloudflare digest answered for a different device")
        return body

    def inventory(self, device_id: str | None = None) -> dict:
        path = "/inventory" + (
            "?" + urllib.parse.urlencode({"device": device_id}) if device_id else ""
        )
        status, payload, _ = self._request("GET", path)
        if status != 200:
            raise self._error(status, payload, "inventory")
        return self._json(payload, "inventory")


# --------------------------------------------------------------------------
# Shared outer-file ingestion
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OuterFile:
    """Classification of one synced outer file."""

    path: Path | None
    format: str  # cmpt | enpt | jsonl | unknown
    size_bytes: int
    container: Container | None = None
    payload: bytes = b""
    detail: str | None = None


@dataclass(frozen=True)
class EncryptedDiagnosticPolicy:
    """Explicit opt-in for uploading diagnostics, encrypted by the caller.

    ``encrypt(plaintext, name)`` must return ciphertext.  The SDK never
    encrypts on its own here because the envelope must stay decryptable by the
    owner's key; the callable typically wraps the owner public key.  The
    result is uploaded with kind ``diagnostic`` and the ``scheme`` label.
    """

    encrypt: Callable[[bytes, str], bytes]
    scheme: str = "owner-enpt"

    def apply(self, plaintext: bytes, name: str) -> bytes:
        ciphertext = self.encrypt(plaintext, name)
        if not isinstance(ciphertext, (bytes, bytearray)) or not ciphertext:
            raise ContainerError(f"diagnostic policy returned no ciphertext for {name}")
        ciphertext = bytes(ciphertext)
        if ciphertext == plaintext:
            raise ContainerError(f"diagnostic policy returned plaintext for {name}")
        if len(ciphertext) > MAX_OBJECT_BYTES:
            raise ContainerError(f"encrypted diagnostic {name} exceeds {MAX_OBJECT_BYTES} bytes")
        return ciphertext


def classify_outer_file(path: Path | str) -> OuterFile:
    """Classify a synced outer file by magic/structure, never by suffix.

    I/O errors and malformed CMPT/enpt data raise; diagnostics and unknown
    formats are returned for the caller to keep locally and report.
    """
    file_path = Path(path)
    data = file_path.read_bytes()  # OSError propagates: I/O errors fail
    if data[:4] == b"CMPT":
        from .container import parse_cmpt

        return OuterFile(
            path=file_path, format="cmpt", size_bytes=len(data),
            container=parse_cmpt(data, file_path),
        )
    if data[:4] == b"enpt":
        validate_enpt(data)
        return OuterFile(path=file_path, format="enpt", size_bytes=len(data), payload=data)
    stripped = data.lstrip()
    if stripped[:1] in (b"{", b"["):
        try:
            text = data.decode("utf-8")
            lines = [line for line in text.splitlines() if line.strip()]
            if not lines:
                raise ValueError("empty JSONL")
            for line in lines:
                json.loads(line)
        except (UnicodeDecodeError, ValueError):
            return OuterFile(
                path=file_path, format="unknown", size_bytes=len(data), payload=data,
                detail="looked like JSONL but did not parse",
            )
        return OuterFile(
            path=file_path, format="jsonl", size_bytes=len(data), payload=data,
            detail=f"{len(lines)} JSONL diagnostic lines",
        )
    return OuterFile(
        path=file_path, format="unknown", size_bytes=len(data), payload=data
    )


def _not_uploaded(
    target: list[dict], *, source: str, name: str, kind: str, reason: str, size: int
) -> None:
    target.append(
        {"source": source, "entry_name": name, "kind": kind, "reason": reason, "size_bytes": size}
    )


def ingest_outer(
    outer: OuterFile,
    storage: Storage,
    device_id: str,
    *,
    diagnostic_policy: EncryptedDiagnosticPolicy | None = None,
    not_uploaded: list[dict] | None = None,
) -> dict:
    """Ingest one classified outer file; returns per-file upload counts."""
    skipped = not_uploaded if not_uploaded is not None else []
    source = str(outer.path) if outer.path else "<bytes>"
    counts = {"stored": 0, "duplicates": 0, "total": 0, "encrypted_diagnostics": 0}

    def upload(item, diagnostic_plaintext: bytes | None = None) -> None:
        result = storage.put_entry(device_id, item)
        counts["total"] += 1
        status = result.get("status")
        if status in ("stored", "repaired"):
            counts["stored"] += 1
        elif status == "duplicate":
            counts["duplicates"] += 1
        else:
            raise XinliqiuError(f"unexpected storage status {status!r} for {item.name}")
        if diagnostic_plaintext is not None:
            counts["encrypted_diagnostics"] += 1

    def handle_plaintext(name: str, payload: bytes, kind: str, index: int = 0) -> None:
        if diagnostic_policy is None:
            _not_uploaded(
                skipped, source=source, name=name, kind=kind,
                reason="diagnostic-or-unknown-kept-local", size=len(payload),
            )
            return
        ciphertext = diagnostic_policy.apply(payload, name)
        upload(
            StorageItem(name=name, payload=ciphertext, kind=DIAGNOSTIC_KIND,
                        encryption=diagnostic_policy.scheme, index=index),
            diagnostic_plaintext=payload,
        )

    if outer.format == "cmpt":
        assert outer.container is not None
        for entry in outer.container.entries:
            kind = storage_kind(entry.name)
            if kind in CIPHERTEXT_KINDS:
                if entry.payload[:4] != b"enpt":
                    # A plaintext-named audio entry is not ciphertext: keep it
                    # local rather than weakening the store's hard rule.
                    _not_uploaded(
                        skipped, source=source, name=entry.name, kind=kind,
                        reason="payload-is-not-enpt-ciphertext", size=len(entry.payload),
                    )
                    continue
                validate_enpt(entry.payload)  # malformed enpt fails the ingest
                upload(entry)
            else:
                handle_plaintext(entry.name, entry.payload, kind, entry.index)
    elif outer.format == "enpt":
        name = outer.path.name if outer.path else "direct.enpt"
        kind = storage_kind(name)
        if kind in CIPHERTEXT_KINDS:
            upload(StorageItem(name=name, payload=outer.payload, kind=kind))
        else:
            _not_uploaded(
                skipped, source=source, name=name, kind=kind,
                reason="enpt-payload-with-unrecognised-name", size=outer.size_bytes,
            )
    else:
        name = outer.path.name if outer.path else "outer"
        handle_plaintext(name, outer.payload, outer.format)
    return counts


def ingest_files(
    paths: Iterable[Path | str],
    storage: Storage,
    device_id: str,
    *,
    diagnostic_policy: EncryptedDiagnosticPolicy | None = None,
) -> dict:
    """Classify and ingest every synced outer file, reporting what stayed local."""
    totals = {
        "stored": 0, "duplicates": 0, "total": 0, "containers": 0,
        "direct_enpt": 0, "encrypted_diagnostics": 0,
    }
    not_uploaded: list[dict] = []
    files: list[dict] = []
    for path in paths:
        outer = classify_outer_file(path)  # malformed CMPT/enpt and I/O fail
        counts = ingest_outer(
            outer, storage, device_id,
            diagnostic_policy=diagnostic_policy, not_uploaded=not_uploaded,
        )
        if outer.format == "cmpt":
            totals["containers"] += 1
        elif outer.format == "enpt":
            totals["direct_enpt"] += 1
        for key in ("stored", "duplicates", "total", "encrypted_diagnostics"):
            totals[key] += counts[key]
        files.append({
            "path": str(outer.path), "format": outer.format,
            "size_bytes": outer.size_bytes, "detail": outer.detail, **counts,
        })
    return {
        **totals,
        "files": files,
        "not_uploaded": not_uploaded,
        "not_uploaded_count": len(not_uploaded),
        "diagnostic_policy": diagnostic_policy.scheme if diagnostic_policy else None,
    }


def ingest_container(
    container: Container,
    storage: Storage,
    device_id: str,
    *,
    diagnostic_policy: EncryptedDiagnosticPolicy | None = None,
) -> dict:
    """Push the uploadable entries of a synced container into a Storage backend.

    Return keys ``stored``/``duplicates``/``total`` are unchanged for existing
    callers; ``not_uploaded`` lists everything deliberately kept local.
    """
    outer = OuterFile(
        path=container.path, format="cmpt", size_bytes=container.declared_length,
        container=container,
    )
    not_uploaded: list[dict] = []
    counts = ingest_outer(
        outer, storage, device_id,
        diagnostic_policy=diagnostic_policy, not_uploaded=not_uploaded,
    )
    return {
        **counts,
        "not_uploaded": not_uploaded,
        "not_uploaded_count": len(not_uploaded),
        "diagnostic_policy": diagnostic_policy.scheme if diagnostic_policy else None,
    }
