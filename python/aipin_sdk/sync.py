# -*- coding: utf-8 -*-
"""Device-to-store replication and store-to-client pull.

Two distinct operations, often confused:

* ``push_range``  - ask the device for a time range and upload ciphertext.
* ``pull_changes`` - read what another client already uploaded.

A client never needs a private key to participate in either. Decryption is a
separate, explicit step.
"""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from typing import Protocol

from .client import Xinliqiu
from .errors import XinliqiuError
from .storage import (
    DEFAULT_CHANGES_LIMIT,
    DEFAULT_END_MS,
    DEFAULT_START_MS,
    DIGEST_VERSION,
    EncryptedDiagnosticPolicy,
    StorageIdentity,
    StoredObject,
    canonical_device_key,
    ingest_files,
    resolve_storage_identity,
    validate_limit,
    validate_since,
)


class RemoteStore(Protocol):
    def put_entry(self, device_id: str, entry) -> dict: ...
    def list(self, device_id: str, start_ms: int, end_ms: int) -> list[StoredObject]: ...
    def get(self, object_key: str) -> bytes: ...


class IncrementalStore(RemoteStore, Protocol):
    def changes(self, device_id: str, since: int = 0, limit: int = 500) -> dict: ...
    def digest(
        self,
        device_id: str,
        start_ms: int = DEFAULT_START_MS,
        end_ms: int = DEFAULT_END_MS,
        *,
        include_untimed: bool = True,
    ) -> dict: ...


def push_range(
    ball: Xinliqiu,
    store: RemoteStore,
    device_id: str | None,
    start_ms: int,
    end_ms: int,
    *,
    output_dir: Path | None = None,
    seconds: int = 300,
    storage_device_id: str | None = None,
    identity: StorageIdentity | None = None,
    diagnostic_policy: EncryptedDiagnosticPolicy | None = None,
) -> dict:
    """Fetch a device range and upload the ciphertext it contains.

    ``device_id`` is the BLE identity used for the connection; storage keys
    use a separate, stable identity (explicit > environment > saved config >
    pairing-derived > BLE UUID).  The report always states which one was used
    and whether it is stable across hosts.

    Every outer file is classified by content: CMPT containers, direct enpt
    payloads and JSONL diagnostics.  Malformed CMPT/enpt data and I/O errors
    raise instead of being counted as "skipped".  Diagnostics and unknown
    entries stay in the local output directory and are listed in
    ``not_uploaded`` unless an encrypted diagnostic policy was supplied.
    """
    resolved = identity or resolve_storage_identity(
        storage_device_id,
        credentials=getattr(ball, "credentials", None),
        ble_device_id=device_id,
    )
    result = ball.sync_range(start_ms, end_ms, output_dir, seconds=seconds)
    out_dir = Path(result["_output_dir"])
    device_sync = dict(result)
    # Keep the complete device outcome: published files can be uploaded even
    # when the range itself is partial or unverified, but that must never be
    # repackaged as a stateless success. Upload failures raise before return.
    outcome = {
        key: result.get(key)
        for key in ("state", "ok", "verified", "range_complete", "retry")
    }
    # Device-supplied file names may use any suffix, so drive the upload from
    # the files the sync actually wrote rather than a "*.bin" glob.
    upload = ingest_files(
        device_sync["files"], store, resolved.device_id,
        diagnostic_policy=diagnostic_policy,
    )
    return {
        **outcome,
        "device_sync": device_sync,
        "upload": {k: v for k, v in upload.items() if k not in ("files", "not_uploaded")},
        "files": upload["files"],
        "not_uploaded": upload["not_uploaded"],
        "not_uploaded_count": upload["not_uploaded_count"],
        "skipped_non_cmpt": sum(1 for f in upload["files"] if f["format"] != "cmpt"),
        "storage_identity": resolved.as_dict(),
        "output_dir": str(out_dir),
    }


def _local_name(object_key: str) -> str:
    """Flat, path-safe mirror file name for an object key.

    Keys produced by this SDK are already safe; anything else is sanitised and
    disambiguated with a key hash so two keys cannot collide on one file.
    """
    base = object_key.replace("/", "_")
    if base and all(c.isascii() and (c.isalnum() or c in "._-") for c in base) and ".." not in base:
        return base + ".bin"
    safe = "".join(c if c.isascii() and (c.isalnum() or c in "._-") else "_" for c in base)
    digest = hashlib.sha256(object_key.encode("utf-8")).hexdigest()[:16]
    return f"{safe[:120]}-{digest}.bin"


def _publish_verified(target: Path, data: bytes, obj: StoredObject) -> str:
    """Write one object atomically; returns written | replaced."""
    tmp = target.with_name(target.name + f".{os.getpid()}.{threading.get_ident()}.part")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    replaced = target.exists()
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            tmp.unlink()
    return "replaced" if replaced else "written"


def _verify_bytes(data: bytes, obj: StoredObject) -> None:
    if len(data) != obj.size_bytes:
        raise XinliqiuError(
            f"size mismatch for {obj.object_key}: store declared {obj.size_bytes}, "
            f"got {len(data)}"
        )
    actual = hashlib.sha256(data).hexdigest()
    if actual != obj.sha256:
        raise XinliqiuError(
            f"sha256 mismatch for {obj.object_key}: store declared {obj.sha256}, got {actual}"
        )


def pull_changes(
    store: IncrementalStore,
    device_id: str,
    *,
    since: int = 0,
    limit: int = DEFAULT_CHANGES_LIMIT,
    download: bool = False,
    local_dir: Path | None = None,
) -> dict:
    """Read what a store holds beyond a cursor, verifying every byte.

    With ``download=True`` each object is fetched, checked against the
    declared size and SHA-256, and published atomically under ``local_dir``.
    Existing files are verified too: a matching file is reused, a corrupt one
    is replaced by a verified copy and reported in ``replaced``.  Any failure
    raises before the cursor is returned, so a caller's persisted cursor only
    ever advances past a completely verified page.
    """
    validate_since(since)
    validate_limit(limit)
    if download and local_dir is None:
        raise ValueError("download=True requires local_dir")
    page = store.changes(device_id, since=since, limit=limit)
    objects = page["objects"]
    cursor = page["cursor"]
    if objects and cursor <= since:
        raise XinliqiuError("store returned objects without advancing the cursor")
    written: list[str] = []
    replaced: list[str] = []
    verified_existing: list[str] = []
    if download and local_dir is not None:
        local_dir = Path(local_dir)
        local_dir.mkdir(parents=True, exist_ok=True)
        for obj in objects:
            target = local_dir / _local_name(obj.object_key)
            if target.exists():
                try:
                    existing = target.read_bytes()
                except OSError as exc:
                    raise XinliqiuError(f"cannot read existing mirror file {target}: {exc}") from exc
                if len(existing) == obj.size_bytes and hashlib.sha256(existing).hexdigest() == obj.sha256:
                    verified_existing.append(str(target))
                    continue
            data = store.get(obj.object_key)
            _verify_bytes(data, obj)
            outcome = _publish_verified(target, data, obj)
            (replaced if outcome == "replaced" else written).append(str(target))
    return {
        "count": len(objects),
        "cursor": cursor,
        "has_more": page["has_more"],
        "latest_seq": page.get("latest_seq"),
        "objects": [
            {
                "object_key": o.object_key,
                "entry_name": o.entry_name,
                "kind": o.kind,
                "size_bytes": o.size_bytes,
                "sha256": o.sha256,
                "start_ms": o.start_ms,
                "end_ms": o.end_ms,
                "seq": o.seq,
            }
            for o in objects
        ],
        "written": written,
        "replaced": replaced,
        "verified_existing": verified_existing,
        "verified": len(objects) if download else 0,
    }


def compare(
    store: IncrementalStore,
    device_id: str,
    other: dict,
    start_ms: int | None = None,
    end_ms: int | None = None,
    *,
    include_untimed: bool | None = None,
) -> dict:
    """Compare this store's digest against another client's digest.

    Digests are only comparable for the same device, range, untimed policy and
    digest version; a mismatch is reported explicitly instead of being
    mistaken for "out of sync".
    """
    start = other.get("start_ms", DEFAULT_START_MS) if start_ms is None else start_ms
    end = other.get("end_ms", DEFAULT_END_MS) if end_ms is None else end_ms
    untimed = other.get("include_untimed", True) if include_untimed is None else include_untimed
    mine = store.digest(device_id, start, end, include_untimed=untimed)
    reasons = []
    if other.get("digest_version") != DIGEST_VERSION:
        reasons.append("digest-version")
    if other.get("device") != device_id:
        reasons.append("device")
    if other.get("device_key") not in (None, canonical_device_key(device_id)):
        reasons.append("device-key")
    if other.get("start_ms") != start or other.get("end_ms") != end:
        reasons.append("range")
    if bool(other.get("include_untimed", True)) != bool(untimed):
        reasons.append("untimed-policy")
    comparable = not reasons
    return {
        "comparable": comparable,
        "mismatches": reasons,
        "in_sync": comparable and mine.get("digest") == other.get("digest"),
        "local": mine,
        "remote": other,
    }
