# -*- coding: utf-8 -*-
"""SystemFT: the file stream that carries recordings off the device.

Once the file service is open, the device pushes files over two kinds of
session:

* the **control** session carries JSON messages (``0x00`` plain flag, then the
  message body),
* each **data** session carries one file (``0x00`` plain flag, then ``0x01``
  chunk header byte, then raw bytes).

There is no per-chunk offset, length, CRC or acknowledgement at this layer. A
chunk is just bytes appended in order; the only integrity check is the optional
MD5 in the setup message, verified after the final byte.

Bytes are staged in ``<fileName>.part``. Once the declared size has arrived
the staging file is flushed, fsynced and MD5-checked (:meth:`IncomingFile.seal`),
then ``complete-req`` is sent. The final name is created by an atomic rename
(:meth:`IncomingFile.publish`) only after the peer's ``complete-rsp`` for the
same ``transId`` reports ``result 0``; a rejection abandons the staging file.
The final name therefore never holds a half-written, unverified or
peer-rejected file. ``abandon()`` removes the staging file.

Lifecycle of one file::

    <- setup-req   {transId, fileName, filePath, fileSize, channelId, ...}
    -> setup-rsp   {result: 0}            accept, or {result: 1, reason: N}
    <- data        channelId: 0x00 0x01 <bytes>
    -> complete-req{transId}              once fileSize bytes have arrived
    <- complete-rsp{transId, result: 0}   only now is the file published

This module holds the wire format and the per-file state machine. Driving it
over Bluetooth lives in :mod:`.sync`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from ..errors import XinliqiuError

# Body framing.
PLAIN_CHANNEL_FLAG = 0x00
CHUNK_HEADER_BYTE = 0x01

# Control channel within the file service.
CONTROL_CHANNEL_ID = 100

# Message identifiers, lowercase as the device sends them.
MSG_SETUP_REQ = "filetransfer-setup-req"
MSG_SETUP_RSP = "filetransfer-setup-rsp"
MSG_COMPLETE_REQ = "filetransfer-complete-req"
MSG_COMPLETE_RSP = "filetransfer-complete-rsp"
MSG_CANCEL_REQ = "filetransfer-cancel-req"
MSG_CANCEL_RSP = "filetransfer-cancel-rsp"
MSG_PROGRESS = "filetransfer-receive-progress"
MSG_WINDOW = "filetransfer-window-size"
MSG_APPALIVE_REQ = "filetransfer-appalive-req"
MSG_APPALIVE_RSP = "filetransfer-appalive-rsp"

# Rejection reasons the device defines. Only the ones this code emits are named.
REASON_BAD_CHANNEL = 1
REASON_SINK_FAILED = 2
REASON_DUPLICATE = 8
REASON_POLICY = 9
REASON_MD5_MISMATCH = 10

MAX_CHUNK_BYTES = 64 * 1024

# Every transfer is staged next to its final name under this suffix.
PART_SUFFIX = ".part"

# Structural limits for a setup request. ``fileName`` becomes a host path and
# the device is not trusted, so a NUL, an empty name or an absurd length is a
# malformed message to reject, not something to sanitise silently.
MAX_FILE_NAME_CHARS = 200
MD5_HEX_CHARS = 32
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class FileTransferError(XinliqiuError):
    """A transfer frame was malformed or arrived out of order."""


def _require_int(obj: dict, key: str) -> int:
    """A required JSON integer field, validated rather than coerced.

    ``int("3")`` and ``int(True)`` both succeed, but neither is what the wire
    format means. Coercing here would accept a malformed offer and move the
    failure into the transfer, where the device can no longer be told why.
    """
    if key not in obj:
        raise FileTransferError(f"setup request is missing {key}")
    value = obj[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise FileTransferError(f"setup request field {key} is not an integer")
    return value


def _optional_int(obj: dict, key: str) -> int | None:
    if obj.get(key) is None:
        return None
    return _require_int(obj, key)


def _require_text(obj: dict, key: str) -> str:
    """An identifier field, coerced to text.

    The device is inconsistent about quoting numeric ids (``channelId`` in
    particular), and none of these fields becomes a path, so the original
    coercion is kept. A missing or null field is still a malformed offer.
    """
    if key not in obj:
        raise FileTransferError(f"setup request is missing {key}")
    value = obj[key]
    if value is None:
        raise FileTransferError(f"setup request field {key} is null")
    return str(value)


def _parse_file_name(obj: dict) -> str:
    """Validate ``fileName`` before it can become a path.

    A NUL truncates the name at the C layer, and a stray surrogate cannot be
    re-encoded into the reject reply, so both are rejected here rather than
    producing a path the receiver cannot trust.
    """
    name = obj.get("fileName")
    if not isinstance(name, str):
        raise FileTransferError("setup request field fileName is not a string")
    if not 1 <= len(name) <= MAX_FILE_NAME_CHARS:
        raise FileTransferError(
            f"setup request fileName is {len(name)} characters, "
            f"expected 1..{MAX_FILE_NAME_CHARS}"
        )
    if "\x00" in name:
        raise FileTransferError("setup request fileName contains NUL")
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        raise FileTransferError(
            "setup request fileName is not valid UTF-8"
        ) from None
    return name


def _validate_md5(value: object) -> str:
    """A digest must be exactly 32 hexadecimal characters to be comparable."""
    if (
        not isinstance(value, str)
        or len(value) != MD5_HEX_CHARS
        or any(char not in _HEX_DIGITS for char in value)
    ):
        raise FileTransferError(
            "setup request md5 is not 32 hexadecimal characters"
        )
    return value


def _parse_md5(obj: dict) -> str | None:
    """The optional digest, or ``None`` when the sender supplied none.

    Anything other than exactly 32 hexadecimal characters cannot be compared
    against an MD5 later, so a digest of the wrong shape rejects the offer
    instead of failing - or silently skipping verification - at the end.
    """
    value = obj.get("md5")
    if value is None or value == "":
        return None  # no digest supplied
    return _validate_md5(value)


@dataclass(frozen=True)
class SetupRequest:
    trans_id: int
    file_name: str
    file_path: str
    file_size: int
    peer_id: str
    container_id: str
    channel_id: str
    md5: str | None = None
    file_last_modified: int | None = None
    file_author: str | None = None
    file_info: str | None = None

    def __post_init__(self) -> None:
        # ``from_json`` validates already; direct construction must not be able
        # to smuggle a digest that ``finish`` would then compare unchecked.
        if self.md5 is not None:
            _validate_md5(self.md5)

    @property
    def channel(self) -> int:
        """The numeric channel id, parsed from its string form."""
        try:
            return int(self.channel_id)
        except (TypeError, ValueError):
            raise FileTransferError(
                f"channel id {self.channel_id!r} is not numeric"
            ) from None

    @classmethod
    def from_json(cls, payload: bytes) -> "SetupRequest":
        obj = _decode_json(payload)
        return cls(
            trans_id=_require_int(obj, "transId"),
            file_name=_parse_file_name(obj),
            file_path=_require_text(obj, "filePath"),
            file_size=_require_int(obj, "fileSize"),
            peer_id=_require_text(obj, "peerId"),
            container_id=_require_text(obj, "containerId"),
            channel_id=_require_text(obj, "channelId"),
            md5=_parse_md5(obj),
            file_last_modified=_optional_int(obj, "fileLastModified"),
            file_author=obj.get("fileAuthor"),
            file_info=obj.get("fileInfo"),
        )


@dataclass(frozen=True)
class CompleteResponse:
    trans_id: int
    result: int
    reason: int

    @classmethod
    def from_json(cls, payload: bytes) -> "CompleteResponse":
        obj = _decode_json(payload)
        values: dict[str, int] = {}
        for key in ("transId", "result", "reason"):
            # JSON booleans are Python ints, and int() also accepts strings and
            # integral floats. None of those is a valid transaction response.
            if key not in obj or type(obj[key]) is not int:
                raise FileTransferError(
                    f"complete response field {key} must be a JSON integer"
                )
            values[key] = obj[key]
        return cls(
            trans_id=values["transId"],
            result=values["result"],
            reason=values["reason"],
        )


def _decode_json(payload: bytes) -> dict:
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FileTransferError(f"control body is not JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise FileTransferError("control body is not a JSON object")
    return obj


def _encode_json(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def message_id(payload: bytes) -> str:
    """The lowercased ``msgId`` of a control body."""
    value = _decode_json(payload).get("msgId")
    if not isinstance(value, str) or not value:
        raise FileTransferError("control body has no msgId")
    return value.lower()


def encode_setup_accept(request: SetupRequest, *, max_window: int = 0) -> bytes:
    """Accept a file offer."""
    return _encode_json(
        {
            "msgId": MSG_SETUP_RSP,
            "transId": request.trans_id,
            "result": 0,
            "reason": 0,
            "maxWindowSize": max_window,
            "flowControlFlag": 0,
            "fileName": request.file_name,
        }
    )


def encode_setup_reject(request: SetupRequest, reason: int) -> bytes:
    return encode_setup_reject_fields(request.trans_id, reason, request.file_name)


def encode_setup_reject_fields(
    trans_id: int, reason: int, file_name: str = ""
) -> bytes:
    """Reject a transaction by id.

    Needed when the offer was too malformed to yield a :class:`SetupRequest`
    but still named a transaction, so the device is not left waiting.
    """
    return _encode_json(
        {
            "msgId": MSG_SETUP_RSP,
            "transId": trans_id,
            "result": 1,
            "reason": reason,
            "maxWindowSize": 0,
            "flowControlFlag": 0,
            "fileName": file_name,
        }
    )


def encode_complete_request(trans_id: int, file_name: str | None = None) -> bytes:
    body = {"msgId": MSG_COMPLETE_REQ, "transId": trans_id}
    if file_name is not None:
        body["fileName"] = file_name
    return _encode_json(body)


def encode_cancel_request(trans_id: int, reason: int) -> bytes:
    """Ask the peer to abandon a transaction this receiver cannot finish.

    Sent after a local failure (overflow, sink error, digest mismatch) so the
    sender stops pushing bytes for a file that will never be published.
    """
    return _encode_json(
        {"msgId": MSG_CANCEL_REQ, "transId": trans_id, "reason": reason}
    )


def is_voiceprint_name(file_name: str) -> bool:
    """True for the explicit voiceprint feature file, ``*.vp.opus``.

    ``.enc.vp.opus`` is covered by the same suffix. End markers and every other
    recording name are not voiceprint files. Only the last path component is
    considered; the name is a policy selector, never a local path.
    """
    if not isinstance(file_name, str):
        return False
    name = file_name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name.endswith(".vp.opus") and not name.endswith(".end.enc.opus")


def encode_progress(trans_id: int, received: int, file_name: str | None = None) -> bytes:
    body = {"msgId": MSG_PROGRESS, "transId": trans_id, "progress": received}
    if file_name is not None:
        body["fileName"] = file_name
    return _encode_json(body)


def encode_appalive_response(trans_id: int, *, result: int = 0, reason: int = -1) -> bytes:
    return _encode_json(
        {
            "msgId": MSG_APPALIVE_RSP,
            "transId": trans_id,
            "result": result,
            "reason": reason,
        }
    )


def encode_cancel_response(trans_id: int, reason: int, *, result: int = 0) -> bytes:
    """Acknowledge a peer cancellation.

    the protocol sends this before releasing the partial;
    a receiver that stays silent leaves the sender waiting on its cancel.
    """
    return _encode_json(
        {
            "msgId": MSG_CANCEL_RSP,
            "transId": trans_id,
            "result": result,
            "reason": reason,
        }
    )


def decode_chunk(payload: bytes) -> bytes:
    """Strip the ``0x01`` chunk header.

    ``payload`` is what remains after the plain channel flag, so its first byte
    must be the chunk header. A different value means this is not file data.
    """
    if not payload:
        raise FileTransferError("empty chunk")
    if payload[0] != CHUNK_HEADER_BYTE:
        raise FileTransferError(
            f"not a data chunk (header 0x{payload[0]:02x}, expected 0x01)"
        )
    body = payload[1:]
    if len(body) > MAX_CHUNK_BYTES:
        raise FileTransferError(f"chunk of {len(body)} bytes exceeds the limit")
    return body


def wrap_chunk(data: bytes) -> bytes:
    """Inverse of :func:`decode_chunk`, for tests and for senders."""
    return bytes([CHUNK_HEADER_BYTE]) + data


def wrap_control(message: bytes) -> bytes:
    """A control body as it appears on the wire: plain flag then JSON."""
    return bytes([PLAIN_CHANNEL_FLAG]) + message


def part_path_for(path: Path) -> Path:
    """The staging path a final path is written under."""
    return path.with_name(path.name + PART_SUFFIX)


def _fsync_parent(path: Path) -> None:
    """Persist the final directory entry after an atomic publish, best effort."""
    try:
        fd = os.open(str(path.parent), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


@dataclass
class IncomingFile:
    """One file being received.

    The final name is never opened for writing: bytes go to ``<name>.part``.
    Publication atomically hard-links that sealed staging file to the final
    name and then removes the staging link, only after transfer completion,
    digest verification and the peer's confirmation. Link creation is
    no-clobber: a final created by anyone after reservation is preserved.
    That keeps an interrupted transfer from leaving a plausible-looking
    recording, and keeps a concurrent reader from seeing half a file.
    """

    request: SetupRequest
    path: Path
    received: int = 0
    digest: "hashlib._Hash" = field(default_factory=hashlib.md5)
    _handle: BinaryIO | None = None
    sealed: bool = False
    published: bool = False

    @property
    def part_path(self) -> Path:
        return part_path_for(self.path)

    def open(self) -> None:
        """Create the staging file exclusively.

        ``O_EXCL`` refuses any path that already exists and ``O_NOFOLLOW``
        refuses to traverse a link, so a planted symlink or a stale ``.part``
        cannot redirect this write. ``EEXIST`` surfaces as
        :class:`FileExistsError` for the caller to try the next name.
        """
        if self._handle is not None:
            raise FileTransferError("file is already open")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(self.part_path, flags, 0o600)
        try:
            self._handle = os.fdopen(fd, "wb")
        except OSError:
            os.close(fd)
            raise

    def write(self, data: bytes) -> None:
        handle = self._handle
        if handle is None:
            raise FileTransferError("file is not open")
        if self.received + len(data) > self.request.file_size:
            raise FileTransferError(
                f"chunk would exceed the declared size {self.request.file_size}"
            )
        handle.write(data)
        self.digest.update(data)
        self.received += len(data)

    def seal(self) -> str:
        """Flush, fsync, close and verify the staging file; do not publish.

        The handle is closed in a ``finally`` before the digest check, so an
        ``ENOSPC``/``EIO`` during flush cannot leak a descriptor. Returns the
        hex MD5 of what was received. Raises :class:`FileTransferError` when the
        sender supplied a digest that does not match.
        """
        if self.sealed:
            return self.digest.hexdigest()
        handle = self._handle
        if handle is None:
            raise FileTransferError("file is not open")
        if self.received != self.request.file_size:
            raise FileTransferError(
                f"cannot seal {self.request.file_name}: {self.received} of "
                f"{self.request.file_size} bytes received"
            )
        try:
            try:
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                # Close before the digest check and whatever happens above: a
                # close that is skipped on the error path leaks the descriptor
                # and leaves the staging bytes behind.
                handle.close()
        finally:
            self._handle = None

        actual = self.digest.hexdigest()
        if self.request.md5:
            expected = self.request.md5.lower()
            # Constant-time comparison: the digest comes from the peer and a
            # byte-by-byte comparison would leak how much of it matched.
            if not hmac.compare_digest(actual, expected):
                raise FileTransferError(
                    f"MD5 mismatch for {self.request.file_name}: "
                    f"expected {expected}, got {actual}"
                )
        self.sealed = True
        return actual

    def publish(self) -> Path:
        """Atomically publish the sealed file without replacing an existing name.

        Call only after the peer confirmed the transaction (``complete-rsp``
        result 0). ``os.replace`` would silently overwrite a file created after
        name reservation. A hard link instead creates the final directory entry
        atomically with O_EXCL-like no-clobber behaviour: if a racer got there
        first, ``FileExistsError`` leaves both the racer and staging file
        untouched. Once linked, both names reference the same sealed inode;
        removing the staging link completes publication without a copy or a
        partially visible final file.
        """
        if not self.sealed:
            raise FileTransferError("file must be sealed before it is published")
        if self.published:
            return self.path
        os.link(self.part_path, self.path, follow_symlinks=False)
        self.published = True
        try:
            self.part_path.unlink()
        except OSError:
            # The final name already exists and is the publication point; a
            # leftover staging link must not make the caller report the file
            # as lost. The next run's stale-part cleanup removes it.
            pass
        _fsync_parent(self.path)
        return self.path

    def finish(self) -> str:
        """Seal and publish in one step (no peer confirmation in between).

        Kept for callers that drive :class:`IncomingFile` directly. The sync
        receiver uses :meth:`seal` and :meth:`publish` separately so that
        nothing is published before the peer's ``complete-rsp``.
        """
        actual = self.seal()
        self.publish()
        return actual

    def abandon(self) -> None:
        """Drop the staging file; the final name was never touched."""
        if self.published:
            return  # a confirmed, published file is never removed here
        handle, self._handle = self._handle, None
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        try:
            self.part_path.unlink()
        except OSError:
            pass

    @property
    def complete(self) -> bool:
        return self.received == self.request.file_size