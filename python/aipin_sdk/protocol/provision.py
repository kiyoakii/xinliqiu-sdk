# -*- coding: utf-8 -*-
"""Provisioning built on the native protocol stack.

This is the entry point users interact with. It pairs a device, stores the
result, and reports what happened - without shelling out to an external binary.

Pairing is implemented here without shelling out to an external binary.
Owner-key INIT lives in ``client.Xinliqiu.init_device`` and uses caller-supplied
signing material; this module deliberately handles only pairing persistence.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from ..errors import XinliqiuError
from . import pairing as pairing_proto
from .auth import Pairing
from .transport import Session


class ProvisionError(XinliqiuError):
    """Provisioning could not be completed."""


class PairingOutcomeUnknown(ProvisionError):
    """The KSC request was written but its confirmation was not observed.

    ``pending_file`` holds the staged material and is deliberately kept: the
    device may have bound it. Test it (``promote_pending_pairing`` then a
    status read) before pairing again.
    """

    def __init__(self, message: str, *, pending_file: Path, peer_id_file: Path) -> None:
        super().__init__(message)
        self.pending_file = pending_file
        self.peer_id_file = peer_id_file


PAIRING_FILE = "pairing.json"
PENDING_FILE = "pairing.pending.json"
PEER_ID_FILE = "peer-id.txt"


@dataclass
class PairResult:
    pairing: Pairing
    key_file: Path
    peer_id_file: Path
    steps: list[tuple[str, int, int]]
    alias_hex: str = ""
    status: str = "paired"


def _write_private(path: Path, data: str) -> None:
    """Write credential material privately and atomically.

    A pairing file must never be left truncated by a crash, and an existing
    file's mode must be narrowed before the first byte rather than after the
    write. The visible path changes only when the complete file is in place.
    """
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = -1
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(str(tmp))
        except FileNotFoundError:
            pass
        raise


def _fsync_dir(directory: Path) -> None:
    """Make a rename durable: fsync the directory entry, best effort."""
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


PEER_ID_PREFIX = "OAFP_"
PEER_ID_LENGTH = 36


def generate_peer_id() -> str:
    """A stable 36-character identifier for this host.

    The device requires exactly 36 printable ASCII bytes with the OAFP_ prefix,
    and rejects anything else during negotiation. The value appears in the
    negotiation answer; it is an identifier, not a secret.
    """
    import secrets

    tail = PEER_ID_LENGTH - len(PEER_ID_PREFIX)
    return PEER_ID_PREFIX + secrets.token_hex(32)[:tail]


def validate_peer_id(peer_id: str) -> str:
    """Return the peer id unchanged, or explain why the device would reject it."""
    if len(peer_id) != PEER_ID_LENGTH:
        raise ProvisionError(
            f"peer id must be {PEER_ID_LENGTH} characters, got {len(peer_id)}"
        )
    if not peer_id.startswith(PEER_ID_PREFIX):
        raise ProvisionError(f"peer id must start with {PEER_ID_PREFIX}")
    if not all(32 <= ord(c) < 127 for c in peer_id):
        raise ProvisionError("peer id must be printable ASCII")
    return peer_id


def save_pairing(pairing: Pairing, path: Path, *, state: str | None = None) -> None:
    """Persist pairing material as JSON with owner-only permissions.

    The field names match the credential shape used by the device tooling
    (``kscAliasHex`` / ``providerDeviceIdHex``). ``load_pairing`` also accepts
    the legacy ``aliasHex`` / ``providerIdHex`` spellings. ``state`` records
    where in the exchange the file was written (``prepared_before_transmit`` for
    a staged copy); it is informational and ignored by :func:`load_pairing`.
    """
    payload = {
        "schemaVersion": 1,
        "kscHex": pairing.ksc.hex(),
        "kscAliasHex": pairing.alias.hex(),
        "seekerIdHex": pairing.seeker_id.hex(),
        "providerDeviceIdHex": pairing.provider_id.hex(),
    }
    if state:
        payload["state"] = state
    _write_private(path, json.dumps(payload, indent=2) + "\n")


def read_alias(path: Path) -> str | None:
    """The 12-hex KSC alias stored in a pairing file, or ``None``.

    Used to keep re-pairing on the same device slot when the remembered
    config is gone but a pairing file survived. Never raises.
    """
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    alias = data.get("kscAliasHex", data.get("aliasHex"))
    if not isinstance(alias, str):
        return None
    try:
        if len(bytes.fromhex(alias)) != 6:
            return None
    except ValueError:
        return None
    return alias.lower()


def promote_pending_pairing(out_dir: Path) -> Path:
    """Make a staged ``pairing.pending.json`` the active ``pairing.json``.

    For the case :class:`PairingOutcomeUnknown` describes, after a status read
    with the pending file succeeded. Refuses to replace an existing pairing.
    """
    out = Path(out_dir).expanduser().resolve()
    pending = out / PENDING_FILE
    target = out / PAIRING_FILE
    if not pending.exists():
        raise ProvisionError(f"no staged pairing at {pending}")
    if target.exists():
        raise ProvisionError(f"{target} already exists; move it aside first")
    load_pairing(pending)  # it must at least be well-formed
    os.replace(pending, target)
    _fsync_dir(out)
    return target


def load_pairing(path: Path) -> Pairing:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProvisionError(f"no pairing material at {path}") from exc
    except json.JSONDecodeError as exc:
        raise ProvisionError(f"pairing material at {path} is not valid JSON") from exc

    if not isinstance(data, dict):
        raise ProvisionError(f"pairing material at {path} is not a JSON object")

    # Older SDK builds wrote ``aliasHex`` / ``providerIdHex``. Keep reading
    # those files so an upgrade does not orphan an existing pairing, but always
    # write the canonical names.
    fields = {
        "kscHex": data.get("kscHex"),
        "kscAliasHex": data.get("kscAliasHex", data.get("aliasHex")),
        "seekerIdHex": data.get("seekerIdHex"),
        "providerDeviceIdHex": data.get(
            "providerDeviceIdHex", data.get("providerIdHex")
        ),
    }
    missing = [
        name for name, value in fields.items()
        if not isinstance(value, str) or not value
    ]
    if missing:
        raise ProvisionError(
            "pairing material is missing " + ", ".join(missing)
        )

    try:
        return Pairing(
            ksc=bytes.fromhex(fields["kscHex"]),
            alias=bytes.fromhex(fields["kscAliasHex"]),
            seeker_id=bytes.fromhex(fields["seekerIdHex"]),
            provider_id=bytes.fromhex(fields["providerDeviceIdHex"]),
        )
    except (TypeError, ValueError) as exc:
        raise ProvisionError(f"pairing material is malformed: {exc}") from exc


def pair(
    session: Session,
    *,
    out_dir: Path,
    alias: bytes | None = None,
    timeout: float = 40.0,
) -> PairResult:
    """Pair an already-connected device and persist the result.

    Order of durable writes:

    1. the peer id (if absent) - an identifier, written before the radio work;
    2. ``pairing.pending.json`` - staged and fsynced *before* the KSC request
       is written, so a crash can never leave a binding nobody recorded;
    3. after the device confirms, the staged file is renamed to
       ``pairing.json``.

    If the confirmation is missing or unreadable, the staged file is kept and
    :class:`PairingOutcomeUnknown` is raised. An explicit device refusal removes
    it (the key was not bound). Paths in the result are absolute.
    """
    out = Path(out_dir).expanduser().resolve()
    key_file = out / PAIRING_FILE
    pending_file = out / PENDING_FILE
    peer_file = out / PEER_ID_FILE

    if key_file.exists():
        raise ProvisionError(
            f"{key_file} already exists. Move it aside first: overwriting pairing "
            "material orphan the recordings encrypted to the previous key."
        )
    if pending_file.exists():
        raise ProvisionError(
            f"{pending_file} holds material from a pairing whose outcome was never "
            "confirmed; the device may be bound to it. Try it first "
            "(promote_pending_pairing / `xinliqiu pair --promote-pending`), or move "
            "it aside if a status read with it fails."
        )

    out.mkdir(parents=True, exist_ok=True)
    if not peer_file.exists():
        _write_private(peer_file, generate_peer_id() + "\n")

    def stage(material: Pairing) -> None:
        save_pairing(material, pending_file, state="prepared_before_transmit")

    try:
        pairing, steps = pairing_proto.pair(
            session, alias=alias, timeout=timeout, stage=stage
        )
    except pairing_proto.PairingUncertain as exc:
        raise PairingOutcomeUnknown(
            f"{exc}. The staged key is kept at {pending_file}; it may already be "
            "bound on the device. Do not pair again before testing it.",
            pending_file=pending_file,
            peer_id_file=peer_file,
        ) from exc
    except pairing_proto.PairingError:
        # A definite refusal (or a failure before the KSC write): nothing new
        # is bound, so a staged copy is not credential material.
        try:
            os.unlink(pending_file)
        except FileNotFoundError:
            pass
        raise

    if key_file.exists():
        # Someone else wrote a pairing meanwhile; keep both and say so.
        raise PairingOutcomeUnknown(
            f"pairing confirmed, but {key_file} appeared during the exchange; the "
            f"confirmed key is kept at {pending_file}",
            pending_file=pending_file,
            peer_id_file=peer_file,
        )
    os.replace(pending_file, key_file)
    _fsync_dir(out)

    return PairResult(
        pairing=pairing,
        key_file=key_file,
        peer_id_file=peer_file,
        steps=[(s.name, s.sent, s.received) for s in steps],
        alias_hex=pairing.alias.hex(),
    )
