# -*- coding: utf-8 -*-
"""First-time provisioning: turn a fresh device into one this SDK can talk to.

Pairing and owner-key installation are separate operations:

* ``pair`` / ``pair_device`` establish a KSC and write ``pairing.json`` plus a
  stable peer id. They do not format, flash, or erase recordings.
* ``client.Xinliqiu.init_device`` installs an owner public key through the
  explicitly confirmed INIT path, which will erase existing content. It needs
  caller-supplied signing material and verifies the owner private/public key
  match before radio use. The helpers here generate and check that owner key material.

Without an owner private key, callers can still pair and move ciphertext, but
cannot decrypt it. See docs/getting-started.md for the operational and evidence limits.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import XinliqiuError
from .protocol.provision import (
    PENDING_FILE,
    PairResult,
    PairingOutcomeUnknown,
    load_pairing,
    pair,
    promote_pending_pairing,
    read_alias,
    validate_peer_id,
)


@dataclass(frozen=True)
class Provisioned:
    device_id: str
    key_file: Path
    peer_id_file: Path
    paired: bool


# Pairing JSON is validated by protocol.provision.load_pairing so legacy
# alias/provider spellings stay usable after an upgrade.


def _unlink_quiet(path: Path) -> None:
    try:
        os.unlink(str(path))
    except FileNotFoundError:
        pass


def _stage_file(path: Path, payload: bytes, mode: int) -> Path:
    """Write ``payload`` to ``<path>.tmp`` and return the temporary path.

    The descriptor is made owner-only before any bytes are written, so an
    existing file's wider permissions can never leak through. Nothing visible
    at ``path`` changes until the caller renames the temporary into place.
    """
    tmp = path.with_name(path.name + ".tmp")
    fd = -1
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        return tmp
    except BaseException:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        _unlink_quiet(tmp)
        raise


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = _stage_file(path, payload, mode)
    try:
        os.replace(tmp, path)
    except BaseException:
        _unlink_quiet(tmp)
        raise


def _write_private(path: Path, data: str) -> None:
    """Write ``data`` privately and atomically.

    A crash must never leave a truncated credential behind, and an existing
    file's mode must be narrowed before the first byte (``fchmod``) rather
    than after the write.
    """
    _atomic_write(path, data.encode("utf-8"), 0o600)


def _owner_key_exists(target: Path) -> XinliqiuError:
    return XinliqiuError(
        f"an owner key already exists at {target}.\n"
        "Replacing it would make every recording encrypted to the old key "
        "permanently unreadable. Move it aside first, then rerun."
    )


def generate_peer_id() -> str:
    """Delegate to the protocol implementation.

The device requires exactly 36 characters; an earlier local copy produced 37
and every negotiation was rejected.
"""
    from .protocol.provision import generate_peer_id as _impl

    return _impl()


def recover_alias(out_dir: Path | str | None, *extra_files: Path | str | None) -> str | None:
    """The alias an earlier pairing used, read from surviving pairing files.

    Checked in order: each ``extra_files`` entry, then ``<out_dir>/pairing.json``
    and ``<out_dir>/pairing.pending.json``. Re-pairing under this alias makes
    the device update the slot this host already owns instead of evicting a
    least-recently-used one, even when the remembered config was lost.
    """
    candidates: list[Path] = [Path(f).expanduser() for f in extra_files if f]
    if out_dir:
        base = Path(out_dir).expanduser()
        candidates += [base / "pairing.json", base / PENDING_FILE]
    for candidate in candidates:
        alias = read_alias(candidate)
        if alias:
            return alias
    return None


def pair_device(
    device_id: str,
    out_dir: Path,
    ksc_alias: str | None = None,
    *,
    timeout: float = 40.0,
    connect_timeout: float = 30.0,
) -> PairResult:
    """Pair a device by identifier and persist the result.

    This is the entry point the CLI uses: it opens the link, runs the pairing
    exchange, stages the key before the KSC write, promotes it after the
    device confirms, and closes the link. Paths in the result are absolute.

    Without ``ksc_alias`` the alias of a pairing file already in ``out_dir``
    is reused, so a lost config never costs the user's phone its slot.
    """
    from .protocol.bleak_backend import BleakBackend
    from .protocol.pairing import SUBSCRIBE_ORDER
    from .protocol.transport import Session

    out = Path(out_dir).expanduser().resolve()
    # Validate the remembered alias before touching the radio: a corrupted
    # config value should not cost a connection attempt or leak a ValueError.
    alias = _alias_bytes(ksc_alias or recover_alias(out))
    if (out / "pairing.json").exists():
        raise XinliqiuError(
            f"{out / 'pairing.json'} already exists. Move it aside first: "
            "overwriting pairing material orphans the key it holds."
        )
    if (out / PENDING_FILE).exists():
        raise PairingOutcomeUnknown(
            f"{out / PENDING_FILE} holds a key whose binding was never confirmed. "
            "Test it with `xinliqiu pair --promote-pending --out-dir "
            f"{out}` and a status read before pairing again.",
            pending_file=out / PENDING_FILE,
            peer_id_file=out / "peer-id.txt",
        )
    backend = BleakBackend()
    try:
        session = Session(backend, device_id, timeout=connect_timeout)
        session.open(SUBSCRIBE_ORDER)
        return pair(session, out_dir=out, alias=alias, timeout=timeout)
    finally:
        backend.disconnect()


def _alias_bytes(ksc_alias: str | None) -> bytes | None:
    if not ksc_alias:
        return None
    try:
        alias = bytes.fromhex(ksc_alias)
    except (TypeError, ValueError) as exc:
        raise XinliqiuError(
            f"saved KSC alias {ksc_alias!r} is not valid hexadecimal; "
            "re-pair to replace it"
        ) from exc
    if len(alias) != 6:
        raise XinliqiuError(
            f"saved KSC alias {ksc_alias!r} is not 6 bytes (12 hex characters)"
        )
    return alias


def default_owner_key_path() -> Path:
    """Where the owner key lives by default.

    A dotfile under the user's home directory, not the working directory: a
    key that is lost with a `cd` or a deleted checkout is a key that takes
    every recording with it.
    """
    override = os.environ.get("XINLIQIU_OWNER_KEY_DIR")
    base = (
        Path(override).expanduser().absolute()
        if override else Path.home() / ".config" / "xinliqiu"
    )
    return base / "owner.pem"


def generate_owner_key(
    out_dir: Path | str | None = None,
    *,
    bits: int = 2048,
    overwrite: bool = False,
) -> dict:
    """Create an owner key pair and report where the pieces went.

    Refuses to overwrite an existing key unless asked: replacing it makes every
    recording encrypted to the previous key permanently unreadable.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as exc:  # pragma: no cover
        raise XinliqiuError(
            "generating a key requires the cryptography package: "
            "pip install xinliqiu-sdk"
        ) from exc

    target = (
        (Path(out_dir).expanduser() / "owner.pem").absolute()
        if out_dir
        else default_owner_key_path()
    )
    spki = target.with_suffix(".spki.txt")

    if not overwrite and target.exists():
        raise _owner_key_exists(target)

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    target.parent.mkdir(parents=True, exist_ok=True)

    old_spki: bytes | None = None
    if spki.exists():
        try:
            old_spki = spki.read_bytes()
        except OSError:
            old_spki = None

    # Claim the destination before writing anything visible. O_EXCL closes the
    # check-then-write race: two concurrent keygens cannot both replace the
    # same key. --force deliberately skips the claim.
    claimed = False
    if not overwrite:
        try:
            fd = os.open(
                str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
        except FileExistsError as exc:
            raise _owner_key_exists(target) from exc
        try:
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        except BaseException:
            _unlink_quiet(target)
            raise
        claimed = True

    key_tmp: Path | None = None
    spki_tmp: Path | None = None
    spki_replaced = False
    try:
        # The public half goes first: whichever step fails, a private key is
        # never left behind without its matching .spki.txt.
        spki_tmp = _stage_file(spki, base64.b64encode(der), 0o644)
        # Stage the private half already at 0400: once it replaces the
        # destination there is no later chmod that could fail and leave a
        # half-finished pair.
        key_tmp = _stage_file(target, pem.encode("ascii"), 0o400)
        os.replace(spki_tmp, spki)
        spki_tmp = None
        spki_replaced = True
        os.replace(key_tmp, target)
        key_tmp = None
    except BaseException:
        for tmp in (key_tmp, spki_tmp):
            if tmp is not None:
                _unlink_quiet(tmp)
        if spki_replaced:
            if old_spki is None:
                _unlink_quiet(spki)
            else:
                try:
                    _atomic_write(spki, old_spki, 0o644)
                except OSError:
                    pass
        if claimed:
            _unlink_quiet(target)
        raise

    return {
        "private_key": str(target),
        "public_key_spki": str(spki),
        "bits": bits,
        "warning": (
            "Back this file up now, somewhere outside this machine. If it is "
            "lost, every recording encrypted to it becomes unreadable forever. "
            "There is no recovery and no reset."
        ),
    }


def verify_owner_key(private_key: Path | str, sample: bytes | None = None) -> dict:
    """Check that a private key is present, readable, and actually usable.

    ``sample`` is an enpt payload; when supplied the key is exercised against
    it, which is the only check that proves the key matches this device.
    """
    path = Path(private_key).expanduser()
    if not path.exists():
        return {"ok": False, "reason": "missing", "path": str(path)}

    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        return {"ok": False, "reason": f"unreadable: {exc}", "path": str(path)}

    if mode & 0o077:
        return {
            "ok": False,
            "reason": (
                f"private key permissions are too open ({oct(mode)}); "
                "chmod 600 it"
            ),
            "path": str(path),
            "mode": oct(mode),
        }

    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:  # pragma: no cover
        return {"ok": False, "reason": "cryptography package not installed"}

    try:
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": f"unreadable: {exc}", "path": str(path)}

    result = {
        "ok": True,
        "path": str(path),
        "bits": getattr(loaded, "key_size", None),
        "mode": oct(mode),
    }
    if sample is not None:
        from .container import decrypt_enpt

        try:
            decrypt_enpt(sample, path)
            result["decrypted_sample"] = True
        except Exception:  # noqa: BLE001
            result["decrypted_sample"] = False
            result["ok"] = False
            result["reason"] = "key does not match this recording"
    return result


def doctor(
    device_id: str | None,
    peer_id_file: Path | str | None,
    key_file: Path | str | None,
    owner_key: Path | str | None = None,
    *,
    agent_public_key: Path | str | None = None,
    owner_public_key: Path | str | None = None,
) -> dict:
    """Check local prerequisites and report what is missing.

    Never contacts the device and never writes anything. Every check reports
    the absolute path it looked at. The peer id is validated exactly as the
    device validates it; the pairing file must load; an agent public key must
    be a valid SPKI; an owner key must load, be private (mode 0600/0400), and
    match ``owner_public_key`` when that is given.
    """
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    def absolute(value) -> Path | None:
        return Path(value).expanduser().absolute() if value else None

    check("device_id", bool(device_id), device_id or "missing")

    peer_path = absolute(peer_id_file)
    key_path = absolute(key_file)
    owner_path = absolute(owner_key)
    agent_path = absolute(agent_public_key)
    owner_pub_path = absolute(owner_public_key)

    for label, path in (
        ("peer_id_file", peer_path),
        ("key_file", key_path),
    ):
        if path is None:
            check(label, False, "not provided")
            continue
        try:
            info = path.stat()
        except OSError as exc:
            check(label, False, f"{path}: {exc.strerror or exc}")
            continue
        is_file = stat.S_ISREG(info.st_mode)
        mode = stat.S_IMODE(info.st_mode)
        check(label, is_file, f"{path} mode={oct(mode)}" + ("" if is_file else " (not a file)"))
        if is_file and label == "key_file" and mode & 0o077:
            # Not a readiness gate, but worth fixing: the KSC is a secret.
            check("key_file_private", False, f"mode {oct(mode)} is readable by others; chmod 600")

    if peer_path and peer_path.is_file():
        try:
            content = peer_path.read_text(encoding="utf-8").strip()
            validate_peer_id(content)
        except (OSError, UnicodeDecodeError) as exc:
            check("peer_id", False, f"unreadable: {exc}")
        except XinliqiuError as exc:
            check("peer_id", False, str(exc))
        else:
            check("peer_id", True, "36 printable ASCII characters with the OAFP_ prefix")
        # Keep the older check name as an alias for scripts that consumed it;
        # it now covers the full device-side validation, not just length.
        peer_check = next((c for c in checks if c["check"] == "peer_id"), None)
        if peer_check is not None:
            checks.append({"check": "peer_id_length", "ok": peer_check["ok"],
                           "detail": peer_check["detail"]})

    if key_path and key_path.is_file():
        try:
            data = json.loads(key_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            check("key_file_json", False, f"not valid JSON: {exc}")
        else:
            if not isinstance(data, dict):
                check("key_file_json", False, "not a JSON object")
            else:
                # load_pairing accepts the legacy aliasHex/providerIdHex
                # spellings too; a presence check on canonical names would
                # reject a credential that still authenticates.
                try:
                    load_pairing(key_path)
                except Exception as exc:  # noqa: BLE001
                    check(
                        "key_file_json",
                        False,
                        f"not a usable pairing file: {exc}",
                    )
                else:
                    check("key_file_json", True, "parsed")
        pending = key_path.with_name(PENDING_FILE)
        if key_path.name == PENDING_FILE:
            # The pending file is the documented recovery credential; pointing
            # a command at it must not be reported as a staged leftover.
            check("pending_pairing", True, f"using the pending pairing at {key_path}")
        elif pending.exists():
            check(
                "pending_pairing", False,
                f"{pending} is a staged key from an unconfirmed pairing; resolve it "
                "before pairing again",
            )
        else:
            check("pending_pairing", True, f"no staged pairing at {pending}")

    if agent_path is not None:
        from .protocol.connect import ConnectError, load_agent_public_key, validate_agent_spki

        try:
            der = load_agent_public_key(agent_path)
            algorithm = validate_agent_spki(der)
        except ConnectError as exc:
            check("agent_public_key", False, f"{agent_path}: {exc}")
        else:
            check("agent_public_key", True, f"{agent_path} {algorithm} SPKI, {len(der)} bytes")

    if owner_path is None:
        check("owner_key", False, "not provided (needed only to decrypt audio)")
        if owner_pub_path is not None:
            check(
                "owner_key_matches_public", False,
                "--owner-public-key requires --owner-key to check the match",
            )
    else:
        verdict = verify_owner_key(owner_path)
        if verdict.get("ok"):
            check("owner_key", True, f"{owner_path} RSA-{verdict.get('bits')} mode={verdict.get('mode')}")
        else:
            check("owner_key", False, f"{owner_path}: {verdict.get('reason')}")
        if owner_pub_path is not None:
            if not verdict.get("ok"):
                check("owner_key_matches_public", False, "owner private key is unusable")
            else:
                try:
                    match = owner_key_matches_public(owner_path, owner_pub_path)
                except XinliqiuError as exc:
                    check("owner_key_matches_public", False, str(exc))
                else:
                    check(
                        "owner_key_matches_public", match,
                        "private key matches the public key" if match
                        else f"{owner_path} does not match {owner_pub_path}",
                    )

    required = {
        "device_id",
        "peer_id_file",
        "key_file",
        "peer_id",
        "peer_id_length",
        "key_file_json",
        "pending_pairing",
    }
    if any(c["check"] == "key_file_private" for c in checks):
        required.add("key_file_private")
    if owner_path is not None:
        required.add("owner_key")
        if owner_pub_path is not None:
            required.add("owner_key_matches_public")
    elif owner_pub_path is not None:
        # A public-only check can never be ready: there is nothing to compare.
        required.add("owner_key_matches_public")
    if agent_path is not None:
        required.add("agent_public_key")
    names = {c["check"] for c in checks}
    ready = required <= names and all(
        c["ok"] for c in checks if c["check"] in required
    )
    return {"ready": ready, "checks": checks}


def owner_key_matches_public(private_key: Path | str, public_key: Path | str) -> bool:
    """True when the RSA private key's public half equals the owner SPKI.

    ``public_key`` is the base64 SPKI text file INIT installs (``*.spki.txt``),
    or raw DER / PEM. Raises :class:`XinliqiuError` when either cannot be read.
    """
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:  # pragma: no cover
        raise XinliqiuError("checking the owner key requires the cryptography package") from exc
    priv_path = Path(private_key).expanduser()
    pub_path = Path(public_key).expanduser()
    try:
        loaded = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    except Exception as exc:  # noqa: BLE001
        raise XinliqiuError(f"owner private key {priv_path} is unreadable: {exc}") from exc
    try:
        raw = pub_path.read_bytes()
    except OSError as exc:
        raise XinliqiuError(f"owner public key {pub_path} is unreadable: {exc}") from exc
    der: bytes
    stripped = raw.strip()
    if stripped[:1] == b"\x30":
        der = raw
    elif stripped.startswith(b"-----BEGIN"):
        try:
            der = serialization.load_pem_public_key(stripped).public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as exc:  # noqa: BLE001
            raise XinliqiuError(f"owner public key {pub_path} is not a PEM key") from exc
    else:
        try:
            der = base64.b64decode(stripped, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise XinliqiuError(f"owner public key {pub_path} is not base64 SPKI") from exc
    mine = loaded.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return mine == der
