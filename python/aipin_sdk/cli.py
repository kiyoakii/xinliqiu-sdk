# -*- coding: utf-8 -*-
"""Command line interface.

Examples::

    xinliqiu capabilities
    xinliqiu status
    xinliqiu inventory
    xinliqiu record start
    xinliqiu record stop
    xinliqiu voiceprint 30 --out ./captures
    xinliqiu sync 1792748000000 1792750200000 --out ./captures
    xinliqiu sync --ranges '1792748000000:1792749000000;1792749000001:1792750200000'
    xinliqiu sync 1792748000000 1792750200000 --store cloudflare

Exit codes: 0 verified success (a sync whose range completed, even with no
files); 1 usage or local error; 3 the operation ran but did not verify (the
JSON ``state`` and ``retry`` fields say what happened and what is safe).

Credentials come from flags or environment:

    XINLIQIU_DEVICE_ID
    XINLIQIU_PEER_ID_FILE
    XINLIQIU_KEY_FILE
    XINLIQIU_AGENT_PUBLIC_KEY   (optional package SPKI; enables the 00 01 type-6 path)
    XINLIQIU_AGENT_PACKAGE      (optional; default com.oplusai.moss.phone with a key)
    XINLIQIU_BIND_START_DELAY_MS (optional; default 1000, the tested profile)
    XINLIQIU_OWNER_KEY          (only needed to decrypt / export audio)
    XINLIQIU_STORE_URL / XINLIQIU_STORE_TOKEN  (Cloudflare store)
    XINLIQIU_STORAGE_DEVICE_ID  (optional stable storage identity override)
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from .client import Credentials, Xinliqiu, scan
from .errors import OperationIncomplete, XinliqiuError
from .provision import (
    PairingOutcomeUnknown,
    pair_device,
    default_owner_key_path,
    doctor,
    generate_owner_key,
    pair,
    promote_pending_pairing,
    recover_alias,
    verify_owner_key,
)
from .userconfig import UserConfig, absolute_path, config_path, resolve

# Exit code for "ran, but not a verified success" (mirrors the tested tool).
EXIT_UNVERIFIED = 3
from .container import parse_cmpt_file
from . import __version__
from .storage import CloudflareStorage, LocalStorage, ingest_files, resolve_storage_identity


class CliError(Exception):
    """A user-facing failure: ``main`` prints it and returns exit code 1."""


class _Parser(argparse.ArgumentParser):
    """Treat usage errors as a normal CLI failure instead of SystemExit(2)."""

    def error(self, message):
        raise CliError(message)


def _expand(value: str | None) -> str | None:
    """Expand ``~`` and make a user-supplied path absolute."""
    return absolute_path(value) if value else None


def _resolve(args: argparse.Namespace):
    resolved = resolve(
        device=getattr(args, "device", None),
        peer_id_file=getattr(args, "peer_id_file", None),
        key_file=getattr(args, "key_file", None),
        owner_key=getattr(args, "owner_key", None),
        agent_public_key=getattr(args, "agent_public_key", None),
        agent_package=getattr(args, "agent_package", None),
        bind_start_delay_ms=getattr(args, "bind_start_delay_ms", None),
    )
    # Paths from flags, environment, and the saved config may all contain "~"
    # or be relative. Make them absolute once here so every consumer gets a
    # real path; Credentials does the same for its own fields.
    for field in ("peer_id_file", "key_file", "owner_key", "agent_public_key"):
        value = getattr(resolved, field)
        if value:
            setattr(resolved, field, absolute_path(value))
    return resolved


def _credentials(args: argparse.Namespace) -> Credentials:
    resolved = _resolve(args)
    if not resolved.device:
        raise CliError(
            "No device selected.\n"
            "  1. xinliqiu scan                            find your device id\n"
            "  2. xinliqiu pair --device <id> --out-dir ./xinliqiu-creds\n"
            "     writes credentials and remembers them for later commands"
        )
    if not resolved.peer_id_file or not resolved.key_file:
        raise CliError(
            "Missing credentials for device %s.\n"
            "  Run: xinliqiu pair --device %s --out-dir ./xinliqiu-creds\n"
            "  Or pass --peer-id-file and --key-file explicitly."
            % (resolved.device, resolved.device)
        )
    return Credentials(
        device_id=resolved.device,
        peer_id_file=Path(resolved.peer_id_file).expanduser(),
        key_file=Path(resolved.key_file).expanduser(),
    )


def _client(args: argparse.Namespace) -> Xinliqiu:
    resolved = _resolve(args)
    ball = Xinliqiu(
        _credentials(args),
        agent_public_key=(
            Path(resolved.agent_public_key) if resolved.agent_public_key else None
        ),
        owner_private_key=(
            Path(resolved.owner_key) if resolved.owner_key else None
        ),
        agent_package=resolved.agent_package,
        bind_start_delay_ms=resolved.bind_start_delay_ms,
    )
    try:
        # Validate agent key/package/delay before any radio use.
        ball.connect_options()
    except Exception as exc:  # noqa: BLE001
        raise CliError(f"invalid agent configuration: {exc}") from exc
    return ball


def _outcome(result: dict) -> int:
    """0 for a verified success, 3 for a structured non-success."""
    return 0 if result.get("ok") else EXIT_UNVERIFIED


def _print(obj: object) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def cmd_capabilities(args: argparse.Namespace) -> int:
    if getattr(args, "json", False):
        _print(Xinliqiu.capabilities())
        return 0

    caps = Xinliqiu.capabilities()
    statuses = caps["statuses"]
    print()
    print("  " + caps["device"])
    print()
    labels = (
        ("supported", "可用"),
        ("bounded", "可用但有边界"),
        ("unavailable", "不可用 - 不要基于这些做设计"),
    )
    for key, label in labels:
        items = statuses.get(key) or []
        if not items:
            continue
        print("  " + label)
        print("  " + "-" * 58)
        for item in items:
            print("    " + item["name"])
            for chunk in _wrap(item["note"], 52):
                print("        " + chunk)
        print()
    print("  Tip: pass --json for machine-readable output.")
    print()
    return 0


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = (current + " " + word) if current else word
    if current:
        lines.append(current)
    return lines or [""]


def cmd_status(args: argparse.Namespace) -> int:
    _print(_client(args).status().__dict__)
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Format the device and install the owner public key.

    INIT will erase existing content and is supported only behind the explicit format gate.
    Repeating it is not a verification or recovery procedure; every invocation
    needs separate informed authorization and matching owner key material.
    """
    if not args.allow_format:
        raise CliError(
            "init will erase existing content and requires explicit authorization for every "
            "invocation; re-run with --allow-format only after confirming that "
            "all existing device content may be erased. Do not repeat INIT to "
            "obtain a missing confirmation or readback"
        )
    ball = _client(args)
    if ball.owner_private_key is None:
        raise CliError(
            "init requires --owner-key (the owner PRIVATE key): it is checked "
            "against --owner-public-key before anything is sent, so the device is "
            "never given a key whose private half you do not hold"
        )
    result = ball.init_device(
        owner_public_key=Path(_expand(args.owner_public_key)),
        signing_key=Path(_expand(args.signing_key)),
        account=args.account,
        public_key_version=args.public_key_version,
    )
    _print(result)
    return _outcome(result)


def cmd_storage(args: argparse.Namespace) -> int:
    _print(_client(args).storage_info())
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    _print(_client(args).inventory_totals(args.start_ms, args.end_ms))
    return 0

def cmd_record(args: argparse.Namespace) -> int:
    ball = _client(args)
    result = ball.record_start() if args.action == "start" else ball.record_stop()
    _print({"action": args.action, **result})
    return _outcome(result)


def cmd_voiceprint(args: argparse.Namespace) -> int:
    ball = _client(args)
    out_dir = Path(_expand(args.out)) if args.out else None
    result = ball.collect_voiceprint(
        args.seconds, out_dir, window_seconds=args.window
    )
    summary = dict(result)
    summary["output_dir"] = summary.pop("_output_dir", None)
    _print(summary)
    return _outcome(result)


def _build_storage(args: argparse.Namespace):
    """Validate the store configuration before any BLE work starts."""
    store_name = args.store
    if not store_name:
        return None
    if store_name == "local":
        return LocalStorage(Path(args.store_path or "./xinliqiu-store").expanduser())
    if store_name == "cloudflare":
        url = os.environ.get("XINLIQIU_STORE_URL")
        token = os.environ.get("XINLIQIU_STORE_TOKEN")
        if not url or not token:
            raise CliError(
                "XINLIQIU_STORE_URL and XINLIQIU_STORE_TOKEN are required"
            )
        return CloudflareStorage(url, token)
    raise CliError(f"unknown store: {store_name}")


def _parse_ranges(text: str) -> list[tuple[int, int]]:
    pairs = []
    for item in text.split(";"):
        bounds = item.split(":")
        if len(bounds) != 2 or not all(b.strip().isdigit() for b in bounds):
            raise CliError(
                f"--ranges expects 'start:end;start:end' decimal pairs, got {item!r}"
            )
        pairs.append((int(bounds[0]), int(bounds[1])))
    return pairs


def cmd_sync(args: argparse.Namespace) -> int:
    if args.ranges and (args.start_ms is not None or args.end_ms is not None):
        raise CliError("use either start_ms end_ms or --ranges, not both")
    ball = _client(args)
    # Build the store first: a bad backend or missing token must not waste the
    # multi-minute BLE transfer that sync_range performs.
    storage = _build_storage(args)
    storage_identity = None
    if storage is not None:
        try:
            storage_identity = resolve_storage_identity(
                getattr(args, "storage_device_id", None),
                credentials=ball.credentials,
                ble_device_id=ball.credentials.device_id,
            )
        except (XinliqiuError, ValueError) as exc:
            raise CliError(f"invalid storage identity: {exc}") from exc
        if not storage_identity.stable:
            raise CliError(
                "sync --store requires a stable storage identity; the host BLE UUID "
                "is not a default cloud identity. Re-pair with a valid pairing.json, "
                "pass --storage-device-id, or set XINLIQIU_STORAGE_DEVICE_ID."
            )
    out_dir = Path(_expand(args.out)) if args.out else None
    if not args.ranges:
        # Convenience defaults: ``sync`` fetches everything the device holds so
        # far, ``sync START`` fetches from START to now. The end is always the
        # authenticated device clock, never the host clock.
        if args.start_ms is None:
            args.start_ms = 0
        if args.end_ms is None:
            status = ball.status()
            if status.device_timestamp_ms is None:
                raise CliError(
                    "the device did not report a timestamp; pass an explicit "
                    "finite past end_ms"
                )
            args.end_ms = status.device_timestamp_ms
    try:
        if args.ranges:
            result = ball.sync_ranges(
                _parse_ranges(args.ranges), out_dir, seconds=args.seconds
            )
        else:
            result = ball.sync_range(
                args.start_ms, args.end_ms, out_dir, seconds=args.seconds
            )
    except ValueError as exc:
        raise CliError(str(exc)) from exc
    summary = {
        "state": result.get("state"),
        "ok": bool(result.get("ok")),
        "verified": result.get("verified", bool(result.get("ok"))),
        "range_complete": result.get("range_complete", bool(result.get("ok"))),
        "output_dir": result.get("_output_dir"),
        "files": result.get("files") or [],
        "count": result.get("count") or 0,
        "bytes": result.get("bytes") or 0,
        "offers": result.get("offers") or 0,
        "rejected": result.get("rejected_pairs") or [],
        "rejected_total": result.get("rejected_total")
        or (result.get("rejected") if isinstance(result.get("rejected"), int) else 0),
        "retry": result.get("retry"),
    }
    for key in ("ranges", "stopped_at", "failures", "abandoned", "diagnostics", "published"):
        if key in result:
            summary[key] = result[key]
    if storage is not None:
        # Classify every published outer file by content, not suffix. The shared
        # ingestion path handles CMPT, direct enpt and JSONL without mistaking a
        # diagnostic for a malformed container or silently dropping it.
        upload = ingest_files(
            summary["files"], storage, storage_identity.device_id
        )
        summary["store"] = {
            "backend": args.store,
            "storage_identity": storage_identity.as_dict(),
            **upload,
        }
    _print(summary)
    # An empty range that the device completed is a success: exit 0.
    return 0 if summary["ok"] else EXIT_UNVERIFIED


def cmd_scan(args: argparse.Namespace) -> int:
    found = scan(args.name, args.seconds)
    _print({"devices": found, "count": len(found)})
    return 0 if found else 1


def cmd_keygen(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir).expanduser() if args.out_dir else None
    info = generate_owner_key(out_dir, overwrite=args.force)
    _print(info)
    print(file=sys.stderr)
    print("  Back this file up NOW, outside this machine.", file=sys.stderr)
    print("  If it is lost, every recording encrypted to it is unreadable forever.", file=sys.stderr)
    return 0


def cmd_keycheck(args: argparse.Namespace) -> int:
    key = (
        Path(args.owner_key).expanduser()
        if args.owner_key
        else default_owner_key_path()
    )
    sample = None
    if args.sample:
        from .container import parse_cmpt_file

        sample_path = Path(args.sample).expanduser()
        if sample_path.is_file():
            candidates = [sample_path]
        elif sample_path.is_dir():
            candidates = sorted(p for p in sample_path.iterdir() if p.is_file())
        else:
            candidates = []
        for path in candidates:
            try:
                container = parse_cmpt_file(path)
            except Exception:  # noqa: BLE001 - not every captured file is CMPT
                continue
            entries = container.by_kind("audio")
            if entries:
                sample = entries[0].payload
                break
    result = verify_owner_key(key, sample)
    if args.sample:
        result["sample_used"] = sample is not None
    _print(result)
    if args.sample and sample is None:
        # The key may be fine, but the requested check could not run.
        return 1
    return 0 if result.get("ok") else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    # Same precedence as every other command: flag > environment > saved
    # config, so `doctor` checks exactly what `status` would use.
    resolved = _resolve(args)
    result = doctor(
        resolved.device or "",
        resolved.peer_id_file,
        resolved.key_file,
        resolved.owner_key,
        agent_public_key=resolved.agent_public_key,
        owner_public_key=_expand(getattr(args, "owner_public_key", None)),
    )
    result["config"] = str(config_path())
    _print(result)
    return 0 if result["ready"] else 1


def _remember(device: str, key_file: Path, peer_id_file: Path, alias: str | None) -> Path:
    saved = UserConfig.load().merged(
        device=device,
        peer_id_file=absolute_path(str(peer_id_file)),
        key_file=absolute_path(str(key_file)),
        ksc_alias=alias,
    )
    return saved.save()


def cmd_pair(args: argparse.Namespace) -> int:
    if not args.device:
        raise CliError("pair requires --device <id>  (run: xinliqiu scan)")
    out_dir = Path(_expand(args.out_dir))

    if args.promote_pending:
        # Only after a status read with the pending key worked.
        try:
            key_file = promote_pending_pairing(out_dir)
        except Exception as exc:  # noqa: BLE001
            raise CliError(str(exc)) from exc
        peer_file = out_dir / "peer-id.txt"
        remembered = _remember(args.device, key_file, peer_file, recover_alias(None, key_file))
        _print({"promoted": True, "key_file": str(key_file), "remembered_in": str(remembered)})
        return 0

    # Reuse the alias this host first paired under, if any. The device updates a
    # matching slot in place instead of evicting the least-recently-used one, so
    # a re-pair cannot push the user's phone out of its slot. When the config
    # was lost, the alias is recovered from a surviving pairing file.
    prior = UserConfig.load()
    alias = (
        prior.ksc_alias
        or recover_alias(out_dir, _expand(getattr(args, "key_file", None)), prior.key_file)
        or secrets.token_hex(6)
    )

    # Persist the alias up front: if pairing stops early (for example because
    # an old pairing.json must be moved aside), the slot alias survives the
    # next invocation too.
    UserConfig.load().merged(ksc_alias=alias).save()

    try:
        result = pair_device(args.device, out_dir, ksc_alias=alias)
    except PairingOutcomeUnknown as exc:
        # Remember the alias anyway, so a later pair reuses the same slot.
        UserConfig.load().merged(ksc_alias=alias).save()
        _print({
            "paired": False,
            "state": "pairing_outcome_unknown",
            "pending_key_file": str(exc.pending_file),
            "peer_id_file": str(exc.peer_id_file),
            "detail": str(exc),
            "retry": (
                "Do not pair again yet. Test the pending key: "
                f"xinliqiu status --device {args.device} --key-file {exc.pending_file} "
                f"--peer-id-file {exc.peer_id_file}; if that works, run "
                f"xinliqiu pair --device {args.device} --out-dir {out_dir} --promote-pending. "
                "If it fails, move the pending file aside and pair again (same alias)."
            ),
        })
        return EXIT_UNVERIFIED

    # Remember the paths (absolute) so later commands need no flags at all.
    remembered = _remember(
        args.device, result.key_file, result.peer_id_file, result.alias_hex or alias
    )

    _print({
        "paired": True,
        "key_file": str(result.key_file),
        "peer_id_file": str(result.peer_id_file),
        "ksc_alias": result.alias_hex or alias,
        "remembered_in": str(remembered),
        "next": "run: xinliqiu status",
    })
    return 0


def build_parser() -> argparse.ArgumentParser:
    # Credential flags are accepted both before and after the subcommand so that
    # `xinliqiu --device X status` and `xinliqiu status --device X` both work.
    common = argparse.ArgumentParser(add_help=False)
    # SUPPRESS keeps a value parsed before the subcommand from being
    # overwritten by the subparser's default.
    common.add_argument("--device", default=argparse.SUPPRESS, help="CoreBluetooth UUID")
    common.add_argument("--peer-id-file", default=argparse.SUPPRESS)
    common.add_argument("--key-file", default=argparse.SUPPRESS)
    common.add_argument("--agent-public-key", default=argparse.SUPPRESS, help="package SPKI (DER/PEM/base64)")
    common.add_argument("--owner-key", default=argparse.SUPPRESS)
    common.add_argument("--agent-package", default=argparse.SUPPRESS, help="local agent registration package")
    common.add_argument(
        "--bind-start-delay-ms", type=int, default=argparse.SUPPRESS,
        help="delay before the first business request, 0..2000 (default 1000)",
    )

    parser = _Parser(prog="xinliqiu", description="心力球 SDK CLI")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--device", default=argparse.SUPPRESS, help="CoreBluetooth UUID")
    parser.add_argument("--peer-id-file", default=argparse.SUPPRESS)
    parser.add_argument("--key-file", default=argparse.SUPPRESS)
    parser.add_argument("--agent-public-key", default=argparse.SUPPRESS)
    parser.add_argument("--owner-key", default=argparse.SUPPRESS)
    parser.add_argument("--agent-package", default=argparse.SUPPRESS)
    parser.add_argument("--bind-start-delay-ms", type=int, default=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    caps = sub.add_parser("capabilities", parents=[common], help="show what the device supports")
    caps.add_argument("--json", action="store_true", help="raw JSON instead of a table")

    sub.add_parser("status", parents=[common], help="read recording state, battery, error byte")

    sc = sub.add_parser("scan", help="discover nearby devices")
    sc.add_argument("--name", help="filter by advertised name substring")
    sc.add_argument("--seconds", type=int, default=15)

    kg = sub.add_parser("keygen", help="create an owner key pair")
    kg.add_argument("--out-dir")
    kg.add_argument("--force", action="store_true", help="replace an existing key")

    kc = sub.add_parser("keycheck", parents=[common], help="verify the owner key")
    kc.add_argument("--sample", help="directory of synced containers to test against")

    doc = sub.add_parser("doctor", parents=[common], help="check local prerequisites")
    doc.add_argument(
        "--owner-public-key", help="also check the owner private key matches this SPKI"
    )

    pr = sub.add_parser("pair", parents=[common], help="pair with a fresh device and write credentials")
    pr.add_argument("--out-dir", required=True)
    pr.add_argument(
        "--promote-pending", action="store_true",
        help="adopt pairing.pending.json after a status read with it succeeded",
    )

    ini = sub.add_parser(
        "init",
        parents=[common],
        help="install an owner public key (will erase existing content; explicit authorization required)",
    )
    ini.add_argument("--owner-public-key", required=True, help="base64 SPKI text file")
    ini.add_argument("--signing-key", required=True, help="P-256 private key that the device trusts")
    ini.add_argument("--account", default="local-owner")
    ini.add_argument("--public-key-version", type=int, default=1)
    ini.add_argument(
        "--allow-format",
        action="store_true",
        help="acknowledge that this erases everything the device currently holds",
    )

    sto = sub.add_parser("storage", parents=[common], help="usage and low-space thresholds")

    inv = sub.add_parser("inventory", parents=[common], help="aggregate counts for a device-clock range")
    inv.add_argument("--start-ms", type=int, default=0)
    inv.add_argument(
        "--end-ms", type=int, default=None,
        help="finite past device-clock end (default: read device_timestamp_ms first)",
    )

    rec = sub.add_parser("record", parents=[common], help="start or stop recording")
    rec.add_argument("action", choices=["start", "stop"])

    vp = sub.add_parser(
        "voiceprint", parents=[common],
        help="single voiceprint capture (1..127 s), file received on the same link",
    )
    vp.add_argument("seconds", type=int, nargs="?", default=6)
    vp.add_argument("--out", help="directory for the received .vp.opus file")
    vp.add_argument(
        "--window", type=float, default=None,
        help="host wait in seconds (default max(45, seconds+39), max 3600)",
    )

    syn = sub.add_parser(
        "sync", parents=[common],
        help="fetch a device-clock range (default: everything up to the device's current time)",
    )
    syn.add_argument(
        "start_ms", type=int, nargs="?",
        help="finite past device-clock start (default 0)",
    )
    syn.add_argument(
        "end_ms", type=int, nargs="?",
        help="finite past device-clock end (default: read device_timestamp_ms)",
    )
    syn.add_argument(
        "--ranges", help="'start:end;start:end' (1..16 distinct) on one connection"
    )
    syn.add_argument(
        "--seconds", type=int, default=300,
        help="overall host window, 1..3600 (default 300)",
    )
    syn.add_argument("--out")
    syn.add_argument("--store", choices=["local", "cloudflare"])
    syn.add_argument("--store-path", help="path for --store local")
    syn.add_argument(
        "--storage-device-id",
        help="stable storage identity (default: env/config/pairing-derived, never BLE UUID)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except CliError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    handlers = {
        "capabilities": cmd_capabilities,
        "status": cmd_status,
        "storage": cmd_storage,
        "inventory": cmd_inventory,
        "record": cmd_record,
        "voiceprint": cmd_voiceprint,
        "sync": cmd_sync,
        "scan": cmd_scan,
        "keygen": cmd_keygen,
        "keycheck": cmd_keycheck,
        "doctor": cmd_doctor,
        "pair": cmd_pair,
        "init": cmd_init,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        return 130
    except CliError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ValueError as exc:
        print(json.dumps({"error": f"invalid argument: {exc}"}), file=sys.stderr)
        return 1
    except OperationIncomplete as exc:
        _print(exc.result)
        return EXIT_UNVERIFIED
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
