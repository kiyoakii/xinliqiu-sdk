# -*- coding: utf-8 -*-
"""Remember where credentials live so users stop retyping paths.

After `pair`, the credential paths are saved to a small config file. Every
later command picks them up automatically, which turns the common case from

    xinliqiu sync 0 1800000000000 \\
      --device X --peer-id-file ./creds/peer-id.txt --key-file ./creds/pairing.json

into

    xinliqiu sync 0 1800000000000

Precedence, highest first:

    command line flag  >  environment variable  >  saved config

The config holds **paths and public settings only** - never credential
contents, never keys. Every path is stored absolute: a relative path saved
from one working directory would silently point somewhere else from the next.
The KSC alias is an identifier, not a secret, and is kept so a re-pair
reuses the same device slot.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CONFIG_ENV = "XINLIQIU_CONFIG"

#: Fields that hold filesystem paths; these are made absolute on save/resolve.
PATH_FIELDS = ("peer_id_file", "key_file", "owner_key", "agent_public_key")


def config_path() -> Path:
    override = os.environ.get(CONFIG_ENV)
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".config"
    return root / "xinliqiu" / "config.json"


def absolute_path(value: str | None, *, base: Path | None = None) -> str | None:
    """Expand ``~`` and anchor a relative path (to ``base`` or the cwd)."""
    if not value:
        return value
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (base or Path.cwd()) / path
    return os.path.normpath(str(path))


@dataclass
class UserConfig:
    device: str | None = None
    peer_id_file: str | None = None
    key_file: str | None = None
    owner_key: str | None = None
    agent_public_key: str | None = None
    store: str | None = None
    store_url: str | None = None
    storage_device_id: str | None = None
    ksc_alias: str | None = None
    #: Registration package for the local agent (tested: com.oplusai.moss.phone
    #: together with its SPKI). ``None`` lets the client choose.
    agent_package: str | None = None
    #: Delay before the first business request, 0...2000 ms (tested: 1000).
    bind_start_delay_ms: int | None = None

    @classmethod
    def load(cls) -> "UserConfig":
        path = config_path()
        if not path.exists():
            return cls()
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - a broken config must never break the CLI
            return cls()
        if not isinstance(data, dict):
            return cls()
        loaded = cls(**{k: data.get(k) for k in cls.__dataclass_fields__})
        # A hand-edited or damaged config must not turn into a Path/type error
        # later. Unknown/wrongly typed fields are treated as absent.
        for name in cls.__dataclass_fields__:
            value = getattr(loaded, name)
            if name == "bind_start_delay_ms":
                if isinstance(value, bool) or not isinstance(value, int):
                    setattr(loaded, name, None)
            elif value is not None and not isinstance(value, str):
                setattr(loaded, name, None)
        # Configs written by older builds may hold relative paths; retain the
        # old command-line semantics and resolve those against the cwd. New
        # saves are absolute, so this only affects legacy files.
        for name in PATH_FIELDS:
            value = getattr(loaded, name)
            if isinstance(value, str) and value:
                setattr(loaded, name, absolute_path(value))
        return loaded

    def save(self) -> Path:
        """Write the config atomically with owner-only permissions."""
        path = config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {}
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if value is None or value == "":
                continue
            if name in PATH_FIELDS:
                value = absolute_path(value)
            payload[name] = value
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fd = -1
                json.dump(payload, fh, indent=2, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            if fd != -1:
                os.close(fd)
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        return path

    def merged(self, **overrides: Any) -> "UserConfig":
        """Return a copy where explicit values win over saved ones.

        ``None`` and ``""`` mean "not given"; ``0`` is a real value (a bind
        start delay of zero is a deliberate choice).
        """
        merged = UserConfig(**{k: getattr(self, k) for k in self.__dataclass_fields__})
        for key, value in overrides.items():
            if value is not None and value != "":
                setattr(merged, key, value)
        return merged


def _env_int(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def resolve(*, device: str | None, peer_id_file: str | None, key_file: str | None,
            owner_key: str | None = None, agent_public_key: str | None = None,
            agent_package: str | None = None,
            bind_start_delay_ms: int | None = None) -> UserConfig:
    """Resolve credentials from flags, then environment, then saved config.

    Every path in the result is absolute: relative flag/env values are taken
    relative to the current directory, saved ones were stored absolute.
    """
    saved = UserConfig.load()
    merged = saved.merged(
        device=device or os.environ.get("XINLIQIU_DEVICE_ID"),
        peer_id_file=absolute_path(peer_id_file or os.environ.get("XINLIQIU_PEER_ID_FILE")),
        key_file=absolute_path(key_file or os.environ.get("XINLIQIU_KEY_FILE")),
        owner_key=absolute_path(owner_key or os.environ.get("XINLIQIU_OWNER_KEY")),
        agent_public_key=absolute_path(
            agent_public_key or os.environ.get("XINLIQIU_AGENT_PUBLIC_KEY")
        ),
        agent_package=agent_package or os.environ.get("XINLIQIU_AGENT_PACKAGE"),
        bind_start_delay_ms=(
            bind_start_delay_ms
            if bind_start_delay_ms is not None
            else _env_int("XINLIQIU_BIND_START_DELAY_MS")
        ),
    )
    return merged
