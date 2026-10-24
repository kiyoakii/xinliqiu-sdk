# -*- coding: utf-8 -*-
"""The wire protocol: framing, handshake, channels, and the file stream.

Every module here is transport-agnostic. ``connect`` composes them into a
usable link but never touches Bluetooth itself, which is what lets the whole
stack be tested without a device.
"""

from . import (  # noqa: F401 - re-exported for convenience
    auth,
    commands,
    connect,
    crypto,
    epi,
    framing,
    pipe,
    secure,
    systemft,
    transport,
    ukey2,
)

__all__ = [
    "auth",
    "commands",
    "connect",
    "crypto",
    "epi",
    "framing",
    "pipe",
    "secure",
    "systemft",
    "transport",
    "ukey2",
]