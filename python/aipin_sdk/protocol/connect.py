# -*- coding: utf-8 -*-
"""Business channel: from "Bluetooth is connected" to "a command can be sent".

Five exchanges happen in a fixed order; each must succeed before the next is
legal, and the device simply stops answering if one is skipped or reordered.

=========  =====================================================  ==============
stage      exchange                                               deadline
=========  =====================================================  ==============
1          EPI transport negotiation                              15 s
2          session authentication (HMAC-SHA512 challenges)        15 s
3          capability query: who provides jg.pipe.message/file    15 s
4a         service connection request (message, then file)        10 s each
4b         agent authenticate request / response (type 5/6)      within 4a
5          bind challenge, then the device-info read              8 s + 10 s
=========  =====================================================  ==============

Stages 1 and 2 are plain one-byte-prefixed frames. Every *business* message -
the bind and the device-info read in particular - carries the flag ``0x04``
followed by the AES-128-GCM envelope in :mod:`.secure`.
The channel handed to the caller keeps both counters and the framing state, so
:meth:`ConnectedChannel.send_command` is the only thing that should put bytes
on the wire afterwards.

``sync=True`` adds one optional consumer after stage 4a. The device only opens
``system:filetransfer`` for a peer that advertised it, so without this third
consumer a ``06 00`` range request is answered once and the recording stream
never starts.
"""

from __future__ import annotations

import base64
import binascii
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..errors import XinliqiuError
from . import epi, framing, pipe, secure
from .auth import AuthError, AuthState, Pairing
from .transport import (
    BUSINESS_NOTIFY,
    BUSINESS_WRITE,
    LinkLost,
    Notification,
    Session,
    TransportError,
    is_idle_error,
)

# --------------------------------------------------------------------------
# Protocol constants, each with the role it plays on the wire.
# --------------------------------------------------------------------------


# The ``AA`` pipe envelope that wraps every business body.
PIPE_MAGIC = 0xAA
PIPE_MESSAGE_TYPE = 0x10
PIPE_MAX_BODY = 0x0FFF_FFFF

# Sessions and channels. Session 1 carries service negotiation, session 2 the
# capability query; the message service gets the first business session.
DEFAULT_SESSION_ID = 32
DEFAULT_CHANNEL_ID = 104
# The file channel is one past the last session the message service accepted.
DEFAULT_FILE_SESSION_ID = 33
SESSION_SERVICE = 1
SESSION_CAPEX = 2

# Service/command pairs used during bring-up.
BIND_SERVICE = 0x02
BIND_COMMAND = 0x0D
INFO_SERVICE = 0x05
INFO_COMMAND = 0x03
INFO_REPLY_SERVICE = 0x03
INFO_REPLY_COMMAND = 0xFF
# The auth response is a 3-byte header plus 24 bytes of challenge, time and tag.
AUTH_RESPONSE_TYPE = 0x11
AUTH_RESPONSE = 27

# Service profiles.
PROFILE_MESSAGE = "jg.pipe.message"
PROFILE_FILE = "jg.pipe.file"
# Only a sync caller advertises this third consumer.
PROFILE_SYSTEM = "system:filetransfer"
# Inside that service, channel 100 carries JSON control and 101..105 file data.
CONTROL_CHANNEL_ID = 100
FILE_CHANNEL_ID = 107
FILE_QOS_TYPE = 5
FILE_QOS_CLASS = 1
FILE_PAYLOAD_TYPE = 0
# The host-initiated system offer reuses the file-service values; the device's
# own service request proposes (4,3)/(4,0), and QoS is advisory either way.
SYSTEM_QOS_TYPE = FILE_QOS_TYPE
SYSTEM_QOS_CLASS = FILE_QOS_CLASS
SYSTEM_PAYLOAD_TYPE = FILE_PAYLOAD_TYPE
# Four bytes meaning "this host has no package signature to offer".
AGENT_AUTH_UNAVAILABLE = bytes([1, 1, 0, 0])
# The type-6 payload that carries a package signing key: 00 01, a big-endian
# u16 length, then the SubjectPublicKeyInfo DER (the APK's normal path).
AGENT_AUTH_SPKI_PREFIX = bytes([0, 1])
MAX_AGENT_SPKI_BYTES = 0xFFFF
_RSA_OID = bytes.fromhex("2a864886f70d010101")
_EC_OID = bytes.fromhex("2a8648ce3d0201")

# The query advertises exactly one service profile: the file consumer is
# optional, so one answer fits every operation.
EPI_SERVICE_PROFILES = 1

# Defaults that are *choices*, not protocol. Both are overridable.
DEFAULT_AGENT_ID = 42
DEFAULT_PACKAGE = "local.insico.macprobe"
DEFAULT_AGENT_NAME = "MacProbe"
# The package the tested hardware profile registered together with a package
# SPKI (docs/recording-protocol.md). Used as the default only when a key is
# configured; without one the host keeps its own package and the fallback.
OFFICIAL_AGENT_PACKAGE = "com.oplusai.moss.phone"
# The tested profile delays the first business request (the bind) by 1000 ms
# after both services are accepted. It changes no frame, only timing.
TESTED_BIND_START_DELAY_MS = 1000
MAX_BIND_START_DELAY_MS = 2000

# Per-stage deadlines. The device opens system:filetransfer on its own once it
# has a file to push, so the host-initiated offer gets a shorter, tolerant limit:
# a reply is accepted when it comes.
CAPEX_SECONDS = 15.0
MESSAGE_SERVICE_SECONDS = 10.0
FILE_SERVICE_SECONDS = 10.0
SYSTEM_SERVICE_SECONDS = 5.0
# A bind response is optional: after 8 s we read device info anyway.
BIND_FALLBACK_SECONDS = 8.0
DEVICE_INFO_SECONDS = 10.0

# Frames for other sessions seen while waiting for a business reply are parked
# for read_raw(); bounded so a chatty link cannot grow memory without limit.
MAX_PARKED_FRAMES = 512
# Unrelated business messages seen while waiting for a specific reply are
# skipped (they are events, not the answer); bounded per wait.
MAX_SKIPPED_REPLIES = 256


class ConnectError(XinliqiuError):
    """The business channel could not be brought up."""


class StageError(ConnectError):
    """One stage of the sequence failed; ``stage`` names which."""

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(f"{stage}: {message}")
        self.stage = stage


class PipeMessageError(ConnectError, pipe.PipeError):
    """A decrypted body is not a pipe envelope this host understands.

    Raised as :mod:`.pipe`'s own ``PipeError`` by the shared decoder and
    re-raised under this name at the points that care.
    """

    def __init__(self, message: str = "pipe message error") -> None:
        ConnectError.__init__(self, message)


class ReplyTimeout(ConnectError):
    """No matching business reply arrived before the deadline.

    Distinct from :class:`transport.LinkLost`: the link is still up, the
    device simply did not answer (or answered something else).
    """


@dataclass
class Step:
    """One observed exchange, for diagnostics when something stops."""

    name: str
    sent: int = 0
    received: int = 0


@dataclass(frozen=True)
class BusinessMessage:
    """One decoded message-session business frame.

    ``authenticated`` is True only for a ``0x04`` secure envelope that opened
    under the session key; an explicit plain (``0x00``) body is legal on the
    wire but proves nothing about who sent it.
    """

    service: int
    command: int
    payload: bytes
    authenticated: bool

    @property
    def data(self) -> bytes:
        """``service || command || payload``, the shape send_command returns."""
        return bytes([self.service, self.command]) + self.payload


# Replies whose contents change what the caller may trust (state, storage, or
# an owner-key installation) must be authenticated by default. Other business
# commands retain the protocol's explicit-plain option for compatibility.
_AUTHENTICATED_REQUESTS = frozenset({(0x05, 0x02), (0x05, 0x04), (0x02, 0x08)})
_AUTHENTICATED_REPLY_HEADERS = frozenset({(0x02, 0xFF), (0x04, 0xFF), (0x02, 0x08)})


def _request_requires_authentication(service: int, command: int) -> bool:
    return (service, command) in _AUTHENTICATED_REQUESTS


def _reply_requires_authentication(expect: tuple[int, int] | None) -> bool:
    return expect is not None and tuple(expect) in _AUTHENTICATED_REPLY_HEADERS


# --------------------------------------------------------------------------
# Agent authentication material
# --------------------------------------------------------------------------


def _der_read(data: bytes, offset: int) -> tuple[int, int, int]:
    """Read one DER TLV: ``(tag, content_offset, end_offset)``."""
    if offset + 2 > len(data):
        raise ConnectError("agent public key: truncated DER")
    tag = data[offset]
    first = data[offset + 1]
    cursor = offset + 2
    length = first
    if first & 0x80:
        count = first & 0x7F
        if not 1 <= count <= 3 or cursor + count > len(data):
            raise ConnectError("agent public key: invalid DER length")
        length = int.from_bytes(data[cursor : cursor + count], "big")
        cursor += count
    if cursor + length > len(data):
        raise ConnectError("agent public key: DER value exceeds buffer")
    return tag, cursor, cursor + length


def validate_agent_spki(der: bytes) -> str:
    """Validate SubjectPublicKeyInfo DER the way the tested Swift tool does.

    One outer SEQUENCE covering every byte, an AlgorithmIdentifier SEQUENCE
    whose OID is RSA or EC, then a BIT STRING with zero unused bits ending
    exactly at the outer end. Returns ``"RSA"`` or ``"EC"``.
    """
    if not isinstance(der, (bytes, bytearray)):
        raise ConnectError("agent public key must be bytes")
    der = bytes(der)
    if not 1 <= len(der) <= MAX_AGENT_SPKI_BYTES:
        raise ConnectError("agent public key must be 1...65535 bytes")
    tag, content, end = _der_read(der, 0)
    if tag != 0x30 or end != len(der):
        raise ConnectError("agent public key is not one DER SEQUENCE")
    tag, alg_content, alg_end = _der_read(der, content)
    if tag != 0x30 or alg_end > end:
        raise ConnectError("agent public key algorithm is not a SEQUENCE")
    tag, oid_content, oid_end = _der_read(der, alg_content)
    if tag != 0x06:
        raise ConnectError("agent public key algorithm OID missing")
    oid = der[oid_content:oid_end]
    if oid == _RSA_OID:
        algorithm = "RSA"
    elif oid == _EC_OID:
        algorithm = "EC"
    else:
        raise ConnectError("agent public key is neither RSA nor EC SPKI")
    tag, bits_content, bits_end = _der_read(der, alg_end)
    if (
        tag != 0x03
        or bits_content >= bits_end
        or der[bits_content] != 0
        or bits_end != end
    ):
        raise ConnectError("agent public key BIT STRING missing or malformed")
    return algorithm


def agent_auth_payload_from_spki(der: bytes) -> bytes:
    """``00 01 || BE16(len) || SPKI DER`` - the type-6 payload for a key."""
    validate_agent_spki(der)
    return AGENT_AUTH_SPKI_PREFIX + len(der).to_bytes(2, "big") + bytes(der)


def load_agent_public_key(path: str | Path) -> bytes:
    """Read a package SPKI and return the validated DER.

    Accepts raw DER (the tested input), a PEM ``PUBLIC KEY`` block, or one
    line of base64. The file is read once; nothing is written.
    """
    candidate = Path(path).expanduser()
    try:
        raw = candidate.read_bytes()
    except OSError as exc:
        raise ConnectError(f"cannot read agent public key {candidate}: {exc}") from exc
    if not raw:
        raise ConnectError(f"agent public key {candidate} is empty")
    if raw[:1] == b"\x30":
        der = raw
    else:
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise ConnectError("agent public key is neither DER, PEM nor base64") from exc
        if text.startswith("-----BEGIN"):
            text = "".join(
                line.strip() for line in text.splitlines()
                if line.strip() and not line.startswith("-----")
            )
        try:
            der = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ConnectError("agent public key is neither DER, PEM nor base64") from exc
    validate_agent_spki(der)
    return der


# --------------------------------------------------------------------------
# Secure business channel and pipe envelope
# --------------------------------------------------------------------------
#
# The byte layouts live in :mod:`.secure` (the ``0x04`` AES-128-GCM envelope of
# :mod:`.secure`) and :mod:`.pipe` (the ``AA`` envelope of
# This module only composes them, so there is exactly one
# implementation of each on the wire.

#: The flag byte in front of every encrypted business body.
BUSINESS_FLAG_ENCRYPTED = secure.FLAG_ENCRYPTED
#: The flag byte in front of a deliberately plain business body
#: The flag byte in front of a deliberately plain business body.
BUSINESS_FLAG_PLAIN = 0x00

# A fresh name for the channel is kept because ``secure.SecureChannel`` is also
# reachable from this package's public surface; this alias is what
# ``connect()`` returns inside :class:`ConnectedChannel`.
SecureBusinessChannel = secure.SecureChannel

# Compatibility aliases: the envelope helpers keep their descriptive names at
# this level, but they are the same functions ``pipe`` exports.
def encode_pipe_message(data: bytes) -> bytes:
    """this module: ``02 0d 01`` -> ``AA 04 10 02 0d 01``."""
    return pipe.encode(data)


def decode_pipe_message(wire: bytes) -> pipe.PipeMessage:
    """this module; raises :class:`pipe.PipeError` on anything odd."""
    return pipe.decode(wire)


# --------------------------------------------------------------------------
# Capability frames
# --------------------------------------------------------------------------


class _Cursor:
    """Read big-endian integers and ``;``-terminated text."""

    def __init__(self, data: bytes, stage: str) -> None:
        self.data = data
        self.offset = 0
        self._stage = stage

    def uint(self, width: int) -> int:
        if self.offset + width > len(self.data):
            raise StageError(self._stage, "truncated integer")
        chunk = self.data[self.offset : self.offset + width]
        self.offset += width
        return int.from_bytes(chunk, "big")

    def text(self) -> str:
        end = self.data.find(b";", self.offset)
        if end < 0:
            raise StageError(self._stage, "missing semicolon or invalid UTF-8")
        chunk = self.data[self.offset : end]
        self.offset = end + 1
        try:
            return chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StageError(self._stage, "invalid UTF-8 in protocol text") from exc

    def require_end(self, what: str) -> None:
        if self.offset != len(self.data):
            raise StageError(self._stage, f"trailing bytes in {what}")


def _text(value: str, stage: str = "capex") -> bytes:
    if ";" in value or "\x00" in value:
        raise StageError(stage, "semicolon/NUL in a protocol string")
    return value.encode("utf-8") + b";"


@dataclass(frozen=True)
class CapabilityQuery:
    """A capability query: which service profiles the peer wants."""

    query_type: int
    checksum: int
    profiles: tuple[str, ...]

    @classmethod
    def parse(cls, body: bytes) -> "CapabilityQuery":
        a = _Cursor(body, "capex")
        if a.uint(1) != 1:
            raise StageError("capex", "expected a capability query")
        query_type = a.uint(1)
        if query_type not in (2, 3):
            raise StageError("capex", "only checksum-bearing query types 2/3 are supported")
        checksum = a.uint(4)
        count = a.uint(1)
        profiles = []
        for _ in range(count):
            text = a.text()
            if not text:
                raise StageError("capex", "empty requested profile")
            profiles.append(text)
        a.require_end("capability query")
        return cls(query_type, checksum, tuple(profiles))


@dataclass(frozen=True)
class CapabilityAgent:
    id: int
    profile: str
    version: int
    role_flags: int
    connection_timeout: int


@dataclass(frozen=True)
class CapabilityApplication:
    package: str
    name: str
    agents: tuple[CapabilityAgent, ...]


@dataclass(frozen=True)
class CapabilityResponse:
    """The peer's answer: one entry per profile it provides."""

    query_type: int
    checksum: int
    applications: tuple[CapabilityApplication, ...]

    @classmethod
    def parse(cls, body: bytes) -> "CapabilityResponse":
        a = _Cursor(body, "capex")
        if a.uint(1) != 2:
            raise StageError("capex", "expected a capability response")
        query_type = a.uint(1)
        if query_type not in (2, 3):
            raise StageError("capex", "only checksum-bearing responses are supported")
        checksum = a.uint(4)
        count = a.uint(2)
        apps = []
        for _ in range(count):
            package = a.text()
            name = a.text()
            agent_count = a.uint(2)
            agents = []
            for _ in range(agent_count):
                agent_id = a.uint(2)
                profile = a.text()
                if profile.startswith("="):
                    raise StageError("capex", "compact 17-byte profile form is not implemented")
                agents.append(
                    CapabilityAgent(
                        id=agent_id,
                        profile=profile,
                        version=a.uint(2),
                        role_flags=a.uint(1),
                        connection_timeout=a.uint(2),
                    )
                )
            apps.append(CapabilityApplication(package, name, tuple(agents)))
        a.require_end("capability response")
        return cls(query_type, checksum, tuple(apps))


@dataclass(frozen=True)
class ServiceConnectionResponse:
    """The peer's answer to a service connection request."""

    initiator_agent_id: int
    acceptor_agent_id: int
    profile: str
    status: int
    session_ids: tuple[int, ...]
    trailing: bytes

    @classmethod
    def parse(cls, body: bytes) -> "ServiceConnectionResponse":
        a = _Cursor(body, "service")
        if a.uint(1) != 2:
            raise StageError("service", "expected a service creation response")
        initiator = a.uint(2)
        acceptor = a.uint(2)
        profile = a.text()
        status = a.uint(1)
        count = a.uint(2)
        sessions = tuple(a.uint(2) for _ in range(count))
        return cls(initiator, acceptor, profile, status, sessions, body[a.offset :])

    def require_accepted(
        self, *, local_agent_id: int, remote_agent_id: int, profile: str, session_ids: Iterable[int]
    ) -> None:
        # Strict: status 0, exact profile, exact
        # session list, initiator(local) first and acceptor(remote) second.
        expected = tuple(session_ids)
        if self.status != 0:
            raise StageError("service", f"service connection rejected with status {self.status}")
        if self.profile != profile:
            raise StageError("service", f"unexpected service profile {self.profile!r}")
        if self.session_ids != expected:
            raise StageError(
                "service",
                f"accepted sessions {self.session_ids} are not exactly {expected}",
            )
        if self.initiator_agent_id != local_agent_id or self.acceptor_agent_id != remote_agent_id:
            raise StageError(
                "service",
                "response agent order is not initiator(local) first, acceptor(remote) second",
            )


@dataclass(frozen=True)
class AgentAuthenticateRequest:
    """A type-5 agent challenge."""

    first_agent_id: int
    second_agent_id: int
    profile: str
    trailing: bytes

    @classmethod
    def parse(cls, body: bytes) -> "AgentAuthenticateRequest":
        a = _Cursor(body, "agent-auth")
        if a.uint(1) != 5:
            raise StageError("agent-auth", "expected an agent authenticate request")
        first = a.uint(2)
        second = a.uint(2)
        profile = a.text()
        return cls(first, second, profile, body[a.offset :])


def capex_query_body(profiles: Iterable[str], checksum: int = 0) -> bytes:
    """A capability query body, type 3."""
    profiles = list(profiles)
    if not profiles or len(profiles) > 255:
        raise StageError("capex", "invalid profile count")
    body = bytes([1, 3]) + checksum.to_bytes(4, "big") + bytes([len(profiles)])
    for profile in profiles:
        if not profile:
            raise StageError("capex", "empty profile")
        body += _text(profile)
    return body


def capex_response_body_from(
    applications: Iterable[CapabilityApplication],
    checksum: int,
    *,
    local_system_agent_id: int | None = None,
) -> bytes:
    """A capability response body.

    ``local_system_agent_id`` is the consumer the caller advertised for
    ``system:filetransfer``. The application records are assembled by
    :func:`capex_response_body`, the only place that knows the package, name
    and requested profile list; passing the id here lets the encoder prove that
    any record using it is the single system consumer, never a second copy and
    never another profile, before a byte is written.
    """
    apps = list(applications)
    if local_system_agent_id is not None:
        system_agents = [
            agent
            for app in apps
            for agent in app.agents
            if agent.id == local_system_agent_id
        ]
        if len(system_agents) > 1:
            raise StageError("capex", "duplicate system consumer record")
        if system_agents and system_agents[0].profile != PROFILE_SYSTEM:
            raise StageError("capex", "system consumer id carries another profile")
    if len(apps) > 0xFFFF:
        raise StageError("capex", "too many application records")
    body = bytes([2, 3]) + checksum.to_bytes(4, "big") + len(apps).to_bytes(2, "big")
    for app in apps:
        if len(app.agents) > 0xFFFF:
            raise StageError("capex", "too many agents")
        body += _text(app.package)
        body += _text(app.name)
        body += len(app.agents).to_bytes(2, "big")
        for agent in app.agents:
            if not agent.profile or agent.profile.startswith("="):
                raise StageError("capex", "unsupported profile string")
            body += agent.id.to_bytes(2, "big")
            body += _text(agent.profile)
            body += agent.version.to_bytes(2, "big")
            body += bytes([agent.role_flags])
            body += agent.connection_timeout.to_bytes(2, "big")
    return body


def capex_response_body(
    query: CapabilityQuery,
    *,
    local_agent_id: int,
    local_file_agent_id: int,
    package: str,
    name: str,
    local_system_agent_id: int | None = None,
) -> tuple[bytes, int]:
    """A capability response body for one consumer.

    One app record holding our message and file consumers (version 1.0,
    roleFlags 0x09, timeout 10), the APK's 65535/FF00 unsupported dummy for any
    requested profile we do not implement, and the CRC32 cache checksum over the
    filtered real records plus the sorted requested profile names.
    """
    if not (0 < local_agent_id < 0xFF00) or not (0 < local_file_agent_id < 0xFF00):
        raise StageError("capex", "local consumer agent id outside the reviewed range")
    if local_agent_id == local_file_agent_id:
        raise StageError("capex", "message and file consumers must be distinct agents")
    if local_system_agent_id is not None and not (
        0 < local_system_agent_id < 0xFF00
    ):
        raise StageError(
            "capex", "local system consumer agent id outside the reviewed range"
        )
    if local_system_agent_id is not None and local_system_agent_id in (
        local_agent_id,
        local_file_agent_id,
    ):
        raise StageError("capex", "system consumer must be a distinct agent")
    profiles = list(query.profiles)
    if not profiles or len(set(profiles)) != len(profiles):
        raise StageError("capex", "duplicate profile in a capability query")

    real = [
        CapabilityAgent(local_agent_id, PROFILE_MESSAGE, 0x0100, 0x09, 10),
        CapabilityAgent(local_file_agent_id, PROFILE_FILE, 0x0100, 0x09, 10),
    ]
    if local_system_agent_id is not None:
        # The official XML declares timeout 30 for system:filetransfer; 0x09 is
        # the honest consumer+socket minimum because no wake path is implemented.
        real.append(
            CapabilityAgent(local_system_agent_id, "system:filetransfer", 0x0100, 0x09, 30)
        )
    real = [agent for agent in real if agent.profile in profiles]

    apps: list[CapabilityApplication] = []
    if real:
        apps.append(CapabilityApplication(package, name, tuple(real)))
    known = [PROFILE_MESSAGE, PROFILE_FILE]
    if local_system_agent_id is not None:
        known.append("system:filetransfer")
    missing = [
        CapabilityAgent(0xFF00, profile, 0x0100, 1, 0)
        for profile in profiles
        if profile not in known
    ]
    if missing:
        # e5.a.a: package 65535 / empty name / agent FF00 means "unsupported".
        apps.append(CapabilityApplication("65535", "", tuple(missing)))

    # e5.a.c sorts the filtered real records by package/profile, then appends
    # the requested profile names.
    canonical = ""
    for agent in sorted(real, key=lambda a: a.profile):
        canonical += (
            package
            + agent.profile
            + str(agent.id)
            + "1"
            + "1.0"
            + "4"
            + "0"
            + str(agent.connection_timeout)
        )
    canonical += "".join(sorted(profiles))
    checksum = zlib.crc32(canonical.encode("utf-8")) & 0xFFFFFFFF
    return (
        capex_response_body_from(
            apps, checksum, local_system_agent_id=local_system_agent_id
        ),
        checksum,
    )


@dataclass(frozen=True)
class ChannelProposal:
    """One proposed channel: session, channel id and QoS."""

    session_id: int
    channel_id: int
    qos_type: int
    qos_class: int
    payload_type: int


@dataclass(frozen=True)
class ServiceConnectionRequest:
    """this module: the type-1 mirror of the response.

    The initiator writes the remote (acceptor) agent first and its own local
    agent second; sessions and channels are two
    parallel arrays, followed by one (qos type, class) pair and one payload
    type per channel. A device-initiated ``system:filetransfer`` offer uses this
    exact shape on reserved session 1.
    """

    remote_agent_id: int
    local_agent_id: int
    profile: str
    channels: tuple[ChannelProposal, ...]
    trailing: bytes

    @classmethod
    def parse(cls, body: bytes) -> "ServiceConnectionRequest":
        a = _Cursor(body, "service")
        if a.uint(1) != 1:
            raise StageError("service", "expected a service connection request")
        remote = a.uint(2)
        local = a.uint(2)
        profile = a.text()
        count = a.uint(2)
        if not 0 < count <= 64:
            raise StageError("service", "service channel count out of range")
        sessions = [a.uint(2) for _ in range(count)]
        channel_ids = [a.uint(2) for _ in range(count)]
        qos = [(a.uint(1), a.uint(1)) for _ in range(count)]
        payloads = [a.uint(1) for _ in range(count)]
        channels = tuple(
            ChannelProposal(sessions[i], channel_ids[i], qos[i][0], qos[i][1], payloads[i])
            for i in range(count)
        )
        return cls(remote, local, profile, channels, body[a.offset :])


def service_connection_response_body(
    *,
    initiator_agent_id: int,
    acceptor_agent_id: int,
    profile: str,
    status: int,
    session_ids: Iterable[int],
) -> bytes:
    """this module (type 2).

    The response reverses the request's agent order - initiator first, acceptor
    second - and echoes the accepted session list verbatim:
    91-114). ``status`` 0 accepts; a rejection carries no sessions.
    """
    sessions = list(session_ids)
    if not (0 < acceptor_agent_id < 0xFF00) or not (0 <= initiator_agent_id < 0xFF00):
        raise StageError("service", "invalid service connection agent id")
    if not 0 <= status <= 0xFF:
        raise StageError("service", "invalid service connection status")
    if len(sessions) > 0xFFFF or len(set(sessions)) != len(sessions):
        raise StageError("service", "invalid accepted session list")
    if any(not 32 <= session < 1024 for session in sessions):
        raise StageError("service", "accepted session id outside 32..1023")
    if status == 0 and not sessions:
        raise StageError("service", "an accepted service names at least one session")
    body = bytes([2])
    body += initiator_agent_id.to_bytes(2, "big")
    body += acceptor_agent_id.to_bytes(2, "big")
    body += _text(profile, "service")
    body += bytes([status]) + len(sessions).to_bytes(2, "big")
    for session in sessions:
        body += session.to_bytes(2, "big")
    return body


def service_connection_request_body(
    *,
    local_agent_id: int,
    remote_agent_id: int,
    profile: str,
    channels: Iterable[ChannelProposal],
) -> bytes:
    """The service connection request body.

    The remote (acceptor) id is written first, then the local (initiator) id;
    every channel array is length-prefixed once, then (qos type, class) pairs,
    then payload types - the order ``storage.db.a.d`` writes.
    """
    channels = list(channels)
    if not (0 < local_agent_id < 0xFF00) or not (0 <= remote_agent_id < 0xFF00):
        raise StageError("service", "invalid service connection agent id")
    if not channels or len(channels) > 0xFFFF:
        raise StageError("service", "invalid service connection proposal")
    if len(profile.encode("utf-8")) > 64:
        raise StageError("service", "service profile longer than 64 bytes")
    if len({c.session_id for c in channels}) != len(channels):
        raise StageError("service", "duplicate session id in proposal")
    if len({c.channel_id for c in channels}) != len(channels):
        raise StageError("service", "duplicate channel id in proposal")
    if not all(32 <= c.session_id < 1024 for c in channels):
        raise StageError("service", "proposed session id outside 32..1023")

    body = bytes([1]) + remote_agent_id.to_bytes(2, "big") + local_agent_id.to_bytes(2, "big")
    body += _text(profile, "service")
    body += len(channels).to_bytes(2, "big")
    for channel in channels:
        body += channel.session_id.to_bytes(2, "big")
    for channel in channels:
        body += channel.channel_id.to_bytes(2, "big")
    for channel in channels:
        body += bytes([channel.qos_type, channel.qos_class])
    for channel in channels:
        body += bytes([channel.payload_type])
    return body


def agent_authenticate_body(
    *, first_agent_id: int, second_agent_id: int, profile: str, auth_payload: bytes
) -> bytes:
    """The type-6 response body.

    ``06 || first:u16 BE || second:u16 BE || profile || 0x3b || authPayload``.
    The caller swaps the request's pair.
    """
    if not profile:
        raise StageError("agent-auth", "invalid type-6 auth payload")
    if len(auth_payload) > 0xFFFF:
        raise StageError("agent-auth", "agent auth payload too large")
    body = (
        bytes([6])
        + first_agent_id.to_bytes(2, "big")
        + second_agent_id.to_bytes(2, "big")
        + profile.encode("utf-8")
        + b";"
        + auth_payload
    )
    if len(body) > 0xFFFF:
        raise StageError("agent-auth", "type-6 body too large")
    return body


# --------------------------------------------------------------------------
# Device info
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceInfo:
    """Parsed ``03 ff`` payload: deviceType then 2, 3 or 5 length-prefixed fields."""

    device_type: int
    field_count: int
    serial: str
    firmware_version: str
    device_model: str | None
    device_id_bytes: bytes | None
    device_name: str | None

    @classmethod
    def parse(cls, payload: bytes) -> "DeviceInfo":
        if len(payload) < 3:
            raise StageError("device-info", "device info payload is shorter than 3 bytes")
        device_type = payload[0]
        fields: list[bytes] = []
        offset = 1
        while offset < len(payload):
            if len(fields) >= 5:
                raise StageError("device-info", "device info has more than five fields")
            length = payload[offset]
            offset += 1
            # The source reads a signed Java byte, so 0x80..0xff is rejected.
            if length > 127 or length > len(payload) - offset:
                raise StageError("device-info", "device info field length out of range")
            fields.append(payload[offset : offset + length])
            offset += length
        if len(fields) not in (2, 3, 5):
            raise StageError(
                "device-info", f"device info has {len(fields)} fields, expected 2, 3 or 5"
            )
        return cls(
            device_type=device_type,
            field_count=len(fields),
            serial=fields[0].decode("utf-8", "replace"),
            firmware_version=fields[1].decode("utf-8", "replace"),
            device_model=(fields[2].decode("utf-8", "replace") or None)
            if len(fields) >= 3
            else None,
            device_id_bytes=fields[3] if len(fields) == 5 else None,
            device_name=fields[4].decode("utf-8", "replace") if len(fields) == 5 else None,
        )


# --------------------------------------------------------------------------
# The connected channel handed back to the caller
# --------------------------------------------------------------------------


@dataclass
class ConnectedChannel:
    """A usable business channel on session 32 / channel 104.

    Keep one instance per link. Two counters live in here - the send counter of
    the secure envelope and the receive counter the device's frames advance -
    and the device refuses a frame whose counter does not increase, so a second
    channel rebuilt from the same credentials cannot be used in parallel.

    A ``sync=True`` channel additionally exposes the device-driven recording
    stream: ``system_provider_id`` and ``system_session_id`` identify the
    ``system:filetransfer`` service, ``file_channels`` is its session -> channel
    map when the device declared one, and :meth:`read_raw` returns its frames
    without decrypting or routing them.
    """

    session: Session
    secure: SecureBusinessChannel
    session_id: int
    channel_id: int
    message_provider_id: int
    file_provider_id: int
    device_info: DeviceInfo | None
    bind_payload: bytes
    system_provider_id: int | None = None
    system_session_id: int | None = None
    file_channels: dict[int, int] = field(default_factory=dict)
    # Frames parked while connect() still owned the read loop, and the
    # per-session reassembly state it used; read_raw() continues both.
    pending_frames: list[tuple[int, bytes]] = field(default_factory=list)
    framers: dict[int, framing.Framer] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)
    #: Business messages skipped while waiting for a specific reply.
    skipped_replies: int = 0
    #: Plain (unauthenticated) business messages seen on the message session.
    unauthenticated_messages: int = 0
    #: Message-session frames that failed authentication and were skipped.
    rejected_frames: int = 0

    def close(self) -> None:
        self.session.close()

    @property
    def link_lost(self) -> bool:
        return self.session.link_lost

    @property
    def disconnected(self) -> bool:
        return self.link_lost

    def __enter__(self) -> "ConnectedChannel":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- sending ---------------------------------------------------------

    def encode_business(self, service: int, command: int, payload: bytes = b"") -> bytes:
        """this module.

        ``[service, command, payload]`` -> AA pipe envelope -> secure seal ->
        one TL frame on the message session.
        """
        if not 0 <= service <= 0xFF or not 0 <= command <= 0xFF:
            raise ConnectError("service and command are one byte each")
        plaintext = encode_pipe_message(bytes([service, command]) + payload)
        body = self.secure.seal(plaintext)
        return framing.encode(self.session_id, body)

    def send_command(
        self,
        service: int,
        command: int,
        payload: bytes = b"",
        *,
        expect: tuple[int, int] | None = None,
        require_authenticated: bool | None = None,
        timeout: float | None = None,
    ) -> bytes:
        """Send one business request and return the device's reply.

        A reply is the ``AA`` envelope's ``service || command || payload`` - the
        same shape :meth:`encode_business` accepts as input. ``expect`` names the
        reply header ``(service, command)``: other business messages arriving
        first are device events, not the answer, and are skipped. When
        ``require_authenticated`` is true, only a reply that opened under
        the session key counts. If omitted, status/storage/INIT require it and other
        commands accept the protocol's explicit-plain replies. Use
        :mod:`.commands` to parse known replies.
        """
        frame = self.encode_business(service, command, payload)
        self.session.write(BUSINESS_WRITE, frame, self.session.timeout)
        if require_authenticated is None:
            require_authenticated = _request_requires_authentication(service, command)
        return self.read_reply(
            timeout, expect=expect, require_authenticated=require_authenticated
        )

    def send_command_large(
        self,
        service: int,
        command: int,
        payload: bytes = b"",
        *,
        expect: tuple[int, int] | None = None,
        require_authenticated: bool | None = None,
        timeout: float | None = None,
    ) -> bytes:
        """Send one business request whose body does not fit a single frame.

        The INIT payload is 568 bytes, far past the 232-byte frame body, so it
        has to be split. The answer is large too - it carries the account and key
        readback - so frames are reassembled before the envelope is opened;
        handing a fragment to open() fails authentication.
        """
        plaintext = encode_pipe_message(bytes([service, command]) + payload)
        body = self.secure.seal(plaintext)
        for frame in framing.split(self.session_id, body):
            self.session.write(BUSINESS_WRITE, frame, self.session.timeout)
        if require_authenticated is None:
            require_authenticated = _request_requires_authentication(service, command)
        return self.read_reply(
            timeout, expect=expect, require_authenticated=require_authenticated
        )

    def send_only(self, service: int, command: int, payload: bytes = b"") -> bytes:
        """Send one request without waiting for a reply (``07/00`` toggles).

        Returning means the write was handed to the link, nothing more: these
        commands have no application ACK, so a caller reports
        "write attempted" until something else (a status read) is observed.
        """
        frame = self.encode_business(service, command, payload)
        self.session.write(BUSINESS_WRITE, frame, self.session.timeout)
        return frame

    # -- receiving -------------------------------------------------------

    def _next_frame(self, remaining: float) -> tuple[int, bytes] | None:
        """One complete TL frame, or ``None`` on an idle tick.

        Fragments are reassembled per session. :class:`LinkLost` propagates:
        a dropped link is never an idle tick.
        """
        try:
            payload = self.session.read(max(0.1, remaining)).payload
        except LinkLost:
            raise
        except TransportError as exc:
            if self.session.link_lost:
                raise LinkLost("the link dropped") from None
            if is_idle_error(exc):
                return None
            raise
        try:
            frame = framing.decode(payload)
        except framing.FrameError:
            return None  # not a TL frame we can read; ignore rather than stop
        framer = self.framers.setdefault(frame.session_id, framing.Framer())
        try:
            body = framer.feed(payload)
        except framing.FrameError:
            framer.reset()
            return None
        if body is None:
            return None
        return frame.session_id, body

    def _park(self, session_id: int, body: bytes) -> None:
        if len(self.pending_frames) < MAX_PARKED_FRAMES:
            self.pending_frames.append((session_id, body))

    def decode_business(self, body: bytes) -> BusinessMessage | None:
        """Decode one complete message-session body, or ``None`` if it is not
        a business message (empty, or an ACK/control pipe subtype).

        Raises :class:`ConnectError` for an unknown flag or an encrypted body
        without a secure context, :class:`secure.SecureChannelError` when the
        envelope fails authentication, and :class:`PipeMessageError` for a
        malformed pipe envelope.
        """
        if not body:
            return None
        flag = body[0]
        if flag == BUSINESS_FLAG_PLAIN:
            # explicit plain business stays legal on a secure channel (e.g. the
            # ``30 02 00`` state event), but it is not authenticated.
            plaintext = body[1:]
            authenticated = False
        elif flag == BUSINESS_FLAG_ENCRYPTED:
            if self.secure is None:
                raise ConnectError("encrypted business frame without a secure context")
            plaintext = self.secure.open(body)
            authenticated = True
        else:
            raise ConnectError(f"unsupported business flag 0x{flag:02x}")
        try:
            message = decode_pipe_message(plaintext)
        except pipe.PipeError as exc:
            raise PipeMessageError(str(exc)) from exc
        if (message.type & 0x0F) in (3, 4):
            # ACK/control subtypes have no reviewed read path and are not a
            # reply to a business request.
            return None
        if len(message.data) < 2:
            raise StageError("business", "pipe message shorter than service/command")
        if not authenticated:
            self.unauthenticated_messages += 1
        return BusinessMessage(
            service=message.data[0],
            command=message.data[1],
            payload=bytes(message.data[2:]),
            authenticated=authenticated,
        )

    def read_message(self, timeout: float | None = None) -> BusinessMessage | None:
        """Next message-session business message, or ``None`` at the deadline.

        Message-session frames parked during ``connect()`` come first. Frames
        for any other session are parked for :meth:`read_raw` instead of being
        dropped. A frame that fails authentication is skipped without moving
        the receive counter (see :mod:`.secure`) and counted in
        ``rejected_frames``.
        """
        deadline = time.monotonic() + (
            timeout if timeout is not None else self.session.timeout
        )
        while True:
            parked = next(
                (i for i, (sid, _b) in enumerate(self.pending_frames)
                 if sid == self.session_id),
                None,
            )
            if parked is not None:
                _sid, body = self.pending_frames.pop(parked)
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                got = self._next_frame(remaining)
                if got is None:
                    continue
                session_id, body = got
                if session_id != self.session_id:
                    self._park(session_id, body)
                    continue
            try:
                message = self.decode_business(body)
            except secure.SecureChannelError:
                self.rejected_frames += 1
                continue
            if message is not None:
                return message

    def read_reply(
        self,
        timeout: float | None = None,
        *,
        expect: tuple[int, int] | None = None,
        require_authenticated: bool | None = None,
    ) -> bytes:
        """Return the next matching ``service || command || payload`` reply.

        TL fragments are reassembled before the envelope is opened, so a large
        reply (the INIT readback) arrives whole. With ``require_authenticated``
        a plain body is never the answer; if it is omitted, the known
        status/storage/INIT reply headers require it. With ``expect`` only that
        header is.
        Everything skipped is counted; the timeout message says what was seen.
        Raises :class:`ReplyTimeout` at the deadline and :class:`LinkLost` when
        the link drops.
        """
        if require_authenticated is None:
            require_authenticated = _reply_requires_authentication(expect)
        deadline = time.monotonic() + (
            timeout if timeout is not None else self.session.timeout
        )
        skipped = 0
        plain = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            message = self.read_message(remaining)
            if message is None:
                break
            if require_authenticated and not message.authenticated:
                plain += 1
                continue
            if expect is not None and (message.service, message.command) != tuple(expect):
                skipped += 1
                self.skipped_replies += 1
                if skipped >= MAX_SKIPPED_REPLIES:
                    break
                continue
            return message.data
        detail = []
        if expect is not None:
            detail.append(f"expected {expect[0]:02x}/{expect[1]:02x}")
        if skipped:
            detail.append(f"{skipped} other business message(s) skipped")
        if plain:
            detail.append(f"{plain} unauthenticated message(s) ignored")
        if self.rejected_frames:
            detail.append(f"{self.rejected_frames} frame(s) failed authentication")
        raise ReplyTimeout(
            "timed out waiting for a business reply"
            + (" (" + "; ".join(detail) + ")" if detail else "")
        )

    def read_raw(self, timeout: float | None = None) -> tuple[int, bytes] | None:
        """Read one complete TL frame as ``(session_id, body)``, or ``None``.

        The body is not decrypted, routed or otherwise interpreted. This is the
        reader a sync receiver needs for the device's reserved-session type-1
        ``system:filetransfer`` proposal: that
        frame is not message-session business and must not go through
        :meth:`read_reply`. Frames parked while ``connect()`` still owned the
        read loop are returned first, in arrival order. Fragments are
        reassembled per session, exactly as the connect() read loop does, so a
        body split across notifications comes back whole; ``None`` means the
        caller's deadline expired, not that one idle tick did.

        :class:`transport.LinkLost` is raised, never mapped to ``None``: a
        dropped link is not an idle stream.
        """
        if self.pending_frames:
            return self.pending_frames.pop(0)
        deadline = time.monotonic() + (
            timeout if timeout is not None else self.session.timeout
        )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            got = self._next_frame(remaining)
            if got is not None:
                return got

    def _accept(self, payload: bytes) -> bytes | None:
        """Feed one notification; return ``service||command||payload`` or None.

        Single-frame helper kept for compatibility; :meth:`read_message`
        reassembles fragments and should be preferred.
        """
        try:
            frame = framing.decode(payload)
        except framing.FrameError:
            return None
        if frame.session_id != self.session_id:
            return None
        return self._decode_body(frame.body)

    def _decode_body(self, body: bytes) -> bytes | None:
        """Decode one complete business body into ``service||command||payload``."""
        message = self.decode_business(body)
        return message.data if message is not None else None


# --------------------------------------------------------------------------
# The sequence itself
# --------------------------------------------------------------------------


def connect(
    session: Session,
    pairing: Pairing,
    local_peer_id: str,
    *,
    timeout: float = 45.0,
    agent_id: int = DEFAULT_AGENT_ID,
    package: str = DEFAULT_PACKAGE,
    name: str = DEFAULT_AGENT_NAME,
    agent_auth_payload: bytes | None = None,
    sync: bool = False,
    agent_public_key: bytes | None = None,
    bind_start_delay_ms: int = 0,
) -> ConnectedChannel:
    """Bring up the business channel on an already-connected session.

    ``session`` must be open and subscribed to the notification
    characteristic :data:`transport.BUSINESS_NOTIFY` (AA16); frames are written
    to :data:`transport.BUSINESS_WRITE` (AA17), where the device accepts them.
    ``pairing`` is the KSC material the pairing step
    produced, and ``local_peer_id`` is this host's stable 36-byte ``OAFP_...``
    identity that the EPI answer echoes.

    ``agent_id`` selects the local message consumer; the file consumer is
    ``agent_id + 1`` (this module). ``agent_auth_payload``
    is what the type-6 reply carries: by default the APK's four-byte
    "no package signature" fallback, because this host has no Android package
    to sign with. ``agent_public_key`` (SPKI DER) instead sends the APK's
    normal ``00 01 || BE16(len) || SPKI`` payload, exactly as the tested Swift
    tool does; it is validated before any byte is written. The two are
    mutually exclusive.

    ``bind_start_delay_ms`` (0...2000) delays only the first business request
    after both services are accepted. The tested profile used 1000 ms; it
    changes no frame and is a timing choice, not a readiness guarantee.

    ``sync`` additionally advertises the ``system:filetransfer`` profile with a
    third local consumer (``agent_id + 2``), which is what makes the device
    willing to push recordings. Without it a ``06 00`` range request is accepted
    and then nothing arrives. Turn it on only when a sync is actually coming:
    the record is not advertised for ordinary control traffic. The returned
    channel's ``system_provider_id``, ``system_session_id`` and ``file_channels``
    describe that service, and :meth:`ConnectedChannel.read_raw` exposes the
    device's own type-1 plus every later control/data frame untouched.

    Raises :class:`StageError` naming the stage that stopped, or
    :class:`ConnectError` for a local protocol violation.
    """
    if len(local_peer_id) != 36 or not local_peer_id.startswith("OAFP_"):
        raise ConnectError("local peer id must be the 36-byte OAFP_ identity")
    if not 0 < agent_id < 0xFEFF:
        # file = message + 1 must stay below FF00.
        raise ConnectError("agent id must be 1..65278 so the file consumer stays below 0xff00")

    if sync and not 0 < agent_id < 0xFEFE:
        # system = message + 2 must stay below FF00.
        raise ConnectError(
            "agent id must be 1..65277 so the system consumer stays below 0xff00"
        )
    if agent_public_key is not None and agent_auth_payload is not None:
        raise ConnectError("pass agent_public_key or agent_auth_payload, not both")
    if agent_public_key is not None:
        if isinstance(agent_public_key, (str, Path)):
            agent_public_key = load_agent_public_key(agent_public_key)
        agent_auth_payload = agent_auth_payload_from_spki(agent_public_key)
    elif agent_auth_payload is None:
        agent_auth_payload = AGENT_AUTH_UNAVAILABLE
    if (
        isinstance(bind_start_delay_ms, bool)
        or not isinstance(bind_start_delay_ms, int)
        or not 0 <= bind_start_delay_ms <= MAX_BIND_START_DELAY_MS
    ):
        raise ConnectError("bind start delay must be an integer 0...2000 ms")
    if not package or "\x00" in package or len(package.encode("utf-8")) > 255:
        raise ConnectError("agent package must be 1...255 non-NUL UTF-8 bytes")

    runner = _Runner(
        session=session,
        pairing=pairing,
        local_peer_id=local_peer_id,
        agent_id=agent_id,
        package=package,
        name=name,
        agent_auth_payload=agent_auth_payload,
        deadline=time.monotonic() + timeout,
        sync=sync,
        bind_start_delay_ms=bind_start_delay_ms,
    )
    return runner.run()


class _Runner:
    """One run of the five stages; kept separate so ``connect`` stays readable."""

    def __init__(
        self,
        *,
        session: Session,
        pairing: Pairing,
        local_peer_id: str,
        agent_id: int,
        package: str,
        name: str,
        agent_auth_payload: bytes,
        deadline: float,
        sync: bool = False,
        bind_start_delay_ms: int = 0,
    ) -> None:
        self.session = session
        self.bind_start_delay_ms = bind_start_delay_ms
        self.pairing = pairing
        self.local_peer_id = local_peer_id
        self.agent_id = agent_id
        # File consumer: message + 1.
        self.file_agent_id = agent_id + 1
        # System consumer: message + 2, advertised for sync
        # only.
        self.sync = sync
        self.system_agent_id = agent_id + 2 if sync else None
        self.system_provider_id: int | None = None
        self.system_session_id: int | None = None
        self.file_channels: dict[int, int] = {}
        # Complete TL frames seen while the sequence still owns the read loop.
        self.raw_frames: list[tuple[int, bytes]] = []
        self._next_system_session: int | None = None
        self._system_auth_answered = False
        self._file_accepted = False
        self.package = package
        self.name = name
        self.agent_auth_payload = agent_auth_payload
        self.deadline = deadline
        self.steps: list[Step] = []

        self.secure: SecureBusinessChannel | None = None
        self.framers: dict[int, framing.Framer] = {}
        # Complete TL frames that arrived before the sequence could read them.
        self._early_frames: list[tuple[int, bytes]] = []
        self.message_provider_id: int | None = None
        self.file_provider_id: int | None = None
        self.bind_payload = b""
        self.device_info: DeviceInfo | None = None
        # "message" / "file" / "system" while a request is outstanding. The
        # terminal value is ``_services_done``: a sync link finishes after the
        # system stage, a plain link after the file stage.
        self._pending_service = ""
        self._services_done = "system_accepted" if sync else "file_accepted"
        self.file_session_id: int | None = None
        self._next_file_session = DEFAULT_FILE_SESSION_ID
        self._file_agent_id: int | None = None
        self._message_auth_answered = False
        self._file_auth_answered = False
        self._last_business_authenticated = False

    # -- plumbing --------------------------------------------------------

    def _note(self, name: str, sent: int = 0, received: int = 0) -> None:
        self.steps.append(Step(name, sent, received))

    def _remaining(self, cap: float) -> float:
        """The sooner of the stage's own limit and the caller's total budget."""
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise StageError("timeout", "the overall connect() budget is exhausted")
        return max(0.1, min(cap, left))

    def _write(self, payload: bytes) -> None:
        self.session.write(BUSINESS_WRITE, payload, self.session.timeout)

    def _decode_tl(self, payload: bytes) -> tuple[int, bytes] | None:
        """Return ``(session_id, body)`` if ``payload`` completes a TL frame.

        Fragment sequences are reassembled per session id by
        :class:`framing.Framer` (this module,
        A notification that is not a TL
        frame returns ``None``.
        """
        try:
            frame = framing.decode(payload)
        except framing.FrameError:
            return None
        framer = self.framers.setdefault(frame.session_id, framing.Framer())
        try:
            body = framer.feed(payload)
        except framing.FrameError as exc:
            framer.reset()
            raise StageError(
                "read", f"bad frame on session {frame.session_id}: {exc}"
            ) from exc
        if body is None:
            return None
        return frame.session_id, body

    def _read_frame(self, limit: float) -> tuple[int, bytes]:
        """Return ``(session_id, body)`` for the next complete TL frame.

        Frames the device sends during the plain-text handshake (its own
        capability query is the one observed case) are parked in
        ``_early_frames`` and returned here in arrival order, so nothing the
        peer said is silently dropped while the channel was not yet readable.
        """
        if self._early_frames:
            return self._early_frames.pop(0)
        end = time.monotonic() + limit
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise StageError("read", "timed out waiting for a frame")
            try:
                note: Notification = self.session.read(max(0.1, remaining))
            except LinkLost:
                raise
            except TransportError:
                if self.session.link_lost:
                    raise LinkLost("the link dropped during connect") from None
                raise
            decoded = self._decode_tl(note.payload)
            if decoded is not None:
                return decoded

    def _read_length_prefixed(self) -> bytes:
        """Read one ``[len][payload]`` notification and return ``payload``.

        The EPI offer uses this shape.
        """
        end = time.monotonic() + self._remaining(CAPEX_SECONDS)
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise StageError("read", "timed out waiting for the EPI offer")
            payload = self.session.read(max(0.1, remaining)).payload
            if payload and len(payload) == payload[0] + 1:
                return payload[1:]

    def _read_handshake(self, limit: float) -> tuple[str, bytes]:
        """Read one notification for the plain-text stages.

        Returns ``("auth", 27-byte payload)`` for the authentication response,
        or ``("frame", body)`` for a complete TL frame, which is parked in
        ``_early_frames`` for the stage that needs it.
        """
        end = time.monotonic() + limit
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise StageError("read", "timed out during the plain-text handshake")
            payload = self.session.read(max(0.1, remaining)).payload
            if not payload:
                continue
            length = payload[0]
            if len(payload) != length + 1:
                continue  # not one complete length-prefixed notification
            body = payload[1:]
            # exactly 27 bytes, type 0x11.
            if len(body) == AUTH_RESPONSE and body[0] == AUTH_RESPONSE_TYPE:
                return "auth", body
            # A complete TL frame sent during the plain-text stage (the device's
            # own capability query is the observed case) is parked, not lost.
            decoded = self._decode_tl(payload)
            if decoded is not None:
                self._early_frames.append(decoded)
                return "frame", decoded[1]
            # Neither the auth response nor a TL frame: nothing this sequence
            # knows how to use before the secure channel exists.
            continue



    # -- stage 1: EPI ------------------------------------------------

    def _negotiate_transport(self) -> None:
        """Answer the device's EPI offer.

        The offer is buffered, then answered by ``build_answer``, which is
        and the answer is written once.
        The offer arrives as one length-prefixed notification; the answer goes
        back once as a plain write, and later frames are read without replies.
        """
        # The offer is completed by its own leading length byte
        # byte and hands the rest to the EPI answer builder:
        # the offer body is everything after that byte, NOT a TL body.
        offer = self._read_length_prefixed()
        try:
            parsed = epi.parse_offer(offer)
            epi.check_offer(parsed)
            answer = epi.build_answer(self.local_peer_id, service_profiles=EPI_SERVICE_PROFILES)
        except epi.NegotiationError as exc:
            raise StageError("epi", str(exc)) from exc
        # ``answerSent = true`` then one write - never retried.
        self._write(answer)
        self._note("epi_answer", len(answer), len(offer))

    # -- stage 2: authentication -------------------------------------

    def _authenticate(self) -> None:
        """HMAC-SHA512 challenge/response.

        The request is sent; then
        The response is verified as 27 bytes and
        sends the confirm. Both are plain one-byte-length-prefixed frames, built
        byte for byte by :mod:`.auth`.

        The confirm is the last plain frame: everything after it carries the
        ``0x04`` secure envelope.
        """
        # key = KSC, localID = seeker id.
        state = AuthState(pairing=self.pairing, local_id=self.pairing.seeker_id)
        request = state.request()
        self._write(request)

        # The response arrives as a bare length-prefixed frame, NOT a TL frame:
        # consumes it from ``authBuffer`` before any
        # transport parsing (captures show ``1b 11 01 00 ...`` on the wire).
        kind, body = "", b""
        while kind != "auth":
            kind, body = self._read_handshake(self._remaining(CAPEX_SECONDS))
        # Anything that was a TL frame instead is kept in ``_early_frames``.
        try:
            confirm = state.confirm(body)
        except AuthError as exc:
            raise StageError("authenticate", str(exc)) from exc
        self._write(confirm)
        self._note("authenticate", len(request) + len(confirm), len(body))

        # AuthState.transcript is qc || qs, which is exactly what
        # and the resulting context becomes the secure channel key.
        # context = KSC plus the two challenges.
        # hands it to the flow right after the confirm is queued.
        if state.server_challenge is None:
            raise StageError("authenticate", "no server challenge to build the secure context")
        self.secure = SecureBusinessChannel(self.pairing.ksc, state.transcript)

    # -- stages 3 and 4: capability, services, agent auth ------------

    def _exchange_capabilities(self) -> None:
        """Discover providers, then open both services.

        The exchange: the provider query,
        ``consumeCapex`` , ``consumeAgentAuthenticate`` 
        and ``consumeService`` . The order is strict: query, message
        service request, its type-5 challenge, its type-2 response, then the
        same for the file service. With ``sync`` a third ``system:filetransfer``
        offer follows the accepted file service.
        """
        # takeProviderQuery: e5.a.d(3, checksum 0, [message, file]) on session 2.
        profiles = [PROFILE_MESSAGE, PROFILE_FILE]
        if self.sync:
            # Only a sync caller advertises the third consumer
            #; the device will not push recordings
            # to a peer that never asked for system:filetransfer.
            profiles.append(PROFILE_SYSTEM)
        query = framing.encode(SESSION_CAPEX, capex_query_body(profiles, 0))
        self._write(query)

        while self._pending_service != self._services_done:
            # each service response has its own limit.
            if self._pending_service == "message":
                stage_limit = MESSAGE_SERVICE_SECONDS
            elif self._pending_service == "system":
                stage_limit = SYSTEM_SERVICE_SECONDS
            else:
                stage_limit = FILE_SERVICE_SECONDS
            try:
                session_id, body = self._read_frame(self._remaining(stage_limit))
            except LinkLost:
                # A dropped link is never "the device did not answer".
                raise
            except (StageError, TransportError) as exc:
                timed_out = (
                    isinstance(exc, TransportError) and is_idle_error(exc)
                ) or (
                    isinstance(exc, StageError)
                    and exc.stage == "read" and "timed out" in str(exc)
                )
                if self.sync and self._pending_service == "system" and timed_out:
                    # The native device opens system:filetransfer itself when it
                    # has a file to push and does not answer a host-initiated
                    # request (the notes above 2.1).
                    # read_raw() delivers that type-1 after connect() returns.
                    self._note("system_service_no_reply")
                    self._pending_service = self._services_done
                    continue
                raise
            if session_id == SESSION_CAPEX:
                self._handle_capex(body)
            elif session_id == SESSION_SERVICE:
                self._handle_service(body)
            # Any other session is not part of this sequence and is ignored.

    def _handle_capex(self, body: bytes) -> None:
        if not body:
            raise StageError("capex", "empty capability body")
        if body[0] == 1:
            # answer a device query.
            query = CapabilityQuery.parse(body)
            reply, _checksum = capex_response_body(
                query,
                local_agent_id=self.agent_id,
                local_file_agent_id=self.file_agent_id,
                local_system_agent_id=self.system_agent_id,
                package=self.package,
                name=self.name,
            )
            frame = framing.encode(SESSION_CAPEX, reply)
            self._write(frame)
            self._note("capex_response", len(frame), len(body))
            return
        if body[0] != 2:
            raise StageError("capex", f"unknown capability message type {body[0]}")

        response = CapabilityResponse.parse(body)
        message_candidates: list[CapabilityAgent] = []
        file_candidates: list[CapabilityAgent] = []
        system_candidates: list[CapabilityAgent] = []
        for app in response.applications:
            if app.package == "65535":
                continue
            for agent in app.agents:
                if agent.id == 0xFF00:
                    continue
                # d5.c.p: role bits 0-1, 0 = provider. socketSupport is only
                # capability metadata, never a selection gate.
                if agent.role_flags & 0x03:
                    continue
                if agent.profile == PROFILE_MESSAGE:
                    message_candidates.append(agent)
                elif agent.profile == PROFILE_FILE:
                    file_candidates.append(agent)
                elif agent.profile == PROFILE_SYSTEM:
                    system_candidates.append(agent)
        if len(message_candidates) > 1 or len(file_candidates) > 1:
            # ambiguity stops rather than picking.
            raise StageError(
                "capex",
                "multiple providers: message="
                f"{[a.id for a in message_candidates]} "
                f"file={[a.id for a in file_candidates]}",
            )
        if self.sync:
            # sync advertises the third consumer,
            # so the device must name the provider its type-1 will target.
            if len(system_candidates) > 1:
                raise StageError(
                    "capex",
                    f"multiple system providers: {[a.id for a in system_candidates]}",
                )
            if not system_candidates:
                raise StageError(
                    "capex",
                    "the device offers no system:filetransfer provider, so it will "
                    "not push recordings on this link",
                )

        if not message_candidates or not file_candidates:
            # the device has not registered yet.
            raise StageError(
                "capex",
                "providers not found: message="
                f"{[a.id for a in message_candidates]} "
                f"file={[a.id for a in file_candidates]}",
            )

        self.message_provider_id = message_candidates[0].id
        self.file_provider_id = file_candidates[0].id
        if self.sync:
            self.system_provider_id = system_candidates[0].id
        self._note("capex_providers", 0, len(body))
        # the message service request follows.
        self._send_service_request("message")

    def _send_service_request(self, which: str) -> None:
        # (message) and (file).
        if which == "system":
            if self.system_agent_id is None or self._next_system_session is None:
                raise StageError("service", "system service request without a derived session")
            proposal = ChannelProposal(
                self._next_system_session,
                CONTROL_CHANNEL_ID,
                SYSTEM_QOS_TYPE,
                SYSTEM_QOS_CLASS,
                SYSTEM_PAYLOAD_TYPE,
            )
            local, remote, profile = (
                self.system_agent_id,
                self.system_provider_id,
                PROFILE_SYSTEM,
            )
        elif which == "message":
            proposal = ChannelProposal(DEFAULT_SESSION_ID, DEFAULT_CHANNEL_ID, 4, 1, 0)
            local, remote, profile = self.agent_id, self.message_provider_id, PROFILE_MESSAGE
        else:
            proposal = ChannelProposal(
                DEFAULT_FILE_SESSION_ID,
                FILE_CHANNEL_ID,
                FILE_QOS_TYPE,
                FILE_QOS_CLASS,
                FILE_PAYLOAD_TYPE,
            )
            local, remote, profile = self.file_agent_id, self.file_provider_id, PROFILE_FILE
        if remote is None or local is None:
            raise StageError("service", f"{which} service request without a provider")
        body = service_connection_request_body(
            local_agent_id=local,
            remote_agent_id=remote,
            profile=profile,
            channels=[proposal],
        )
        frame = framing.encode(SESSION_SERVICE, body)
        self._write(frame)
        self._pending_service = which
        self._note(f"{which}_service_request", len(frame), len(body))

    def _require_service_reply(
        self,
        response: "ServiceConnectionResponse",
        *,
        local_agent_id: int,
        profile: str,
        session_ids: tuple[int, ...],
    ) -> None:
        """Apply the strict acceptance rules, with one honest relaxation.

        A reply whose session list is not
        exactly the proposal. The hardware observation (oaf-query-20261020-15)
        is looser: its message-service reply echoes ``(32, 33)`` for a single
        proposed session 32, and its file-service reply echoes ``(34,)``. Both
        replies *contain* what was proposed, so acceptance requires the proposed
        id to be present, and the runner then uses the device's own numbering
        for anything afterwards (the file session is derived from the full list).

        The agent pair is likewise checked only for presence of our local id:
        the real reply carries the provider id as acceptor and a second id (the
        device's own consumer) as initiator, so an exact pair would reject a
        working link.
        """
        if response.status != 0:
            raise StageError("service", f"service connection rejected with status {response.status}")
        if response.profile != profile:
            raise StageError("service", f"unexpected service profile {response.profile!r}")
        missing = [sid for sid in session_ids if sid not in response.session_ids]
        if missing or not response.session_ids:
            raise StageError(
                "service",
                f"accepted sessions {response.session_ids} do not contain {missing or session_ids}",
            )
        named = {response.initiator_agent_id, response.acceptor_agent_id}
        if local_agent_id not in named:
            raise StageError(
                "service",
                f"reply names agents {sorted(named)} but not local agent {local_agent_id}",
            )

    def _handle_service(self, body: bytes) -> None:
        if not body:
            raise StageError("service", "empty service body")
        if body[0] == 5:
            # type 5 is the agent authenticate request.
            self._handle_agent_auth(body)
            return
        if body[0] == 1:
            if not self.sync:
                raise StageError("service", f"unexpected service frame type {body[0]}")
            # The sync layer answers this offer. Keep the frame verbatim for
            # ConnectedChannel.read_raw; accepting it here would hide the
            # session/channel declaration from the only consumer that needs it.
            self.raw_frames.append((SESSION_SERVICE, body))
            self._observe_service_request(body)
            if self._pending_service == "system":
                # The device opened the service on its own; stop waiting for a
                # reply to our host-initiated offer.
                self._pending_service = self._services_done
            return
        if body[0] != 2:
            raise StageError("service", f"unexpected service frame type {body[0]}")

        response = ServiceConnectionResponse.parse(body)
        if self._pending_service == "message":
            if self.message_provider_id is None:
                raise StageError("service", "message service frame before provider selection")
            self._require_service_reply(
                response,
                local_agent_id=self.agent_id,
                profile=PROFILE_MESSAGE,
                session_ids=(DEFAULT_SESSION_ID,),
            )
            # the file session follows every
            # session the message service accepted (the device may accept more
            # than the one proposed; see _require_service_reply).
            self._next_file_session = max(response.session_ids) + 1
            # The file consumer is our message
            # consumer + 1, i.e. the reply's initiator id + 1 on this link.
            self._file_agent_id = response.initiator_agent_id + 1
            self._note("message_service_accepted", 0, len(body))
            self._pending_service = ""
            self._send_service_request("file")
            return
        if self._pending_service == "file":
            if self.file_provider_id is None:
                raise StageError("service", "file service frame before provider selection")
            # The real device adopts the message service's full accepted list
            # (32, 33) as the base and answers the file service with (34,): the
            # file session is one past the last session the message service
            # accepted, not one past the proposed id.
            self._require_service_reply(
                response,
                local_agent_id=self._file_agent_id or self.file_agent_id,
                profile=PROFILE_FILE,
                session_ids=(self._next_file_session,),
            )
            self.file_session_id = response.session_ids[0]
            self._file_accepted = True
            self._note("file_service_accepted", 0, len(body))
            if self.sync and self.system_session_id is None:
                # the next local session follows
                # every session the file service accepted. A device that
                # already declared the service itself is not asked again.
                self._next_system_session = max(response.session_ids) + 1
                self._send_service_request("system")
            else:
                self._pending_service = self._services_done
            return
        if self._pending_service == "system":
            # A provider that accepts the host-initiated system offer answers on
            # the same reserved session. A real device instead sends its own
            # type-1 (handled above).
            if self.system_provider_id is None or self.system_agent_id is None:
                raise StageError("service", "system service frame before it was requested")
            if self._next_system_session is None:
                raise StageError("service", "system service frame before session derivation")
            try:
                self._require_service_reply(
                    response,
                    local_agent_id=self.system_agent_id,
                    profile=PROFILE_SYSTEM,
                    session_ids=(self._next_system_session,),
                )
            except StageError:
                # A refusal is not fatal here. The device opens this service on
                # its own when it has something to push, and a real device does
                # reject a host-initiated offer (observed status 3) precisely
                # because it manages the profile itself. The exchange continues
                # and the device's own type-1 declares the channels later.
                self._note("system_service_refused", 0, len(body))
                self._pending_service = self._services_done
                return
            self.system_session_id = response.session_ids[0]
            # Only the control channel was proposed, so every accepted session
            # belongs to it; a device type-1 replaces this with the real map.
            self.file_channels = {
                session: CONTROL_CHANNEL_ID for session in response.session_ids
            }
            self._note("system_service_accepted", 0, len(body))
            self._pending_service = self._services_done
            return
        raise StageError("service", "service response without a pending request")

    def _observe_service_request(self, body: bytes) -> None:
        """Record a device-initiated system offer without accepting it.

        The sync layer owns the accept: it reads the same frame through
        ConnectedChannel.read_raw and sends its own type-2. Parsing here only fills the
        descriptive fields; a malformed or foreign type-1 stays parked for the
        sync layer to report.
        """
        if self.system_agent_id is None:
            return
        try:
            request = ServiceConnectionRequest.parse(body)
        except StageError:
            return
        if request.profile != PROFILE_SYSTEM:
            return
        if request.remote_agent_id != self.system_agent_id:
            return
        # The device is the authority on which session carries which channel
        #; keep its exact declaration.
        channels = {
            channel.session_id: channel.channel_id for channel in request.channels
        }
        if len(channels) != len(request.channels):
            return  # duplicate session id: leave the malformed offer parked
        self.file_channels = channels
        self.system_session_id = next(
            (session for session, channel in channels.items() if channel == CONTROL_CHANNEL_ID),
            None,
        )
        self._system_accepted = True
        self._note("system_service_declared", 0, len(body))

    def _handle_agent_auth(self, body: bytes) -> None:
        """Answer a type-5 challenge with a type-6 response."""
        request = AgentAuthenticateRequest.parse(body)
        if (
            request.profile == PROFILE_SYSTEM
            and self.sync
            and self.system_agent_id is not None
        ):
            # Not a prerequisite of the native system-FT initiator
            # (the notes above 2.6), but answered if a
            # provider challenges the local system consumer.
            if self._system_auth_answered:
                raise StageError("agent-auth", "duplicate system agent authenticate")
            if self.system_provider_id is None:
                raise StageError(
                    "agent-auth", "system agent authenticate before provider selection"
                )
            local, provider = self.system_agent_id, self.system_provider_id
            self._system_auth_answered = True
        elif self._pending_service == "message":
            if self._message_auth_answered:
                raise StageError("agent-auth", "duplicate message agent authenticate")
            if request.profile != PROFILE_MESSAGE:
                raise StageError(
                    "agent-auth",
                    f"agent authenticate profile {request.profile!r} during the message phase",
                )
            if self.message_provider_id is None:
                raise StageError("agent-auth", "message agent authenticate before provider selection")
            local, provider = self.agent_id, self.message_provider_id
            self._message_auth_answered = True
        elif self._pending_service == "file":
            if self._file_auth_answered:
                raise StageError("agent-auth", "duplicate file agent authenticate")
            if request.profile != PROFILE_FILE:
                raise StageError(
                    "agent-auth",
                    f"agent authenticate profile {request.profile!r} during the file phase",
                )
            if self.file_provider_id is None:
                raise StageError("agent-auth", "file agent authenticate before provider selection")
            local, provider = self.file_agent_id, self.file_provider_id
            self._file_auth_answered = True
        else:
            raise StageError("agent-auth", "agent authenticate without a pending service request")

        if request.first_agent_id != local or request.second_agent_id != provider:
            raise StageError(
                "agent-auth",
                f"agent authenticate pair is not local={local}/provider={provider}",
            )
        # swap the request's pair; the fallback
        # payload is used unless a package public key was supplied.
        reply_body = agent_authenticate_body(
            first_agent_id=request.second_agent_id,
            second_agent_id=request.first_agent_id,
            profile=request.profile,
            auth_payload=self.agent_auth_payload,
        )
        # The business body frames are the frames below
        frames = framing.split(SESSION_SERVICE, reply_body)
        for frame in frames:
            self._write(frame)
        self._note("agent_authenticate_response", sum(len(f) for f in frames), len(body))

    # -- stage 5: bind, then device info -----------------------------

    def _read_business(self, limit: float) -> tuple[int, bytes]:
        """Read one business frame and return ``(session_id, service||command||payload)``.

        On a sync link the device can send its own ``system:filetransfer`` type-1
        on reserved session 1 while the bind and device-info stages are still
        reading. That is not a message-session
        business frame, so it is parked verbatim for
        :meth:`ConnectedChannel.read_raw` instead of aborting the sequence.
        """
        if self.secure is None:
            raise StageError("business", "no secure context")
        end = time.monotonic() + limit
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise StageError("read", "timed out waiting for a frame")
            session_id, body = self._read_frame(max(0.1, remaining))
            if self.sync and session_id == SESSION_SERVICE:
                self.raw_frames.append((session_id, body))
                if body and body[0] == 1:
                    # Fill the descriptive fields without answering: read_raw()
                    # still hands the frame to the sync layer.
                    self._observe_service_request(body)
                continue
            if session_id != DEFAULT_SESSION_ID:
                # Only the message session carries the bind challenge and the
                # device info. Anything else (a secondary profile session, a
                # file-service session) is kept for read_raw(), never decoded
                # as if it were the answer - and never allowed to advance the
                # secure receive counter.
                if len(self.raw_frames) < MAX_PARKED_FRAMES:
                    self.raw_frames.append((session_id, body))
                self._note("business_read_other_session", 0, len(body))
                continue
            flag = body[0] if body else -1
            if flag == BUSINESS_FLAG_PLAIN:
                plaintext = body[1:]
                self._last_business_authenticated = False
            elif flag == BUSINESS_FLAG_ENCRYPTED:
                plaintext = self.secure.open(body)
                self._last_business_authenticated = True
            else:
                raise StageError("business", f"unsupported business flag 0x{flag & 0xFF:02x}")
            try:
                message = decode_pipe_message(plaintext)
            except pipe.PipeError as exc:
                raise PipeMessageError(str(exc)) from exc
            if (message.type & 0x0F) in (3, 4):
                # ACK/control subtypes carry no
                # service or command, so they can never be a business reply.
                raise StageError(
                    "business",
                    f"control pipe subtype 0x{message.type:02x} during a business read",
                )
            if len(message.data) < 2:
                raise StageError("business", "pipe message shorter than service/command")
            return session_id, message.data

    def _bind_and_info(self) -> None:
        """Send the bind request, then read the device info.

        The service exchange ends by sending
        ``02 0d 01``; ``awaitingBind``  turns the 34-byte challenge
        into ``05 03 ff``; ``awaitingDeviceInfo``  consumes ``03 ff``.
        If no bind response arrives within 8 s the info read is sent anyway
        (falling back to the plain device-info request).
        """
        if self.bind_start_delay_ms:
            delay = self.bind_start_delay_ms / 1000.0
            left = self.deadline - time.monotonic()
            if left <= delay:
                raise StageError("timeout", "no budget left for the bind start delay")
            time.sleep(delay)
            self._note("bind_start_delay", 0, self.bind_start_delay_ms)
        bind = self._encode_business(BIND_SERVICE, BIND_COMMAND, b"\x01")
        self._write(bind)

        bind_deadline = time.monotonic() + self._remaining(BIND_FALLBACK_SECONDS)
        bind_seen = False
        while not bind_seen:
            left = bind_deadline - time.monotonic()
            if left <= 0:
                info = self._encode_business(INFO_SERVICE, INFO_COMMAND, b"\xff")
                self._write(info)
                self._note("device_info_request_fallback", len(info), 0)
                break
            try:
                _, data = self._read_business(left)
            except LinkLost:
                raise
            except (StageError, TransportError) as exc:
                # Silence until the bind limit is the documented fallback
                # case, not a failure: send the device-info read anyway.
                if isinstance(exc, StageError) and exc.stage != "read":
                    raise
                if isinstance(exc, TransportError) and not is_idle_error(exc):
                    raise
                bind_deadline = time.monotonic()
                continue
            service, command, payload = data[0], data[1], data[2:]
            if service != BIND_SERVICE or command != BIND_COMMAND:
                # the first channel frame must be
                # the bind challenge.
                raise StageError("bind", f"first business frame is {service:02x}/{command:02x}")
            if len(payload) < 34 or payload[0] != 1:
                raise StageError("bind", "bind challenge is shorter than 34 bytes or version != 1")
            self.bind_payload = payload
            bind_seen = True
            self._note("bind_challenge", len(bind), len(payload))
            info = self._encode_business(INFO_SERVICE, INFO_COMMAND, b"\xff")
            self._write(info)

        # awaitingDeviceInfo: only 03/ff is the reply; anything else stops.
        info_deadline = time.monotonic() + self._remaining(DEVICE_INFO_SECONDS)
        while True:
            left = info_deadline - time.monotonic()
            if left <= 0:
                raise StageError("device-info", "no 03/ff reply within the stage limit")
            _, data = self._read_business(left)
            service, command, payload = data[0], data[1], data[2:]
            if not self._last_business_authenticated:
                raise StageError(
                    "device-info", "device info arrived without the secure envelope"
                )
            if service != INFO_REPLY_SERVICE or command != INFO_REPLY_COMMAND:
                raise StageError(
                    "device-info",
                    f"device info stage received {service:02x}/{command:02x}, expected 03/ff",
                )
            self.device_info = DeviceInfo.parse(payload)
            self._note("device_info", 0, len(payload))
            return

    def _encode_business(self, service: int, command: int, payload: bytes) -> bytes:
        if self.secure is None:
            raise StageError("business", "business frame before authentication")
        plaintext = encode_pipe_message(bytes([service, command]) + payload)
        return framing.encode(DEFAULT_SESSION_ID, self.secure.seal(plaintext))

    # -- run -------------------------------------------------------------

    def run(self) -> ConnectedChannel:
        self._negotiate_transport()      # stage 1
        self._authenticate()             # stage 2
        self._exchange_capabilities()    # stages 3 and 4
        self._bind_and_info()            # stage 5
        if self.secure is None:
            raise StageError("business", "no secure context at the end of the sequence")
        if self.message_provider_id is None or self.file_provider_id is None:
            raise StageError("capex", "services accepted without a provider id")
        return ConnectedChannel(
            session=self.session,
            secure=self.secure,
            session_id=DEFAULT_SESSION_ID,
            channel_id=DEFAULT_CHANNEL_ID,
            message_provider_id=self.message_provider_id,
            file_provider_id=self.file_provider_id,
            system_provider_id=self.system_provider_id,
            system_session_id=self.system_session_id,
            file_channels=dict(self.file_channels),
            pending_frames=self._early_frames + self.raw_frames,
            framers=self.framers,
            device_info=self.device_info,
            bind_payload=self.bind_payload,
            steps=self.steps,
        )
