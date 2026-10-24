# -*- coding: utf-8 -*-
"""Xinliqiu SDK - talk to an OPPO AI Xinliqiu (心力球) from your own code.

Quick start::

    from aipin_sdk import Xinliqiu, Credentials

    ball = Xinliqiu(Credentials(
        device_id="<CoreBluetooth UUID>",
        peer_id_file="~/.config/xinliqiu/peer-id.txt",
        key_file="~/.config/xinliqiu/pairing.json",
    ))
    print(ball.status())
    print(ball.capabilities())

Range retrieval can include CMPT/enpt and plaintext JSONL diagnostics. Storage
uploads are ciphertext-only by policy; decryption always requires an explicit
owner private key supplied by the caller. Device operations with uncertain
outcomes return dictionaries containing ``state``, ``ok`` and ``retry``;
:meth:`Xinliqiu.require_ok` optionally converts a non-success to
:class:`OperationIncomplete`.
"""

from .audio import AudioExportError, OpusLayout, to_ogg, to_wav
from .capabilities import CAPABILITIES, describe
from .client import CONNECT_FAILED, Credentials, RecordStatus, Xinliqiu, scan
from .container import (
    CMPT_KINDS,
    STORAGE_KINDS,
    Container,
    Entry,
    EnptInfo,
    audio_variant_of,
    cmpt_kind_of,
    decrypt_enpt,
    extension_of,
    generated_output_name,
    name_is_safe,
    parse_cmpt,
    parse_cmpt_file,
    parse_enpt,
    parse_marker,
)
from .errors import (
    ContainerError,
    DecryptError,
    NotAuthenticated,
    OperationIncomplete,
    ProbeFailed,
    Unsupported,
    XinliqiuError,
)
from .oggopus import encode_packets, opus_tags, samples_per_packet
from .protocol.init import Pkcs8Signer, Signer
from .provision import (
    PairingOutcomeUnknown,
    Provisioned,
    default_owner_key_path,
    doctor,
    generate_owner_key,
    generate_peer_id,
    owner_key_matches_public,
    pair,
    pair_device,
    promote_pending_pairing,
    recover_alias,
    verify_owner_key,
)
from .protocol.provision import PairResult
from .protocol.sync import (
    LINK_LOST,
    NOT_STARTED,
    RANGE_COMPLETED,
    RANGE_COMPLETED_DRAIN_TIMEOUT,
    RANGE_COMPLETED_WITH_FAILURES,
    RANGE_REQUEST_NOT_WRITTEN,
    TRANSFER_FAILED,
    VOICEPRINT_COLLECTED,
    VOICEPRINT_LINK_LOST,
    VOICEPRINT_NO_FILE,
    VOICEPRINT_START_NOT_WRITTEN,
    VOICEPRINT_TRANSFER_FAILED,
    WINDOW_ELAPSED_FILES_PUBLISHED_RANGE_UNVERIFIED,
    WINDOW_ELAPSED_NO_FILES,
    WINDOW_ELAPSED_PARTIAL_UNVERIFIED,
    SyncError,
    retry_guidance,
)
from .protocol.transport import LinkLost, NotificationTimeout, TransportError
from .session import SessionState
from .storage import (
    CloudflareStorage,
    EncryptedDiagnosticPolicy,
    LocalStorage,
    OuterFile,
    Storage,
    StorageIdentity,
    StorageItem,
    StoredObject,
    canonical_device_key,
    classify_outer_file,
    derive_storage_device_id,
    entry_times,
    ingest_container,
    ingest_files,
    ingest_outer,
    prepare_upload,
    resolve_storage_identity,
    save_storage_device_id,
    storage_kind,
    validate_enpt,
)
from .sync import IncrementalStore, RemoteStore, compare, pull_changes, push_range
from .tasks import Task, TaskRegistry
from .userconfig import UserConfig, config_path

__version__ = "0.2.1"

__all__ = [
    "AudioExportError",
    "CAPABILITIES",
    "CMPT_KINDS",
    "CONNECT_FAILED",
    "CloudflareStorage",
    "Container",
    "ContainerError",
    "Credentials",
    "DecryptError",
    "EncryptedDiagnosticPolicy",
    "Entry",
    "EnptInfo",
    "IncrementalStore",
    "LINK_LOST",
    "LinkLost",
    "LocalStorage",
    "NOT_STARTED",
    "NotAuthenticated",
    "NotificationTimeout",
    "OperationIncomplete",
    "OpusLayout",
    "Pkcs8Signer",
    "Signer",
    "OuterFile",
    "PairResult",
    "PairingOutcomeUnknown",
    "ProbeFailed",
    "Provisioned",
    "RANGE_COMPLETED",
    "RANGE_COMPLETED_DRAIN_TIMEOUT",
    "RANGE_COMPLETED_WITH_FAILURES",
    "RANGE_REQUEST_NOT_WRITTEN",
    "RecordStatus",
    "RemoteStore",
    "STORAGE_KINDS",
    "SessionState",
    "Storage",
    "StorageIdentity",
    "StorageItem",
    "StoredObject",
    "SyncError",
    "TRANSFER_FAILED",
    "Task",
    "TaskRegistry",
    "TransportError",
    "Unsupported",
    "UserConfig",
    "VOICEPRINT_COLLECTED",
    "VOICEPRINT_LINK_LOST",
    "VOICEPRINT_NO_FILE",
    "VOICEPRINT_START_NOT_WRITTEN",
    "VOICEPRINT_TRANSFER_FAILED",
    "WINDOW_ELAPSED_FILES_PUBLISHED_RANGE_UNVERIFIED",
    "WINDOW_ELAPSED_NO_FILES",
    "WINDOW_ELAPSED_PARTIAL_UNVERIFIED",
    "Xinliqiu",
    "XinliqiuError",
    "__version__",
    "audio_variant_of",
    "canonical_device_key",
    "classify_outer_file",
    "cmpt_kind_of",
    "compare",
    "config_path",
    "decrypt_enpt",
    "default_owner_key_path",
    "derive_storage_device_id",
    "describe",
    "doctor",
    "encode_packets",
    "entry_times",
    "extension_of",
    "generate_owner_key",
    "generate_peer_id",
    "generated_output_name",
    "ingest_container",
    "ingest_files",
    "ingest_outer",
    "name_is_safe",
    "owner_key_matches_public",
    "opus_tags",
    "pair",
    "pair_device",
    "parse_cmpt",
    "parse_cmpt_file",
    "parse_enpt",
    "parse_marker",
    "prepare_upload",
    "promote_pending_pairing",
    "pull_changes",
    "push_range",
    "recover_alias",
    "resolve_storage_identity",
    "retry_guidance",
    "samples_per_packet",
    "save_storage_device_id",
    "scan",
    "storage_kind",
    "to_ogg",
    "to_wav",
    "validate_enpt",
    "verify_owner_key",
]
