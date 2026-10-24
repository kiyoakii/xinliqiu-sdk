# -*- coding: utf-8 -*-
"""Exception hierarchy."""


class XinliqiuError(Exception):
    """Base error for the SDK."""


class NotAuthenticated(XinliqiuError):
    """Credentials are missing or unusable."""


class ProbeFailed(XinliqiuError):
    """The underlying transport could not complete the operation."""

    def __init__(self, message: str, **context: object) -> None:
        super().__init__(message)
        self.context = context


class Unsupported(XinliqiuError):
    """The requested capability has no established integration path in this SDK."""


class ContainerError(XinliqiuError):
    """A CMPT container or enpt envelope is malformed."""


class DecryptError(XinliqiuError):
    """Owner-key decryption failed (wrong key or corrupted payload)."""


class OperationIncomplete(XinliqiuError):
    """A device operation finished without a verified success.

    Raised only on request (``Xinliqiu.require_ok``); the operations themselves
    return a structured result whose ``state`` names what happened. ``result``
    is that dictionary, including its ``retry`` guidance and diagnostics.
    """

    def __init__(self, result: dict) -> None:
        state = result.get("state", "unknown")
        retry = result.get("retry") or ""
        super().__init__(f"{state}: {retry}" if retry else str(state))
        self.result = result
        self.state = state
