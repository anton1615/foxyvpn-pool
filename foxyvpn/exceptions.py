"""Exception hierarchy used across the package."""

from __future__ import annotations

from typing import Optional


class FoxyVPNError(Exception):
    """Base class for all FoxyVPN errors."""


class FastlyChallengeError(FoxyVPNError):
    """Raised when the Fastly anti-bot challenge could not be solved."""


class FxaApiError(FoxyVPNError):
    """Raised for Firefox Accounts API errors."""

    def __init__(self, message: str, *, errno: Optional[int] = None, status_code: Optional[int] = None):
        super().__init__(message)
        self.errno = errno
        self.status_code = status_code


class GuardianHTTPError(FoxyVPNError):
    """Raised for Mozilla VPN Guardian control-plane HTTP errors."""

    def __init__(self, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class QuotaExceededError(GuardianHTTPError):
    """Raised when the account has exhausted its proxy quota."""


class TokenInvalidError(GuardianHTTPError):
    """Raised when the access token was rejected by Guardian."""


class ProxyError(FoxyVPNError):
    """Raised for upstream proxy/tunnel errors."""
