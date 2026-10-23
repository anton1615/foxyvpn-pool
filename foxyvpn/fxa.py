"""Firefox Accounts (FxA) client: password-based login (onepw protocol),
email 2FA verification, and OAuth token issuance/refresh.

Implements the publicly documented ``identity.mozilla.com/picl/v1`` key
stretching and Hawk request-signing scheme used by Firefox Accounts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import FxaApiError
from .fastly import solve_fastly_challenge
from .headers import apply_mozilla_vpn_headers
from .http_client import get_client, read_error_body

logger = logging.getLogger("foxyvpn.fxa")

FXA_AUTH_SERVER = "https://api.accounts.firefox.com/v1"
FIREFOX_CLIENT_ID = "5882386c6d801776"
OAUTH_SCOPE = "profile https://identity.mozilla.com/apps/vpn"
PROTOCOL_VERSION = "identity.mozilla.com/picl/v1/"
PBKDF2_ROUNDS = 1000
STRETCHED_PW_LEN = 32
HKDF_LEN = 32

# verificationMethodEmail2FA tells FxA to deliver the sign-in confirmation
# as a short numeric code emailed to the account, instead of the default
# confirmation link. The link redirects through accounts.firefox.com,
# which is not something a CLI client can follow, and (unlike a code) is
# silently useless to a login flow that only knows how to prompt for a code.
VERIFICATION_METHOD_EMAIL_2FA = "email-2fa"

FXA_ERRNO_INVALID_PARAMETER = 107

# Mirrors the original Go client's maxChallengeAttempts: how many times a
# control-plane call re-solves Fastly's anti-bot challenge before giving up.
# With rotating-exit proxies a solved challenge cookie can be rejected when
# the retried request leaves through a different upstream IP.
FXA_MAX_CHALLENGE_ATTEMPTS = 5

_HKDF_SALT = b"\x00" * 32


@dataclass
class LoginResponse:
    uid: str
    session_token: str
    verified: bool
    verification_method: Optional[str] = None


@dataclass
class TokenResponse:
    access_token: str
    refresh_token: str = ""
    expires_in: int = 0
    scope: str = ""
    token_type: str = "bearer"


def _hkdf(ikm: bytes, info: str, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=_HKDF_SALT, info=info.encode("utf-8")).derive(ikm)


def _derive_quick_stretch(email: str, password: str) -> bytes:
    salt = f"{PROTOCOL_VERSION}quickStretch:{email}".encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS, dklen=STRETCHED_PW_LEN)


def _derive_auth_pw(email: str, password: str) -> bytes:
    quick_stretched = _derive_quick_stretch(email, password)
    return _hkdf(quick_stretched, f"{PROTOCOL_VERSION}authPW", HKDF_LEN)


def _derive_hawk_credentials(session_token_hex: str) -> tuple[str, bytes]:
    session_token = bytes.fromhex(session_token_hex)
    expanded = _hkdf(session_token, f"{PROTOCOL_VERSION}sessionToken", 64)
    token_id, hmac_key = expanded[:32], expanded[32:64]
    return token_id.hex(), hmac_key


def _hawk_header(method: str, url: httpx.URL, token_id: str, hmac_key: bytes, body: bytes = b"") -> str:
    ts = str(int(time.time()))
    nonce = base64.urlsafe_b64encode(os.urandom(6)).decode().rstrip("=")
    path = url.raw_path.decode() if isinstance(url.raw_path, bytes) else str(url.raw_path)
    port = url.port or (443 if url.scheme == "https" else 80)

    payload_hash = ""
    if body:
        digest = hashlib.sha256()
        digest.update(b"hawk.1.payload\napplication/json\n")
        digest.update(body)
        digest.update(b"\n")
        payload_hash = base64.b64encode(digest.digest()).decode()

    normalized = "\n".join(
        ["hawk.1.header", ts, nonce, method.upper(), path, url.host, str(port), payload_hash, "", ""]
    )
    mac = hmac.new(hmac_key, normalized.encode("utf-8"), hashlib.sha256).digest()
    mac_b64 = base64.b64encode(mac).decode()

    header = f'Hawk id="{token_id}", ts="{ts}", nonce="{nonce}", mac="{mac_b64}"'
    if payload_hash:
        header += f', hash="{payload_hash}"'
    return header


def _fxa_do(method: str, path: str, *, session_token: Optional[str] = None, json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Send an FxA API request, transparently solving Fastly's anti-bot
    "Client Challenge" when the edge answers HTTP 406 (empty body, no FxA
    error payload).

    Mirrors the original Go client's ``fxaDo``: the request -- including its
    Hawk ``Authorization`` header, which embeds a timestamp and nonce -- is
    rebuilt fresh on every attempt instead of being reused across retries.
    Solving a proof-of-work challenge can take a non-trivial amount of time,
    so reusing a Hawk header computed before that delay risks the timestamp
    aging out of FxA's clock-skew tolerance by the time the retried request
    is actually sent.
    """
    client = get_client()
    url = httpx.URL(f"{FXA_AUTH_SERVER}{path}")
    # Serialize the body ourselves (rather than passing json=json_body to
    # httpx) so the exact bytes used for the Hawk payload hash are
    # guaranteed to match the bytes actually sent on the wire.
    body_bytes = json.dumps(json_body, separators=(",", ":")).encode("utf-8") if json_body is not None else b""

    token_id: Optional[str] = None
    hmac_key: Optional[bytes] = None
    if session_token:
        token_id, hmac_key = _derive_hawk_credentials(session_token)

    def _headers() -> Dict[str, str]:
        headers = apply_mozilla_vpn_headers({"Content-Type": "application/json"})
        if session_token:
            assert token_id is not None and hmac_key is not None
            headers["Authorization"] = _hawk_header(method, url, token_id, hmac_key, body_bytes)
        return headers

    response: Optional[httpx.Response] = None
    for _attempt in range(FXA_MAX_CHALLENGE_ATTEMPTS):
        headers = _headers()
        if json_body is not None:
            response = client.request(method, str(url), headers=headers, content=body_bytes)
        else:
            response = client.request(method, str(url), headers=headers)
        if response.status_code != 406:
            break
        solve_fastly_challenge(client, response)
    assert response is not None

    if response.status_code >= 400:
        try:
            error_body = response.json()
        except ValueError:
            error_body = {}
        errno = error_body.get("errno")
        message = error_body.get("message") or read_error_body(response) or f"HTTP {response.status_code}"
        raise FxaApiError(message, errno=errno, status_code=response.status_code)

    if not response.content:
        return {}
    return response.json()


def _login_attempt(
    email: str,
    password: str,
    *,
    with_verification_method: bool = True,
) -> Dict[str, Any]:
    # Mirrors Go's fxaLoginAttempt exactly: the login body carries only
    # email, authPW, and (optionally) verificationMethod. Extra parameters
    # like keys=true or a service/reason pair are NOT part of the original
    # request and can change how FxA evaluates the sign-in (e.g. silently
    # overriding the requested verificationMethod), so they are deliberately
    # left out here.
    auth_pw = _derive_auth_pw(email, password).hex()
    body: Dict[str, Any] = {"email": email, "authPW": auth_pw}
    if with_verification_method:
        body["verificationMethod"] = VERIFICATION_METHOD_EMAIL_2FA
    try:
        return _fxa_do("POST", "/account/login", json_body=body)
    except FxaApiError as exc:
        if exc.errno == FXA_ERRNO_INVALID_PARAMETER and with_verification_method:
            logger.debug("login with verificationMethod rejected (errno 107), retrying without it")
            return _login_attempt(email, password, with_verification_method=False)
        raise


def login(email: str, password: str) -> LoginResponse:
    data = _login_attempt(email, password)
    return LoginResponse(
        uid=data.get("uid", ""),
        session_token=data["sessionToken"],
        verified=bool(data.get("verified", False)),
        verification_method=data.get("verificationMethod"),
    )


def verify_session(session_token: str, code: str) -> None:
    _fxa_do("POST", "/session/verify_code", session_token=session_token, json_body={"code": code})


def oauth_token(session_token: str) -> TokenResponse:
    body = {
        "client_id": FIREFOX_CLIENT_ID,
        "grant_type": "fxa-credentials",
        "scope": OAUTH_SCOPE,
        "access_type": "offline",
    }
    data = _fxa_do("POST", "/oauth/token", session_token=session_token, json_body=body)
    return TokenResponse(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token", ""),
        expires_in=int(data.get("expires_in", 0) or 0),
        scope=data.get("scope", OAUTH_SCOPE),
        token_type=data.get("token_type", "bearer"),
    )


def refresh_token(refresh_token_value: str) -> TokenResponse:
    body = {
        "client_id": FIREFOX_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token_value,
        "scope": OAUTH_SCOPE,
    }
    data = _fxa_do("POST", "/oauth/token", json_body=body)
    return TokenResponse(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token", refresh_token_value),
        expires_in=int(data.get("expires_in", 0) or 0),
        scope=data.get("scope", OAUTH_SCOPE),
        token_type=data.get("token_type", "bearer"),
    )
