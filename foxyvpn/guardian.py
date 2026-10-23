"""Mozilla VPN "Guardian" control-plane client: proxy-pass issuance/renewal,
account entitlement lookups, and Fastly-challenge-aware HTTP calls.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

from .exceptions import GuardianHTTPError, QuotaExceededError, TokenInvalidError
from .fastly import solve_fastly_challenge
from .headers import apply_mozilla_vpn_headers
from .http_client import get_client, read_error_body

logger = logging.getLogger("foxyvpn.guardian")

GUARDIAN_ENDPOINT_DEFAULT = "https://vpn.mozilla.org"
PROXY_PASS_CLAIM_TIME_TOLERANCE = timedelta(minutes=1)
PROXY_PASS_CLAIM_TIME_MAX_FUTURE = timedelta(hours=2)


@dataclass
class ProxyPassClaims:
    sub: str = ""
    aud: str = ""
    iat: int = 0
    nbf: int = 0
    exp: int = 0
    iss: str = ""


@dataclass
class ProxyPassInfo:
    raw_token: str
    claims: ProxyPassClaims
    clock_offset: timedelta = field(default_factory=lambda: timedelta(0))
    quota_max: str = ""
    quota_left: str = ""
    quota_reset: str = ""

    def not_before(self) -> datetime:
        return datetime.fromtimestamp(self.claims.nbf, tz=timezone.utc) + self.clock_offset

    def expires_at(self) -> datetime:
        return datetime.fromtimestamp(self.claims.exp, tz=timezone.utc) + self.clock_offset

    def bearer_token(self) -> str:
        return f"Bearer {self.raw_token}"


@dataclass
class Entitlement:
    subscribed: bool = False
    uid: str = ""
    max_bytes: str = ""
    limited_bandwidth: bool = False


def _parse_jwt_claims(token: str) -> ProxyPassClaims:
    parts = token.split(".")
    if len(parts) < 2:
        raise GuardianHTTPError("malformed proxy pass token: expected a JWT with at least 2 segments")
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except (ValueError, json.JSONDecodeError) as exc:
        raise GuardianHTTPError(f"could not decode proxy pass claims: {exc}") from exc
    return ProxyPassClaims(
        sub=payload.get("sub", ""),
        aud=payload.get("aud", ""),
        iat=int(payload.get("iat", 0) or 0),
        nbf=int(payload.get("nbf", 0) or 0),
        exp=int(payload.get("exp", 0) or 0),
        iss=payload.get("iss", ""),
    )


def _proxy_pass_claim_start_time(claims: ProxyPassClaims) -> Optional[datetime]:
    if claims.nbf:
        return datetime.fromtimestamp(claims.nbf, tz=timezone.utc)
    if claims.iat:
        return datetime.fromtimestamp(claims.iat, tz=timezone.utc)
    return None


def _proxy_pass_expiration_looks_fresh(now: datetime, exp: datetime) -> bool:
    if exp < now - PROXY_PASS_CLAIM_TIME_TOLERANCE:
        return False
    return (exp - now) <= PROXY_PASS_CLAIM_TIME_MAX_FUTURE


def _within_time_window(t: datetime, start: datetime, end: datetime) -> bool:
    return start <= t <= end


def _proxy_pass_claim_time_offset_candidates(now: datetime) -> List[timedelta]:
    """Candidate offsets to try, in the same order as the Go client: the
    machine's own local UTC offset first (the most likely cause of a server
    timezone bug), then every 15-minute increment from -12h to +14h so that
    fractional-hour zones (e.g. +05:30, +05:45, +12:45) are covered too."""
    seen = set()
    candidates: List[timedelta] = []

    def add(offset: timedelta) -> None:
        if offset == timedelta(0) or offset in seen:
            return
        seen.add(offset)
        candidates.append(offset)

    local_offset = now.astimezone().utcoffset()
    if local_offset is not None:
        add(local_offset)

    minutes = -12 * 60
    while minutes <= 14 * 60:
        add(timedelta(minutes=minutes))
        minutes += 15
    return candidates


def _detect_proxy_pass_claim_time_offset(claims: ProxyPassClaims, now: datetime) -> timedelta:
    """Some Guardian deployments have been observed to issue proxy-pass JWTs
    whose ``exp``/``nbf``/``iat`` claims are off by a fixed offset (a server
    timezone bug). Detect such an offset the same way as the original Go
    client: prefer accepting the claims unshifted when the whole validity
    window (start claim to ``exp``, or just ``exp`` if there is no usable
    start claim) already plausibly contains ``now``; otherwise search
    candidate shifts and return the first one that makes it plausible."""
    if not claims.exp:
        return timedelta(0)

    raw_exp = datetime.fromtimestamp(claims.exp, tz=timezone.utc)
    raw_start = _proxy_pass_claim_start_time(claims)

    if raw_start is not None:
        if raw_start >= raw_exp:
            return timedelta(0)
        if _within_time_window(now, raw_start - PROXY_PASS_CLAIM_TIME_TOLERANCE, raw_exp + PROXY_PASS_CLAIM_TIME_TOLERANCE):
            return timedelta(0)
    elif _proxy_pass_expiration_looks_fresh(now, raw_exp):
        return timedelta(0)

    for offset in _proxy_pass_claim_time_offset_candidates(now):
        shifted_exp = raw_exp + offset
        if raw_start is not None:
            shifted_start = raw_start + offset
            if _within_time_window(now, shifted_start - PROXY_PASS_CLAIM_TIME_TOLERANCE, shifted_exp + PROXY_PASS_CLAIM_TIME_TOLERANCE):
                return offset
        elif _proxy_pass_expiration_looks_fresh(now, shifted_exp):
            return offset
    return timedelta(0)


def _authorized_request(method: str, url: str, access_token: str, **kwargs: Any) -> httpx.Response:
    client = get_client()
    headers = apply_mozilla_vpn_headers(kwargs.pop("headers", {}) or {})
    headers.setdefault("Content-Type", "application/json")
    headers["Authorization"] = f"Bearer {access_token}"
    response = client.request(method, url, headers=headers, **kwargs)
    if response.status_code == 406:
        solve_fastly_challenge(client, response)
        response = client.request(method, url, headers=headers, **kwargs)
    return response


def fetch_proxy_pass(endpoint: str, access_token: str) -> ProxyPassInfo:
    # Matches the original Go client's GET /api/v1/fpn/token. An earlier
    # revision of this port called invented /api/v2/proxy/pass endpoints
    # that do not exist on the real Guardian deployment and were rejected
    # with {"errno":120,"error":"invalid algorithm"}.
    url = f"{endpoint.rstrip('/')}/api/v1/fpn/token"
    response = _authorized_request("GET", url, access_token)
    if response.status_code in (401, 403):
        raise TokenInvalidError("access token was rejected by Guardian", status_code=response.status_code)
    if response.status_code == 429:
        raise QuotaExceededError("account proxy quota exceeded", status_code=429)
    if response.status_code != 200:
        raise GuardianHTTPError(
            f"failed to fetch proxy pass: HTTP {response.status_code}: {read_error_body(response)}",
            status_code=response.status_code,
        )
    body: Dict[str, Any] = response.json()
    raw_token = body.get("token")
    if not raw_token:
        raise GuardianHTTPError("proxy pass response did not contain a token")
    claims = _parse_jwt_claims(raw_token)
    offset = _detect_proxy_pass_claim_time_offset(claims, datetime.now(timezone.utc))
    if offset != timedelta(0):
        logger.debug("detected %s clock offset in proxy pass claims", offset)
    return ProxyPassInfo(
        raw_token=raw_token,
        claims=claims,
        clock_offset=offset,
        quota_max=response.headers.get("X-Quota-Limit", ""),
        quota_left=response.headers.get("X-Quota-Remaining", ""),
        quota_reset=response.headers.get("X-Quota-Reset", ""),
    )


def _parse_entitlement(body: Dict[str, Any]) -> Entitlement:
    # The real Guardian response is flat: {"subscribed": bool, "uid": int,
    # "maxBytes": string, "limited_bandwidth": bool}. An earlier revision of
    # this port looked for a nested subscriptions.vpn.active shape that the
    # server never sends, which meant `subscribed` always read as false.
    return Entitlement(
        subscribed=bool(body.get("subscribed", False)),
        uid=str(body.get("uid", "")),
        max_bytes=str(body.get("maxBytes", "")),
        limited_bandwidth=bool(body.get("limited_bandwidth", False)),
    )


def fetch_user_info(endpoint: str, access_token: str) -> Entitlement:
    url = f"{endpoint.rstrip('/')}/api/v1/fpn/status"
    response = _authorized_request("GET", url, access_token)
    if response.status_code != 200:
        raise GuardianHTTPError(
            f"failed to fetch account info: HTTP {response.status_code}: {read_error_body(response)}",
            status_code=response.status_code,
        )
    return _parse_entitlement(response.json())


def activate_guardian(endpoint: str, access_token: str) -> Entitlement:
    """Activate the Guardian VPN entitlement for this account (idempotent).
    Mirrors the original client's automatic recovery when a proxy-pass
    request comes back with an invalid-token error on a first login."""
    url = f"{endpoint.rstrip('/')}/api/v1/fpn/activate"
    response = _authorized_request("POST", url, access_token)
    if response.status_code != 200:
        raise GuardianHTTPError(
            f"failed to activate guardian entitlement: HTTP {response.status_code}: {read_error_body(response)}",
            status_code=response.status_code,
        )
    return _parse_entitlement(response.json())
