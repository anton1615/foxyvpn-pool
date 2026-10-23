"""Shared HTTP client used for control-plane calls (FxA, Guardian, Remote Settings)."""

from __future__ import annotations

import os
import threading
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

CONTROL_PLANE_HTTP_TIMEOUT = 30.0

# Some system-wide proxy tooling (v2ray, Xray, Clash, and similar) exports
# proxy environment variables using a bare "socks://" scheme rather than the
# "socks5://"/"socks5h://" schemes httpx requires. Normalize known aliases so
# a perfectly usable SOCKS5 proxy doesn't hard-crash the process.
_PROXY_SCHEME_ALIASES = {"socks": "socks5"}

# Checked in the same order common CLI tools use: an explicit all-protocols
# override first, then the protocol-specific vars, uppercase before lowercase.
_ENV_PROXY_VARS = ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")

_lock = threading.Lock()
_client: Optional[httpx.Client] = None
_proxy_url: Optional[str] = None
_timeout: float = CONTROL_PLANE_HTTP_TIMEOUT


def _normalize_proxy_url(url: str) -> str:
    parts = urlsplit(url)
    scheme = _PROXY_SCHEME_ALIASES.get(parts.scheme.lower(), parts.scheme)
    if scheme == parts.scheme:
        return url
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))


def _env_proxy_url() -> Optional[str]:
    for var in _ENV_PROXY_VARS:
        value = os.environ.get(var)
        if value:
            return value
    return None


def _build_client() -> httpx.Client:
    # Resolve the effective proxy ourselves -- an explicit --api-proxy wins,
    # otherwise fall back to the ambient system proxy env vars -- and turn
    # off httpx's own trust_env-based environment lookup so we get a chance
    # to normalize scheme aliases before httpx ever validates the URL.
    proxy = _proxy_url or _env_proxy_url()
    kwargs = {"timeout": _timeout, "http2": True, "follow_redirects": True, "trust_env": False}
    if proxy:
        kwargs["proxy"] = _normalize_proxy_url(proxy)
    return httpx.Client(**kwargs)


def get_client() -> httpx.Client:
    global _client
    with _lock:
        if _client is None:
            _client = _build_client()
        return _client


def set_control_plane_proxy(proxy_url: Optional[str]) -> None:
    """Set (or clear) the proxy URL used for control-plane HTTP calls, rebuilding
    the shared client so the new proxy takes effect immediately."""
    global _client, _proxy_url
    with _lock:
        _proxy_url = proxy_url
        if _client is not None:
            _client.close()
        _client = _build_client()


def set_control_plane_timeout(timeout: Optional[float]) -> None:
    """Set the default per-request timeout (seconds) used for control-plane
    HTTP calls (FxA, Guardian, Remote Settings), rebuilding the shared client
    so the new timeout takes effect immediately. Falls back to
    CONTROL_PLANE_HTTP_TIMEOUT when ``timeout`` is None or not positive.
    """
    global _client, _timeout
    with _lock:
        _timeout = timeout if timeout and timeout > 0 else CONTROL_PLANE_HTTP_TIMEOUT
        if _client is not None:
            _client.close()
        _client = _build_client()


def read_error_body(response: httpx.Response, limit: int = 2048) -> str:
    try:
        text = response.text
    except Exception:  # noqa: BLE001
        return ""
    return text[:limit]
