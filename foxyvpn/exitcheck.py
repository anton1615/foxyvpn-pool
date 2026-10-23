"""Non-fatal exit-IP verification: probes the exit country through the
established proxy and warns if it doesn't match the requested country.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("foxyvpn.exitcheck")

DEFAULT_EXIT_CHECK_URL = "https://www.cloudflare.com/cdn-cgi/trace"
DEFAULT_EXIT_CHECK_TIMEOUT = 10.0

# Mirrors the original Go client's maxExitCheckResponseSize: bound how much
# of the exit-check response is buffered, so a broken or hostile endpoint
# behind --exit-check-url can't make this probe consume unbounded memory.
MAX_EXIT_CHECK_RESPONSE_SIZE = 64 * 1024

# "REC" is Firefox's pseudo-country code for the automatically-recommended
# server: it maps to a rotating/anycast endpoint whose real terminating
# country varies by network conditions, so comparing the observed country
# against the literal "REC" label always looks like a mismatch even though
# nothing is wrong.
_AUTO_SELECT_COUNTRY_CODES = {"REC"}

_COUNTRY_CODE_RE = re.compile(r"^[A-Z]{2}$")


def _extract_trace_fields(body: str) -> dict:
    """Parse "key=value" trace-format lines (e.g. Cloudflare's
    /cdn-cgi/trace), mirroring the original Go client's parsing: split the
    body into lines, cut each trimmed line on the *first* "=" (equivalent
    to Go's strings.Cut, which does not restrict what characters may
    appear in the key), and lowercase/trim the key before storing it."""
    fields: dict = {}
    for line in body.split("\n"):
        line = line.strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip().lower()] = value.strip()
    return fields


def _extract_json_fields(body: str) -> dict:
    body = body.strip()
    if not body.startswith("{"):
        return {}
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _json_string(payload: dict, key: str) -> str:
    """Mirrors the original Go client's jsonString helper: only accept
    string-typed JSON values for the given key, treating any other type
    (number, bool, null, object, array, or missing) as absent, exactly
    like a failed type assertion in Go does."""
    value = payload.get(key)
    return value if isinstance(value, str) else ""


def _first_nonempty(*values: Optional[str]) -> str:
    for value in values:
        if value and str(value).strip():
            return str(value)
    return ""


def _parse_exit_probe_response(body: str) -> Tuple[str, str]:
    """Extract (ip, country_code) from a response, mirroring the original
    Go client's parseExitProbeResponse: parse "key=value" trace-format
    lines first (e.g. Cloudflare's /cdn-cgi/trace's "ip"/"loc" fields),
    then fall back to top-level JSON fields for whichever of ip/country is
    still missing (e.g. ip-api.com-style responses, which use "query" for
    the IP and "countryCode" for the country). Trace and JSON parsing are
    layered fallbacks, not mutually exclusive alternatives.

    Finally, just like the Go client, validate that the result is an
    actual IP address and a two-letter (ASCII) country code, raising
    instead of silently returning malformed/bogus data if not."""
    trace_fields = _extract_trace_fields(body)
    ip = _first_nonempty(trace_fields.get("ip"), trace_fields.get("query"))
    country = _first_nonempty(
        trace_fields.get("loc"), trace_fields.get("country_code"), trace_fields.get("countrycode")
    )
    if not ip or not country:
        json_fields = _extract_json_fields(body)
        ip = _first_nonempty(ip, _json_string(json_fields, "ip"), _json_string(json_fields, "query"))
        country = _first_nonempty(
            country, _json_string(json_fields, "country_code"), _json_string(json_fields, "countryCode")
        )

    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise RuntimeError("exit verification response did not contain a valid IP address")

    country = country.strip().upper()
    if not _COUNTRY_CODE_RE.match(country):
        raise RuntimeError("exit verification response did not contain a valid two-letter country code")

    return ip, country


async def _read_capped(response: httpx.Response) -> str:
    """Stream the response body, aborting once it exceeds
    MAX_EXIT_CHECK_RESPONSE_SIZE instead of buffering an unbounded amount,
    matching the Go client's io.LimitReader(resp.Body, maxExitCheckResponseSize)."""
    chunks = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > MAX_EXIT_CHECK_RESPONSE_SIZE:
            raise RuntimeError(f"exit verification response exceeds {MAX_EXIT_CHECK_RESPONSE_SIZE} bytes")
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


async def verify_exit_country(
    local_proxy_url: str,
    expected_country: str,
    *,
    check_url: str = DEFAULT_EXIT_CHECK_URL,
    timeout: float = DEFAULT_EXIT_CHECK_TIMEOUT,
) -> Optional[str]:
    """Fetch ``check_url`` through the local SOCKS5 proxy and return the
    observed exit country code, logging a warning on mismatch. Never raises,
    since exit verification must not block the proxy from serving traffic."""
    try:
        parsed = urlparse(check_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise RuntimeError("exit check URL must use HTTPS and include a host")

        headers = {
            "Accept": "text/plain, application/json",
            "User-Agent": "foxyvpn-exit-check/1",
        }
        async with httpx.AsyncClient(proxy=local_proxy_url, timeout=timeout) as client:
            async with client.stream("GET", check_url, headers=headers) as resp:
                if resp.status_code < 200 or resp.status_code >= 300:
                    raise RuntimeError(f"exit verification endpoint returned HTTP {resp.status_code}")
                body = await _read_capped(resp)

        ip, observed = _parse_exit_probe_response(body)
        is_auto_select = bool(expected_country) and expected_country.upper() in _AUTO_SELECT_COUNTRY_CODES
        if is_auto_select:
            logger.info(
                "exit verification: recommended (%s) server resolved to %s, exit ip %s",
                expected_country,
                observed,
                ip,
            )
        elif observed and expected_country and observed.upper() != expected_country.upper():
            logger.warning(
                "exit verification: expected country %s but observed %s (exit ip %s)",
                expected_country,
                observed,
                ip,
            )
        else:
            logger.info("exit verification: exit ip %s, country %s", ip, observed)
        return observed or None
    except Exception as exc:  # noqa: BLE001
        logger.warning("exit verification failed (non-fatal): %s", exc)
        return None
