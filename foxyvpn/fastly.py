"""Client-side solver for Fastly's JavaScript anti-bot "Client Challenge",
served with HTTP 406 responses in front of some Firefox Accounts endpoints.

Ported from the original Go client's fastly.go: two candidate hosts are
tried in order (the FxA API host, then the FxA site host, since the API
host itself usually serves no challenge page at all and the cookie Fastly
issues is scoped to Domain=firefox.com). Each attempt uses a throwaway
client with its own cookie jar sharing the main client's transport, so the
challenge is solved through the same exit IP that will make the retried API
call -- the issued cookie is bound to that exit IP.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
import threading
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from .exceptions import FastlyChallengeError

FXA_API_HOST = "https://api.accounts.firefox.com"
FXA_SITE_URL = "https://accounts.firefox.com"

FASTLY_SOLVE_TIMEOUT = 60.0
MAX_POST_BACK_ROUNDS = 3
FASTLY_SOLVER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

_CHALLENGE_PREFIX_RE = re.compile(r"/_fs-ch-[A-Za-z0-9]+")
_INIT_CALL_RE = re.compile(r'init\((\[[^\]]*\]),\s*"([^"]+)",\s*"([^"]+)"')
# The challenge script brute-forces a fixed 2-character alphanumeric suffix
# such that sha256(base + suffix) equals the target hash; this mirrors the
# exact alphabet and length the real Fastly challenge script uses.
_POW_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_SHA256_DIGEST_SIZE = 32

# Serializes the whole solve-challenge flow across concurrent callers,
# matching the original Go client's package-level challengeSolveMu: two
# challenge solves running at once would otherwise race on the shared
# control-plane client's cookie jar while installing the resulting cookies.
_CHALLENGE_SOLVE_LOCK = threading.Lock()


class _NoChallengePage(Exception):
    """Raised internally when a host does not serve a Fastly challenge page."""


def _base_origin(prefix_url: str) -> str:
    idx = prefix_url.find("/_fs-ch-")
    if idx > 0:
        return prefix_url[:idx]
    return prefix_url


def _solve_pow(base: str, target_hex: str) -> Optional[str]:
    try:
        target = bytes.fromhex(target_hex)
    except ValueError:
        return None
    if len(target) != _SHA256_DIGEST_SIZE:
        return None
    for a, b in itertools.product(_POW_ALPHABET, repeat=2):
        suffix = a + b
        if hashlib.sha256((base + suffix).encode()).digest() == target:
            return suffix
    return None


def _fetch_text(
    client: httpx.Client,
    url: str,
    *,
    accept: str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
) -> str:
    response = client.get(
        url,
        headers={"User-Agent": FASTLY_SOLVER_USER_AGENT, "Accept": accept},
        timeout=FASTLY_SOLVE_TIMEOUT,
    )
    if response.status_code != 200:
        raise FastlyChallengeError(f"GET {url} returned HTTP {response.status_code}")
    return response.text


def _fetch_challenge_page(client: httpx.Client, page_url: str) -> Tuple[str, bool]:
    body = _fetch_text(client, page_url)
    is_challenge = "/_fs-ch-" in body and "Client Challenge" in body
    return body, is_challenge


def _parse_challenge_init(script: str) -> Tuple[List[Dict[str, Any]], str]:
    matches = _INIT_CALL_RE.findall(script)
    if not matches:
        raise FastlyChallengeError("challenge init() call not found in script")
    challenges_json, token, _next_path = matches[-1]
    try:
        challenges = json.loads(challenges_json)
    except json.JSONDecodeError as exc:
        raise FastlyChallengeError(f"could not parse challenge list: {exc}") from exc
    if not challenges:
        raise FastlyChallengeError("empty challenge list")
    return challenges, token


def _fetch_pat(client: httpx.Client, prefix_url: str, token: str) -> str:
    """POST for a Private Access Token. A 400/401 means the client cannot
    mint one (a browser-platform feature); returning an empty auth value
    makes the server fall back to solvable challenges, matching the Go
    client's fetchPAT."""
    pat_url = f"{prefix_url}/pat?token={quote(token, safe='')}"
    response = client.post(
        pat_url,
        headers={
            "Accept": "text/plain",
            "Content-Type": "application/json",
            "User-Agent": FASTLY_SOLVER_USER_AGENT,
            "Origin": _base_origin(prefix_url),
        },
        timeout=FASTLY_SOLVE_TIMEOUT,
    )
    if response.status_code in (400, 401):
        return ""
    if response.status_code != 200:
        raise FastlyChallengeError(f"PAT request returned HTTP {response.status_code}")
    try:
        auth = response.json().get("auth", "")
    except json.JSONDecodeError as exc:
        raise FastlyChallengeError(f"could not parse PAT response: {exc}") from exc
    if not auth:
        raise FastlyChallengeError("empty PAT auth token")
    return auth


def _client_metrics_answer() -> Dict[str, Any]:
    # Mozilla's configuration currently issues only PAT/PoW challenges, so
    # this is a best-effort fallback mirroring the Go client's benign
    # static browser-metrics payload.
    return {
        "ty": "clientmetrics",
        "webdriver": False,
        "bot_detection_result": {"bot_detected": False, "bot_kind": None},
        "browser_metrics": {"client_data": "{}", "error_trace": None},
        "detector_results": {},
        "v": 2,
    }


def _answer_challenge(client: httpx.Client, prefix_url: str, token: str, challenge: Dict[str, Any]) -> Dict[str, Any]:
    challenge_type = challenge.get("ty")
    data = challenge.get("data") or {}
    if challenge_type == "pow":
        base = data.get("base", "")
        answer = _solve_pow(base, data.get("hash", ""))
        if answer is None:
            raise FastlyChallengeError(f"no proof-of-work solution found for base {base!r}")
        return {
            "ty": "pow",
            "base": base,
            "answer": answer,
            "hmac": data.get("hmac", ""),
            "expires": data.get("expires", ""),
        }
    if challenge_type == "pat":
        return {"ty": "pat", "auth": _fetch_pat(client, prefix_url, token)}
    if challenge_type == "clientmetrics":
        return _client_metrics_answer()
    raise FastlyChallengeError(f"unsupported Fastly challenge type {challenge_type!r} (captcha cannot be solved automatically)")


def _install_challenge_cookies(solver: httpx.Client, main_client: httpx.Client) -> None:
    cookies = dict(solver.cookies)
    if not cookies:
        raise FastlyChallengeError("challenge completed but no cookies were issued")
    # The cookie is issued with Domain=firefox.com, which covers both the
    # API host and the site host, matching the Go client installing it
    # into both the API and site jars.
    for name, value in cookies.items():
        main_client.cookies.set(name, value, domain="firefox.com")
        main_client.cookies.set(name, value)


def _solve_challenge_on_host(main_client: httpx.Client, base: str) -> None:
    # A throw-away client with a fresh cookie jar: re-solving with a client
    # that already holds a valid challenge cookie fails because Fastly then
    # serves the real page instead of the challenge page. It shares the
    # main client's transport so the request exits through the same proxy
    # (and exit IP) as the retried API call.
    solver = httpx.Client(transport=getattr(main_client, "_transport", None), timeout=FASTLY_SOLVE_TIMEOUT)
    try:
        page_url = base + "/"
        page, is_challenge = _fetch_challenge_page(solver, page_url)
        if not is_challenge:
            raise _NoChallengePage()

        prefix_match = _CHALLENGE_PREFIX_RE.search(page)
        if not prefix_match:
            raise FastlyChallengeError(f"challenge asset prefix not found on {base}")
        prefix_url = base + prefix_match.group(0)

        script = _fetch_text(solver, f"{prefix_url}/script.js?reload=true")
        challenges, token = _parse_challenge_init(script)

        for _round in range(MAX_POST_BACK_ROUNDS):
            answers = [_answer_challenge(solver, prefix_url, token, challenge) for challenge in challenges]
            response = solver.post(
                f"{prefix_url}/fst-post-back",
                json={"token": token, "data": answers},
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": FASTLY_SOLVER_USER_AGENT,
                    "Origin": _base_origin(prefix_url),
                },
                timeout=FASTLY_SOLVE_TIMEOUT,
            )
            if response.status_code != 200:
                raise FastlyChallengeError(f"challenge post-back returned HTTP {response.status_code}")
            body = response.json()
            if body.get("status") == "success":
                # Probe before installing the cookie: with rotating-exit
                # proxies the cookie may be bound to an IP the API call
                # will not reuse, and the probe catches that immediately.
                _, still_challenged = _fetch_challenge_page(solver, page_url)
                if still_challenged:
                    raise FastlyChallengeError("challenge cookie not accepted on this exit IP")
                _install_challenge_cookies(solver, main_client)
                return
            next_challenges, next_token = body.get("ch") or [], body.get("tok") or ""
            if not next_challenges or not next_token:
                raise FastlyChallengeError(f"unexpected post-back response: {body!r}")
            challenges, token = next_challenges, next_token
        raise FastlyChallengeError(f"Fastly challenge did not complete within {MAX_POST_BACK_ROUNDS} rounds")
    finally:
        solver.close()


def solve_fastly_challenge(client: httpx.Client, response: httpx.Response) -> None:
    """Given a 406 response believed to be a Fastly challenge, solve it and
    install the resulting cookies on ``client`` so a retried request will
    succeed. Raises FastlyChallengeError if no candidate host actually
    serves a solvable challenge.

    Serialized process-wide via _CHALLENGE_SOLVE_LOCK, matching the Go
    client's challengeSolveMu, so concurrent callers never interleave
    cookie installs on the shared client.
    """
    with _CHALLENGE_SOLVE_LOCK:
        last_error: Optional[Exception] = None
        for base in (FXA_API_HOST, FXA_SITE_URL):
            try:
                _solve_challenge_on_host(client, base)
                return
            except _NoChallengePage:
                continue
            except FastlyChallengeError as exc:
                last_error = exc
        raise last_error or FastlyChallengeError("host did not serve a Fastly challenge page")
