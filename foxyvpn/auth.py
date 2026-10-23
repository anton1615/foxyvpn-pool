"""High-level authentication orchestration: cached tokens, refresh, fresh
interactive login, and session-token-pool rotation on quota exhaustion.
"""

from __future__ import annotations

import getpass
import logging
from dataclasses import dataclass
from typing import Optional

from . import fxa, tokens
from .exceptions import FxaApiError
from .session_tokens import SessionTokenPool

logger = logging.getLogger("foxyvpn.auth")


@dataclass
class RuntimeAuth:
    token: fxa.TokenResponse
    session_token_pool: Optional[SessionTokenPool] = None

    @property
    def access_token(self) -> str:
        return self.token.access_token


def _verify_session_interactively(email: str, session_token: str, verification_method: Optional[str]) -> None:
    """Confirm a new sign-in, matching the original Go client's behavior.

    FxA can confirm a sign-in from an unrecognized device either by
    emailing a short numeric code (verification_method == "email-2fa",
    which is what we ask for during login) or, if that is unavailable, by
    emailing a confirmation *link* (verification_method == "email"). A
    link can't be "entered", so it needs its own prompt instead of the
    numeric-code flow.
    """
    if verification_method == "email":
        print(f"This sign-in must be confirmed: a confirmation link was sent to {email}.")
        input("Open the link from the email, then press Enter here to continue: ")
        return

    while True:
        code = input("Enter the confirmation code emailed to you: ").strip()
        if not code:
            continue
        try:
            fxa.verify_session(session_token, code)
            return
        except FxaApiError as exc:
            print(f"Verification failed: {exc}")


def _login_interactively(email: str, password: Optional[str] = None) -> fxa.TokenResponse:
    if password is None:
        password = getpass.getpass(f"Firefox Accounts password for {email}: ")
    login_resp = fxa.login(email, password)
    if not login_resp.verified:
        _verify_session_interactively(email, login_resp.session_token, login_resp.verification_method)
    token = fxa.oauth_token(login_resp.session_token)
    tokens.save_tokens(token)
    return token


def _refresh(saved: tokens.SavedTokens) -> fxa.TokenResponse:
    token = fxa.refresh_token(saved.refresh_token)
    tokens.save_tokens(token)
    return token


def _from_single_session_token(session_token: str) -> fxa.TokenResponse:
    token = fxa.oauth_token(session_token)
    tokens.save_tokens(token)
    return token


def obtain_auth(
    *,
    email: Optional[str] = None,
    password: Optional[str] = None,
    force_login: bool = False,
    session_token_or_path: Optional[str] = None,
) -> RuntimeAuth:
    """Resolve a valid access token following the same precedence as the
    original CLI: explicit session token(s) > forced fresh login > cached
    tokens (refreshing if needed) > fresh interactive login."""
    if session_token_or_path:
        pool: Optional[SessionTokenPool] = None
        try:
            pool = SessionTokenPool.load(session_token_or_path)
            session_token = pool.current()
        except (OSError, ValueError):
            session_token = session_token_or_path.strip()
        token = _from_single_session_token(session_token)
        return RuntimeAuth(token=token, session_token_pool=pool)

    if not force_login:
        saved = tokens.load_tokens()
        if saved is not None:
            if saved.access_token_valid():
                return RuntimeAuth(
                    token=fxa.TokenResponse(
                        access_token=saved.access_token,
                        refresh_token=saved.refresh_token,
                        scope=saved.scope,
                        expires_in=saved.expires_in,
                    )
                )
            if saved.refresh_token:
                try:
                    return RuntimeAuth(token=_refresh(saved))
                except FxaApiError as exc:
                    logger.warning("refresh token rejected (%s), falling back to fresh login", exc)

    if not email:
        email = input("Firefox Accounts email: ").strip()
    return RuntimeAuth(token=_login_interactively(email, password))


def rotate_session_token(auth: RuntimeAuth) -> Optional[RuntimeAuth]:
    """Advance through the session token pool, matching the original Go
    client's activateNextPoolToken: each remaining token's OAuth exchange is
    tried in turn, silently skipping any token Firefox Accounts itself
    rejects, until one succeeds or the pool is exhausted.

    Returns ``None`` when the pool is exhausted (or absent) without ever
    finding a usable token.
    """
    if auth.session_token_pool is None:
        return None
    pool = auth.session_token_pool
    while True:
        next_token = pool.rotate()
        if next_token is None:
            return None
        try:
            token = _from_single_session_token(next_token)
        except FxaApiError as exc:
            logger.warning("session token rejected by Firefox Accounts; trying next token: %s", exc)
            continue
        return RuntimeAuth(token=token, session_token_pool=pool)
