"""Cached OAuth token storage at ``~/.foxyvpn-tokens.json`` (mode 0600)."""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

TOKEN_FILE_NAME = ".foxyvpn-tokens.json"

# Refresh this many seconds before the access token's real expiry.
ACCESS_TOKEN_EXPIRY_LEAD_SECONDS = 120


@dataclass
class SavedTokens:
    access_token: str
    refresh_token: str
    scope: str
    obtained_at: float = field(default_factory=time.time)
    expires_in: int = 0

    def access_token_valid(self) -> bool:
        if not self.access_token:
            return False
        expires_at = self.obtained_at + self.expires_in
        return time.time() < (expires_at - ACCESS_TOKEN_EXPIRY_LEAD_SECONDS)


def _token_path() -> Path:
    return Path.home() / TOKEN_FILE_NAME


def load_tokens() -> Optional[SavedTokens]:
    path = _token_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    try:
        return SavedTokens(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token", ""),
            scope=data.get("scope", ""),
            obtained_at=data.get("obtained_at", time.time()),
            expires_in=data.get("expires_in", 0),
        )
    except KeyError:
        return None


def save_tokens(token) -> SavedTokens:
    """Persist ``token`` (an ``fxa.TokenResponse``-like object) atomically
    with owner-only (0600) permissions."""
    saved = SavedTokens(
        access_token=token.access_token,
        refresh_token=getattr(token, "refresh_token", "") or "",
        scope=getattr(token, "scope", "") or "",
        obtained_at=time.time(),
        expires_in=getattr(token, "expires_in", 0) or 0,
    )
    path = _token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=TOKEN_FILE_NAME + ".tmp-", dir=str(path.parent))
    try:
        os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(asdict(saved), fh)
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return saved


def delete_tokens() -> None:
    try:
        _token_path().unlink()
    except FileNotFoundError:
        pass
