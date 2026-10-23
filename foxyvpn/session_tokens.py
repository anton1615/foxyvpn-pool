"""A rotating pool of pre-provisioned FxA session tokens.

Reads one session token per line from a file (skipping blanks and ``#``
comments and de-duplicating), and persists which token is "active" to a
sidecar ``<file>.state`` JSON file keyed by a SHA-256 checksum of the token
file, so token-file edits invalidate stale activation state.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class SessionTokenPool:
    tokens: List[str]
    checksum: str
    state_path: Path
    active_index: int = 0

    @classmethod
    def load(cls, file_path: str) -> "SessionTokenPool":
        path = Path(file_path)
        raw = path.read_text(encoding="utf-8")
        tokens: List[str] = []
        seen = set()
        for line in raw.splitlines():
            token = line.strip()
            if not token or token.startswith("#"):
                continue
            # Matches the original Go client's loadSessionTokenPool, which
            # performs no token-format validation at all: any non-empty,
            # non-comment, de-duplicated line is accepted as-is.
            if token in seen:
                continue
            seen.add(token)
            tokens.append(token)
        if not tokens:
            raise ValueError(f"no session tokens found in {file_path}")

        checksum = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        state_path = path.with_suffix(path.suffix + ".state")
        pool = cls(tokens=tokens, checksum=checksum, state_path=state_path)
        pool.active_index = pool._load_active_index()
        return pool

    def _load_active_index(self) -> int:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return 0
        if data.get("checksum") != self.checksum:
            return 0
        index = int(data.get("active_index", 0) or 0)
        if 0 <= index < len(self.tokens):
            return index
        return 0

    def _persist_active_index(self) -> None:
        payload = {"checksum": self.checksum, "active_index": self.active_index}
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=self.state_path.name + ".tmp-", dir=str(self.state_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(tmp_path, self.state_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def current(self) -> str:
        return self.tokens[self.active_index]

    def rotate(self) -> Optional[str]:
        """Advance to the next session token. Returns ``None`` when every
        token in the pool has already been tried (wrapped around)."""
        next_index = self.active_index + 1
        if next_index >= len(self.tokens):
            return None
        self.active_index = next_index
        self._persist_active_index()
        return self.current()

    def reset(self) -> None:
        self.active_index = 0
        self._persist_active_index()
