"""A small pool of upstream proxy sessions (HTTP/2 or HTTP/3).

When more than one upstream connection is configured, SOCKS5 clients are
assigned to a session using a stable hash of an affinity key (typically the
client's source IP), so repeated connections from the same client route
through the same upstream session/IP.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
from typing import Awaitable, Callable, List, Optional, Union

from .h3_session import H3ProxySession, H3Stream
from .session import H2ProxySession, H2Stream

logger = logging.getLogger("foxyvpn.proxy.pool")

# Both session classes expose the same duck-typed interface (connect,
# update_token, open_stream, close, is_closed); which one a given pool uses
# is decided by ProxyController based on --http3.
ProxySession = Union[H2ProxySession, H3ProxySession]
ProxyStream = Union[H2Stream, H3Stream]
SessionFactory = Callable[[], Awaitable[ProxySession]]


class SessionPool:
    def __init__(self, size: int, factory: SessionFactory):
        self.size = max(1, size)
        self._factory = factory
        self._sessions: List[ProxySession] = []
        self._rr = itertools.count()
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        self._sessions = await asyncio.gather(*(self._factory() for _ in range(self.size)))

    def update_token(self, token: str) -> None:
        for session in self._sessions:
            session.update_token(token)

    async def _session_for(self, affinity_key: Optional[str]) -> ProxySession:
        async with self._lock:
            if affinity_key is not None:
                index = hash(affinity_key) % len(self._sessions)
            else:
                index = next(self._rr) % len(self._sessions)
            session = self._sessions[index]
            if session.is_closed:
                logger.warning("upstream session %d closed, reconnecting", index)
                session = await self._factory()
                self._sessions[index] = session
            return session

    async def open_stream(self, target_host: str, target_port: int, affinity_key: Optional[str] = None) -> ProxyStream:
        session = await self._session_for(affinity_key)
        return await session.open_stream(target_host, target_port)

    async def close(self) -> None:
        await asyncio.gather(*(s.close() for s in self._sessions), return_exceptions=True)
