"""Bidirectional byte relay between a local SOCKS5 client socket and a
tunneled upstream :class:`H2Stream`."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from .session import H2Stream

logger = logging.getLogger("foxyvpn.proxy.relay")

READ_CHUNK_SIZE = 65536

# Matches the original Go client's halfCloseDrainTimeout: once one direction
# finishes cleanly (a half-close), the other direction gets this long to keep
# draining any remaining data before the tunnel is forced closed.
HALF_CLOSE_DRAIN_TIMEOUT = 120.0


async def _pump_client_to_upstream(reader: asyncio.StreamReader, upstream: H2Stream, idle_timeout: float) -> None:
    try:
        while True:
            if idle_timeout > 0:
                data = await asyncio.wait_for(reader.read(READ_CHUNK_SIZE), timeout=idle_timeout)
            else:
                data = await reader.read(READ_CHUNK_SIZE)
            if not data:
                break
            await upstream.write(data)
    finally:
        await upstream.close()


async def _pump_upstream_to_client(upstream: H2Stream, writer: asyncio.StreamWriter, idle_timeout: float) -> None:
    try:
        while True:
            if idle_timeout > 0:
                data = await asyncio.wait_for(upstream.read(), timeout=idle_timeout)
            else:
                data = await upstream.read()
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        try:
            writer.write_eof()
        except (OSError, RuntimeError, NotImplementedError):
            pass


async def relay_bidirectional(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    upstream: H2Stream,
    idle_timeout: float = 0.0,
) -> None:
    """Pump bytes in both directions, matching the original Go client's
    proxyBidirectional: when one direction finishes cleanly (a half-close),
    the other direction is given up to HALF_CLOSE_DRAIN_TIMEOUT seconds to
    keep draining any remaining buffered data before the tunnel is forced
    closed. If a direction instead fails with an error (including hitting
    ``idle_timeout``), both sides are torn down immediately.
    """
    to_upstream = asyncio.create_task(_pump_client_to_upstream(reader, upstream, idle_timeout))
    to_client = asyncio.create_task(_pump_upstream_to_client(upstream, writer, idle_timeout))
    tasks = {to_upstream, to_client}

    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    first_error = next(iter(done)).exception()

    if first_error is not None or not pending:
        for task in pending:
            task.cancel()
    else:
        # Clean half-close on one side: let the other side keep draining,
        # bounded by the same grace period the original Go client uses.
        _drained, still_pending = await asyncio.wait(pending, timeout=HALF_CLOSE_DRAIN_TIMEOUT)
        if still_pending:
            logger.debug("closing half-closed tunnel after drain timeout=%ss", HALF_CLOSE_DRAIN_TIMEOUT)
        for task in still_pending:
            task.cancel()

    for task in tasks:
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
