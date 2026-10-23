"""A single HTTP/2 session to an upstream Mozilla VPN proxy node.

Each outbound TCP connection requested by a SOCKS5 client is tunneled as an
HTTP/2 stream on this session using the standard HTTP/2 CONNECT method
(RFC 7540 section 8.3), authenticated with the Guardian proxy-pass bearer
token.
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import time
from typing import Dict, Optional

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    PingAckReceived,
    ResponseReceived,
    StreamEnded,
    StreamReset,
)
from h2.exceptions import StreamClosedError

from ..exceptions import ProxyError

logger = logging.getLogger("foxyvpn.proxy.session")

DEFAULT_HANDSHAKE_TIMEOUT = 10.0

# Mirrors the original Go client's upstream http2.Transport configuration
# (ReadIdleTimeout, PingTimeout, WriteByteTimeout) so a silently dead
# upstream connection is actively detected and torn down for reconnection
# instead of hanging tunnels indefinitely.
READ_IDLE_TIMEOUT = 30.0
PING_TIMEOUT = 15.0
WRITE_TIMEOUT = 30.0
# How often the keepalive loop checks idle time; independent of the above.
_KEEPALIVE_POLL_INTERVAL = 1.0


def _format_authority(host: str, port: int) -> str:
    """Format a host:port authority for the HTTP/2 :authority header,
    matching what Go's net.JoinHostPort does: an IPv6 literal (which
    contains colons of its own) must be wrapped in brackets so the
    trailing ":<port>" is unambiguous. Hostnames and IPv4 literals have no
    internal colons and pass through unchanged."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


class H2Stream:
    """One tunneled TCP connection multiplexed over a parent HTTP/2 session."""

    def __init__(self, session: "H2ProxySession", stream_id: int):
        self._session = session
        self.stream_id = stream_id
        self._incoming: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue()
        self.established = asyncio.Event()
        self.failed: Optional[Exception] = None

    async def wait_established(self) -> None:
        await self.established.wait()
        if self.failed:
            raise self.failed

    async def read(self) -> Optional[bytes]:
        """Return the next chunk of data, or ``None`` at end-of-stream."""
        return await self._incoming.get()

    def _feed(self, chunk: Optional[bytes]) -> None:
        self._incoming.put_nowait(chunk)

    async def write(self, data: bytes) -> None:
        await self._session._send_data(self.stream_id, data)

    async def close(self) -> None:
        await self._session._end_stream(self.stream_id)


def _connect_status_ok(status: Optional[object]) -> bool:
    """Mirrors the original Go client's CONNECT response check
    (StatusCode < 200 || StatusCode > 299): accept any 2xx status, not
    just the literal 200, since some upstreams reply with e.g. 204."""
    if status is None:
        return False
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    return 200 <= code <= 299


class H2ProxySession:
    def __init__(self, host: str, port: int, token: str):
        self.host = host
        self.port = port
        self.token = token
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._conn: Optional[H2Connection] = None
        self._streams: Dict[int, H2Stream] = {}
        self._write_lock = asyncio.Lock()
        self._reader_task: Optional[asyncio.Task] = None
        self._keepalive_task: Optional[asyncio.Task] = None
        self._closed = False
        self._last_activity = time.monotonic()
        self._pending_ping: Optional[bytes] = None
        self._pending_ping_sent_at: float = 0.0

    async def connect(self, timeout: float = DEFAULT_HANDSHAKE_TIMEOUT) -> None:
        ssl_context = ssl.create_default_context()
        ssl_context.set_alpn_protocols(["h2"])
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, ssl=ssl_context), timeout=timeout
        )
        negotiated = self._writer.get_extra_info("ssl_object")
        if negotiated is not None and negotiated.selected_alpn_protocol() not in (None, "h2"):
            raise ProxyError(f"upstream {self.host}:{self.port} did not negotiate HTTP/2")

        config = H2Configuration(
            client_side=True,
            header_encoding="utf-8",
            # Work around a long-standing h2 bug (python-hyper/h2 issues
            # #1247 and #1308, only fixed by h2 PR #1309) where h2
            # incorrectly raises ProtocolError("Header block missing
            # mandatory :path header") for a spec-compliant *ordinary*
            # HTTP/2 CONNECT request. RFC 9113 section 8.3 requires an
            # ordinary CONNECT to include only ":method" and ":authority"
            # and explicitly omit ":scheme"/":path" (those are only
            # required for *extended* CONNECT, e.g. RFC 8441 WebSocket).
            # The headers we send below are already spec-compliant; the
            # original Go client's net/http2 stack has no such bug and
            # accepts them, so disable h2's outbound validation here to
            # match that behavior regardless of the installed h2 version.
            validate_outbound_headers=False,
        )
        self._conn = H2Connection(config=config)
        self._conn.initiate_connection()
        await self._flush()
        self._last_activity = time.monotonic()
        self._reader_task = asyncio.create_task(self._read_loop())
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    def update_token(self, token: str) -> None:
        """Update the bearer token used for streams opened from now on."""
        self.token = token

    async def _flush(self) -> None:
        assert self._conn is not None and self._writer is not None
        data = self._conn.data_to_send()
        if data:
            self._writer.write(data)
            try:
                # Mirrors the original Go client's http2.Transport
                # WriteByteTimeout: a write that cannot make progress
                # within this window indicates a dead connection.
                await asyncio.wait_for(self._writer.drain(), timeout=WRITE_TIMEOUT)
            except asyncio.TimeoutError:
                self._mark_unhealthy()
                raise ProxyError(f"write to upstream {self.host}:{self.port} timed out after {WRITE_TIMEOUT}s")

    async def _read_loop(self) -> None:
        assert self._reader is not None and self._conn is not None
        try:
            while True:
                chunk = await self._reader.read(65536)
                if not chunk:
                    break
                self._last_activity = time.monotonic()
                events = self._conn.receive_data(chunk)
                for event in events:
                    self._handle_event(event)
                async with self._write_lock:
                    await self._flush()
        except Exception as exc:  # noqa: BLE001
            logger.debug("upstream session read loop ended: %s", exc)
        finally:
            self._closed = True
            for stream in list(self._streams.values()):
                stream._feed(None)

    async def _keepalive_loop(self) -> None:
        """Detect a silently dead upstream connection the same way the
        original Go client's http2.Transport does: if no frame has been
        read for READ_IDLE_TIMEOUT, send a PING; if no ack arrives within
        PING_TIMEOUT, treat the session as unhealthy and close it so the
        session pool reconnects."""
        try:
            while True:
                await asyncio.sleep(_KEEPALIVE_POLL_INTERVAL)
                if self._closed:
                    return
                now = time.monotonic()
                if self._pending_ping is not None:
                    if now - self._pending_ping_sent_at >= PING_TIMEOUT:
                        logger.warning(
                            "upstream %s:%s did not ack keepalive ping within %ss; marking session unhealthy",
                            self.host,
                            self.port,
                            PING_TIMEOUT,
                        )
                        self._mark_unhealthy()
                        return
                    continue
                if now - self._last_activity >= READ_IDLE_TIMEOUT:
                    await self._send_ping()
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("upstream session keepalive loop ended: %s", exc)

    async def _send_ping(self) -> None:
        assert self._conn is not None
        payload = os.urandom(8)
        try:
            async with self._write_lock:
                self._conn.ping(payload)
                await self._flush()
        except Exception as exc:  # noqa: BLE001
            logger.debug("sending keepalive ping to %s:%s failed: %s", self.host, self.port, exc)
            self._mark_unhealthy()
            return
        self._pending_ping = payload
        self._pending_ping_sent_at = time.monotonic()

    def _mark_unhealthy(self) -> None:
        """Mark this session closed so SessionPool treats it like any other
        dead session and transparently reconnects on next use."""
        self._closed = True
        if self._reader_task:
            self._reader_task.cancel()
        for stream in list(self._streams.values()):
            stream._feed(None)

    def _handle_event(self, event) -> None:
        if isinstance(event, ResponseReceived):
            stream = self._streams.get(event.stream_id)
            if stream is None:
                return
            status = next((v for k, v in event.headers if k == ":status"), None)
            if _connect_status_ok(status):
                stream.established.set()
            else:
                stream.failed = ProxyError(f"upstream refused CONNECT with status {status}")
                stream.established.set()
                stream._feed(None)
        elif isinstance(event, DataReceived):
            stream = self._streams.get(event.stream_id)
            if stream is not None:
                stream._feed(event.data)
            self._conn.acknowledge_received_data(len(event.data), event.stream_id)
        elif isinstance(event, (StreamEnded, StreamReset)):
            stream = self._streams.pop(event.stream_id, None)
            if stream is not None:
                if isinstance(event, StreamReset) and not stream.established.is_set():
                    stream.failed = ProxyError("upstream reset the stream before it was established")
                    stream.established.set()
                stream._feed(None)
        elif isinstance(event, PingAckReceived):
            if self._pending_ping is not None and event.ping_data == self._pending_ping:
                self._pending_ping = None
                self._last_activity = time.monotonic()
        elif isinstance(event, ConnectionTerminated):
            logger.info("upstream %s:%s terminated the connection: %s", self.host, self.port, event.error_code)

    async def open_stream(self, target_host: str, target_port: int) -> H2Stream:
        assert self._conn is not None
        async with self._write_lock:
            stream_id = self._conn.get_next_available_stream_id()
            headers = [
                (":method", "CONNECT"),
                (":authority", _format_authority(target_host, target_port)),
                ("proxy-authorization", f"Bearer {self.token}"),
            ]
            self._conn.send_headers(stream_id, headers)
            stream = H2Stream(self, stream_id)
            self._streams[stream_id] = stream
            await self._flush()
        await stream.wait_established()
        return stream

    async def _send_data(self, stream_id: int, data: bytes) -> None:
        async with self._write_lock:
            try:
                max_frame = self._conn.max_outbound_frame_size
                for offset in range(0, len(data), max_frame):
                    self._conn.send_data(stream_id, data[offset : offset + max_frame])
                await self._flush()
            except StreamClosedError:
                pass

    async def _end_stream(self, stream_id: int) -> None:
        async with self._write_lock:
            try:
                self._conn.end_stream(stream_id)
                await self._flush()
            except StreamClosedError:
                pass

    async def close(self) -> None:
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    @property
    def is_closed(self) -> bool:
        return self._closed
