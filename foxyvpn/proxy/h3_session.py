"""A single HTTP/3 (QUIC) session to an upstream Mozilla VPN proxy node.

Mirrors :mod:`foxyvpn.proxy.session`, but tunnels each outbound TCP
connection requested by a SOCKS5 client as an HTTP/3 CONNECT stream
(RFC 9114 section 4.4, the HTTP/3 analog of the HTTP/2 CONNECT method used
by :class:`~foxyvpn.proxy.session.H2ProxySession`) over a single QUIC
connection, authenticated with the Guardian proxy-pass bearer token. This
matches the original Go client's -h3 upstream transport, which is backed by
quic-go/http3's h3ProxySession, including its behavior of resolving every IP
for the proxy host and dialing each in turn until one succeeds.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Dict, List, Optional

from aioquic.asyncio import connect as quic_connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamReset

from ..exceptions import ProxyError

logger = logging.getLogger("foxyvpn.proxy.h3_session")

DEFAULT_HANDSHAKE_TIMEOUT = 10.0

# Mirrors the original Go client's QUIC keepalive/idle handling so a
# silently dead upstream QUIC connection (UDP has no equivalent of a TCP
# RST to signal this) is actively detected instead of hanging tunnels
# indefinitely.
KEEPALIVE_PERIOD = 30.0
PING_TIMEOUT = 15.0
_KEEPALIVE_POLL_INTERVAL = 1.0

# Mirrors the original Go client's explicit InitialPacketSize: 1200 tuning
# (documented there as needed to avoid QUIC handshake timeouts on
# low-MTU/lossy links): start with a conservative datagram size instead of
# the library default, which can be dropped outright on some paths before
# PMTU discovery has a chance to shrink it. Unlike Go's InitialPacketSize
# (which only bounds packets sent before path MTU is confirmed and is then
# allowed to grow), aioquic's max_datagram_size is a simple fixed ceiling
# for the whole connection, so this trades a little theoretical throughput
# headroom on high-bandwidth paths for reliably surviving low-MTU ones.
INITIAL_MAX_DATAGRAM_SIZE = 1200

# Mirrors the original Go client's per-address dial timeout floor: with
# multiple resolved IPs, dividing the overall handshake timeout evenly
# across all of them could make each individual attempt too short to ever
# succeed, so no attempt gets less than this floor.
_MIN_PER_ADDRESS_TIMEOUT = 3.0


def _format_authority(host: str, port: int) -> str:
    """Same IPv6-bracketing rule as the HTTP/2 session's :authority
    formatting: an IPv6 literal contains colons of its own, so it must be
    wrapped in brackets for the trailing \":<port>\" to be unambiguous."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


class H3Stream:
    """One tunneled TCP connection multiplexed over a parent HTTP/3
    session. Deliberately mirrors :class:`~foxyvpn.proxy.session.H2Stream`'s
    interface (read/write/close/wait_established) so SessionPool and the
    SOCKS5 relay loop work with either transport unmodified."""

    def __init__(self, session: "H3ProxySession", stream_id: int):
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


class _H3ClientProtocol(QuicConnectionProtocol):
    """Bridges aioquic's QUIC event loop into an H3ProxySession's stream
    table, mirroring how the h2 library's events feed H2ProxySession."""

    def __init__(self, *args, owner: "H3ProxySession", **kwargs):
        super().__init__(*args, **kwargs)
        self._owner = owner
        self.http = H3Connection(self._quic, enable_webtransport=False)

    def quic_event_received(self, event) -> None:
        if isinstance(event, StreamReset):
            self._owner._handle_stream_reset(event.stream_id)
        elif isinstance(event, ConnectionTerminated):
            self._owner._mark_closed()
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self._owner._handle_headers(http_event)
            elif isinstance(http_event, DataReceived):
                self._owner._handle_data(http_event)
        self.transmit()


class H3ProxySession:
    def __init__(self, host: str, port: int, token: str):
        self.host = host
        self.port = port
        self.token = token
        self._protocol: Optional[_H3ClientProtocol] = None
        self._http: Optional[H3Connection] = None
        self._connect_cm = None
        self._streams: Dict[int, H3Stream] = {}
        self._write_lock = asyncio.Lock()
        self._keepalive_task: Optional[asyncio.Task] = None
        self._closed = False
        self._last_activity = time.monotonic()

    async def _resolve(self, timeout: float) -> List[str]:
        loop = asyncio.get_running_loop()
        try:
            if timeout and timeout > 0:
                addrinfos = await asyncio.wait_for(
                    loop.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM),
                    timeout=timeout,
                )
            else:
                addrinfos = await loop.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)
        except asyncio.TimeoutError:
            raise ProxyError(f"resolving upstream {self.host} timed out after {timeout}s")
        except OSError as exc:
            raise ProxyError(f"resolving upstream {self.host} failed: {exc}") from exc

        seen = set()
        ips: List[str] = []
        for _family, _type, _proto, _canonname, sockaddr in addrinfos:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        if not ips:
            raise ProxyError(f"no addresses found for upstream {self.host}")
        return ips

    async def connect(self, timeout: float = DEFAULT_HANDSHAKE_TIMEOUT) -> None:
        ips = await self._resolve(timeout)

        # Mirrors the original Go client: divide the overall timeout evenly
        # across every resolved address, with a floor so a host with many
        # addresses doesn't get an unusably short per-attempt timeout.
        per_attempt_timeout: Optional[float] = None
        if timeout and timeout > 0:
            per_attempt_timeout = max(timeout / len(ips), _MIN_PER_ADDRESS_TIMEOUT)

        def create_protocol(*args, **kwargs):
            return _H3ClientProtocol(*args, owner=self, **kwargs)

        # Only "h3" is ever offered as an ALPN candidate below, so a
        # handshake that completes successfully already implies the peer
        # negotiated "h3": QUIC/TLS 1.3 aborts the handshake outright on an
        # ALPN mismatch rather than silently completing with no agreed
        # protocol, so no separate post-handshake protocol check is needed
        # here (unlike a real ALPN list with multiple candidates).
        last_exc: Optional[Exception] = None
        for ip in ips:
            configuration = QuicConfiguration(
                alpn_protocols=H3_ALPN,
                is_client=True,
                server_name=self.host,
                idle_timeout=KEEPALIVE_PERIOD * 3,
            )
            configuration.max_datagram_size = INITIAL_MAX_DATAGRAM_SIZE

            connect_cm = quic_connect(
                ip,
                self.port,
                configuration=configuration,
                create_protocol=create_protocol,
            )
            try:
                protocol = await asyncio.wait_for(connect_cm.__aenter__(), timeout=per_attempt_timeout)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                logger.debug("HTTP/3 dial to %s (resolved from %s) failed: %r", ip, self.host, exc)
                continue
            self._protocol = protocol
            self._connect_cm = connect_cm
            break
        else:
            # Some failure modes here (asyncio.TimeoutError from a
            # per-address handshake timeout, or a bare ConnectionError
            # raised with no message by aioquic/asyncio) stringify to an
            # empty string, which would otherwise make this error look
            # truncated/blank. Fall back to repr() so the exception type
            # is always visible for diagnosis.
            detail = "unknown error"
            if last_exc is not None:
                detail = str(last_exc) or repr(last_exc)
            raise ProxyError(
                f"upstream {self.host}:{self.port} QUIC handshake failed for all "
                f"{len(ips)} resolved address(es); last error: {detail}"
            )

        self._http = self._protocol.http
        self._last_activity = time.monotonic()
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

    def update_token(self, token: str) -> None:
        """Update the bearer token used for streams opened from now on."""
        self.token = token

    async def _keepalive_loop(self) -> None:
        """Best-effort silently-dead-connection detection. Unlike TCP,
        UDP/QUIC has no way to observe that a path went dark other than
        actively probing, so periodically ping the connection once it has
        been idle for KEEPALIVE_PERIOD and mark the session unhealthy (so
        SessionPool transparently reconnects) if it does not answer within
        PING_TIMEOUT. If the installed aioquic version has no active
        ping() API, this degrades to relying on the QUIC-level idle_timeout
        configured in connect() to eventually surface a dead connection."""
        try:
            while True:
                await asyncio.sleep(_KEEPALIVE_POLL_INTERVAL)
                if self._closed:
                    return
                if time.monotonic() - self._last_activity < KEEPALIVE_PERIOD:
                    continue
                ping = getattr(self._protocol, "ping", None)
                if ping is None:
                    return
                try:
                    await asyncio.wait_for(ping(), timeout=PING_TIMEOUT)
                    self._last_activity = time.monotonic()
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "upstream %s:%s did not ack keepalive ping within %ss; marking session unhealthy: %s",
                        self.host,
                        self.port,
                        PING_TIMEOUT,
                        exc,
                    )
                    self._mark_closed()
                    return
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.debug("upstream h3 session keepalive loop ended: %s", exc)

    def _mark_closed(self) -> None:
        """Mark this session closed so SessionPool treats it like any other
        dead session and transparently reconnects on next use."""
        self._closed = True
        for stream in list(self._streams.values()):
            stream._feed(None)

    def _handle_stream_reset(self, stream_id: int) -> None:
        stream = self._streams.pop(stream_id, None)
        if stream is not None:
            if not stream.established.is_set():
                stream.failed = ProxyError("upstream reset the stream before it was established")
                stream.established.set()
            stream._feed(None)

    def _handle_headers(self, event) -> None:
        self._last_activity = time.monotonic()
        stream = self._streams.get(event.stream_id)
        if stream is None:
            return
        status = None
        for name, value in event.headers:
            if name == b":status":
                status = value.decode("ascii", errors="replace")
                break
        status_code: Optional[int] = None
        if status is not None:
            try:
                status_code = int(status)
            except ValueError:
                status_code = None
        # Mirrors the original Go client's CONNECT response check
        # (StatusCode < 200 || StatusCode > 299): accept any 2xx status,
        # not just the literal 200.
        if status_code is not None and 200 <= status_code <= 299:
            stream.established.set()
        else:
            stream.failed = ProxyError(f"upstream refused CONNECT with status {status}")
            stream.established.set()
            stream._feed(None)
        if event.stream_ended:
            self._streams.pop(event.stream_id, None)
            stream._feed(None)

    def _handle_data(self, event) -> None:
        self._last_activity = time.monotonic()
        stream = self._streams.get(event.stream_id)
        if stream is None:
            return
        if event.data:
            stream._feed(event.data)
        if event.stream_ended:
            self._streams.pop(event.stream_id, None)
            stream._feed(None)

    async def open_stream(self, target_host: str, target_port: int) -> H3Stream:
        if self._http is None or self._protocol is None:
            raise ProxyError(f"upstream {self.host}:{self.port} HTTP/3 session is not connected")
        async with self._write_lock:
            stream_id = self._protocol._quic.get_next_available_stream_id()
            headers = [
                (b":method", b"CONNECT"),
                (b":authority", _format_authority(target_host, target_port).encode("utf-8")),
                (b"proxy-authorization", f"Bearer {self.token}".encode("utf-8")),
            ]
            stream = H3Stream(self, stream_id)
            self._streams[stream_id] = stream
            self._http.send_headers(stream_id=stream_id, headers=headers, end_stream=False)
            self._protocol.transmit()
        await stream.wait_established()
        return stream

    async def _send_data(self, stream_id: int, data: bytes) -> None:
        async with self._write_lock:
            if self._http is None or self._protocol is None or stream_id not in self._streams:
                return
            try:
                self._http.send_data(stream_id=stream_id, data=data, end_stream=False)
                self._protocol.transmit()
            except Exception as exc:  # noqa: BLE001
                logger.debug("sending data on closed h3 stream %s failed: %s", stream_id, exc)

    async def _end_stream(self, stream_id: int) -> None:
        async with self._write_lock:
            if self._http is None or self._protocol is None:
                return
            try:
                self._http.send_data(stream_id=stream_id, data=b"", end_stream=True)
                self._protocol.transmit()
            except Exception as exc:  # noqa: BLE001
                logger.debug("ending closed h3 stream %s failed: %s", stream_id, exc)

    async def close(self) -> None:
        self._closed = True
        if self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        for stream in list(self._streams.values()):
            stream._feed(None)
        if self._connect_cm is not None:
            try:
                await self._connect_cm.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            self._connect_cm = None

    @property
    def is_closed(self) -> bool:
        return self._closed
