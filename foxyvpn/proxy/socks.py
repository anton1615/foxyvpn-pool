"""A minimal RFC 1928 SOCKS5 server, CONNECT-only, with no authentication
(intended to be bound to localhost only), tunneling accepted connections
through a :class:`~foxyvpn.proxy.pool.SessionPool`.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
from typing import Optional, Tuple

from .pool import SessionPool
from .relay import relay_bidirectional

logger = logging.getLogger("foxyvpn.proxy.socks")

SOCKS_VERSION = 0x05
_CMD_CONNECT = 0x01
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04
_AUTH_NO_AUTH = 0x00
_AUTH_NO_ACCEPTABLE = 0xFF
_REP_SUCCEEDED = 0x00
_REP_GENERAL_FAILURE = 0x01
_REP_COMMAND_NOT_SUPPORTED = 0x07
_REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class Socks5Server:
    def __init__(self, host: str, port: int, pool: SessionPool, *, max_connections: int = 256, idle_timeout: float = 0.0):
        self.host = host
        self.port = port
        self.pool = pool
        self.idle_timeout = idle_timeout
        # Mirrors the original Go client's --max-conns flag, which is
        # documented as "0 disables the limit". asyncio.Semaphore(0) would
        # instead permanently block every connection, so only allocate a
        # semaphore when a positive limit is requested.
        self._semaphore = asyncio.Semaphore(max_connections) if max_connections > 0 else None
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else None
        if self._semaphore is not None:
            await self._semaphore.acquire()
        try:
            await self._negotiate_and_serve(reader, writer, client_ip)
        except (ConnectionError, asyncio.IncompleteReadError) as exc:
            logger.debug("socks client %s disconnected: %s", peer, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("socks client %s error: %s", peer, exc)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            if self._semaphore is not None:
                self._semaphore.release()

    async def _negotiate_and_serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_ip: Optional[str]) -> None:
        version, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        if version != SOCKS_VERSION:
            raise ConnectionError(f"unsupported SOCKS version {version}")
        offered_methods = await reader.readexactly(nmethods)
        method = _AUTH_NO_AUTH if _AUTH_NO_AUTH in offered_methods else _AUTH_NO_ACCEPTABLE
        writer.write(struct.pack("!BB", SOCKS_VERSION, method))
        await writer.drain()
        if method == _AUTH_NO_ACCEPTABLE:
            raise ConnectionError("client did not offer a supported SOCKS auth method")

        header = await reader.readexactly(4)
        version, cmd, _rsv, atyp = struct.unpack("!BBBB", header)
        if version != SOCKS_VERSION:
            await self._reply(writer, _REP_GENERAL_FAILURE)
            raise ConnectionError(f"unsupported SOCKS version {version}")
        if cmd != _CMD_CONNECT:
            await self._reply(writer, _REP_COMMAND_NOT_SUPPORTED)
            return

        if atyp == _ATYP_IPV4:
            addr_bytes = await reader.readexactly(4)
            target_host = str(ipaddress.IPv4Address(addr_bytes))
        elif atyp == _ATYP_DOMAIN:
            (length,) = struct.unpack("!B", await reader.readexactly(1))
            # The original Go proxy treats the domain bytes as a raw string
            # with no IDNA processing; match that instead of using the
            # "idna" codec, which only supports errors="strict" and raises
            # UnicodeError for any other error-handling mode (crashing this
            # handler before a SOCKS5 reply could be sent).
            target_host = (await reader.readexactly(length)).decode("utf-8", errors="replace")
        elif atyp == _ATYP_IPV6:
            addr_bytes = await reader.readexactly(16)
            target_host = str(ipaddress.IPv6Address(addr_bytes))
        else:
            await self._reply(writer, _REP_ADDRESS_TYPE_NOT_SUPPORTED)
            return

        (target_port,) = struct.unpack("!H", await reader.readexactly(2))

        try:
            upstream = await self.pool.open_stream(target_host, target_port, affinity_key=client_ip)
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to open upstream tunnel to %s:%s: %s", target_host, target_port, exc)
            await self._reply(writer, _REP_GENERAL_FAILURE)
            return

        await self._reply(writer, _REP_SUCCEEDED, writer.get_extra_info("sockname"))
        await relay_bidirectional(reader, writer, upstream, self.idle_timeout)

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, rep: int, local_addr: Optional[Tuple] = None) -> None:
        host = "0.0.0.0"
        port = 0
        if local_addr:
            host, port = local_addr[0], local_addr[1]

        atyp = _ATYP_IPV4
        addr_bytes = bytes(4)
        try:
            ip_obj = ipaddress.ip_address(host)
        except ValueError:
            ip_obj = None
        if isinstance(ip_obj, ipaddress.IPv6Address):
            atyp = _ATYP_IPV6
            addr_bytes = ip_obj.packed
        elif isinstance(ip_obj, ipaddress.IPv4Address):
            atyp = _ATYP_IPV4
            addr_bytes = ip_obj.packed

        writer.write(struct.pack("!BBBB", SOCKS_VERSION, rep, 0x00, atyp) + addr_bytes + struct.pack("!H", port))
        await writer.drain()
