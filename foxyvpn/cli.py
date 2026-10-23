"""Command-line entry point. Mirrors every flag of the original Go CLI."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import List, Optional, Tuple

from . import auth as auth_module
from . import guardian, serverlist
from .buildinfo import version_string
from .controller import ControllerConfig, ProxyController
from .exitcheck import DEFAULT_EXIT_CHECK_TIMEOUT, DEFAULT_EXIT_CHECK_URL, verify_exit_country
from .http_client import set_control_plane_proxy, set_control_plane_timeout
from .logging_config import configure_logger
from .proxy.session import DEFAULT_HANDSHAKE_TIMEOUT
from .proxy.socks import Socks5Server
from .proxystate import ProxyStateStore, resolve_proxy

logger = logging.getLogger("foxyvpn.cli")

GUARDIAN_ENDPOINT_DEFAULT = guardian.GUARDIAN_ENDPOINT_DEFAULT
DEFAULT_LISTEN = "127.0.0.1:1080"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="foxyvpn", description="Local SOCKS5 proxy client for the Mozilla VPN / Firefox VPN proxy service.")
    parser.add_argument("--api-proxy", default=None, help="Proxy URL (http/https/socks5/socks5h) used only for FxA/Guardian/Remote-Settings control-plane calls.")
    parser.add_argument("--guardian", default=GUARDIAN_ENDPOINT_DEFAULT, help="Guardian (Mozilla VPN control plane) endpoint.")
    parser.add_argument("--listen", default=DEFAULT_LISTEN, help="Local SOCKS5 listen address (host:port, or [ipv6]:port).")
    parser.add_argument("--login", action="store_true", help="Force a fresh interactive login, ignoring cached tokens.")
    parser.add_argument("--email", default=None, help="Firefox Accounts email (prompted if omitted and needed).")
    parser.add_argument("--session-token", default=None, help="An FxA session token, or a path to a file with one token per line for automatic rotation.")
    parser.add_argument("--print-info", action="store_true", help="Print account entitlement info and exit.")
    parser.add_argument("--list-servers", action="store_true", help="Print the available VPN server list and exit.")
    parser.add_argument("--proxy", default=None, help="Exact upstream proxy host:port (mutually exclusive with --country).")
    parser.add_argument("--country", default=None, help="Two-letter country code to select an upstream proxy from. Defaults to the recommended \"REC\" server (auto-selected by Firefox) when omitted.")
    parser.add_argument("--timeout", type=float, default=20.0, help="Default request timeout in seconds for FxA/Guardian/Remote-Settings control-plane calls.")
    parser.add_argument("--handshake-timeout", type=float, default=DEFAULT_HANDSHAKE_TIMEOUT, help="Upstream TLS/HTTP2/QUIC handshake timeout in seconds.")
    parser.add_argument("--http3", action="store_true", help="Use HTTP/3 (QUIC over UDP) instead of HTTP/2 (TCP) for the upstream tunnel transport.")
    parser.add_argument("--idle-timeout", type=float, default=0.0, help="Idle connection timeout in seconds (0 disables it).")
    parser.add_argument("--max-conns", type=int, default=256, help="Maximum concurrent client connections; 0 disables the limit.")
    parser.add_argument("--upstream-conns", type=int, default=1, help="Number of upstream sessions to pool (>1 enables client-IP affinity routing).")
    parser.add_argument("--status-file", default=None, help="Path to write a JSON status file describing proxy-pass health.")
    parser.add_argument("--proxy-state-file", default=None, help="Path to persist the selected upstream proxy across restarts.")
    parser.add_argument("--verify-exit", dest="verify_exit", action="store_true", default=True, help="Verify the exit country after connecting (default: enabled).")
    parser.add_argument("--no-verify-exit", dest="verify_exit", action="store_false", help="Disable exit-country verification.")
    parser.add_argument("--exit-check-url", default=DEFAULT_EXIT_CHECK_URL, help="URL used to verify the exit IP/country.")
    parser.add_argument("--exit-check-timeout", type=float, default=DEFAULT_EXIT_CHECK_TIMEOUT, help="Timeout in seconds for the exit-check request.")
    parser.add_argument("--verbose", action="store_true", help="Shorthand for --log-level debug.")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warn", "error"], help="Log level.")
    parser.add_argument("--log-format", default="text", choices=["text", "json"], help="Log output format.")
    parser.add_argument("--version", action="store_true", help="Print version information and exit.")
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    if args.proxy and args.country:
        raise SystemExit("--proxy and --country are mutually exclusive")
    if args.upstream_conns < 1:
        raise SystemExit("--upstream-conns must be >= 1")
    if args.max_conns < 0:
        raise SystemExit("--max-conns must be >= 0 (0 disables the limit)")
    if args.idle_timeout < 0:
        raise SystemExit("--idle-timeout must not be negative")
    if args.verify_exit and args.exit_check_timeout <= 0:
        raise SystemExit("--exit-check-timeout must be positive when exit verification is enabled")


def _parse_listen(listen: str) -> Tuple[Optional[str], int]:
    host: Optional[str]
    if listen.startswith("["):
        end = listen.find("]")
        if end == -1 or not listen[end + 1 :].startswith(":"):
            raise SystemExit(f"invalid --listen value {listen!r}, expected host:port or [ipv6]:port")
        host = listen[1:end]
        port_str = listen[end + 2 :]
    else:
        host, _, port_str = listen.rpartition(":")
        if not host:
            # An empty host (e.g. ":1080") means "listen on all interfaces",
            # matching Go's net.Listen("tcp", listen) passthrough behavior.
            host = None
    try:
        port = int(port_str)
    except ValueError:
        raise SystemExit(f"invalid --listen value {listen!r}, expected host:port")
    return host, port


# Hosts that mean "listen on all interfaces" and are therefore not
# themselves dialable as a client-facing address.
_BIND_ALL_HOSTS = {"0.0.0.0", "::", "*"}


def _format_socks_authority(host: Optional[str], port: int) -> str:
    """Build a socks5:// authority for the exit-check probe. A bind-all
    --listen (host is None, e.g. \":1080\", or explicitly \"0.0.0.0\"/\"::\"/\"*\")
    is not itself dialable, so fall back to the loopback address the server
    also accepts connections on. IPv6 literals must be bracketed, or the
    URL is ambiguous/invalid since the address itself contains colons (same
    issue the upstream HTTP/2 :authority pseudo-header had)."""
    resolved_host = host if (host is not None and host not in _BIND_ALL_HOSTS) else "127.0.0.1"
    if ":" in resolved_host and not resolved_host.startswith("["):
        resolved_host = f"[{resolved_host}]"
    return f"{resolved_host}:{port}"


def _install_benign_future_exception_filter(loop: asyncio.AbstractEventLoop) -> None:
    """Downgrade a specific, benign asyncio warning to a debug log line
    instead of the default noisy stderr dump.

    An HTTP/3 (QUIC) dial can try several resolved addresses in turn
    (see proxy.h3_session.H3ProxySession.connect), abandoning any attempt
    that does not finish within its per-address handshake timeout. The
    underlying aioquic/asyncio machinery can then later receive a delayed
    notification for that already-abandoned attempt (for example a
    connection-refused signal arriving after this client moved on to the
    next address, or gave up entirely) and set it as the result of an
    internal Future that nothing awaits anymore. asyncio's default
    exception handler reports these as "Future exception was never
    retrieved"; the attempt already failed and was already accounted for
    via the ProxyError this client raises, so this is diagnostic noise
    about a already-handled failure, not a second, separate one. Only a
    bare ConnectionError with no message attached to a Future is
    downgraded here, so unrelated, genuinely informative exceptions are
    still surfaced through the normal handler.
    """
    default_handler = loop.get_exception_handler()

    def handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
        exc = context.get("exception")
        if isinstance(exc, ConnectionError) and not str(exc) and "future" in context:
            logger.debug("suppressed benign abandoned-dial future exception: %r", exc)
            return
        if default_handler is not None:
            default_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(handler)


async def _async_main(args: argparse.Namespace) -> int:
    _install_benign_future_exception_filter(asyncio.get_running_loop())
    set_control_plane_timeout(args.timeout)
    if args.api_proxy:
        set_control_plane_proxy(args.api_proxy)

    if args.list_servers:
        countries = serverlist.fetch_server_list()
        serverlist.print_server_list(countries)
        return 0

    runtime_auth = auth_module.obtain_auth(
        email=args.email,
        force_login=args.login,
        session_token_or_path=args.session_token,
    )

    if args.print_info:
        entitlement = guardian.fetch_user_info(args.guardian, runtime_auth.access_token)
        print(f"subscribed={entitlement.subscribed} uid={entitlement.uid} maxBytes={entitlement.max_bytes} limitedBandwidth={entitlement.limited_bandwidth}")
        return 0

    countries = serverlist.fetch_server_list() if not args.proxy else []
    state_store = ProxyStateStore(args.proxy_state_file) if args.proxy_state_file else None
    candidate, selected_from_state = resolve_proxy(countries, explicit_proxy=args.proxy, country_code=args.country, state_store=state_store)
    logger.info("selected upstream proxy %s (%s)", candidate.authority, candidate.country_code or "explicit")

    config = ControllerConfig(
        guardian_endpoint=args.guardian,
        candidate=candidate,
        upstream_conns=args.upstream_conns,
        handshake_timeout=args.handshake_timeout,
        status_file=args.status_file,
        use_http3=args.http3,
    )
    controller = ProxyController(config, runtime_auth)
    try:
        pool = await controller.start()
    except Exception:
        if selected_from_state and state_store is not None:
            failures, cleared = state_store.record_failure()
            if cleared:
                logger.warning(
                    "persisted proxy failed repeatedly; selection cleared for next restart (proxy=%s, failures=%s)",
                    candidate.authority,
                    failures,
                )
            else:
                logger.warning(
                    "persisted proxy failed to establish; retaining selection until failure threshold (proxy=%s, failures=%s, threshold=3)",
                    candidate.authority,
                    failures,
                )
        raise

    host, port = _parse_listen(args.listen)
    server = Socks5Server(host, port, pool, max_connections=args.max_conns, idle_timeout=args.idle_timeout)
    await server.start()
    logger.info("SOCKS5 proxy listening on %s:%s", host, port)

    if args.verify_exit:
        local_proxy_url = f"socks5://{_format_socks_authority(host, port)}"
        asyncio.create_task(
            verify_exit_country(
                local_proxy_url,
                candidate.country_code,
                check_url=args.exit_check_url,
                timeout=args.exit_check_timeout,
            )
        )

    try:
        await server.serve_forever()
    finally:
        await controller.stop()
        await server.close()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(version_string())
        return 0

    _validate_args(args)
    configure_logger("debug" if args.verbose else args.log_level, args.log_format)

    try:
        return asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        return 130
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("fatal: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
