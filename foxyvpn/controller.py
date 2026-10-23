"""Top-level orchestrator: owns the current Guardian proxy pass, the upstream
session pool, background renewal/quota-monitor loops, and the optional JSON
status file.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from . import auth as auth_module
from . import guardian
from .exceptions import QuotaExceededError, TokenInvalidError
from .proxy.h3_session import H3ProxySession
from .proxy.pool import ProxySession, SessionPool
from .proxy.session import H2ProxySession
from .proxystate import ProxyCandidate

logger = logging.getLogger("foxyvpn.controller")

PROXY_PASS_RENEW_LEAD_SECONDS = 120
PROXY_PASS_RETRY_DELAY_SECONDS = 30
PROXY_PASS_RENEW_TIMEOUT_SECONDS = 120
QUOTA_CHECK_INTERVAL_SECONDS = 15 * 60


@dataclass
class ControllerConfig:
    guardian_endpoint: str
    candidate: ProxyCandidate
    upstream_conns: int
    handshake_timeout: float
    status_file: Optional[str] = None
    # Mirrors the original Go client's -h3 flag: use HTTP/3 (QUIC/UDP)
    # instead of HTTP/2 (TCP) for the upstream tunnel transport.
    use_http3: bool = False


class ProxyController:
    """Owns the Guardian proxy pass lifecycle and the upstream session pool."""

    def __init__(self, config: ControllerConfig, auth: auth_module.RuntimeAuth):
        self.config = config
        self.auth = auth
        self.proxy_pass: Optional[guardian.ProxyPassInfo] = None
        self.pool: Optional[SessionPool] = None
        self.accepting = False
        self._reason = "starting"
        self._tasks: List[asyncio.Task] = []
        self._stopped = asyncio.Event()

    async def start(self) -> SessionPool:
        await self._acquire_initial_pass()

        logger.info("upstream transport=%s", "http3" if self.config.use_http3 else "http2")

        async def factory() -> ProxySession:
            session: ProxySession
            if self.config.use_http3:
                session = H3ProxySession(
                    self.config.candidate.host,
                    self.config.candidate.port,
                    self.proxy_pass.raw_token,
                )
            else:
                session = H2ProxySession(
                    self.config.candidate.host,
                    self.config.candidate.port,
                    self.proxy_pass.raw_token,
                )
            await session.connect(timeout=self.config.handshake_timeout)
            return session

        self.pool = SessionPool(self.config.upstream_conns, factory)
        await self.pool.start()
        self.accepting = True
        self._reason = "ok"
        await self._write_status_file()

        self._tasks.append(asyncio.create_task(self._renewal_loop()))
        self._tasks.append(asyncio.create_task(self._quota_monitor_loop()))
        return self.pool

    async def _acquire_usable_pass(self) -> guardian.ProxyPassInfo:
        """Fetch a Guardian proxy pass that is actually usable (not
        quota-exhausted), mirroring the original Go client's
        acquireUsablePass/acquireInitialPass:

        - A token-invalid rejection (401/403) is recovered from by
          activating the Guardian entitlement and retrying once.
        - If the current session token is still unusable afterwards
          (invalid or quota-exhausted) and a session token pool is
          configured, rotation continues through the pool (skipping any
          token that itself gets rejected) until a usable pass is found.
        - Raises the original error once there is no pool to rotate
          through, or the pool is exhausted.
        """
        while True:
            try:
                return guardian.fetch_proxy_pass(self.config.guardian_endpoint, self.auth.access_token)
            except TokenInvalidError as exc:
                logger.info("access token invalid, activating guardian entitlement and retrying")
                try:
                    guardian.activate_guardian(self.config.guardian_endpoint, self.auth.access_token)
                    return guardian.fetch_proxy_pass(self.config.guardian_endpoint, self.auth.access_token)
                except TokenInvalidError:
                    pass  # still rejected after activation; fall through to pool rotation
                rotated = auth_module.rotate_session_token(self.auth)
                if rotated is None:
                    raise exc
                logger.info("session token rejected by guardian, rotated to next session token")
                self.auth = rotated
            except QuotaExceededError as exc:
                rotated = auth_module.rotate_session_token(self.auth)
                if rotated is None:
                    raise exc
                logger.info("quota exceeded, rotated to next session token")
                self.auth = rotated

    async def _acquire_initial_pass(self) -> None:
        self.proxy_pass = await self._acquire_usable_pass()

    async def _renewal_loop(self) -> None:
        try:
            while True:
                expires_at = self.proxy_pass.expires_at()
                now = datetime.now(timezone.utc)
                delay = (expires_at - now).total_seconds() - PROXY_PASS_RENEW_LEAD_SECONDS
                if delay > 0:
                    await asyncio.sleep(delay)

                renewed = False
                deadline = time.monotonic() + PROXY_PASS_RENEW_TIMEOUT_SECONDS
                while time.monotonic() < deadline:
                    try:
                        self.proxy_pass = await self._acquire_usable_pass()
                        if self.pool:
                            self.pool.update_token(self.proxy_pass.raw_token)
                        renewed = True
                        self.accepting = True
                        self._reason = "ok"
                        break
                    except (QuotaExceededError, TokenInvalidError) as exc:
                        logger.warning("proxy pass renewal blocked, no usable session token available: %s", exc)
                        self.accepting = False
                        self._reason = f"renewal failing: {exc}"
                        await self._write_status_file()
                        await asyncio.sleep(PROXY_PASS_RETRY_DELAY_SECONDS)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("proxy pass renewal failed, retrying: %s", exc)
                        self._reason = f"renewal failing: {exc}"
                        await self._write_status_file()
                        await asyncio.sleep(PROXY_PASS_RETRY_DELAY_SECONDS)
                if not renewed:
                    logger.error("proxy pass renewal blocked for %ss, exiting for supervisor restart", PROXY_PASS_RENEW_TIMEOUT_SECONDS)
                    os._exit(1)
                await self._write_status_file()
        except asyncio.CancelledError:
            pass

    async def _quota_monitor_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(QUOTA_CHECK_INTERVAL_SECONDS)
                try:
                    entitlement = guardian.fetch_user_info(self.config.guardian_endpoint, self.auth.access_token)
                    if entitlement.limited_bandwidth:
                        rotated = auth_module.rotate_session_token(self.auth)
                        if rotated is not None:
                            logger.info("quota exhausted, rotated session token")
                            self.auth = rotated
                            self.proxy_pass = await self._acquire_usable_pass()
                            if self.pool:
                                self.pool.update_token(self.proxy_pass.raw_token)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("quota monitor check failed (non-fatal): %s", exc)
        except asyncio.CancelledError:
            pass

    async def _write_status_file(self) -> None:
        if not self.config.status_file:
            return
        payload = {
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "pid": os.getpid(),
            "proxy_pass_expires_at": self.proxy_pass.expires_at().isoformat() if self.proxy_pass else None,
            "seconds_until_expiry": (
                (self.proxy_pass.expires_at() - datetime.now(timezone.utc)).total_seconds() if self.proxy_pass else None
            ),
            "accepting": self.accepting,
            "reason": self._reason,
        }
        path = Path(self.config.status_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(tmp_path, path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self.pool:
            await self.pool.close()
        self._stopped.set()
