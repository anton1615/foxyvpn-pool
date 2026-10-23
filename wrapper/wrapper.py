#!/usr/bin/env python3
"""foxyvpn pool wrapper.

Hands out one dedicated Mozilla VPN exit per client.  A client asks for a
node with a name of its own choosing, the wrapper starts a foxyvpn instance
for it, and the client talks to a stable local port for as long as it wants.

Design notes
------------
The wrapper never changes foxyvpn: it only starts the binary and talks to
Guardian for the quota bookkeeping.

Each client gets two ports:

  public   20000+  the tailnet address the client connects to; stable for
                   the life of the client, so a mihomo subscription that
                   points at it never goes stale.
  internal 30000+  foxyvpn's own SOCKS5 listener, bound to 127.0.0.1.

A small TCP relay sits in front of the internal port.  It speaks no
protocol at all -- it just moves bytes -- because SOCKS5 carries one tunnel
per TCP connection, so each client connection is independent of every other
one.  That is what makes a swap invisible: a replacement foxyvpn is started
and warmed up, the relay is pointed at it, and the previous instance is
retired only once the connections it already carries have drained.

Account supply
--------------
`pool.txt` holds the pre-provisioned FxA session tokens, one per line; the
optional `auth/*.json` files hold whatever metadata you keep about them (a
`session_token` plus any fields you find useful -- `uid`, `email`, `quota`;
everything else in them is ignored). Both are read again on every poll
cycle, so tokens added to the pool later are picked up automatically.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POOL = os.path.join(HERE, "pool.txt")
DEFAULT_AUTH_DIR = os.path.join(HERE, "auth")
DEFAULT_POOL_DIR = os.path.join(HERE, "pools")
DEFAULT_DB = os.path.join(HERE, "db.sqlite")
FOXYVPN_BIN = os.path.join(os.path.dirname(HERE), ".venv", "bin", "foxyvpn")

PUBLIC_PORT_BASE = 20000
INTERNAL_PORT_BASE = 30000
TOKENS_PER_INSTANCE = 5
ROTATE_QUOTA_FRACTION = 0.05      # rotate once even the best token is under 5%
DRAIN_TIMEOUT = 120.0             # seconds to wait for the old backend to drain
PROBE_CONCURRENCY = 6
BACKEND_READY_TIMEOUT = 30.0


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def safe_name(uid: str) -> str:
    """A filesystem-safe, collision-free name for a client identifier."""
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", uid)[:40] or "client"
    return f"{stem}-{hashlib.sha1(uid.encode()).hexdigest()[:8]}"


# ── state ───────────────────────────────────────────────────────────────────

@dataclass
class Account:
    token: str
    email: str = ""
    uid: str = ""
    quota_max: int = 0
    quota_left: int = 0
    quota_reset: str = ""
    state: str = "free"          # free | assigned | dead
    assigned_to: str = ""


@dataclass
class Instance:
    uid: str
    public_port: int
    internal_port: int
    country: str = ""
    proxy: str = ""
    tokens: list[str] = field(default_factory=list)
    created_at: float = 0.0
    rotated_at: float = 0.0
    backend: Any = None          # Backend
    front: Any = None            # Front


class Store:
    """SQLite state.  Only ever touched from the event loop thread."""

    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                token       TEXT PRIMARY KEY,
                email       TEXT NOT NULL DEFAULT '',
                uid         TEXT NOT NULL DEFAULT '',
                quota_max   INTEGER NOT NULL DEFAULT 0,
                quota_left  INTEGER NOT NULL DEFAULT 0,
                quota_reset TEXT NOT NULL DEFAULT '',
                state       TEXT NOT NULL DEFAULT 'free',
                assigned_to TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS instances (
                uid           TEXT PRIMARY KEY,
                public_port   INTEGER NOT NULL UNIQUE,
                internal_port INTEGER NOT NULL,
                country       TEXT NOT NULL DEFAULT '',
                proxy         TEXT NOT NULL DEFAULT '',
                tokens        TEXT NOT NULL DEFAULT '[]',
                created_at    REAL NOT NULL DEFAULT 0,
                rotated_at    REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        self.db.commit()

    def next_port(self, key: str, base: int) -> int:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        nxt = int(row["value"]) if row else base
        self.db.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(nxt + 1)))
        self.db.commit()
        return nxt

    def accounts(self) -> list[Account]:
        rows = self.db.execute("SELECT * FROM accounts").fetchall()
        return [Account(token=r["token"], email=r["email"], uid=r["uid"],
                        quota_max=r["quota_max"], quota_left=r["quota_left"],
                        quota_reset=r["quota_reset"], state=r["state"],
                        assigned_to=r["assigned_to"]) for r in rows]

    def upsert_account(self, account: Account) -> None:
        self.db.execute(
            "INSERT INTO accounts(token,email,uid,quota_max,quota_left,quota_reset,state,assigned_to)"
            " VALUES(?,?,?,?,?,?,?,?)"
            " ON CONFLICT(token) DO UPDATE SET email=excluded.email, uid=excluded.uid",
            (account.token, account.email, account.uid, account.quota_max,
             account.quota_left, account.quota_reset, account.state, account.assigned_to))
        self.db.commit()

    def set_account_state(self, token: str, state: str, assigned_to: str = "") -> None:
        self.db.execute("UPDATE accounts SET state=?, assigned_to=? WHERE token=?",
                        (state, assigned_to, token))
        self.db.commit()

    def set_account_quota(self, token: str, quota_max: int, quota_left: int,
                          quota_reset: str) -> None:
        self.db.execute(
            "UPDATE accounts SET quota_max=?, quota_left=?, quota_reset=?,"
            " state=CASE WHEN ?<=0 THEN 'dead' ELSE state END WHERE token=?",
            (quota_max, quota_left, quota_reset, quota_left, token))
        self.db.commit()

    def instances(self) -> list[Instance]:
        rows = self.db.execute("SELECT * FROM instances").fetchall()
        return [Instance(uid=r["uid"], public_port=r["public_port"],
                         internal_port=r["internal_port"], country=r["country"],
                         proxy=r["proxy"], tokens=json.loads(r["tokens"]),
                         created_at=r["created_at"], rotated_at=r["rotated_at"])
                for r in rows]

    def instance(self, uid: str) -> Instance | None:
        for inst in self.instances():
            if inst.uid == uid:
                return inst
        return None

    def put_instance(self, inst: Instance) -> None:
        self.db.execute(
            "INSERT INTO instances(uid,public_port,internal_port,country,proxy,tokens,created_at,rotated_at)"
            " VALUES(?,?,?,?,?,?,?,?)"
            " ON CONFLICT(uid) DO UPDATE SET public_port=excluded.public_port,"
            " internal_port=excluded.internal_port, country=excluded.country,"
            " proxy=excluded.proxy, tokens=excluded.tokens,"
            " created_at=excluded.created_at, rotated_at=excluded.rotated_at",
            (inst.uid, inst.public_port, inst.internal_port, inst.country, inst.proxy,
             json.dumps(inst.tokens), inst.created_at, inst.rotated_at))
        self.db.commit()

    def delete_instance(self, uid: str) -> None:
        self.db.execute("DELETE FROM instances WHERE uid=?", (uid,))
        self.db.commit()


# ── TCP relay ───────────────────────────────────────────────────────────────

class Front:
    """A stable public port that relays to the current backend.

    It moves bytes and knows nothing about SOCKS5.  Each accepted
    connection is bound to the backend that was current when it arrived, so
    retiring a backend does not disturb the connections it already carries.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.backend: tuple[str, int] | None = None
        self._server: asyncio.AbstractServer | None = None
        self._relays: dict[int, tuple[str, int]] = {}
        self._next_id = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        log(f"front listening on {self.host}:{self.port}")

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    def point_at(self, backend: tuple[str, int]) -> None:
        self.backend = backend

    def relay_count(self, backend: tuple[str, int]) -> int:
        return sum(1 for v in self._relays.values() if v == backend)

    def total_relays(self) -> int:
        return len(self._relays)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        backend = self.backend
        if backend is None:
            writer.close()
            return
        br = bw = None
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            try:
                br, bw = await asyncio.wait_for(
                    asyncio.open_connection(*backend), timeout=3.0)
                break
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.3)
        if br is None or bw is None:
            writer.close()
            return
        self._next_id += 1
        relay_id = self._next_id
        self._relays[relay_id] = backend
        try:
            await asyncio.gather(self._pipe(reader, bw), self._pipe(br, writer),
                                 return_exceptions=True)
        finally:
            self._relays.pop(relay_id, None)
            for w in (writer, bw):
                with contextlib.suppress(Exception):
                    w.close()

    @staticmethod
    async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()


# ── foxyvpn backend ─────────────────────────────────────────────────────────

class Backend:
    """One foxyvpn process serving one client."""

    def __init__(self, proc: subprocess.Popen, port: int, tokens: list[str]):
        self.proc = proc
        self.port = port
        self.tokens = tokens
        self.started_at = time.time()

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self, timeout: float = 10.0) -> None:
        if not self.alive():
            return
        with contextlib.suppress(Exception):
            self.proc.terminate()
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(Exception):
                self.proc.kill()
                self.proc.wait(timeout=5)


# ── wrapper ─────────────────────────────────────────────────────────────────

class Wrapper:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.store = Store(args.db)
        self.instances: dict[str, Instance] = {}
        self.loop: asyncio.AbstractEventLoop | None = None
        self._access_tokens: dict[str, tuple[str, float]] = {}
        self._quota_lock = asyncio.Lock()
        self._rotate_lock = asyncio.Lock()

    # -- account supply ---------------------------------------------------

    def read_pool(self) -> list[str]:
        try:
            with open(self.args.pool, encoding="utf-8") as fh:
                return [line.strip() for line in fh
                        if line.strip() and not line.startswith("#")]
        except OSError:
            return []

    def read_metadata(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        try:
            names = os.listdir(self.args.auth_dir)
        except OSError:
            return out
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.args.auth_dir, name), encoding="utf-8") as fh:
                    rec = json.load(fh)
            except (OSError, ValueError):
                continue
            token = (rec.get("session_token") or "").strip()
            if token:
                out[token] = rec
        return out

    def refresh_accounts(self) -> int:
        """Pick up tokens that appeared in the pool since the last scan."""
        known = {a.token for a in self.store.accounts()}
        metadata = self.read_metadata()
        added = 0
        for token in self.read_pool():
            if token in known:
                continue
            rec = metadata.get(token, {})
            quota = rec.get("quota") or {}
            self.store.upsert_account(Account(
                token=token, email=rec.get("email", ""), uid=rec.get("uid", ""),
                quota_max=int(quota.get("x-quota-limit") or 0),
                quota_left=int(quota.get("x-quota-remaining") or 0),
                quota_reset=quota.get("x-quota-reset", "")))
            added += 1
        if added:
            log(f"pool grew: {added} new account(s), {len(self.store.accounts())} total")
        return added

    # -- Guardian quota ----------------------------------------------------

    def _access_token(self, session_token: str) -> str:
        from foxyvpn import fxa

        cached = self._access_tokens.get(session_token)
        now = time.time()
        if cached and cached[1] > now + 60:
            return cached[0]
        resp = fxa.oauth_token(session_token)
        token = resp.access_token
        self._access_tokens[session_token] = (token, now + max(60, resp.expires_in))
        return token

    async def probe_account(self, account: Account) -> None:
        from foxyvpn import guardian

        access = ""
        for attempt in (1, 2):
            try:
                if not access:
                    access = await asyncio.to_thread(self._access_token, account.token)
                info = await asyncio.to_thread(guardian.fetch_proxy_pass,
                                               self.args.guardian, access)
            except guardian.TokenInvalidError:
                # The entitlement may have lapsed. Re-activate it and retry
                # once before writing the account off.
                if attempt == 1 and access:
                    with contextlib.suppress(Exception):
                        await asyncio.to_thread(guardian.activate_guardian,
                                                self.args.guardian, access)
                    continue
                self.store.set_account_state(account.token, "dead")
                log(f"  {account.email or account.token[:12]}: rejected by Guardian")
                return
            except Exception as exc:  # noqa: BLE001
                if attempt == 1:
                    await asyncio.sleep(1.0)
                    continue
                log(f"  {account.email or account.token[:12]}: quota probe failed: {exc}")
                return
            self.store.set_account_quota(
                account.token,
                int(info.quota_max or 0), int(info.quota_left or 0),
                info.quota_reset or "")
            return

    async def probe_quota(self) -> None:
        accounts = self.store.accounts()
        if not accounts:
            return
        semaphore = asyncio.Semaphore(PROBE_CONCURRENCY)

        async def one(account: Account) -> None:
            async with semaphore:
                await self.probe_account(account)

        await asyncio.gather(*(one(a) for a in accounts))

    # -- allocation --------------------------------------------------------

    def allocate_tokens(self, uid: str, count: int) -> list[str]:
        """Hand out the healthiest unassigned accounts.

        An account whose quota is still unknown is handed out too: the
        figures only become known after the first probe, and refusing to
        allocate before then would leave the pool unusable.
        """
        free = [a for a in self.store.accounts()
                if a.state == "free" and (a.quota_left > 0 or a.quota_max == 0)]
        free.sort(key=lambda a: (-a.quota_left, a.email))
        chosen = free[:count]
        for account in chosen:
            self.store.set_account_state(account.token, "assigned", uid)
        return [a.token for a in chosen]

    def release_tokens(self, tokens: list[str]) -> None:
        for token in tokens:
            account = next((a for a in self.store.accounts() if a.token == token), None)
            if account is None:
                continue
            if account.quota_left <= 0:
                self.store.set_account_state(token, "dead")
            else:
                self.store.set_account_state(token, "free")

    def pool_file(self, uid: str) -> str:
        os.makedirs(self.args.pool_dir, exist_ok=True)
        return os.path.join(self.args.pool_dir, safe_name(uid) + ".txt")

    def write_pool_file(self, uid: str, tokens: list[str]) -> str:
        path = self.pool_file(uid)
        with open(path, "w", encoding="utf-8") as fh:
            for token in tokens:
                fh.write(token + "\n")
        os.chmod(path, 0o600)
        return path

    # -- backends ----------------------------------------------------------

    def spawn_backend(self, inst: Instance, tokens: list[str],
                      internal_port: int) -> Backend:
        pool_path = self.write_pool_file(inst.uid, tokens)
        cmd = [self.args.foxyvpn,
               "--session-token", pool_path,
               "--listen", f"127.0.0.1:{internal_port}",
               "--status-file", os.path.join(self.args.pool_dir,
                                             safe_name(inst.uid) + ".status.json")]
        if inst.proxy:
            cmd += ["--proxy", inst.proxy]
        elif inst.country:
            cmd += ["--country", inst.country]
        log(f"starting foxyvpn for {inst.uid}: {' '.join(cmd[1:])}")
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        return Backend(proc, internal_port, tokens)

    async def wait_ready(self, port: int, timeout: float = BACKEND_READY_TIMEOUT) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port), timeout=1.0)
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return True
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.2)
        return False

    async def retire_backend(self, inst: Instance, backend: Backend | None) -> None:
        """Wait for the old backend's connections to drain, then stop it."""
        if backend is None:
            return
        deadline = time.monotonic() + DRAIN_TIMEOUT
        while time.monotonic() < deadline:
            if backend.proc.poll() is not None:
                break
            if inst.front is not None and inst.front.relay_count(("127.0.0.1", backend.port)) == 0:
                break
            await asyncio.sleep(1.0)
        backend.stop()

    async def swap_backend(self, inst: Instance, tokens: list[str],
                           internal_port: int) -> bool:
        """Start a replacement and move the relay over to it.

        The old instance keeps the connections it already carries; the relay
        only sends new ones to the replacement.
        """
        old = inst.backend
        backend = self.spawn_backend(inst, tokens, internal_port)
        if not await self.wait_ready(internal_port):
            log(f"  {inst.uid}: replacement failed to start, keeping the old instance")
            backend.stop()
            return False
        inst.backend = backend
        if inst.front is not None:
            inst.front.point_at(("127.0.0.1", internal_port))
        inst.tokens = tokens
        inst.internal_port = internal_port
        inst.rotated_at = time.time()
        self.store.put_instance(inst)
        asyncio.create_task(self.retire_backend(inst, old))
        return True

    # -- instance lifecycle -------------------------------------------------

    async def create_instance(self, uid: str, country: str = "",
                              proxy: str = "") -> Instance:
        inst = Instance(uid=uid,
                        public_port=self.store.next_port("public_port", PUBLIC_PORT_BASE),
                        internal_port=self.store.next_port("internal_port", INTERNAL_PORT_BASE),
                        country=country, proxy=proxy, created_at=time.time())
        tokens = self.allocate_tokens(uid, TOKENS_PER_INSTANCE)
        if len(tokens) < TOKENS_PER_INSTANCE:
            log(f"  {uid}: only {len(tokens)} free account(s) available")
        inst.tokens = tokens
        self.store.put_instance(inst)

        front = Front(self.args.bind_host, inst.public_port)
        await front.start()
        inst.front = front

        backend = self.spawn_backend(inst, tokens, inst.internal_port)
        inst.backend = backend
        if await self.wait_ready(inst.internal_port):
            front.point_at(("127.0.0.1", inst.internal_port))
            log(f"  {uid}: ready on {self.args.bind_host}:{inst.public_port} "
                f"({len(tokens)} accounts)")
        else:
            log(f"  {uid}: foxyvpn did not come up on port {inst.internal_port}")
        self.instances[uid] = inst
        return inst

    async def delete_instance(self, uid: str) -> bool:
        inst = self.instances.get(uid) or self.store.instance(uid)
        if inst is None:
            return False
        if inst.front is not None:
            await inst.front.close()
        if inst.backend is not None:
            inst.backend.stop()
        self.release_tokens(inst.tokens)
        self.store.delete_instance(uid)
        self.instances.pop(uid, None)
        with contextlib.suppress(OSError):
            os.remove(self.pool_file(uid))
        log(f"  {uid}: deleted, {len(inst.tokens)} account(s) released")
        return True

    async def rotate_upstream(self, uid: str, country: str = "",
                              proxy: str = "") -> bool:
        """Point a client at a different upstream without dropping it."""
        inst = self.instances.get(uid) or self.store.instance(uid)
        if inst is None:
            return False
        if proxy and country:
            raise ValueError("country and proxy are mutually exclusive")
        # Neither given means: fall back to the recommended (REC) server.
        inst.country = country
        inst.proxy = proxy
        internal = self.store.next_port("internal_port", INTERNAL_PORT_BASE)
        ok = await self.swap_backend(inst, inst.tokens, internal)
        if ok:
            what = proxy or country
            log(f"  {uid}: now using {what} (public port unchanged)")
        return ok

    async def rotate_tokens(self, inst: Instance) -> bool:
        """Give a client a fresh set of accounts."""
        tokens = self.allocate_tokens(inst.uid, TOKENS_PER_INSTANCE)
        if not tokens:
            log(f"  {inst.uid}: no free account left, keeping the current set")
            return False
        internal = self.store.next_port("internal_port", INTERNAL_PORT_BASE)
        old_tokens = list(inst.tokens)
        ok = await self.swap_backend(inst, tokens, internal)
        if ok:
            self.release_tokens(old_tokens)
        else:
            for token in tokens:
                self.store.set_account_state(token, "free")
        return ok

    # -- rotation policy ----------------------------------------------------

    async def check_rotations(self) -> None:
        if self._rotate_lock.locked():
            return
        async with self._rotate_lock:
            for inst in list(self.instances.values()):
                if not inst.tokens:
                    continue
                accounts = {a.token: a for a in self.store.accounts()}
                best = max((accounts[t].quota_left for t in inst.tokens
                             if t in accounts), default=0)
                limit = max((accounts[t].quota_max for t in inst.tokens
                             if t in accounts), default=0)
                if limit and best < limit * ROTATE_QUOTA_FRACTION:
                    log(f"  {inst.uid}: quota low ({best}/{limit}), rotating accounts")
                    await self.rotate_tokens(inst)
                    await asyncio.sleep(1.0)

    # -- supervision --------------------------------------------------------

    async def supervise(self) -> None:
        """Restart a backend that died, and adopt the ones that are alive."""
        for inst in list(self.instances.values()):
            if inst.backend is not None and not inst.backend.alive():
                log(f"  {inst.uid}: foxyvpn exited, restarting")
                internal = self.store.next_port("internal_port", INTERNAL_PORT_BASE)
                await self.swap_backend(inst, inst.tokens, internal)

    # -- startup ------------------------------------------------------------

    def kill_our_backends(self) -> None:
        """Kill foxyvpn processes we started earlier but no longer track."""
        marker = str(self.args.pool_dir)
        killed = 0
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            try:
                with open(f"/proc/{name}/cmdline", "rb") as fh:
                    cmdline = fh.read().decode("utf-8", "replace")
            except OSError:
                continue
            if "foxyvpn" not in cmdline or marker not in cmdline:
                continue
            with contextlib.suppress(Exception):
                os.kill(int(name), signal.SIGTERM)
                killed += 1
        if killed:
            log(f"stopped {killed} leftover foxyvpn process(es)")

    async def start(self) -> None:
        self.refresh_accounts()
        await self.probe_quota()
        self.kill_our_backends()
        for inst in self.store.instances():
            tokens = inst.tokens
            if not tokens:
                tokens = self.allocate_tokens(inst.uid, TOKENS_PER_INSTANCE)
            front = Front(self.args.bind_host, inst.public_port)
            await front.start()
            inst.front = front
            backend = self.spawn_backend(inst, tokens, inst.internal_port)
            inst.backend = backend
            if await self.wait_ready(inst.internal_port):
                front.point_at(("127.0.0.1", inst.internal_port))
            else:
                log(f"  {inst.uid}: foxyvpn did not come up")
            inst.tokens = tokens
            self.store.put_instance(inst)
            self.instances[inst.uid] = inst
            log(f"  {inst.uid}: restored on {self.args.bind_host}:{inst.public_port}")

    async def main_loop(self) -> None:
        while True:
            await asyncio.sleep(self.args.poll_interval)
            try:
                self.refresh_accounts()
                await self.probe_quota()
                await self.supervise()
                await self.check_rotations()
            except Exception as exc:  # noqa: BLE001
                log(f"poll cycle failed: {exc}")

    # -- HTTP ---------------------------------------------------------------

    async def handle(self, path: str, query: dict[str, list[str]]) -> tuple[int, str, str]:
        one = {k: v[0] for k, v in query.items() if v}
        if path == "/register":
            uid = one.get("uid", "").strip()
            if not uid:
                return 400, "text/plain", "uid is required\n"
            if uid in self.instances:
                inst = self.instances[uid]
                return 200, "application/json", json.dumps(self._instance_json(inst), indent=2)
            inst = await self.create_instance(uid, one.get("country", ""),
                                              one.get("proxy", ""))
            return 200, "application/json", json.dumps(self._instance_json(inst), indent=2)
        if path == "/delete":
            uid = one.get("uid", "").strip()
            if not uid:
                return 400, "text/plain", "uid is required\n"
            ok = await self.delete_instance(uid)
            return (200 if ok else 404), "application/json", json.dumps({"deleted": ok})
        if path == "/sub":
            uid = one.get("uid", "").strip()
            return 200, "text/yaml", self.subscription(uid or None)
        if path == "/list-servers":
            return 200, "application/json", json.dumps(self.server_list(), indent=2)
        if path == "/status":
            return 200, "application/json", json.dumps(self.status(), indent=2)
        if path == "/country":
            uid = one.get("uid", "").strip()
            if not uid:
                return 400, "text/plain", "uid is required\n"
            try:
                ok = await self.rotate_upstream(uid, one.get("country", ""),
                                                one.get("proxy", ""))
            except ValueError as exc:
                return 400, "text/plain", f"{exc}\n"
            if not ok:
                return 404, "text/plain", "no such client\n"
            inst = self.instances[uid]
            return 200, "application/json", json.dumps(self._instance_json(inst), indent=2)
        return 404, "text/plain", "not found\n"

    def _instance_json(self, inst: Instance) -> dict:
        return {
            "uid": inst.uid,
            "port": inst.public_port,
            "proxy": f"socks5://{self.args.bind_host}:{inst.public_port}",
            "country": inst.country,
            "upstream": inst.proxy,
            "accounts": len(inst.tokens),
            "created_at": inst.created_at,
            "rotated_at": inst.rotated_at,
            "backend_alive": bool(inst.backend and inst.backend.alive()),
        }

    def subscription(self, uid: str | None) -> str:
        instances = ([self.instances[uid]] if uid and uid in self.instances
                     else list(self.instances.values()) if not uid else [])
        lines = ["proxies:"]
        for inst in instances:
            name = f"foxyvpn-{inst.uid}"
            lines += [
                f'  - name: "{name}"',
                "    type: socks5",
                f"    server: {self.args.bind_host}",
                f"    port: {inst.public_port}",
                "    udp: false",
            ]
        lines += ["proxy-groups:"]
        lines += ["  - name: foxyvpn", "    type: select", "    proxies:"]
        for inst in instances:
            lines.append(f'      - "foxyvpn-{inst.uid}"')
        lines += ["rules:", "  - MATCH,foxyvpn"]
        return "\n".join(lines) + "\n"

    def server_list(self) -> dict:
        from foxyvpn import serverlist

        out: dict[str, Any] = {}
        for country in serverlist.fetch_server_list():
            servers = []
            for city in country.cities:
                for server in city.servers:
                    servers.append({"host": server.hostname, "port": server.port,
                                    "city": city.code,
                                    "quarantined": server.quarantined})
            out[country.code] = {"name": country.name, "servers": servers}
        return out

    def status(self) -> dict:
        accounts = self.store.accounts()
        return {
            "instances": [self._instance_json(i) for i in self.instances.values()],
            "accounts": {
                "total": len(accounts),
                "free": sum(1 for a in accounts if a.state == "free"),
                "assigned": sum(1 for a in accounts if a.state == "assigned"),
                "dead": sum(1 for a in accounts if a.state == "dead"),
                "quota_left_bytes": sum(a.quota_left for a in accounts),
            },
        }


# ── HTTP plumbing ───────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    wrapper: Wrapper = None            # type: ignore[assignment]
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        log("http " + (fmt % args))

    def _respond(self, code: int, ctype: str, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _dispatch(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            future = asyncio.run_coroutine_threadsafe(
                self.wrapper.handle(parsed.path, query), self.wrapper.loop)
            code, ctype, body = future.result(timeout=120)
        except Exception as exc:  # noqa: BLE001
            log(f"request failed: {exc}")
            code, ctype, body = 500, "text/plain", f"{exc}\n"
        self._respond(code, ctype, body)

    do_GET = _dispatch
    do_POST = _dispatch
    do_DELETE = _dispatch


def detect_bind_host() -> str | None:
    """Find this host's Tailscale address.

    Binding the wrong address is worse than not binding at all -- a relay
    on 127.0.0.1 is unreachable from the tailnet -- so the lookup tries
    several ways and the caller refuses to start if none of them works.
    """
    for binary in ("tailscale", "/usr/bin/tailscale", "/usr/local/bin/tailscale"):
        try:
            out = subprocess.run([binary, "ip", "-4"], capture_output=True,
                                 text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            continue
        if out:
            return out.splitlines()[0].strip()

    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True,
                             text=True, timeout=10).stdout
        for line in out.splitlines():
            if "tailscale" not in line:
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet":
                return parts[3].split("/")[0]
    except (OSError, subprocess.SubprocessError):
        pass

    # Tailscale hands out addresses in 100.64.0.0/10.
    import socket
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            octets = info[4][0].split(".")
            if len(octets) == 4 and octets[0] == "100" and 64 <= int(octets[1]) <= 127:
                return info[4][0]
    except OSError:
        pass
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="foxyvpn pool wrapper")
    ap.add_argument("--pool", default=DEFAULT_POOL)
    ap.add_argument("--auth-dir", default=DEFAULT_AUTH_DIR)
    ap.add_argument("--pool-dir", default=DEFAULT_POOL_DIR)
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--foxyvpn", default=FOXYVPN_BIN)
    ap.add_argument("--guardian", default="https://vpn.mozilla.org")
    ap.add_argument("--bind-host", default=None,
                    help="address the API and the relays listen on "
                         "(default: this host's Tailscale address)")
    ap.add_argument("--bind-wait", type=float, default=90.0,
                    help="seconds to wait for the Tailscale address to appear")
    ap.add_argument("--api-port", type=int, default=8080)
    ap.add_argument("--poll-interval", type=float, default=600.0,
                    help="seconds between quota polls")
    args = ap.parse_args(argv)
    if args.bind_host is None:
        # After a boot the wrapper can start before tailscaled has come up.
        # Waiting a little is better than binding the wrong address, and
        # failing loudly is better still: a relay on 127.0.0.1 cannot be
        # reached from the tailnet, so it looks alive but serves nobody.
        deadline = time.time() + args.bind_wait
        while True:
            args.bind_host = detect_bind_host()
            if args.bind_host:
                break
            if time.time() >= deadline:
                print("could not determine the Tailscale address; "
                      "pass --bind-host explicitly", file=sys.stderr)
                return 2
            log("waiting for the Tailscale address...")
            time.sleep(5)

    os.makedirs(args.pool_dir, exist_ok=True)
    os.chmod(args.pool_dir, 0o700)
    for path in (args.db,):
        if os.path.exists(path):
            os.chmod(path, 0o600)

    wrapper = Wrapper(args)
    loop = asyncio.new_event_loop()
    wrapper.loop = loop
    asyncio.set_event_loop(loop)

    Handler.wrapper = wrapper
    server = ThreadingHTTPServer((args.bind_host, args.api_port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f"api on http://{args.bind_host}:{args.api_port}")

    async def run() -> None:
        await wrapper.start()
        await wrapper.main_loop()

    try:
        loop.run_until_complete(run())
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        loop.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
