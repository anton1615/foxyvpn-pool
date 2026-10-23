"""Proxy candidate selection and persisted proxy-state file.

An explicit proxy always wins; otherwise a persisted selection is reused if
its country still matches the requested country; otherwise the server list
is filtered by country (auto-selecting when only one country is available)
and a server is chosen, with the choice persisted for next time.
"""

from __future__ import annotations

import json
import os
import random
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from .serverlist import Country, Server


@dataclass
class ProxyCandidate:
    host: str
    port: int
    country_code: str
    country_name: str
    city_code: str = ""

    @property
    def authority(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class _PersistedState:
    host: str
    port: int
    country_code: str
    country_name: str
    city_code: str = ""
    consecutive_failures: int = 0


def _default_connect_protocol(server: Server) -> Optional[Tuple[str, int]]:
    for proto in server.protocols:
        if proto.name == "connect":
            return proto.host or server.hostname, proto.port or server.port
    if not server.protocols:
        return server.hostname, server.port
    return None


def _candidates_for_country(countries: List[Country], country_code: str) -> List[ProxyCandidate]:
    out: List[ProxyCandidate] = []
    for country in countries:
        if country.code.lower() != country_code.lower():
            continue
        for city in country.cities:
            for server in city.servers:
                if server.quarantined:
                    continue
                target = _default_connect_protocol(server)
                if target is None:
                    continue
                host, port = target
                out.append(ProxyCandidate(host=host, port=port, country_code=country.code, country_name=country.name, city_code=city.code))
    return out


def available_country_codes(countries: List[Country]) -> List[str]:
    return sorted({c.code for c in countries if c.cities})


def _parse_host_port(value: str, *, flag: str) -> Tuple[str, int]:
    """Parse a "host:port" or "[ipv6]:port" string, raising ValueError with a
    message naming ``flag`` on any malformed input."""
    if value.startswith("["):
        end = value.find("]")
        if end == -1 or not value[end + 1 :].startswith(":"):
            raise ValueError(f"invalid {flag} value {value!r}, expected host:port or [ipv6]:port")
        host = value[1:end]
        port_str = value[end + 2 :]
    else:
        host, _, port_str = value.rpartition(":")
    if not host:
        raise ValueError(f"invalid {flag} value {value!r}, expected host:port")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"invalid {flag} value {value!r}, expected host:port")
    return host, port


class ProxyStateStore:
    def __init__(self, path: Optional[str]):
        self.path = Path(path) if path else None

    def load(self) -> Optional[_PersistedState]:
        if not self.path:
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return _PersistedState(**{k: data.get(k) for k in _PersistedState.__dataclass_fields__ if k in data})
        except (FileNotFoundError, json.JSONDecodeError, TypeError):
            return None

    def save(self, candidate: ProxyCandidate, consecutive_failures: int = 0) -> None:
        if not self.path:
            return
        state = _PersistedState(
            host=candidate.host,
            port=candidate.port,
            country_code=candidate.country_code,
            country_name=candidate.country_name,
            city_code=candidate.city_code,
            consecutive_failures=consecutive_failures,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=self.path.name + ".tmp-", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(asdict(state), fh, indent=2)
            os.replace(tmp_path, self.path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def record_failure(self) -> Tuple[int, bool]:
        """Record a failed attempt to establish a session on the persisted
        proxy selection, matching the original Go client's
        recordProxySelectionFailure. Returns ``(failures, cleared)``:
        ``cleared`` is True once the failure count reaches 3 and the
        persisted selection file has been removed so the next restart
        picks a fresh server instead of retrying a dead one forever.
        Returns ``(0, False)`` when there is no state file configured or
        no persisted selection currently on disk.
        """
        if not self.path:
            return 0, False
        state = self.load()
        if state is None:
            return 0, False
        state.consecutive_failures += 1
        if state.consecutive_failures >= 3:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            return state.consecutive_failures, True
        self.path.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
        return state.consecutive_failures, False


def resolve_proxy(
    countries: List[Country],
    *,
    explicit_proxy: Optional[str] = None,
    country_code: Optional[str] = None,
    state_store: Optional[ProxyStateStore] = None,
) -> Tuple[ProxyCandidate, bool]:
    """Resolve which upstream proxy to use. Returns ``(candidate,
    selected_from_state)``; ``selected_from_state`` is True when
    ``candidate`` was loaded from ``state_store``'s persisted selection
    (rather than an explicit --proxy or a fresh country-based pick), so
    the caller can attribute a subsequent session-establishment failure
    to that persisted choice via ``ProxyStateStore.record_failure``.
    """
    if explicit_proxy:
        host, port = _parse_host_port(explicit_proxy, flag="--proxy")
        return ProxyCandidate(host=host, port=port, country_code=country_code or "", country_name=""), False

    if state_store is not None and not country_code:
        persisted = state_store.load()
        if persisted is not None:
            return (
                ProxyCandidate(
                    host=persisted.host,
                    port=persisted.port,
                    country_code=persisted.country_code,
                    country_name=persisted.country_name,
                    city_code=persisted.city_code,
                ),
                True,
            )

    codes = available_country_codes(countries)
    if country_code:
        candidates = _candidates_for_country(countries, country_code)
        if not candidates:
            raise ValueError(f"no available servers for country {country_code!r} (available: {', '.join(codes)})")
    else:
        # No --country was given. Mirror Firefox's own client, which treats
        # the "REC" entry in the server list as "automatically choose the
        # best/recommended location" rather than a real country. Prefer it
        # by default instead of forcing the user to pick a country.
        recommended_code = next((c for c in codes if c.upper() == "REC"), None)
        if recommended_code is not None:
            candidates = _candidates_for_country(countries, recommended_code)
            if not candidates:
                raise ValueError(f"no available servers for the recommended {recommended_code!r} country")
        elif len(codes) > 1:
            raise ValueError(f"multiple countries available, specify --country (available: {', '.join(codes)})")
        elif not codes:
            raise ValueError("no countries available in server list")
        else:
            candidates = _candidates_for_country(countries, codes[0])
            if not candidates:
                raise ValueError(f"no available servers for the only available country {codes[0]!r}")

    chosen = random.choice(candidates)
    if state_store is not None:
        state_store.save(chosen)
    return chosen, False
