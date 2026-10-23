"""VPN server list discovery via Firefox Remote Settings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .headers import apply_mozilla_vpn_headers
from .http_client import get_client

REMOTE_SETTINGS_URL = (
    "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"
)


@dataclass
class Protocol:
    name: str
    host: str = ""
    port: int = 0
    scheme: str = ""
    template_string: str = ""

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Protocol":
        return cls(
            name=data.get("name", ""),
            host=data.get("host", ""),
            port=int(data.get("port", 0) or 0),
            scheme=data.get("scheme", ""),
            template_string=data.get("templateString", ""),
        )


@dataclass
class Server:
    hostname: str
    port: int = 0
    quarantined: bool = False
    protocols: List[Protocol] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Server":
        return cls(
            hostname=data.get("hostname", ""),
            port=int(data.get("port", 0) or 0),
            quarantined=bool(data.get("quarantined", False)),
            protocols=[Protocol.from_json(p) for p in data.get("protocols", [])],
        )


@dataclass
class City:
    name: str
    code: str
    servers: List[Server] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "City":
        return cls(
            name=data.get("name", ""),
            code=data.get("code", ""),
            servers=[Server.from_json(s) for s in data.get("servers", [])],
        )


@dataclass
class Country:
    name: str
    code: str
    cities: List[City] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "Country":
        return cls(
            name=data.get("name", ""),
            code=data.get("code", ""),
            cities=[City.from_json(c) for c in data.get("cities", [])],
        )


def fetch_server_list() -> List[Country]:
    client = get_client()
    response = client.get(REMOTE_SETTINGS_URL, headers=apply_mozilla_vpn_headers({}))
    response.raise_for_status()
    body = response.json()
    records = body.get("data", [])
    countries: List[Country] = []
    for record in records:
        country_data = record.get("country", record)
        try:
            country = Country.from_json(country_data)
        except Exception:  # noqa: BLE001
            continue
        # Mirrors the original Go client: skip malformed/placeholder records
        # that have no country code or no cities, instead of surfacing them
        # as blank entries in --list-servers output or to country-selection
        # logic.
        if country.code and country.cities:
            countries.append(country)
    return countries


def print_server_list(countries: List[Country]) -> None:
    for country in countries:
        print(f"\n=== {country.name} ({country.code}) ===")
        for city in country.cities:
            print(f"  City: {city.name} ({city.code})")
            for server in city.servers:
                if server.quarantined:
                    print(f"    [QUARANTINED] {server.hostname}:{server.port}")
                    continue
                print(f"    Server: {server.hostname}:{server.port}")
                for proto in server.protocols:
                    if proto.name == "connect":
                        scheme = proto.scheme or "https"
                        print(f"      Protocol: CONNECT ({scheme}) -> {proto.host}:{proto.port}")
                    elif proto.name == "masque":
                        print(
                            f"      Protocol: MASQUE -> {proto.host}:{proto.port} "
                            f"(template: {proto.template_string})"
                        )
                    else:
                        print(f"      Protocol: {proto.name} -> {proto.host}:{proto.port}")
                if not server.protocols:
                    print(f"      Protocol: CONNECT (https) -> {server.hostname}:{server.port} (default)")
