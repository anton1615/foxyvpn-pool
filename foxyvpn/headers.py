"""Shared HTTP headers to mimic the official Mozilla VPN client."""

from __future__ import annotations

from typing import Dict

MOZILLA_VPN_USER_AGENT = "MozillaVPN/2.35.0 (sys:linux; iap:true)"


def apply_mozilla_vpn_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of ``headers`` with the Mozilla VPN client identity applied."""
    merged = dict(headers)
    merged.setdefault("User-Agent", MOZILLA_VPN_USER_AGENT)
    merged.setdefault("Accept", "application/json")
    return merged
