from __future__ import annotations

import logging
from typing import Optional

import dns.resolver

logger = logging.getLogger(__name__)


def domain_exists(domain: str, timeout: float, retries: int) -> bool:
    if not domain:
        return False
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    attempts = 0
    while attempts <= retries:
        try:
            resolver.resolve(domain, "A")
            return True
        except Exception as exc:
            attempts += 1
            logger.debug("Domain A lookup failed: %s", exc)
    return False


def lookup_mx(domain: str, timeout: float, retries: int) -> list[tuple[int, str]]:
    if not domain:
        return []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    attempts = 0
    while attempts <= retries:
        try:
            answers = resolver.resolve(domain, "MX")
            records = []
            for rdata in answers:
                records.append((int(rdata.preference), str(rdata.exchange).rstrip(".")))
            records.sort(key=lambda x: x[0])
            return records
        except Exception as exc:
            attempts += 1
            logger.debug("MX lookup failed: %s", exc)
    return []
