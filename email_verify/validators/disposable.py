from __future__ import annotations

from pathlib import Path

_DISPOSABLE_FILE = Path(__file__).resolve().parent / "disposable_domains.txt"


def load_disposable_domains() -> set[str]:
    if not _DISPOSABLE_FILE.exists():
        return set()
    domains = set()
    for line in _DISPOSABLE_FILE.read_text().splitlines():
        value = line.strip().lower()
        if value and not value.startswith("#"):
            domains.add(value)
    return domains


def is_disposable(domain: str, domains: set[str]) -> bool:
    if not domain:
        return False
    return domain.lower() in domains
