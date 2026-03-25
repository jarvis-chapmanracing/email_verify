from __future__ import annotations

ROLE_PREFIXES = {
    "admin",
    "billing",
    "careers",
    "contact",
    "help",
    "hello",
    "hr",
    "info",
    "jobs",
    "marketing",
    "media",
    "no-reply",
    "noreply",
    "postmaster",
    "privacy",
    "sales",
    "security",
    "service",
    "support",
    "team",
    "legal",
}


def is_role_account(local_part: str) -> bool:
    if not local_part:
        return False
    return local_part.lower() in ROLE_PREFIXES
