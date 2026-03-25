from __future__ import annotations

from email_validator import EmailNotValidError, validate_email


def validate_syntax(email: str) -> tuple[bool, str, str]:
    try:
        result = validate_email(email, check_deliverability=False)
        normalized = result.normalized
        domain = result.domain
        return True, normalized, domain
    except EmailNotValidError:
        return False, email.strip(), ""
