from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EmailCheckResult:
    email: str
    normalized_email: str
    syntax_valid: bool
    domain_exists: bool
    mx_found: bool
    smtp_reachable: bool
    catch_all: Optional[bool]
    smtp_attempts: list[dict]
    smtp_timeout_seconds: float
    smtp_total_timeout_seconds: float
    smtp_timed_out: bool
    role_account: bool
    disposable_domain: bool
    risk_score: int
    classification: str
    cli_label: str
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "normalized_email": self.normalized_email,
            "syntax_valid": self.syntax_valid,
            "domain_exists": self.domain_exists,
            "mx_found": self.mx_found,
            "smtp_reachable": self.smtp_reachable,
            "catch_all": self.catch_all,
            "smtp_attempts": self.smtp_attempts,
            "smtp_timeout_seconds": self.smtp_timeout_seconds,
            "smtp_total_timeout_seconds": self.smtp_total_timeout_seconds,
            "smtp_timed_out": self.smtp_timed_out,
            "role_account": self.role_account,
            "disposable_domain": self.disposable_domain,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "cli_label": self.cli_label,
            "notes": " ".join(self.notes),
        }
