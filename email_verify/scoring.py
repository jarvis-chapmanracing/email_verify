from __future__ import annotations

from typing import Optional

from .models import EmailCheckResult


def classify_result(
    email: str,
    normalized: str,
    syntax_valid: bool,
    domain_exists: bool,
    mx_found: bool,
    smtp_reachable: bool,
    catch_all: Optional[bool],
    role_account: bool,
    disposable_domain: bool,
) -> EmailCheckResult:
    notes: list[str] = []

    if not syntax_valid:
        notes.append("Syntax is invalid")
        return EmailCheckResult(
            email=email,
            normalized_email=normalized,
            syntax_valid=False,
            domain_exists=False,
            mx_found=False,
            smtp_reachable=False,
            catch_all=None,
            role_account=False,
            disposable_domain=False,
            risk_score=100,
            classification="invalid",
            cli_label="not_verified",
            notes=notes,
        )

    if not domain_exists:
        notes.append("Domain does not resolve")
        return EmailCheckResult(
            email=email,
            normalized_email=normalized,
            syntax_valid=True,
            domain_exists=False,
            mx_found=False,
            smtp_reachable=False,
            catch_all=None,
            role_account=role_account,
            disposable_domain=disposable_domain,
            risk_score=100,
            classification="invalid",
            cli_label="not_verified",
            notes=notes,
        )

    if not mx_found:
        notes.append("No MX records found")
        return EmailCheckResult(
            email=email,
            normalized_email=normalized,
            syntax_valid=True,
            domain_exists=True,
            mx_found=False,
            smtp_reachable=False,
            catch_all=None,
            role_account=role_account,
            disposable_domain=disposable_domain,
            risk_score=90,
            classification="invalid",
            cli_label="not_verified",
            notes=notes,
        )

    risk_score = 0

    if not smtp_reachable:
        risk_score += 25
        notes.append("SMTP server not reachable")

    if catch_all is True:
        risk_score += 15
        notes.append("Catch all domain detected")
    elif catch_all is None:
        risk_score += 5
        notes.append("Catch all status unknown")

    if role_account:
        risk_score += 10
        notes.append("Role account address")

    if disposable_domain:
        risk_score += 35
        notes.append("Disposable email domain")

    if disposable_domain:
        classification = "risky"
    elif risk_score >= 40:
        classification = "risky"
    else:
        classification = "safe_to_send"

    cli_label = "verified" if classification == "safe_to_send" else "sketchy"

    return EmailCheckResult(
        email=email,
        normalized_email=normalized,
        syntax_valid=True,
        domain_exists=True,
        mx_found=True,
        smtp_reachable=smtp_reachable,
        catch_all=catch_all,
        role_account=role_account,
        disposable_domain=disposable_domain,
        risk_score=risk_score,
        classification=classification,
        cli_label=cli_label,
        notes=notes,
    )
