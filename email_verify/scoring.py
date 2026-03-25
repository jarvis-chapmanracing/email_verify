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
    smtp_attempts: list[dict],
    smtp_timeout_seconds: float,
    smtp_total_timeout_seconds: float,
    smtp_timed_out: bool,
    role_account: bool,
    disposable_domain: bool,
    smtp_inconclusive: bool,
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
            smtp_attempts=smtp_attempts,
            smtp_timeout_seconds=smtp_timeout_seconds,
            smtp_total_timeout_seconds=smtp_total_timeout_seconds,
            smtp_timed_out=smtp_timed_out,
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
            smtp_attempts=smtp_attempts,
            smtp_timeout_seconds=smtp_timeout_seconds,
            smtp_total_timeout_seconds=smtp_total_timeout_seconds,
            smtp_timed_out=smtp_timed_out,
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
            smtp_attempts=smtp_attempts,
            smtp_timeout_seconds=smtp_timeout_seconds,
            smtp_total_timeout_seconds=smtp_total_timeout_seconds,
            smtp_timed_out=smtp_timed_out,
            role_account=role_account,
            disposable_domain=disposable_domain,
            risk_score=90,
            classification="invalid",
            cli_label="not_verified",
            notes=notes,
        )

    risk_score = 0

    if smtp_inconclusive:
        risk_score += 20
        notes.append(
            "Syntax, domain, and MX checks passed. SMTP probing did not confirm reachability within timeout. Submission ports do not guarantee mailbox validity."
        )
        if smtp_timed_out:
            notes.append("SMTP probing hit total timeout")
    elif not smtp_reachable:
        risk_score += 25
        notes.append("SMTP server not reachable")

    if smtp_attempts:
        port25_attempted = any(attempt.get("port") == 25 for attempt in smtp_attempts)
        port25_success = any(
            attempt.get("port") == 25 and attempt.get("status") == "ok" for attempt in smtp_attempts
        )
        submission_success = any(
            attempt.get("port") in (587, 465) and attempt.get("status") == "ok" for attempt in smtp_attempts
        )
        if port25_attempted and not port25_success:
            notes.append("MX port 25 unreachable")
        if submission_success and not port25_success:
            notes.append("Submission ports reachable, mailbox validity unconfirmed")

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

    if not smtp_reachable:
        classification = "risky"
    elif disposable_domain:
        classification = "risky"
    elif smtp_inconclusive:
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
        smtp_attempts=smtp_attempts,
        smtp_timeout_seconds=smtp_timeout_seconds,
        smtp_total_timeout_seconds=smtp_total_timeout_seconds,
        smtp_timed_out=smtp_timed_out,
        role_account=role_account,
        disposable_domain=disposable_domain,
        risk_score=risk_score,
        classification=classification,
        cli_label=cli_label,
        notes=notes,
    )
