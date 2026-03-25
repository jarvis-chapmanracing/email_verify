from __future__ import annotations

import logging
import os
from typing import Optional

from .models import EmailCheckResult
from .scoring import classify_result
from .validators.disposable import load_disposable_domains, is_disposable
from .validators.dns_records import domain_exists, lookup_mx
from .validators.role import is_role_account
from .validators.smtp_probe import probe_smtp
from .validators.syntax import validate_syntax

logger = logging.getLogger(__name__)


def _get_int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _get_str_env(name: str, default: str) -> str:
    value = os.getenv(name)
    if not value:
        return default
    return value


def verify_email(
    email: str,
    smtp_strategy: str = "cloud_safe_non25",
    smtp_ports: list[int] | None = None,
    dns_timeout: float | None = None,
    dns_retries: int | None = None,
    smtp_timeout: float | None = None,
    smtp_total_timeout: float | None = None,
    smtp_retries: int | None = None,
    no_port_25: bool = False,
) -> EmailCheckResult:
    dns_timeout = dns_timeout or _get_float_env("EMAIL_VERIFY_DNS_TIMEOUT", 4.0)
    smtp_timeout = smtp_timeout or _get_float_env("EMAIL_VERIFY_SMTP_TIMEOUT", 3.0)
    smtp_total_timeout = smtp_total_timeout or _get_float_env("EMAIL_VERIFY_SMTP_TOTAL_TIMEOUT", 10.0)
    smtp_retries = smtp_retries if smtp_retries is not None else _get_int_env("EMAIL_VERIFY_SMTP_RETRIES", 0)
    dns_retries = dns_retries if dns_retries is not None else _get_int_env("EMAIL_VERIFY_DNS_RETRIES", 0)
    smtp_strategy = smtp_strategy or _get_str_env("EMAIL_VERIFY_SMTP_STRATEGY", "cloud_safe_non25")

    if smtp_ports is None:
        if smtp_strategy == "cloud_safe":
            smtp_ports = [25, 587, 465]
        elif smtp_strategy == "cloud_safe_non25":
            smtp_ports = [587, 465]
        elif smtp_strategy == "dns_only":
            smtp_ports = []
        else:
            smtp_ports = [25]

    if smtp_strategy != "strict":
        no_port_25 = True

    if no_port_25 and smtp_ports:
        smtp_ports = [port for port in smtp_ports if port != 25]

    syntax_valid, normalized, domain = validate_syntax(email)
    local_part = ""
    if "@" in normalized:
        local_part = normalized.split("@", 1)[0]

    role_account = is_role_account(local_part)
    disposable_domains = load_disposable_domains()
    disposable_domain = is_disposable(domain, disposable_domains)

    if not syntax_valid:
        return classify_result(
            email=email,
            normalized=normalized,
            syntax_valid=False,
            domain_exists=False,
            mx_found=False,
            smtp_reachable=False,
            catch_all=None,
            smtp_attempts=[],
            smtp_timeout_seconds=smtp_timeout,
            smtp_total_timeout_seconds=smtp_total_timeout,
            smtp_timed_out=False,
            role_account=role_account,
            disposable_domain=disposable_domain,
            smtp_inconclusive=False,
        )

    domain_ok = domain_exists(domain, dns_timeout, dns_retries)
    mx_records = lookup_mx(domain, dns_timeout, dns_retries)
    mx_hosts = [record[1] for record in mx_records]
    mx_found = len(mx_hosts) > 0

    smtp_reachable = False
    catch_all: Optional[bool] = None
    smtp_attempts: list[dict] = []
    smtp_inconclusive = False

    smtp_timed_out = False
    smtp_timeout_seconds = smtp_timeout
    smtp_total_timeout_seconds = smtp_total_timeout
    if mx_found and smtp_ports:
        smtp_reachable, catch_all, smtp_attempts, smtp_timed_out = probe_smtp(
            mx_hosts,
            domain,
            timeout=smtp_timeout,
            total_timeout=smtp_total_timeout,
            retries=smtp_retries,
            ports=smtp_ports,
        )
        port25_success = any(
            attempt.get("port") == 25 and attempt.get("status") == "ok" for attempt in smtp_attempts
        )
        submission_success = any(
            attempt.get("port") in (587, 465) and attempt.get("status") == "ok" for attempt in smtp_attempts
        )
        if not port25_success:
            smtp_inconclusive = True
        if submission_success and not port25_success:
            smtp_inconclusive = True
    elif mx_found and not smtp_ports:
        smtp_inconclusive = True
    elif mx_found and not smtp_ports:
        smtp_inconclusive = True

    return classify_result(
        email=email,
        normalized=normalized,
        syntax_valid=True,
        domain_exists=domain_ok,
        mx_found=mx_found,
        smtp_reachable=smtp_reachable,
        catch_all=catch_all,
        smtp_attempts=smtp_attempts,
        smtp_timeout_seconds=smtp_timeout_seconds,
        smtp_total_timeout_seconds=smtp_total_timeout_seconds,
        smtp_timed_out=smtp_timed_out,
        role_account=role_account,
        disposable_domain=disposable_domain,
        smtp_inconclusive=smtp_inconclusive,
    )
