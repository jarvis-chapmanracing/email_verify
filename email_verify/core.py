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


def verify_email(email: str) -> EmailCheckResult:
    dns_timeout = _get_float_env("EMAIL_VERIFY_DNS_TIMEOUT", 5.0)
    smtp_timeout = _get_float_env("EMAIL_VERIFY_SMTP_TIMEOUT", 6.0)
    smtp_retries = _get_int_env("EMAIL_VERIFY_SMTP_RETRIES", 2)
    dns_retries = _get_int_env("EMAIL_VERIFY_DNS_RETRIES", 1)

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
            role_account=role_account,
            disposable_domain=disposable_domain,
        )

    domain_ok = domain_exists(domain, dns_timeout, dns_retries)
    mx_records = lookup_mx(domain, dns_timeout, dns_retries)
    mx_hosts = [record[1] for record in mx_records]
    mx_found = len(mx_hosts) > 0

    smtp_reachable = False
    catch_all: Optional[bool] = None
    if mx_found:
        smtp_reachable, catch_all = probe_smtp(
            mx_hosts,
            domain,
            timeout=smtp_timeout,
            retries=smtp_retries,
        )

    return classify_result(
        email=email,
        normalized=normalized,
        syntax_valid=True,
        domain_exists=domain_ok,
        mx_found=mx_found,
        smtp_reachable=smtp_reachable,
        catch_all=catch_all,
        role_account=role_account,
        disposable_domain=disposable_domain,
    )
