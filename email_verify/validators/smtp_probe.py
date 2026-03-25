from __future__ import annotations

import logging
import random
import smtplib
import socket
import string
from typing import Optional

logger = logging.getLogger(__name__)


def _random_local() -> str:
    letters = string.ascii_lowercase + string.digits
    return "probe" + "".join(random.choice(letters) for _ in range(10))


def probe_smtp(
    mx_hosts: list[str],
    domain: str,
    timeout: float,
    retries: int,
) -> tuple[bool, Optional[bool]]:
    if not mx_hosts:
        return False, None

    for host in mx_hosts:
        attempts = 0
        while attempts <= retries:
            attempts += 1
            try:
                with smtplib.SMTP(host, 25, timeout=timeout) as client:
                    client.ehlo_or_helo_if_needed()
                    smtp_reachable = True
                    catch_all = None
                    try:
                        client.mail("<>")
                        probe_address = f"{_random_local()}@{domain}"
                        code, _ = client.rcpt(probe_address)
                        if code in (250, 251):
                            catch_all = True
                        elif code in (550, 551, 552, 553, 554):
                            catch_all = False
                        else:
                            catch_all = None
                        client.rset()
                    except smtplib.SMTPException as exc:
                        logger.debug("SMTP probe failed for %s: %s", host, exc)
                        catch_all = None
                    return smtp_reachable, catch_all
            except (socket.timeout, OSError, smtplib.SMTPException) as exc:
                logger.debug("SMTP connection failed for %s: %s", host, exc)
                continue
    return False, None
