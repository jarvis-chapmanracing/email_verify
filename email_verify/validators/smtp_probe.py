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
    ports: list[int],
) -> tuple[bool, Optional[bool], list[dict]]:
    if not mx_hosts:
        return False, None, []

    attempts_log: list[dict] = []
    smtp_reachable = False
    catch_all: Optional[bool] = None

    for host in mx_hosts:
        for port in ports:
            attempts = 0
            while attempts <= retries:
                attempts += 1
                mode = "plain"
                try:
                    if port == 465:
                        mode = "tls"
                        client = smtplib.SMTP_SSL(host, port, timeout=timeout)
                    else:
                        client = smtplib.SMTP(host, port, timeout=timeout)
                    with client:
                        client.ehlo_or_helo_if_needed()
                        if port == 587:
                            mode = "starttls"
                            client.starttls()
                            client.ehlo()
                        attempt_entry = {"host": host, "port": port, "mode": mode, "status": "ok"}
                        smtp_reachable = True
                        if port == 25:
                            try:
                                client.mail("<>")
                                probe_address = f"{_random_local()}@{domain}"
                                code, _ = client.rcpt(probe_address)
                                if code in (250, 251):
                                    catch_all = True
                                    attempt_entry["rcpt_status"] = "accepted"
                                elif code in (550, 551, 552, 553, 554):
                                    catch_all = False
                                    attempt_entry["rcpt_status"] = "rejected"
                                else:
                                    catch_all = None
                                    attempt_entry["rcpt_status"] = "unknown"
                                client.rset()
                            except smtplib.SMTPException as exc:
                                logger.debug("SMTP RCPT probe failed for %s: %s", host, exc)
                                catch_all = None
                                attempt_entry["rcpt_status"] = "error"
                        attempts_log.append(attempt_entry)
                        return smtp_reachable, catch_all, attempts_log
                except (socket.timeout, OSError, smtplib.SMTPException) as exc:
                    attempts_log.append({"host": host, "port": port, "mode": mode, "status": f"fail: {exc}"})
                    logger.debug("SMTP connection failed for %s:%s: %s", host, port, exc)
                    continue
    return smtp_reachable, catch_all, attempts_log
