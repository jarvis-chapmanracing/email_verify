from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Iterable

from .config import load_config
from .core import verify_email


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _read_emails_from_file(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    text = path.read_text().strip()
    if not text:
        return []
    rows = list(csv.reader(text.splitlines()))
    if not rows:
        return []
    header = [h.strip().lower() for h in rows[0]]
    if "email" in header:
        idx = header.index("email")
        return [row[idx].strip() for row in rows[1:] if len(row) > idx and row[idx].strip()]
    return [row[0].strip() for row in rows if row and row[0].strip()]


def _write_csv(path: Path, results: Iterable[dict]) -> None:
    results = list(results)
    if not results:
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)


def _parse_ports(value: str | None) -> list[int] | None:
    if not value:
        return None
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Email verification tool")
    parser.add_argument("email", nargs="?", help="Email address to verify")
    parser.add_argument("--file", type=str, help="CSV file with email column")
    parser.add_argument("--verbose", action="store_true", help="Pretty JSON output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--csv", dest="csv_path", type=str, help="Write results to CSV file")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level")
    parser.add_argument("--config", type=str, help="Path to JSON config file")
    parser.add_argument(
        "--smtp-strategy",
        type=str,
        choices=["strict", "cloud_safe", "cloud_safe_non25", "dns_only"],
        help="SMTP probe strategy",
    )
    parser.add_argument("--smtp-ports", type=str, help="Comma separated SMTP ports")
    parser.add_argument("--smtp-timeout-seconds", type=float, help="SMTP timeout in seconds")
    parser.add_argument("--smtp-total-timeout-seconds", type=float, help="Total SMTP time budget per email")
    parser.add_argument("--no-port-25", action="store_true", help="Remove port 25 from SMTP probe")

    args = parser.parse_args()

    config = load_config(args.config)

    log_level = args.log_level or config.get("log_level", "INFO")
    _configure_logging(log_level.upper())

    emails: list[str] = []
    if args.file:
        emails.extend(_read_emails_from_file(Path(args.file)))
    if args.email:
        emails.append(args.email)

    if not emails:
        parser.print_help()
        return 2

    smtp_strategy = args.smtp_strategy or config.get("smtp_strategy", "cloud_safe_non25")
    smtp_ports = _parse_ports(args.smtp_ports)
    if smtp_ports is None:
        config_ports = config.get("smtp_ports")
        if isinstance(config_ports, list):
            smtp_ports = [int(port) for port in config_ports]

    dns_timeout = config.get("dns_timeout")
    dns_retries = config.get("dns_retries")
    smtp_timeout = config.get("smtp_timeout")
    if smtp_timeout is None:
        smtp_timeout = config.get("smtp_timeout_seconds")
    if args.smtp_timeout_seconds is not None:
        smtp_timeout = args.smtp_timeout_seconds

    smtp_total_timeout = config.get("smtp_total_timeout")
    if smtp_total_timeout is None:
        smtp_total_timeout = config.get("smtp_total_timeout_seconds")
    if args.smtp_total_timeout_seconds is not None:
        smtp_total_timeout = args.smtp_total_timeout_seconds

    smtp_retries = config.get("smtp_retries")

    no_port_25 = args.no_port_25 or bool(config.get("no_port_25"))

    results = [
        verify_email(
            email,
            smtp_strategy=smtp_strategy,
            smtp_ports=smtp_ports,
            dns_timeout=dns_timeout,
            dns_retries=dns_retries,
            smtp_timeout=smtp_timeout,
            smtp_total_timeout=smtp_total_timeout,
            smtp_retries=smtp_retries,
            no_port_25=no_port_25,
        ).to_dict()
        for email in emails
    ]

    if args.csv_path:
        _write_csv(Path(args.csv_path), results)

    if args.verbose:
        print(json.dumps(results, indent=2))
        return 0

    if args.json:
        print(json.dumps(results))
        return 0

    for result in results:
        print(result["cli_label"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
