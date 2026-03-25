from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Iterable

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


def main() -> int:
    parser = argparse.ArgumentParser(description="Email verification tool")
    parser.add_argument("email", nargs="?", help="Email address to verify")
    parser.add_argument("--file", type=str, help="CSV file with email column")
    parser.add_argument("--verbose", action="store_true", help="Pretty JSON output")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--csv", dest="csv_path", type=str, help="Write results to CSV file")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level")

    args = parser.parse_args()
    _configure_logging(args.log_level.upper())

    emails: list[str] = []
    if args.file:
        emails.extend(_read_emails_from_file(Path(args.file)))
    if args.email:
        emails.append(args.email)

    if not emails:
        parser.print_help()
        return 2

    results = [verify_email(email).to_dict() for email in emails]

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
