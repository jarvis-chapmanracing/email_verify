# email_verify

Production ready email verification CLI that classifies addresses using a risk based model. It does not guarantee delivery. It only estimates risk and deliverability likelihood.

## Features

- Syntax validation
- Domain DNS check
- MX record lookup
- SMTP reachability probe with safe, no send behavior
- Catch all detection when possible
- Role account detection
- Disposable domain detection
- Risk scoring with conservative classification

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

Single email

```bash
email_verify test@example.com
```

Batch file

```bash
email_verify --file sample_data/emails.csv
```

JSON output

```bash
email_verify --json test@example.com
```

Verbose output

```bash
email_verify --verbose test@example.com
```

CSV output

```bash
email_verify --file sample_data/emails.csv --csv output.csv
```

SMTP strategy

```bash
email_verify --smtp-strategy strict test@example.com
email_verify --smtp-strategy cloud_safe test@example.com
email_verify --smtp-strategy dns_only test@example.com
```

SMTP ports

```bash
email_verify --smtp-strategy cloud_safe --smtp-ports 25,587,465 test@example.com
```

Config file example

```json
{
  "smtp_strategy": "cloud_safe",
  "smtp_ports": [25, 587, 465],
  "dns_timeout": 4,
  "dns_retries": 1,
  "smtp_timeout": 5,
  "smtp_retries": 1,
  "log_level": "INFO"
}
```

## Output fields

- email
- normalized_email
- syntax_valid
- domain_exists
- mx_found
- smtp_reachable
- catch_all
- smtp_attempts
- role_account
- disposable_domain
- risk_score
- classification
- cli_label
- notes

## Classification mapping

- safe_to_send maps to verified
- risky maps to sketchy
- invalid maps to not_verified

## Safety and limitations

- No SMTP data is sent and no message content is transmitted
- Port 25 MX checks can help indicate acceptance but do not guarantee delivery
- Submission ports 587 and 465 do not prove mailbox existence
- Some servers accept RCPT for any address and still bounce later
- Some servers block probes or rate limit connections
- Catch all detection is best effort only
- This tool cannot guarantee an email will not bounce

## Development

Run tests

```bash
pytest
```

## License

MIT
