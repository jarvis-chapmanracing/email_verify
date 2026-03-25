from email_verify.core import verify_email


def test_timeout_passed_to_probe(monkeypatch):
    def fake_validate(email):
        return True, email, "example.com"

    def fake_domain_exists(domain, *_args, **_kwargs):
        return True

    def fake_lookup_mx(domain, *_args, **_kwargs):
        return [(10, "mx.example.com")]

    captured = {}

    def fake_probe(mx_hosts, domain, timeout, total_timeout, retries, ports):
        captured["timeout"] = timeout
        captured["total_timeout"] = total_timeout
        return False, None, [], False

    monkeypatch.setattr("email_verify.core.validate_syntax", fake_validate)
    monkeypatch.setattr("email_verify.core.domain_exists", fake_domain_exists)
    monkeypatch.setattr("email_verify.core.lookup_mx", fake_lookup_mx)
    monkeypatch.setattr("email_verify.core.probe_smtp", fake_probe)

    verify_email(
        "user@example.com",
        smtp_timeout=1.5,
        smtp_total_timeout=6.0,
        smtp_strategy="cloud_safe_non25",
    )
    assert captured["timeout"] == 1.5
    assert captured["total_timeout"] == 6.0
