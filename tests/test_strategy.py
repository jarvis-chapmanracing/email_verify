from email_verify.core import verify_email


def test_strict_strategy_uses_port_25(monkeypatch):
    def fake_validate(email):
        return True, email, "example.com"

    def fake_domain_exists(domain, *_args, **_kwargs):
        return True

    def fake_lookup_mx(domain, *_args, **_kwargs):
        return [(10, "mx.example.com")]

    captured = {}

    def fake_probe(mx_hosts, domain, timeout, total_timeout, retries, ports):
        captured["ports"] = ports
        return False, None, [], False

    monkeypatch.setattr("email_verify.core.validate_syntax", fake_validate)
    monkeypatch.setattr("email_verify.core.domain_exists", fake_domain_exists)
    monkeypatch.setattr("email_verify.core.lookup_mx", fake_lookup_mx)
    monkeypatch.setattr("email_verify.core.probe_smtp", fake_probe)

    verify_email("user@example.com", smtp_strategy="strict")
    assert captured["ports"] == [25]


def test_cloud_safe_strategy_uses_submission_ports(monkeypatch):
    def fake_validate(email):
        return True, email, "example.com"

    def fake_domain_exists(domain, *_args, **_kwargs):
        return True

    def fake_lookup_mx(domain, *_args, **_kwargs):
        return [(10, "mx.example.com")]

    captured = {}

    def fake_probe(mx_hosts, domain, timeout, total_timeout, retries, ports):
        captured["ports"] = ports
        return False, None, [], False

    monkeypatch.setattr("email_verify.core.validate_syntax", fake_validate)
    monkeypatch.setattr("email_verify.core.domain_exists", fake_domain_exists)
    monkeypatch.setattr("email_verify.core.lookup_mx", fake_lookup_mx)
    monkeypatch.setattr("email_verify.core.probe_smtp", fake_probe)

    verify_email("user@example.com", smtp_strategy="cloud_safe")
    assert captured["ports"] == [25, 587, 465]


def test_cloud_safe_non25_strategy(monkeypatch):
    def fake_validate(email):
        return True, email, "example.com"

    def fake_domain_exists(domain, *_args, **_kwargs):
        return True

    def fake_lookup_mx(domain, *_args, **_kwargs):
        return [(10, "mx.example.com")]

    captured = {}

    def fake_probe(mx_hosts, domain, timeout, total_timeout, retries, ports):
        captured["ports"] = ports
        return False, None, [], False

    monkeypatch.setattr("email_verify.core.validate_syntax", fake_validate)
    monkeypatch.setattr("email_verify.core.domain_exists", fake_domain_exists)
    monkeypatch.setattr("email_verify.core.lookup_mx", fake_lookup_mx)
    monkeypatch.setattr("email_verify.core.probe_smtp", fake_probe)

    verify_email("user@example.com", smtp_strategy="cloud_safe_non25")
    assert captured["ports"] == [587, 465]


def test_no_port_25_flag(monkeypatch):
    def fake_validate(email):
        return True, email, "example.com"

    def fake_domain_exists(domain, *_args, **_kwargs):
        return True

    def fake_lookup_mx(domain, *_args, **_kwargs):
        return [(10, "mx.example.com")]

    captured = {}

    def fake_probe(mx_hosts, domain, timeout, total_timeout, retries, ports):
        captured["ports"] = ports
        return False, None, [], False

    monkeypatch.setattr("email_verify.core.validate_syntax", fake_validate)
    monkeypatch.setattr("email_verify.core.domain_exists", fake_domain_exists)
    monkeypatch.setattr("email_verify.core.lookup_mx", fake_lookup_mx)
    monkeypatch.setattr("email_verify.core.probe_smtp", fake_probe)

    verify_email("user@example.com", smtp_strategy="cloud_safe", no_port_25=True)
    assert captured["ports"] == [587, 465]
