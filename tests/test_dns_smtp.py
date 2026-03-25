from email_verify.validators.dns_records import lookup_mx, domain_exists
from email_verify.validators.smtp_probe import probe_smtp


def test_domain_exists_false(monkeypatch):
    def fake_resolve(*_args, **_kwargs):
        raise Exception("dns fail")

    class FakeResolver:
        lifetime = 1

        def resolve(self, *args, **kwargs):
            return fake_resolve(*args, **kwargs)

    monkeypatch.setattr("dns.resolver.Resolver", lambda: FakeResolver())
    assert domain_exists("example.com", timeout=1, retries=0) is False


def test_lookup_mx_empty(monkeypatch):
    def fake_resolve(*_args, **_kwargs):
        raise Exception("mx fail")

    class FakeResolver:
        lifetime = 1

        def resolve(self, *args, **kwargs):
            return fake_resolve(*args, **kwargs)

    monkeypatch.setattr("dns.resolver.Resolver", lambda: FakeResolver())
    assert lookup_mx("example.com", timeout=1, retries=0) == []


def test_probe_smtp_unreachable(monkeypatch):
    def fake_smtp(*_args, **_kwargs):
        raise OSError("smtp fail")

    monkeypatch.setattr("smtplib.SMTP", fake_smtp)
    reachable, catch_all, attempts, timed_out = probe_smtp(
        ["mx.example.com"],
        "example.com",
        timeout=1,
        total_timeout=1,
        retries=0,
        ports=[587, 465],
    )
    assert reachable is False
    assert catch_all is None
    assert timed_out is False
