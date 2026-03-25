from email_verify.validators.smtp_probe import probe_smtp


def test_total_timeout_short_circuits():
    reachable, catch_all, attempts, timed_out = probe_smtp(
        ["mx.example.com"],
        "example.com",
        timeout=0.01,
        total_timeout=0.0,
        retries=0,
        ports=[587, 465],
    )
    assert reachable is False
    assert timed_out is True
