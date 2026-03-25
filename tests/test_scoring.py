from email_verify.scoring import classify_result


def test_invalid_without_mx():
    result = classify_result(
        email="user@example.com",
        normalized="user@example.com",
        syntax_valid=True,
        domain_exists=True,
        mx_found=False,
        smtp_reachable=False,
        catch_all=None,
        smtp_attempts=[],
        smtp_timeout_seconds=3.0,
        smtp_total_timeout_seconds=10.0,
        smtp_timed_out=False,
        role_account=False,
        disposable_domain=False,
        smtp_inconclusive=False,
    )
    assert result.classification == "invalid"
    assert result.cli_label == "not_verified"


def test_risky_role_account():
    result = classify_result(
        email="info@example.com",
        normalized="info@example.com",
        syntax_valid=True,
        domain_exists=True,
        mx_found=True,
        smtp_reachable=True,
        catch_all=None,
        smtp_attempts=[],
        smtp_timeout_seconds=3.0,
        smtp_total_timeout_seconds=10.0,
        smtp_timed_out=False,
        role_account=True,
        disposable_domain=False,
        smtp_inconclusive=False,
    )
    assert result.classification in {"risky", "safe_to_send"}


def test_disposable_risky():
    result = classify_result(
        email="user@mailinator.com",
        normalized="user@mailinator.com",
        syntax_valid=True,
        domain_exists=True,
        mx_found=True,
        smtp_reachable=True,
        catch_all=False,
        smtp_attempts=[],
        smtp_timeout_seconds=3.0,
        smtp_total_timeout_seconds=10.0,
        smtp_timed_out=False,
        role_account=False,
        disposable_domain=True,
        smtp_inconclusive=False,
    )
    assert result.classification == "risky"


def test_inconclusive_smtp_is_risky():
    result = classify_result(
        email="user@example.com",
        normalized="user@example.com",
        syntax_valid=True,
        domain_exists=True,
        mx_found=True,
        smtp_reachable=False,
        catch_all=None,
        smtp_attempts=[],
        smtp_timeout_seconds=3.0,
        smtp_total_timeout_seconds=10.0,
        smtp_timed_out=False,
        role_account=False,
        disposable_domain=False,
        smtp_inconclusive=True,
    )
    assert result.classification == "risky"
    assert result.cli_label == "sketchy"


def test_submission_success_still_risky():
    result = classify_result(
        email="user@example.com",
        normalized="user@example.com",
        syntax_valid=True,
        domain_exists=True,
        mx_found=True,
        smtp_reachable=True,
        catch_all=None,
        smtp_attempts=[{"host": "mx.example.com", "port": 587, "status": "ok"}],
        smtp_timeout_seconds=3.0,
        smtp_total_timeout_seconds=10.0,
        smtp_timed_out=False,
        role_account=False,
        disposable_domain=False,
        smtp_inconclusive=True,
    )
    assert result.classification == "risky"
    assert result.cli_label == "sketchy"
