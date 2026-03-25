from email_verify.validators.syntax import validate_syntax


def test_valid_email():
    valid, normalized, domain = validate_syntax("Test.User@example.com")
    assert valid is True
    assert domain == "example.com"
    assert "@" in normalized


def test_invalid_email():
    valid, normalized, domain = validate_syntax("not-an-email")
    assert valid is False
    assert domain == ""
