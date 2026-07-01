from gateway.security import pii_scanner


def test_detects_aws_key():
    findings = pii_scanner.scan_text("access key is AKIAIOSFODNN7EXAMPLE please use it")
    assert any(f.category == "aws_access_key" for f in findings)


def test_detects_email():
    findings = pii_scanner.scan_text("contact me at darani@example.com")
    assert any(f.category == "email" for f in findings)


def test_detects_ssn():
    findings = pii_scanner.scan_text("SSN: 123-45-6789")
    assert any(f.category == "ssn" for f in findings)


def test_detects_valid_credit_card_only():
    # 4111111111111111 is a valid Luhn test Visa number
    findings = pii_scanner.scan_text("card 4111 1111 1111 1111 expires soon")
    assert any(f.category == "credit_card" for f in findings)

    # Random 16-digit number that fails Luhn should NOT be flagged as credit_card
    findings2 = pii_scanner.scan_text("order id 1234 5678 9012 3457")
    assert not any(f.category == "credit_card" for f in findings2)


def test_no_false_positive_on_plain_text():
    findings = pii_scanner.scan_text("The weather today is sunny with a high of 75 degrees.")
    assert findings == []


def test_redact_replaces_span():
    text = "email me at darani@example.com please"
    findings = pii_scanner.scan_text(text)
    redacted = pii_scanner.redact(text, findings)
    assert "darani@example.com" not in redacted
    assert "[REDACTED:EMAIL]" in redacted


def test_scan_arguments_block_vs_redact_vs_allow():
    args = {"body": "here is my ssn 123-45-6789"}
    assert pii_scanner.scan_arguments(args, action="block").allowed is False
    assert pii_scanner.scan_arguments(args, action="redact").allowed is True
    assert pii_scanner.scan_arguments(args, action="allow").allowed is True
