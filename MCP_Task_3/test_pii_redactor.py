from pii_redactor import REDACTION, StreamingPIIRedactor, redact_pii


def test_redacts_email_full_ssn_and_card():
    text = "Email jane@example.com SSN 123-45-6789 card 4111 1111 1111 1111"
    result = redact_pii(text)
    assert "jane@example.com" not in result
    assert "123-45-6789" not in result
    assert "4111 1111 1111 1111" not in result


def test_redacts_partial_ssn_when_labelled():
    assert "9465" not in redact_pii("SSN: 9465")


def test_redacts_labelled_passport():
    assert "W1946269" not in redact_pii("Passport Number: W1946269")


def test_redacts_phone():
    assert "+1 617 888 3595" not in redact_pii("Call +1 617 888 3595")


def test_streaming_split_email_and_passport():
    redactor = StreamingPIIRedactor()
    chunks = [
        redactor.feed("Contact: john.smith@exa"),
        redactor.feed("mple.com. Passport Number: W194"),
        redactor.feed("6269. SSN: 9465"),
        redactor.finish(),
    ]
    combined = "".join(chunks)
    assert "john.smith@example.com" not in combined
    assert "W1946269" not in combined
    assert "9465" not in combined


def test_does_not_redact_unlabelled_four_digit_number():
    assert "Order 9465" == redact_pii("Order 9465")
