import asyncio
import json

from pii_redactor import HOLD_BACK, StreamingPIIRedactor, redact_pii
from main import redacted_stream


def test_email_redaction():
    assert redact_pii("Contact john.smith@example.com today") == "Contact [REDACTED] today"


def test_ssn_redaction():
    assert redact_pii("SSN 123-45-6789") == "SSN [REDACTED]"


def test_credit_card_redaction():
    assert redact_pii("Card 4111 1111 1111 1111") == "Card [REDACTED]"


def test_email_split_across_chunks():
    redactor = StreamingPIIRedactor()
    output = redactor.feed("A" * 500 + "Contact: john.smith@")
    output += redactor.feed("example.com")
    output += redactor.finish()
    assert output.endswith("Contact: [REDACTED]")
    assert "john.smith@example.com" not in output


def test_email_split_at_every_character_boundary():
    email = "john.smith@example.com"
    for split_at in range(1, len(email)):
        redactor = StreamingPIIRedactor()
        output = redactor.feed("x" * 500 + "Contact: " + email[:split_at])
        output += redactor.feed(email[split_at:])
        output += redactor.finish()
        assert output.endswith("[REDACTED]"), (split_at, output[-80:])
        assert email not in output


def test_ssn_and_card_split_across_chunks():
    cases = [
        ("SSN: 123-45-", "6789", "SSN: [REDACTED]"),
        ("Card: 4111 1111 ", "1111 1111", "Card: [REDACTED]"),
    ]
    for first, second, expected_suffix in cases:
        redactor = StreamingPIIRedactor()
        output = redactor.feed("x" * 500 + first)
        output += redactor.feed(second)
        output += redactor.finish()
        assert output.endswith(expected_suffix), output[-100:]


def test_pending_buffer_stays_bounded_for_large_input():
    redactor = StreamingPIIRedactor()
    output = redactor.feed("x" * 1_000_000)
    assert len(output) > 0
    assert len(redactor.pending) <= HOLD_BACK + 1024 + 254


class FakeUpstream:
    def __init__(self, lines):
        self.lines = lines
        self.closed = False

    async def aiter_lines(self):
        for line in self.lines:
            yield line

    async def aclose(self):
        self.closed = True


def test_fastapi_stream_function_redacts_email_split_between_deltas():
    lines = [
        'data: ' + json.dumps({"choices": [{"index": 0, "delta": {"content": "x" * 500 + "Email: john.smith@"}, "finish_reason": None}]}),
        'data: ' + json.dumps({"choices": [{"index": 0, "delta": {"content": "example.com"}, "finish_reason": None}]}),
        "data: [DONE]",
    ]
    upstream = FakeUpstream(lines)

    async def collect():
        chunks = []
        async for chunk in redacted_stream(upstream):
            chunks.append(chunk.decode("utf-8"))
        return "".join(chunks)

    result = asyncio.run(collect())
    assert "john.smith@example.com" not in result
    assert "Email: [REDACTED]" in result
    assert "data: [DONE]" in result
    assert upstream.closed
