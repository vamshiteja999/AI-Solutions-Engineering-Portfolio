
import re

REDACTION = "[REDACTED]"
HOLD_BACK = 320
FEED_SLICE = 1024
MAX_EMAIL_LENGTH = 254

EMAIL = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9-])"
)

# Full US SSN, whether or not punctuation is present.
SSN = re.compile(
    r"(?<!\d)(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}(?!\d)"
)

# Also catch partial SSNs when explicitly labelled, e.g. "SSN: 9465".
LABELLED_SSN = re.compile(
    r"(?i)\b(?:SSN|Social\s+Security(?:\s+Number)?)\s*[:#=-]?\s*"
    r"(?P<value>(?:\d{3}[- ]?)?\d{2}[- ]?\d{4}|\d{4})\b"
)

# Card-like 13-19 digit sequences, with optional spaces/hyphens.
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

# US phone number formats. Require 10 digits (optional leading country code).
PHONE = re.compile(
    r"(?<!\w)(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?!\d)"
)

# Passport values are only matched when introduced by a passport label to
# avoid redacting arbitrary alphanumeric words or IDs.
PASSPORT = re.compile(
    r"(?i)\b(?:US\s+)?Passport(?:\s+(?:Number|No\.?))?\s*[:#=-]?\s*"
    r"(?P<value>[A-Z0-9][A-Z0-9 -]{5,14}[A-Z0-9])\b"
)

# Other explicitly labelled identifiers can be safely redacted by label.
LABELLED_ID = re.compile(
    r"(?i)\b(?:Driver'?s?\s+License|National\s+ID|Tax\s+ID)\s*"
    r"[:#=-]?\s*(?P<value>[A-Z0-9-]{5,20})\b"
)


def _spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []

    for match in EMAIL.finditer(text):
        if len(match.group(0)) <= MAX_EMAIL_LENGTH:
            spans.append((match.start(), match.end()))

    for pattern in (SSN, CARD, PHONE):
        spans.extend((m.start(), m.end()) for m in pattern.finditer(text))

    for pattern in (LABELLED_SSN, PASSPORT, LABELLED_ID):
        spans.extend((m.start("value"), m.end("value")) for m in pattern.finditer(text))

    spans.sort()
    merged: list[list[int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def redact_pii(text: str) -> str:
    """Redact supported PII patterns in a complete string."""
    spans = _spans(text)
    if not spans:
        return text

    output: list[str] = []
    cursor = 0
    for start, end in spans:
        output.extend((text[cursor:start], REDACTION))
        cursor = end
    output.append(text[cursor:])
    return "".join(output)


class StreamingPIIRedactor:
    """Redact streamed text while retaining a bounded tail between chunks."""

    def __init__(self, hold_back: int = HOLD_BACK):
        if hold_back < MAX_EMAIL_LENGTH + 1:
            raise ValueError(
                f"hold_back must be at least {MAX_EMAIL_LENGTH + 1} characters"
            )
        self.hold_back = hold_back
        self.pending = ""

    def feed(self, chunk: str) -> str:
        if not chunk:
            return ""

        output: list[str] = []
        for offset in range(0, len(chunk), FEED_SLICE):
            self.pending += chunk[offset : offset + FEED_SLICE]
            if len(self.pending) <= self.hold_back:
                continue

            cut = len(self.pending) - self.hold_back
            for start, end in _spans(self.pending):
                if start < cut < end:
                    cut = start
                    break

            if cut:
                output.append(redact_pii(self.pending[:cut]))
                self.pending = self.pending[cut:]

        return "".join(output)

    def finish(self) -> str:
        """Redact and return the final retained tail at end-of-stream."""
        result = redact_pii(self.pending)
        self.pending = ""
        return result
