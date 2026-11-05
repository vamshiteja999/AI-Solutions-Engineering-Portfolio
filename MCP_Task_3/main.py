
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from pii_redactor import StreamingPIIRedactor


# Load configuration from .env when running locally.
load_dotenv()

logger = logging.getLogger("pii_gateway")
logging.basicConfig(level=logging.INFO)

UPSTREAM_URL = os.getenv("COHERE_CHAT_COMPLETIONS_URL")
DEFAULT_MODEL = os.getenv("COHERE_MODEL")

if not UPSTREAM_URL:
    raise RuntimeError("COHERE_CHAT_COMPLETIONS_URL is missing")

if not DEFAULT_MODEL:
    raise RuntimeError("COHERE_MODEL is missing")


class ChatRequest(BaseModel):
    """Request schema accepted by the gateway."""

    messages: list[dict[str, Any]] = Field(min_length=1)
    model: Optional[str] = None
    temperature: Optional[float] = Field(default=None, ge=0, le=2)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create one reusable async HTTP client for the application lifetime."""
    app.state.http = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=15,
            # Streaming generations may take longer overall. A production
            # deployment should add an appropriate read-idle timeout.
            read=None,
            write=30,
            pool=15,
        ),
        limits=httpx.Limits(
            max_connections=100,
            max_keepalive_connections=20,
        ),
    )
    try:
        yield
    finally:
        await app.state.http.aclose()


app = FastAPI(
    title="Streaming PII Redaction Gateway",
    version="1.1.0",
    lifespan=lifespan,
)


def sse(payload: Any) -> bytes:
    """Serialize one JSON payload as a Server-Sent Event."""
    return (
        "data: "
        + json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        + "\n\n"
    ).encode("utf-8")


def stream_error(message: str) -> bytes:
    """Create a sanitized SSE error without exposing provider internals."""
    return sse({"error": {"message": message}})


async def redacted_stream(
    upstream: httpx.Response,
) -> AsyncIterator[bytes]:
    """Redact PII incrementally and relay provider SSE events.

    Each choice index has its own redactor so text from separate choices can
    never be combined in the same rolling buffer.
    """
    redactors: dict[int, StreamingPIIRedactor] = {}

    def get_redactor(index: int) -> StreamingPIIRedactor:
        if index not in redactors:
            redactors[index] = StreamingPIIRedactor()
        return redactors[index]

    def flush(index: int) -> Optional[bytes]:
        tail = get_redactor(index).finish()
        if not tail:
            return None

        return sse(
            {
                "choices": [
                    {
                        "index": index,
                        "delta": {"content": tail},
                        "finish_reason": None,
                    }
                ]
            }
        )

    try:
        async for line in upstream.aiter_lines():
            # This gateway expects an OpenAI-compatible SSE stream where each
            # event payload is carried in a "data:" line.
            if not line.startswith("data:"):
                continue

            raw = line[5:].strip()

            if raw == "[DONE]":
                for index in list(redactors):
                    tail_event = flush(index)
                    if tail_event:
                        yield tail_event

                yield b"data: [DONE]\n\n"
                return

            if not raw:
                continue

            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                # Do not log the raw event: it may contain sensitive content.
                logger.warning("Ignoring malformed upstream SSE event")
                continue

            if isinstance(event, dict) and "error" in event:
                yield stream_error("The upstream model stream failed.")
                return

            choices = (
                event.get("choices", [])
                if isinstance(event, dict)
                else []
            )

            for choice in choices:
                if not isinstance(choice, dict):
                    continue

                try:
                    index = int(choice.get("index", 0))
                except (TypeError, ValueError):
                    index = 0

                delta = choice.get("delta") or {}
                if not isinstance(delta, dict):
                    continue

                content = delta.get("content")

                # Preserve the assistant role event.
                if (
                    isinstance(delta.get("role"), str)
                    and not isinstance(content, str)
                ):
                    yield sse(
                        {
                            "choices": [
                                {
                                    "index": index,
                                    "delta": {"role": delta["role"]},
                                    "finish_reason": None,
                                }
                            ]
                        }
                    )

                # Redact generated text before it leaves the gateway.
                if isinstance(content, str):
                    safe_text = get_redactor(index).feed(content)
                    if safe_text:
                        yield sse(
                            {
                                "choices": [
                                    {
                                        "index": index,
                                        "delta": {"content": safe_text},
                                        "finish_reason": None,
                                    }
                                ]
                            }
                        )

                finish_reason = choice.get("finish_reason")
                if finish_reason is not None:
                    tail_event = flush(index)
                    if tail_event:
                        yield tail_event

                    yield sse(
                        {
                            "choices": [
                                {
                                    "index": index,
                                    "delta": {},
                                    "finish_reason": finish_reason,
                                }
                            ]
                        }
                    )

            # Usage-only events do not contain generated text, so they can
            # be forwarded as metadata.
            if (
                not choices
                and isinstance(event, dict)
                and "usage" in event
            ):
                yield sse({"usage": event["usage"]})

        # Some providers close the stream without sending [DONE].
        for index in list(redactors):
            tail_event = flush(index)
            if tail_event:
                yield tail_event

        yield b"data: [DONE]\n\n"

    except httpx.HTTPError as exc:
        # Headers may already have been sent, so report a sanitized SSE error.
        logger.warning(
            "Upstream stream interrupted (%s)",
            type(exc).__name__,
        )
        yield stream_error("The upstream model stream was interrupted.")

    except Exception as exc:
        # Avoid logging exception messages or payloads that could contain PII.
        logger.exception(
            "Unexpected streaming gateway error (%s)",
            type(exc).__name__,
        )
        yield stream_error("The gateway encountered a streaming error.")

    finally:
        # Also runs when the client disconnects and the generator is cancelled.
        await upstream.aclose()


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "provider": "Cohere-compatible Chat Completions",
    }


def redact_message_content(value: Any) -> Any:
    """Recursively redact textual content before it is sent to the provider.

    Non-text payloads (for example image objects) are preserved unchanged.
    """
    if isinstance(value, str):
        from pii_redactor import redact_pii
        return redact_pii(value)
    if isinstance(value, list):
        return [redact_message_content(item) for item in value]
    if isinstance(value, dict):
        return {
            key: redact_message_content(item) if key in {"text", "content"} else item
            for key, item in value.items()
        }
    return value


@app.post("/chat")
async def chat(body: ChatRequest, request: Request):
    api_key = os.getenv("COHERE_API_KEY")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail="COHERE_API_KEY is not configured",
        )

    payload: dict[str, Any] = {
        "model": body.model or DEFAULT_MODEL,
        "messages": [
            {
                **message,
                "content": redact_message_content(message.get("content")),
            }
            for message in body.messages
        ],
        "stream": True,
        "n": 1,
    }

    if body.temperature is not None:
        payload["temperature"] = body.temperature

    upstream_request = request.app.state.http.build_request(
        "POST",
        UPSTREAM_URL,
        headers={
            "Authorization": "Bearer " + api_key,
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
        json=payload,
    )

    try:
        upstream = await request.app.state.http.send(
            upstream_request,
            stream=True,
        )
    except httpx.HTTPError as exc:
        # Log the exception class only; avoid exposing request/provider data.
        logger.warning(
            "Unable to connect to upstream provider (%s)",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="Unable to reach the LLM provider",
        ) from None

    if upstream.is_error:
        status = upstream.status_code

        # Do not read or log the provider error body. It is not needed to
        # produce a useful client response and could contain sensitive data.
        await upstream.aclose()

        logger.error("Provider returned HTTP %s", status)
        raise HTTPException(
            status_code=502,
            detail="LLM provider returned an error (HTTP {})".format(status),
        )

    return StreamingResponse(
        redacted_stream(upstream),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )
