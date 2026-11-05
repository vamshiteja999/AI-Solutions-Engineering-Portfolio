"""Comprehensive unit and integration test suite for the LLM Gateway Router."""

import asyncio
import os
import pytest
import threading
from llm_gateway import SQLiteRateLimiter, LLMGatewayRouter, GatewayError
from mock_llm import MockLLMServer


@pytest.fixture
def test_db():
    db_path = "test_rate_limiter.db"
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture(scope="module")
def mock_llm():
    server = MockLLMServer(("127.0.0.1", 0))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, port
    server.shutdown()
    server.server_close()


def test_rate_limiter_sliding_window(test_db):
    limiter = SQLiteRateLimiter(test_db)
    key = "tenant_test"

    # Within limit (Limit: 1000, Request: 600)
    assert limiter.check_and_consume(key, 600, limit=1000, window=60) is True

    # Exceeds limit (600 + 500 = 1100 > 1000)
    assert limiter.check_and_consume(key, 500, limit=1000, window=60) is False

    # Another tenant is unaffected
    assert limiter.check_and_consume("tenant_other", 900, limit=1000, window=60) is True
    limiter.close()


@pytest.mark.asyncio
async def test_router_primary_success(test_db, mock_llm):
    server, port = mock_llm
    server.reset()
    limiter = SQLiteRateLimiter(test_db)
    router = LLMGatewayRouter(
        primary_url=f"http://127.0.0.1:{port}/primary-success",
        backup_url=f"http://127.0.0.1:{port}/backup-success",
        rate_limiter=limiter,
    )

    res = await router.handle_completion("tenant_1", {"prompt": "test"}, 100)
    assert res["provider"] == "primary"
    assert "Primary response" in res["data"]["choices"][0]["text"]
    limiter.close()


@pytest.mark.asyncio
async def test_router_timeout_failover_to_backup(test_db, mock_llm):
    server, port = mock_llm
    server.reset()
    limiter = SQLiteRateLimiter(test_db)
    router = LLMGatewayRouter(
        primary_url=f"http://127.0.0.1:{port}/primary-slow",  # Sleeps 4s (>3s timeout)
        backup_url=f"http://127.0.0.1:{port}/backup-success",
        rate_limiter=limiter,
    )

    res = await router.handle_completion("tenant_1", {"prompt": "test"}, 100)
    assert res["provider"] == "backup"
    assert "Backup response" in res["data"]["choices"][0]["text"]
    limiter.close()


@pytest.mark.asyncio
async def test_router_429_failover_to_backup(test_db, mock_llm):
    server, port = mock_llm
    server.reset()
    limiter = SQLiteRateLimiter(test_db)
    router = LLMGatewayRouter(
        primary_url=f"http://127.0.0.1:{port}/primary-429",  # Returns 429
        backup_url=f"http://127.0.0.1:{port}/backup-success",
        rate_limiter=limiter,
    )

    res = await router.handle_completion("tenant_1", {"prompt": "test"}, 100)
    assert res["provider"] == "backup"
    assert "Backup response" in res["data"]["choices"][0]["text"]
    limiter.close()


@pytest.mark.asyncio
async def test_router_rate_limit_blocked_locally(test_db, mock_llm):
    server, port = mock_llm
    limiter = SQLiteRateLimiter(test_db)
    router = LLMGatewayRouter(
        primary_url=f"http://127.0.0.1:{port}/primary-success",
        backup_url=f"http://127.0.0.1:{port}/backup-success",
        rate_limiter=limiter,
    )

    # Exhaust the default 50,000 token limit
    assert limiter.check_and_consume("tenant_limited", 50000, limit=50000, window=60) is True

    # Next completion request should raise GatewayError 429 without hitting upstream
    with pytest.raises(GatewayError) as exc_info:
        await router.handle_completion("tenant_limited", {"prompt": "test"}, 10)

    err = exc_info.value
    assert err.status_code == 429
    assert err.error_code == "RATE_LIMIT_EXCEEDED"
    assert "payload" in dir(err)
    assert "error" in err.payload()
    limiter.close()


@pytest.mark.asyncio
async def test_concurrent_rate_limiter_safety(test_db):
    limiter = SQLiteRateLimiter(test_db)
    key = "tenant_concurrent"

    # Run 50 concurrent requests of 200 tokens each against a limit of 5000 tokens
    async def make_request():
        return limiter.check_and_consume(key, 200, limit=5000, window=60)

    results = await asyncio.gather(*(make_request() for _ in range(50)))

    # Exactly 25 requests should pass (25 * 200 = 5000), the rest blocked
    passed = sum(1 for r in results if r is True)
    assert passed == 25
    limiter.close()
