Task 4 --- Token-Aware LLM Gateway with Provider Fallback
Overview
This project implements an LLM gateway that applies token-usage limits
per tenant and routes chat-completion requests across a primary and
secondary provider. If the primary provider is unavailable or rejects a
request for a configured fallback condition, the gateway retries the
same prompt through the secondary provider.

The gateway uses SQLite for persistent token-usage records and
asynchronous orchestration around provider requests.
Key Features
- Per-tenant token-aware rate limiting over a configurable time
  window.
- SQLite-backed usage tracking.
- Primary-provider-first routing.
- Secondary-provider fallback for configured provider failures,
  including rate limits and timeouts.
- Provider-specific usage limits that can cause the primary to be
  skipped.
- Standardized, sanitized gateway errors.
- Concurrent request handling and tests for simultaneous usage.
- Mock provider endpoints for deterministic testing.
Request Flow
1. The client submits a prompt and tenant credential to the gateway.
2. The gateway estimates the request token usage.
3. The tenant-wide token budget is checked and recorded in SQLite.
4. If the tenant budget is exceeded, the gateway returns a rate-limit
   response without calling either provider.
5. If the primary provider's separate budget is exhausted, the gateway
   skips it and tries the secondary provider.
6. Otherwise, the gateway attempts the primary provider first.
7. If the primary returns a configured fallback status or times out,
   the same prompt is sent to the secondary provider.
8. Provider failures are converted into sanitized gateway errors rather
   than exposing raw stack traces or internal details.
The tenant-wide limit is independent of provider selection. Switching
providers does not bypass the tenant's overall token budget.
Rate-Limit Model
The gateway tracks usage by bucket:
- Tenant bucket: enforces the overall token allowance for a tenant
  during the configured window.
- Primary-provider bucket: optionally limits usage sent to the
  primary provider. If this budget is exhausted, the request can be
  routed to the secondary provider.
A rate window is the duration over which usage is counted. For example,
a 60-second window means the gateway evaluates token usage over the
configured one-minute period. The token limit and window duration are
separate settings.

The implementation estimates token usage for admission control. An
estimate is not necessarily identical to the provider's final billed
token count.
Persistence and Concurrency
SQLite stores token usage on disk. The limiter uses transactions to
coordinate concurrent updates and removes expired usage records for the
relevant bucket. Database operations are moved off the event loop using
asyncio.to_thread.

For local development, stop the application before replacing or deleting
an old database. A schema change may require a deliberate migration;
deleting a database is not an appropriate production migration strategy.
Configuration
Configure the primary and secondary provider endpoints, model names,
provider credentials, tenant token limit, rate window, and optional
primary-provider limit using the settings supported by llm_gateway.py
and the local runner.

Keep credentials outside source control. Do not commit API keys or
include them in screenshots, logs, or assessment documentation. Rotate
any key that has been exposed.
Run and Test
Start the mock provider service using the command and options supported
by mock_llm.py or the supplied mock-server runner.

Run the gateway using the supplied application entry point and its
configured provider settings. Check the command-line help or project
runner for the exact options in the submitted version.

Run the router test suite:
python -m pytest -v test_router.py
The tests cover primary success, primary timeout fallback, primary
rate-limit fallback, tenant rate limiting, and concurrent requests
against the mock providers.
Project Components
MCP_TASK_4/
├── llm_gateway.py       # Token limiter and provider routing
├── run_test.py          # Example gateway runner/client
├── mock_llm.py          # Mock provider endpoints
├── test_router.py       # Router and rate-limit tests
└── server.py            # Additional application entry point, if used
The exact files present may vary with the submitted project version. Use
the actual entry point and configuration names in the code being
submitted.
Limitations and Production Considerations
- Token counts are estimated for rate admission and may differ from
  provider-reported usage.
- A synchronous provider request executed in a worker thread cannot be
  forcibly stopped merely by cancelling the awaiting coroutine;
  provider socket timeouts must also be configured.
- Provider-specific fallback rules should be chosen carefully. Falling
  back on authentication or configuration errors can conceal a broken
  primary-provider setup.
- SQLite is appropriate for a small assessment or single-host
  deployment. A multi-instance production gateway may require a shared
  transactional store.
- Production deployments should add client authentication, TLS, secret
  management, observability, request-size limits, and operational
  controls.
Summary
Task 4 demonstrates a token-aware LLM gateway that enforces tenant usage
limits, persists usage in SQLite, attempts a primary provider first, and
falls back to a secondary provider for configured failure conditions
without bypassing the tenant-wide budget.