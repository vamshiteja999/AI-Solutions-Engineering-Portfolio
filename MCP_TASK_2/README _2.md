Task 2 --- MCP Security Gateway Proxy
Overview
This project implements an HTTP/JSON-RPC gateway between an MCP client
and a downstream MCP server. The gateway authenticates incoming bearer
tokens, maps callers to roles, and enforces tool-level authorization
before forwarding requests.
Key Features
- HTTP reverse proxy to a downstream MCP endpoint.
- Bearer-token authentication with viewer and admin roles.
- Transparent forwarding of tools/list.
- Authorization checks for tools/call.
- Admin-only tool policy based on the admin_ tool-name prefix.
- Local JSON-RPC authorization error for denied tool calls.
- Strict JSON-RPC request parsing and validation.
- Request-body limits, header filtering, and origin allow-list
  support.
- Downstream timeout and connection-error handling.
- Streaming/SSE response forwarding.
Authorization Behavior
- A valid viewer token can call ordinary tools.
- A valid admin token can call ordinary and admin_ tools.
- A viewer attempting to call an admin_ tool is denied by the
  gateway.
- The denied call is not forwarded to the downstream server.
- tools/list is forwarded transparently, as required by the
  assessment.
Denied JSON-RPC tool calls return error code -32001 with the message
Unauthorized Tool Call.
Request Flow
1. The client sends an HTTP request with a bearer token.
2. The gateway validates the token and resolves the caller's role.
3. The gateway validates the JSON-RPC envelope and determines the
   requested method.
4. For tools/call, the gateway checks the requested tool against the
   role policy.
5. Authorized requests are forwarded to the downstream MCP server.
6. The gateway relays the downstream response, including streamed
   responses where applicable.
Configuration
The gateway and mock server are configured through command-line options
and environment variables. The implementation supports token-to-role
configuration, a downstream MCP URL, a gateway path, and optional
allowed origins.

For local testing, set explicit non-production credentials rather than
relying on demonstration defaults. Do not commit real credentials or
secrets.
Run Locally
Start the mock downstream server in Terminal 1:
python mock_server.py --port 9001
Start the gateway in Terminal 2:
GATEWAY_TOKENS="adm-secret=admin,view-secret=viewer" \
python gateway.py --port 8080 \
  --downstream http://127.0.0.1:9001/mcp
The exact command-line options and defaults are defined by gateway.py;
use python gateway.py --help to inspect them.
Example Authorization Checks
Viewer calling an ordinary tool:
curl -i http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer view-secret" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status","arguments":{}}}'
Viewer calling an admin tool should receive -32001 and should not
cause a downstream call. An admin token can call the same admin tool.
Tests
Run the test suite from the project directory:
python -m pytest -v test_gateway.py
The tests exercise authentication, role-based tool authorization,
JSON-RPC validation, denial without downstream forwarding, header
handling, origin checks, streaming behavior, and proxy error handling.
Project Structure
MCP_TASK_2/
├── gateway.py
├── mock_server.py
├── test_gateway.py
└── README.md
gateway.py contains the proxy and authorization middleware.
mock_server.py provides downstream tools for local testing.
test_gateway.py tests the gateway behavior using local mock services.
Limitations and Production Considerations
- The assessment implementation includes a handwritten HS256 JWT path;
  production systems should use a maintained JWT library and
  established validation practices.
- Configure real secrets explicitly and disable demonstration
  credentials in production.
- Terminate TLS at a trusted edge and ensure clients cannot bypass the
  gateway to reach the downstream server directly.
- Add deployment-level rate limits, concurrency controls, monitoring,
  and operational secret management.
- The prefix-based admin_ policy is suitable for the assessment
  rule; a production policy may need explicit per-tool permissions.
Summary
Task 2 demonstrates an authenticated MCP reverse proxy that applies
role-based authorization to tool calls, blocks unauthorized admin
operations before forwarding, and preserves downstream MCP responses.