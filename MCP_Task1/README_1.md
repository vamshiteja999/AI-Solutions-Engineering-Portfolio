Task 1 --- MCP Customer Support Server
Overview
This project implements a Model Context Protocol (MCP) server for a
small customer-support workflow. It exposes tools for retrieving a
customer record and triggering a refund. The server uses the MCP Python
SDK, Pydantic validation, and an in-memory mock data store.
Key Features
- MCP tools: get_customer_record and trigger_refund.
- Strict input validation with Pydantic.
- Customer ID format validation.
- Refund amount and reason validation.
- Structured handling of invalid inputs and application errors.
- STDIO transport, with protocol output kept separate from diagnostic
  logging.
- Tests that exercise the server through a subprocess client.
Tool Behavior
- get_customer_record accepts a customer ID and returns the matching
  mock customer record when found.
- trigger_refund validates the customer, amount, and reason before
  recording a mock refund.
- Invalid inputs are rejected before the operation is performed.
- The project includes configurable validation-error behavior for
  JSON-RPC errors or tool-result errors.
The data store is in memory and is intended for assessment and
demonstration purposes; it is not a persistent customer or payment
system.
Requirements
The project pins the MCP SDK to the version used for the assessment and
constrains the supporting packages in requirements.txt.
Setup
Use Python 3.11 or newer. From the project directory:
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
If the supplied project scripts are present, they can also be used:
./setup.sh
Run the Server
Start the MCP server over STDIO:
.venv/bin/python server.py
The server is intended to be launched by an MCP client or Inspector.
STDIO is the protocol channel, so do not add ordinary print()
debugging output to standard output. Send diagnostics to standard error.

To launch MCP Inspector using the project's virtual environment:
./run_inspector.sh
Tests
Run the black-box test suite:
./run_tests.sh
Or, after activating the virtual environment:
python -m pytest -v test_server.py
The tests cover tool discovery and calls, input validation, JSON-RPC
behavior, STDIO output discipline, and server lifecycle/recovery
scenarios.
Configuration Notes
The server supports the protocol modes implemented in the source and
documented in the project README. Keep the MCP SDK version aligned with
requirements.txt; changing SDK versions may change available APIs or
protocol behavior.
Project Structure
TASK_1_MCP_CLEAN/
├── server.py
├── test_server.py
├── try_client.py
├── requirements.txt
├── setup.sh
├── run_tests.sh
├── run_server.sh
├── run_inspector.sh
├── README.md
└── .gitignore
server.py contains the MCP implementation. test_server.py contains
the subprocess-based tests. try_client.py is a small client smoke
test.
Limitations
- Customer and refund data are stored in memory and are lost when the
  process exits.
- The project is a mock customer-support service, not a production
  payment integration.
- Authentication, authorization, durable storage, and integration with
  a real customer or payment system are outside the assessment
  implementation.
Summary
Task 1 demonstrates an MCP server with validated customer-support tools,
STDIO transport, explicit error handling, and black-box protocol tests.