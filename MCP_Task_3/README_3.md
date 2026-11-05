Task 3 --- LLM Gateway with Streaming PII Redaction
Overview
This project implements a FastAPI gateway that proxies chat-completion
requests to a configured Cohere-compatible LLM endpoint. It redacts
supported personally identifiable information (PII) from incoming
messages before forwarding them to the provider and from generated text
before streaming it back to the client.
Key Features
- FastAPI POST /chat endpoint with streamed Server-Sent Events
  (SSE).
- Input-side and output-side PII redaction.
- Incremental redaction for values split across streaming chunks.
- Separate redaction buffers for each response choice.
- Environment-based provider configuration.
- Sanitized provider and streaming error responses.
- GET /health endpoint.
Architecture
1. The client submits a chat request to /chat.
2. FastAPI validates the request.
3. The gateway redacts supported PII patterns in incoming message text.
4. The sanitized request is sent to the configured LLM provider with
   streaming enabled.
5. The gateway processes provider SSE events and redacts generated text
   incrementally.
6. Redacted text is streamed to the client. Any retained text is
   checked and flushed when the stream ends.
The provider receives redacted input, and the client receives redacted
generated output.
PII Coverage
The redactor uses regular-expression patterns to detect:
- Email addresses.
- Full US Social Security numbers.
- Partial SSN values when introduced by an SSN label.
- Payment-card-like digit sequences.
- Common US phone-number formats.
- Passport numbers when introduced by a passport label.
- Other labelled identifiers, such as driver's license, national ID,
  and tax ID.
Matched values are replaced with:
[REDACTED]
Detection is pattern-based and does not verify that an identifier is
genuine or valid. Unlabelled identifiers and unsupported formats may not
be detected.
Streaming Design
The redactor retains a bounded text tail between chunks so a sensitive
value split across provider events can be detected before release. Large
chunks are processed in smaller slices. Each response choice has its own
redactor instance, preventing text from separate choices from being
combined.
Configuration
Create a .env file in the project root:
COHERE_API_KEY=your_provider_api_key
COHERE_CHAT_COMPLETIONS_URL=https://your-provider-host/v1/chat/completions
COHERE_MODEL=your_model_name
Use the endpoint and model configured for your provider account. Do not
commit .env or expose API keys in source control, screenshots, logs,
or assessment submissions. Rotate any key that has been exposed.
Installation
From the project directory:
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Run
Start the FastAPI gateway:
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
- Swagger UI: http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/health
To run the browser chat interface, open a second terminal, activate the
same environment, and run:
python chat_app.py
Then open http://127.0.0.1:5500. Keep the FastAPI gateway running
while using the chat interface.
Tests
Run the focused redactor tests:
python -m pytest -v test_pii_redactor.py
Run the full available test suite:
python -m pytest -v
Tests cover supported PII patterns and streaming chunk-boundary
behavior. Passing tests demonstrate the cases covered by the test suite;
they do not guarantee detection of every possible PII format or prove
every external provider configuration.
Limitations and Security Considerations
- Regex-based detection cannot guarantee detection of every identifier
  format.
- Passport and partial SSN detection depend on labels; unlabelled
  values may not be detected.
- Card and phone detection are pattern-based and may produce false
  positives.
- Redacting input changes what the model receives: matched values are
  replaced with [REDACTED].
- The gateway does not currently provide client authentication, rate
  limiting, or tenant-level authorization. Deploy it behind
  appropriate access controls.
- Production deployments should use TLS, secure secret management,
  suitable upstream timeouts, monitoring, and stricter request
  validation.
Project Structure
MCP_Task_3/
├── main.py
├── pii_redactor.py
├── test_pii_redactor.py
├── chat_app.py
├── requirements.txt
├── .env                 # Local secrets; do not commit
├── README_3.md
└── tests/
main.py contains the FastAPI gateway and streaming proxy.
pii_redactor.py contains the redaction logic. test_pii_redactor.py
contains focused redactor tests, and chat_app.py provides the browser
interface.
Summary
Task 3 demonstrates a streaming LLM gateway that applies pattern-based
PII redaction to both incoming prompts and generated responses. It
combines FastAPI, asynchronous HTTP streaming, SSE processing,
incremental text handling, and focused tests while documenting the
limitations of regex-based detection.