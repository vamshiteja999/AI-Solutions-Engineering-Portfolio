from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import http.client
import json
import logging
import os
import re
import secrets
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

log = logging.getLogger("mcp-gateway")

# --------------------------------------------------------------------------- #
# Error codes
# --------------------------------------------------------------------------- #

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
# MCP reserves -32000..-32019 for implementation-defined errors (-32020..-32099 are the
# spec's own), so these two are safe to use.
UNAUTHENTICATED = -32000
UNAUTHORIZED_TOOL_CALL = -32001  # fixed by the assignment
HEADER_MISMATCH = -32020  # MCP 2026-07-28 "HeaderMismatch"

# --------------------------------------------------------------------------- #
# Authorization policy
# --------------------------------------------------------------------------- #

ROLE_RANK: Mapping[str, int] = {"viewer": 1, "admin": 2}


@dataclass(frozen=True)
class ToolRule:
    """Tools whose (normalised) name starts with ``prefix`` need at least ``min_role``."""

    prefix: str
    min_role: str


TOOL_RULES: tuple[ToolRule, ...] = (ToolRule(prefix="admin_", min_role="admin"),)

# Demo credentials, used ONLY when neither GATEWAY_TOKENS nor GATEWAY_JWT_SECRET is set.
DEMO_TOKENS: Mapping[str, str] = {"admin-token": "admin", "viewer-token": "viewer"}

# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class GatewayError(Exception):
    """An error that maps to one HTTP response carrying a JSON-RPC error object.

    ``reason`` is for the server log only and is never sent to the client.
    """

    def __init__(
        self,
        status: int,
        code: int,
        message: str,
        *,
        rpc_id: Any = None,
        data: Any = None,
        headers: Mapping[str, str] | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.rpc_id = rpc_id
        self.data = data
        self.headers = dict(headers or {})
        self.reason = reason or message

    def payload(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return {"jsonrpc": "2.0", "id": self.rpc_id, "error": error}


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def parse_token_table(spec: str) -> dict[str, str]:
    """Parse ``"tokenA=admin,tokenB=viewer"``. Fails fast on unknown roles."""
    table: dict[str, str] = {}
    for item in filter(None, (part.strip() for part in spec.split(","))):
        token, sep, role = item.rpartition("=")  # rpartition: tokens may contain '='
        if not sep or not token or role not in ROLE_RANK:
            raise ValueError(f"bad GATEWAY_TOKENS entry (expected token=role, role in {sorted(ROLE_RANK)})")
        table[token] = role
    return table


@dataclass(frozen=True)
class Config:
    downstream_url: str = "http://127.0.0.1:9001/mcp"
    mcp_path: str = "/mcp"
    jwt_secret: str | None = None
    static_tokens: Mapping[str, str] = field(default_factory=dict)
    allowed_origins: frozenset[str] = frozenset()
    max_body_bytes: int = 1024 * 1024
    downstream_timeout: float = 60.0  # connect + each blocking read
    client_timeout: float = 30.0  # idle/slow-client guard

    def __post_init__(self) -> None:
        parts = urlsplit(self.downstream_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"downstream_url must be an http(s) URL, got {self.downstream_url!r}")
        if not self.mcp_path.startswith("/"):
            raise ValueError("mcp_path must start with '/'")
        if not self.jwt_secret and not self.static_tokens:
            raise ValueError("configure at least one of jwt_secret / static_tokens")
        for role in self.static_tokens.values():
            if role not in ROLE_RANK:
                raise ValueError(f"unknown role {role!r} in static_tokens")

    @classmethod
    def from_env(cls, **overrides: Any) -> "Config":
        env = os.environ
        tokens = parse_token_table(env.get("GATEWAY_TOKENS", ""))
        secret = env.get("GATEWAY_JWT_SECRET") or None
        if not tokens and not secret:
            log.warning("no GATEWAY_TOKENS / GATEWAY_JWT_SECRET set: using built-in DEMO tokens - do not deploy like this")
            tokens = dict(DEMO_TOKENS)
        if secret and len(secret) < 32:
            log.warning("GATEWAY_JWT_SECRET is shorter than 32 characters; use a long random secret")
        origins = frozenset(o.strip() for o in env.get("GATEWAY_ALLOWED_ORIGINS", "").split(",") if o.strip())
        values: dict[str, Any] = {
            "downstream_url": env.get("GATEWAY_DOWNSTREAM_URL", cls.downstream_url),
            "mcp_path": env.get("GATEWAY_PATH", cls.mcp_path),
            "jwt_secret": secret,
            "static_tokens": tokens,
            "allowed_origins": origins,
        }
        values.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**values)


# --------------------------------------------------------------------------- #
# Authentication: Bearer token -> Identity(role)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Identity:
    subject: str
    role: str


_TOKEN68 = re.compile(r"[A-Za-z0-9\-._~+/]+=*")  # RFC 6750 token68


def parse_bearer(values: list[str] | None) -> str:
    """Extract the token from exactly one ``Authorization: Bearer <token>`` header."""
    if not values:
        raise _unauthenticated("missing Authorization header")
    if len(values) != 1:
        raise _unauthenticated("multiple Authorization headers")
    scheme, _, rest = values[0].partition(" ")
    token = rest.strip()
    if scheme.lower() != "bearer" or not _TOKEN68.fullmatch(token):
        raise _unauthenticated("malformed Authorization header")
    return token


def _unauthenticated(reason: str) -> GatewayError:
    # The client always gets the same generic message; the specific reason is logged only.
    return GatewayError(
        401,
        UNAUTHENTICATED,
        "Authentication required",
        headers={"WWW-Authenticate": 'Bearer realm="mcp-gateway"'},
        reason=reason,
    )


def _b64url_decode(segment: str) -> bytes:
    padded = segment.replace("-", "+").replace("_", "/") + "=" * (-len(segment) % 4)
    return base64.b64decode(padded, validate=True)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue_jwt(secret: str, role: str, subject: str = "user", ttl: int = 3600, now: float | None = None) -> str:
    """Mint an HS256 JWT carrying a ``role`` claim (for demos and tests)."""
    issued = int(time.time() if now is None else now)
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {"sub": subject, "role": role, "iat": issued, "exp": issued + ttl}
    signing_input = ".".join(_b64url_encode(json.dumps(p, separators=(",", ":")).encode()) for p in (header, claims))
    sig = hmac.new(secret.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def verify_jwt(token: str, secret: str, now: float | None = None) -> dict[str, Any]:
    """Verify an HS256 JWT and return its claims. Raises ``ValueError`` on any problem."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        # Only HS256 is accepted: this rejects alg=none and algorithm-confusion attacks.
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            raise ValueError("unsupported alg")
        expected = hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
            raise ValueError("bad signature")
        claims = json.loads(_b64url_decode(payload_b64))
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise ValueError(f"invalid token: {exc}") from None
    if not isinstance(claims, dict):
        raise ValueError("claims are not an object")
    current = time.time() if now is None else now
    for claim, ok in (("exp", lambda v: current < v), ("nbf", lambda v: current >= v)):
        if claim in claims:
            value = claims[claim]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not ok(value):
                raise ValueError(f"{claim} check failed")
    return claims


class Authenticator:
    """Resolves a bearer token to an Identity via signed JWT and/or a static token table."""

    def __init__(self, jwt_secret: str | None, static_tokens: Mapping[str, str]) -> None:
        self._secret = jwt_secret
        self._static = {t.encode(): r for t, r in static_tokens.items()}

    def authenticate(self, authorization_headers: list[str] | None) -> Identity:
        token = parse_bearer(authorization_headers)
        if self._secret and token.count(".") == 2:
            try:
                claims = verify_jwt(token, self._secret)
            except ValueError as exc:
                raise _unauthenticated(str(exc)) from None
            role, subject = claims.get("role"), claims.get("sub")
            return self._identity(role, subject if isinstance(subject, str) else "unknown")

        role = None
        candidate = token.encode()
        for known, known_role in self._static.items():  # no early exit: constant-ish time
            if hmac.compare_digest(known, candidate):
                role = known_role
        if role is None:
            raise _unauthenticated("unknown token")
        return self._identity(role, "static-token")

    @staticmethod
    def _identity(role: Any, subject: str) -> Identity:
        if not isinstance(role, str) or role not in ROLE_RANK:
            # Authenticated, but no role we recognise: fail closed.
            raise GatewayError(403, UNAUTHENTICATED, "Forbidden", reason=f"unrecognised role {role!r}")
        return Identity(subject=subject, role=role)


# --------------------------------------------------------------------------- #
# JSON-RPC parsing
# --------------------------------------------------------------------------- #


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKey(key)
        obj[key] = value
    return obj


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def parse_json(raw: bytes) -> Any:
    """Strictly parse a request body.

    Rejects everything on which two JSON parsers commonly disagree - duplicate object
    keys, NaN/Infinity, invalid UTF-8, a BOM - because a gateway that authorises on one
    reading while the downstream executes another reading is a bypass.
    """
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except _DuplicateKey:
        raise GatewayError(400, INVALID_REQUEST, "Invalid Request: duplicate object keys are not allowed") from None
    except (ValueError, RecursionError):  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        raise GatewayError(400, PARSE_ERROR, "Parse error") from None


_MISSING = object()


@dataclass(frozen=True)
class Message:
    kind: str  # "request" | "notification" | "response"
    id: Any
    method: str | None
    params: Any


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def classify(obj: Any) -> Message:
    """Validate JSON-RPC 2.0 structure and classify the message."""

    def invalid(text: str, rpc_id: Any = None) -> GatewayError:
        return GatewayError(400, INVALID_REQUEST, f"Invalid Request: {text}", rpc_id=rpc_id)

    if isinstance(obj, list):
        # MCP's Streamable HTTP transport carries exactly one message per POST, and
        # accepting batches would let an admin call hide among harmless ones.
        raise invalid("batch requests are not supported; send one message per POST")
    if not isinstance(obj, dict):
        raise invalid("body must be a JSON object")

    raw_id = obj.get("id", _MISSING)
    has_id = raw_id is not _MISSING
    if has_id and not _valid_id(raw_id):
        raise invalid("id must be a string or an integer")
    echo_id = raw_id if has_id else None

    if obj.get("jsonrpc") != "2.0":
        raise invalid('"jsonrpc" must be "2.0"', echo_id)

    if "method" in obj:
        method = obj["method"]
        if not isinstance(method, str) or not method:
            raise invalid('"method" must be a non-empty string', echo_id)
        params = obj.get("params")
        if "params" in obj and not isinstance(params, (dict, list)):
            raise invalid('"params" must be an object or an array', echo_id)
        return Message("request" if has_id else "notification", echo_id, method, params)

    if has_id and ("result" in obj) != ("error" in obj):
        return Message("response", echo_id, None, None)  # client reply to a server-initiated request
    raise invalid("not a request, notification or response", echo_id)


# --------------------------------------------------------------------------- #
# Mirrored MCP headers (Mcp-Method / Mcp-Name)
# --------------------------------------------------------------------------- #

_NAME_FIELD = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}


def _decode_mirrored(value: str) -> str:
    """Decode the ``=?base64?...?=`` sentinel form used for non-ASCII header values."""
    if value.startswith("=?base64?") and value.endswith("?=") and len(value) > 11:
        return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
    return value


def check_mirrored_headers(headers: Any, msg: Message) -> None:
    """Reject requests whose Mcp-Method / Mcp-Name headers disagree with the body.

    The spec mirrors these body fields into headers so intermediaries can route on them;
    if different components trust different sources of truth, that is a bypass.
    Authorization here always uses the body; this just guarantees nobody downstream
    can be steered by a conflicting header.
    """
    if msg.kind == "response":
        return

    def mismatch(what: str) -> GatewayError:
        return GatewayError(400, HEADER_MISMATCH, f"Header mismatch: {what}", rpc_id=msg.id)

    def single(name: str) -> str | None:
        values = headers.get_all(name) or []
        if len(values) > 1:
            raise mismatch(f"duplicate {name} header")
        return values[0] if values else None

    method_header = single("Mcp-Method")
    if method_header is not None and method_header != msg.method:
        raise mismatch("Mcp-Method does not match the request body")

    name_header = single("Mcp-Name")
    source = _NAME_FIELD.get(msg.method or "")
    if name_header is not None and source is not None:
        body_value = msg.params.get(source) if isinstance(msg.params, dict) else None
        try:
            header_value = _decode_mirrored(name_header)
        except (ValueError, UnicodeError, binascii.Error):
            raise mismatch("Mcp-Name is malformed") from None
        if header_value != body_value:
            raise mismatch("Mcp-Name does not match the request body")


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #


def _normalise_tool_name(name: str) -> str:
    """Canonical form used ONLY for the access-control decision.

    NFKC folds look-alikes (full-width letters, ligatures), invisible format/control
    characters are dropped, and case is folded. This can only ever over-match (block
    more), never under-match; the name forwarded downstream is untouched.
    """
    folded = unicodedata.normalize("NFKC", name)
    folded = "".join(ch for ch in folded if unicodedata.category(ch) not in ("Cf", "Cc"))
    return folded.strip().casefold()


def required_role_for_tool(name: str) -> str | None:
    key = _normalise_tool_name(name)
    for rule in TOOL_RULES:
        if key.startswith(rule.prefix):
            return rule.min_role
    return None


def authorize(msg: Message, identity: Identity) -> str | None:
    """Apply the policy; return the tool name for tools/call (for audit logs).

    JSON-RPC *requests* are answered with a JSON-RPC error on HTTP 200 (it is a valid
    JSON-RPC response); *notifications* cannot carry a response, so they get an HTTP
    error status with an id-less error body.
    """
    if msg.method != "tools/call":
        return None
    is_request = msg.kind == "request"

    name = msg.params.get("name") if isinstance(msg.params, dict) else None
    if not isinstance(name, str) or not name:
        raise GatewayError(
            200 if is_request else 400,
            INVALID_PARAMS,
            "Invalid params: 'name' must be a non-empty string",
            rpc_id=msg.id,
        )

    required = required_role_for_tool(name)
    if required is not None and ROLE_RANK[identity.role] < ROLE_RANK[required]:
        raise GatewayError(
            200 if is_request else 403,
            UNAUTHORIZED_TOOL_CALL,
            "Unauthorized Tool Call",
            rpc_id=msg.id,
            data={"tool": name[:128], "requiredRole": required},
            reason=f"role {identity.role!r} lacks {required!r} for tool {name[:128]!r}",
        )
    return name


# --------------------------------------------------------------------------- #
# Header hygiene
# --------------------------------------------------------------------------- #

HOP_BY_HOP = frozenset(
    {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}
)
_FOLD = re.compile(r"\r?\n[ \t]+")


def _connection_listed(headers: Any) -> set[str]:
    listed: set[str] = set()
    for value in headers.get_all("Connection") or []:
        listed.update(token.strip().lower() for token in value.split(",") if token.strip())
    return listed


def build_downstream_headers(incoming: Any, identity: Identity, client_ip: str) -> list[tuple[str, str]]:
    """Headers for the downstream hop.

    * Authorization is NOT forwarded (the downstream never sees the client's credential).
    * Hop-by-hop headers (and any header named by ``Connection``) are dropped.
    * Any client-supplied ``X-Gateway-*`` / ``X-Forwarded-*`` header is dropped so identity
      cannot be spoofed; the gateway then sets the trustworthy values itself.
    * Everything else, including Mcp-*, Accept and Content-Type, passes through.
    """
    drop = HOP_BY_HOP | _connection_listed(incoming) | {"host", "content-length", "authorization", "expect"}
    out: list[tuple[str, str]] = []
    for name, value in incoming.items():
        lower = name.lower()
        if lower in drop or lower.startswith(("x-gateway-", "x-forwarded-")):
            continue
        out.append((name, _FOLD.sub(" ", value)))  # collapse obs-fold line continuations
    out.append(("X-Gateway-User-Role", identity.role))
    out.append(("X-Gateway-Subject", re.sub(r"[^\x21-\x7e]", "?", identity.subject)[:128]))
    out.append(("X-Forwarded-For", client_ip))
    out.append(("Connection", "close"))
    return out


# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #

_CONTENT_LENGTH = re.compile(r"[0-9]{1,12}")


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], config: Config) -> None:
        self.config = config
        self.authenticator = Authenticator(config.jwt_secret, config.static_tokens)
        self.downstream = urlsplit(config.downstream_url)
        super().__init__(address, GatewayHandler)


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mcp-gateway/1.0"
    sys_version = ""
    server: GatewayServer  # type: ignore[assignment]

    # -- plumbing ----------------------------------------------------------- #

    def setup(self) -> None:
        self.timeout = self.server.config.client_timeout
        super().setup()

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        log.debug("%s %s", self.address_string(), format % args)

    do_GET = do_POST = do_DELETE = lambda self: self._handle()  # noqa: E731

    def _begin(self) -> None:
        """Per-request state. One handler instance serves many requests on a keep-alive connection."""
        self.request_id = secrets.token_hex(6)
        self._unread_body = self._declares_body()
        self._headers_sent = False

    def _reject_method(self) -> None:
        self._begin()
        self._send_error(
            GatewayError(405, INVALID_REQUEST, "Method not allowed", headers={"Allow": "GET, POST, DELETE"}),
        )

    do_PUT = do_PATCH = do_HEAD = do_OPTIONS = lambda self: self._reject_method()  # noqa: E731

    # -- responses ---------------------------------------------------------- #

    def _send_json(self, status: int, payload: Any, headers: Mapping[str, str] | None = None, close: bool = False) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-Id", self.request_id)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":  # a HEAD response carries the headers (incl. Content-Length) but never a body
            self.wfile.write(body)

    def _send_error(self, err: GatewayError) -> None:
        # If we answered without consuming the request body, those bytes would be parsed as
        # the next request on a keep-alive connection (request smuggling): close instead.
        close = getattr(self, "_unread_body", False)
        data = err.payload()
        if err.data is None and err.status >= 500:
            data["error"]["data"] = {"requestId": self.request_id}
        self._send_json(err.status, data, err.headers, close=close)

    # -- request body ------------------------------------------------------- #

    def _declares_body(self) -> bool:
        length = self.headers.get("Content-Length")
        return self.headers.get("Transfer-Encoding") is not None or (length is not None and length.strip() != "0")

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            raise GatewayError(411, INVALID_REQUEST, "Length Required: chunked request bodies are not supported")
        lengths = self.headers.get_all("Content-Length") or []
        if not lengths:
            raise GatewayError(411, INVALID_REQUEST, "Length Required")
        if len(lengths) != 1 or not _CONTENT_LENGTH.fullmatch(lengths[0].strip()):
            raise GatewayError(400, INVALID_REQUEST, "Invalid Content-Length")
        size = int(lengths[0])
        if size > self.server.config.max_body_bytes:
            raise GatewayError(413, INVALID_REQUEST, "Request body too large")
        data = self.rfile.read(size)
        if len(data) != size:
            raise GatewayError(400, INVALID_REQUEST, "Incomplete request body")
        self._unread_body = False
        return data

    # -- pipeline ----------------------------------------------------------- #

    def _check_origin(self) -> None:
        origins = self.headers.get_all("Origin") or []
        if not origins:
            return  # non-browser clients (agents, SDKs) send no Origin
        if len(origins) > 1 or origins[0] not in self.server.config.allowed_origins:
            raise GatewayError(403, INVALID_REQUEST, "Forbidden: origin not allowed", reason=f"origin {origins[0][:100]!r}")

    def _handle(self) -> None:
        self._begin()
        identity: Identity | None = None
        msg: Message | None = None
        cfg = self.server.config
        try:
            url = urlsplit(self.path)
            if self.command == "GET" and url.path == "/healthz":
                self._send_json(200, {"status": "ok"}, close=self._unread_body)
                return
            if url.path != cfg.mcp_path:
                raise GatewayError(404, INVALID_REQUEST, "Not found")

            self._check_origin()
            identity = self.server.authenticator.authenticate(self.headers.get_all("Authorization"))

            payload: bytes | None = None
            if self.command == "POST":
                parsed = parse_json(self._read_body())
                msg = classify(parsed)
                check_mirrored_headers(self.headers, msg)
                tool = authorize(msg, identity)
                log.info(
                    "ALLOW id=%s role=%s sub=%r method=%s tool=%r",
                    self.request_id, identity.role, identity.subject[:64], msg.method or "<response>", tool,
                )
                try:
                    payload = json.dumps(parsed, separators=(",", ":")).encode()  # forward what we inspected
                except (RecursionError, ValueError):  # pathological nesting that parsed but cannot be re-serialised
                    raise GatewayError(400, INVALID_REQUEST, "Invalid Request: message too deeply nested", rpc_id=msg.id) from None
            else:
                log.info("ALLOW id=%s role=%s sub=%r http=%s", self.request_id, identity.role, identity.subject[:64], self.command)

            self._forward(identity, payload, msg.id if msg else None, url.query)

        except GatewayError as err:
            level = logging.WARNING if err.status in (401, 403) or err.code == UNAUTHORIZED_TOOL_CALL else logging.INFO
            log.log(
                level,
                "DENY id=%s status=%s code=%s role=%s method=%s reason=%s",
                self.request_id, err.status, err.code, identity.role if identity else "-",
                msg.method if msg else "-", err.reason,
            )
            if err.rpc_id is None and msg is not None:
                err.rpc_id = msg.id
            if self._headers_sent:
                self.close_connection = True
            else:
                self._send_error(err)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True  # client went away or stalled
        except Exception:  # noqa: BLE001 - last-resort guard; details go to the log only
            log.exception("UNHANDLED id=%s", self.request_id)
            self.close_connection = True
            if not self._headers_sent:
                self._send_error(GatewayError(500, INTERNAL_ERROR, "Internal gateway error", rpc_id=msg.id if msg else None))

    # -- forwarding --------------------------------------------------------- #

    def _forward(self, identity: Identity, payload: bytes | None, rpc_id: Any, query: str) -> None:
        cfg, down = self.server.config, self.server.downstream
        target = (down.path or "/") + (f"?{query}" if query else "")
        headers = build_downstream_headers(self.headers, identity, self.client_address[0])
        connection_cls = http.client.HTTPSConnection if down.scheme == "https" else http.client.HTTPConnection
        conn = connection_cls(down.hostname, down.port, timeout=cfg.downstream_timeout)
        try:
            try:
                names = {n.lower() for n, _ in headers}
                conn.putrequest(self.command, target, skip_accept_encoding="accept-encoding" in names)
                for name, value in headers:
                    conn.putheader(name, value)
                if payload is not None:
                    conn.putheader("Content-Length", str(len(payload)))
                conn.endheaders(payload)
                upstream = conn.getresponse()
            except TimeoutError as exc:
                raise GatewayError(
                    504, INTERNAL_ERROR, "Downstream MCP server timed out", rpc_id=rpc_id, reason=f"downstream timeout: {exc!r}"
                ) from None
            except (OSError, http.client.HTTPException, ValueError) as exc:
                raise GatewayError(
                    502, INTERNAL_ERROR, "Downstream MCP server unavailable", rpc_id=rpc_id, reason=f"downstream error: {exc!r}"
                ) from None
            self._relay(upstream)
        finally:
            conn.close()

    def _relay(self, upstream: http.client.HTTPResponse) -> None:
        """Stream the downstream reply to the client without buffering it."""
        status = upstream.status
        drop = HOP_BY_HOP | _connection_listed(upstream.msg) | {"content-length", "server", "date"}
        passthrough = [(k, _FOLD.sub(" ", v)) for k, v in upstream.getheaders() if k.lower() not in drop]
        has_body = self.command != "HEAD" and status not in (204, 304) and not 100 <= status < 200
        chunked_down = "chunked" in (upstream.getheader("Transfer-Encoding") or "").lower()
        known_length = upstream.length is not None and not chunked_down
        content_type = (upstream.getheader("Content-Type") or "").lower()

        self.send_response(status, upstream.reason)
        for name, value in passthrough:
            self.send_header(name, value)
        if content_type.startswith("text/event-stream") and not upstream.getheader("X-Accel-Buffering"):
            self.send_header("X-Accel-Buffering", "no")  # stop nginx-style proxies buffering the stream
        self.send_header("X-Request-Id", self.request_id)

        chunked_out = False
        if not has_body:
            pass
        elif known_length:
            self.send_header("Content-Length", str(upstream.length))
        elif self.request_version == "HTTP/1.1":
            self.send_header("Transfer-Encoding", "chunked")
            chunked_out = True
        else:  # HTTP/1.0 client: delimit by closing the connection
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self._headers_sent = True
        if not has_body:
            return

        try:
            while True:
                chunk = upstream.read1(65536)
                if not chunk:
                    break
                self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk) if chunked_out else chunk)
            if chunked_out:
                self.wfile.write(b"0\r\n\r\n")
        except (OSError, http.client.HTTPException) as exc:
            # Headers are already out, so the status can no longer change. Closing without a
            # terminating chunk is how the client learns the stream was cut short.
            log.warning("STREAM-ABORT id=%s %r", self.request_id, exc)
            self.close_connection = True


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def make_server(config: Config, host: str = "127.0.0.1", port: int = 0) -> GatewayServer:
    return GatewayServer((host, port), config)


def main(argv: Iterable[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="MCP security gateway (authenticating reverse proxy)")
    parser.add_argument("--host", default=os.environ.get("GATEWAY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("GATEWAY_PORT", "8080")))
    parser.add_argument("--downstream", help="downstream MCP endpoint URL (env GATEWAY_DOWNSTREAM_URL)")
    parser.add_argument("--path", help="path this gateway serves (env GATEWAY_PATH, default /mcp)")
    args = parser.parse_args(list(argv) if argv is not None else None)

    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = Config.from_env(downstream_url=args.downstream, mcp_path=args.path)
    server = make_server(config, args.host, args.port)
    log.info("listening on http://%s:%s%s -> %s", args.host, server.server_address[1], config.mcp_path, config.downstream_url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
