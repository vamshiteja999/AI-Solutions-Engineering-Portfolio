
import asyncio
import http.client
import json
import logging
import sqlite3
import threading
import time

from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit


log = logging.getLogger("llm-gateway")

DEFAULT_TOKEN_LIMIT = 50000
DEFAULT_WINDOW_SECONDS = 60

PRIMARY_TIMEOUT_SECONDS = 3.0
SECONDARY_TIMEOUT_SECONDS = 10.0


# ============================================================
# 1. Standardized Gateway Error
# ============================================================

class GatewayError(Exception):

    def __init__(
        self,
        status_code: int,
        error_code: str,
        message: str,
        *,
        reason: Optional[str] = None
    ) -> None:

        super().__init__(message)

        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.reason = reason or message

    def payload(self) -> Dict[str, Any]:

        return {
            "error": {
                "code": self.error_code,
                "message": self.message,
                "type": "gateway_error"
            }
        }


# ============================================================
# 2. SQLite Rate Limiter
# ============================================================

class SQLiteRateLimiter:

    def __init__(
        self,
        db_path: str = "gateway_test.db"
    ) -> None:

        self.db_path = db_path

        self._conn = sqlite3.connect(
            db_path,
            check_same_thread=False,
            timeout=30
        )

        self._lock = threading.Lock()

        self._init_db()

    def _init_db(self) -> None:

        with self._lock:

            self._conn.execute("PRAGMA journal_mode=WAL;")

            # Existing tenant table.
            # Compatible with the existing database schema.
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS token_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_key TEXT NOT NULL,
                    tokens INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)

            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tenant_usage
                ON token_usage(api_key, timestamp)
            """)

            # Separate Primary 1 provider usage table.
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS primary1_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tokens INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                )
            """)

            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_primary1_usage
                ON primary1_usage(timestamp)
            """)

            self._conn.commit()

    def _check_and_consume(
        self,
        table: str,
        token_count: int,
        limit: int,
        window: int,
        tenant_id: Optional[str] = None
    ) -> bool:

        if (
            not isinstance(token_count, int)
            or isinstance(token_count, bool)
            or token_count <= 0
        ):
            raise ValueError("Token count must be positive.")

        if limit <= 0 or window <= 0:
            raise ValueError("Limit and window must be positive.")

        # Only these two internally defined tables are permitted.
        if table not in ("token_usage", "primary1_usage"):
            raise ValueError("Invalid rate-limit table.")

        now = time.time()
        window_start = now - window

        with self._lock:

            try:

                self._conn.execute("BEGIN IMMEDIATE")

                if table == "token_usage":

                    self._conn.execute(
                        """
                        DELETE FROM token_usage
                        WHERE api_key = ?
                        AND timestamp < ?
                        """,
                        (tenant_id, window_start)
                    )

                    cursor = self._conn.execute(
                        """
                        SELECT COALESCE(SUM(tokens), 0)
                        FROM token_usage
                        WHERE api_key = ?
                        AND timestamp >= ?
                        """,
                        (tenant_id, window_start)
                    )

                else:

                    self._conn.execute(
                        """
                        DELETE FROM primary1_usage
                        WHERE timestamp < ?
                        """,
                        (window_start,)
                    )

                    cursor = self._conn.execute(
                        """
                        SELECT COALESCE(SUM(tokens), 0)
                        FROM primary1_usage
                        WHERE timestamp >= ?
                        """
                    )

                current_usage = cursor.fetchone()[0]

                if current_usage + token_count > limit:

                    self._conn.rollback()
                    return False

                if table == "token_usage":

                    self._conn.execute(
                        """
                        INSERT INTO token_usage
                        (api_key, tokens, timestamp)
                        VALUES (?, ?, ?)
                        """,
                        (tenant_id, token_count, now)
                    )

                else:

                    self._conn.execute(
                        """
                        INSERT INTO primary1_usage
                        (tokens, timestamp)
                        VALUES (?, ?)
                        """,
                        (token_count, now)
                    )

                self._conn.commit()

                return True

            except Exception:

                self._conn.rollback()
                log.exception("SQLite rate limiter failure.")
                raise

    def check_tenant_and_consume(
        self,
        tenant_id: str,
        token_count: int,
        limit: int,
        window: int = DEFAULT_WINDOW_SECONDS
    ) -> bool:

        return self._check_and_consume(
            table="token_usage",
            token_count=token_count,
            limit=limit,
            window=window,
            tenant_id=tenant_id
        )

    def check_primary1_and_consume(
        self,
        token_count: int,
        limit: int,
        window: int = DEFAULT_WINDOW_SECONDS
    ) -> bool:

        return self._check_and_consume(
            table="primary1_usage",
            token_count=token_count,
            limit=limit,
            window=window
        )

    def close(self) -> None:

        with self._lock:
            self._conn.close()


# ============================================================
# 3. LLM Gateway Router
# ============================================================

class LLMGatewayRouter:

    def __init__(
        self,
        primary1_url: str,
        primary2_url: str,
        primary1_model: str,
        primary2_model: str,
        rate_limiter: SQLiteRateLimiter,
        primary1_api_key: Optional[str] = None,
        primary2_api_key: Optional[str] = None,
        tenant_token_limit: int = DEFAULT_TOKEN_LIMIT,
        tenant_window_seconds: int = DEFAULT_WINDOW_SECONDS,
        primary1_token_limit: int = 0,
        primary1_token_window_seconds: int = DEFAULT_WINDOW_SECONDS
    ) -> None:

        self.primary1_url = self._validate_url(primary1_url)
        self.primary2_url = self._validate_url(primary2_url)

        self.primary1_model = self._validate_model(primary1_model)
        self.primary2_model = self._validate_model(primary2_model)

        self.primary1_api_key = primary1_api_key
        self.primary2_api_key = primary2_api_key

        self.rate_limiter = rate_limiter

        self.tenant_token_limit = tenant_token_limit
        self.tenant_window_seconds = tenant_window_seconds

        self.primary1_token_limit = primary1_token_limit
        self.primary1_token_window_seconds = (
            primary1_token_window_seconds
        )

        if tenant_token_limit <= 0 or tenant_window_seconds <= 0:
            raise ValueError("Invalid tenant rate-limit configuration.")

        if primary1_token_limit < 0:
            raise ValueError("Primary 1 token limit cannot be negative.")

        if primary1_token_window_seconds <= 0:
            raise ValueError("Invalid Primary 1 token window.")

    @staticmethod
    def _validate_url(url: str) -> str:

        if not url:
            raise ValueError("Provider endpoint is missing.")

        parsed = urlsplit(url)

        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid provider endpoint.")

        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("Invalid provider port.") from exc

        return url

    @staticmethod
    def _validate_model(model: str) -> str:

        if not model or not model.strip():
            raise ValueError("Provider model name is missing.")

        return model.strip()

    # --------------------------------------------------------
    # HTTP request
    # --------------------------------------------------------

    def _sync_http_post(
        self,
        url: str,
        payload: dict,
        timeout: float,
        api_key: Optional[str]
    ) -> Tuple[int, Any]:

        parsed = urlsplit(url)

        host = parsed.hostname
        port = parsed.port

        path = parsed.path or "/"

        if parsed.query:
            path += "?" + parsed.query

        if parsed.scheme == "https":

            connection = http.client.HTTPSConnection(
                host,
                port=port,
                timeout=timeout
            )

        else:

            connection = http.client.HTTPConnection(
                host,
                port=port,
                timeout=timeout
            )

        body = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Connection": "close"
        }

        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:

            connection.request(
                "POST",
                path,
                body=body,
                headers=headers
            )

            response = connection.getresponse()

            status = response.status

            response_body = response.read().decode(
                "utf-8",
                errors="replace"
            )

            try:

                data = (
                    json.loads(response_body)
                    if response_body
                    else {}
                )

            except json.JSONDecodeError:

                data = {"raw": response_body}

            return status, data

        finally:

            connection.close()

    async def _call_provider(
        self,
        url: str,
        payload: dict,
        timeout: float,
        api_key: Optional[str]
    ) -> Tuple[int, Any]:

        return await asyncio.to_thread(
            self._sync_http_post,
            url,
            payload,
            timeout,
            api_key
        )

    # --------------------------------------------------------
    # Primary 1 fallback conditions
    # --------------------------------------------------------

    @staticmethod
    def _should_fallback(
        status: int,
        data: Any
    ) -> bool:

        if status in (401, 403, 404, 408, 429):
            return True

        if 500 <= status <= 599:
            return True

        if status == 400:

            error_text = json.dumps(data).lower()

            model_error_terms = (
                "model not found",
                "model disabled",
                "model unavailable",
                "model is unavailable",
                "unknown model",
                "model is not available",
                "model not enabled"
            )

            return any(
                term in error_text
                for term in model_error_terms
            )

        return False

    # ========================================================
    # 4. Main Request Handler
    # ========================================================

    async def handle_completion(
        self,
        api_key: str,
        payload: dict,
        estimated_tokens: int
    ) -> Dict[str, Any]:

        # Step 1: Validate request.

        if not isinstance(payload, dict):
            raise GatewayError(
                400,
                "INVALID_REQUEST",
                "Request must be a JSON object."
            )

        if not isinstance(payload.get("messages"), list):
            raise GatewayError(
                400,
                "INVALID_REQUEST",
                "Request must contain a messages list."
            )

        if not payload["messages"]:
            raise GatewayError(
                400,
                "INVALID_REQUEST",
                "At least one message is required."
            )

        if (
            not isinstance(estimated_tokens, int)
            or isinstance(estimated_tokens, bool)
            or estimated_tokens <= 0
        ):
            raise GatewayError(
                400,
                "INVALID_TOKEN_ESTIMATE",
                "Estimated tokens must be a positive integer."
            )

        if not api_key:
            raise GatewayError(
                400,
                "INVALID_TENANT",
                "Tenant identifier is required."
            )

        # Step 2: Check gateway-wide tenant limit.
        # If exceeded, reject. Do not switch providers.

        tenant_allowed = await asyncio.to_thread(
            self.rate_limiter.check_tenant_and_consume,
            api_key,
            estimated_tokens,
            self.tenant_token_limit,
            self.tenant_window_seconds
        )

        if not tenant_allowed:

            raise GatewayError(
                429,
                "TENANT_RATE_LIMIT_EXCEEDED",
                "Tenant token limit exceeded. Request rejected."
            )

        # Step 3: Create separate model payloads.

        primary1_payload = {
            **payload,
            "model": self.primary1_model
        }

        primary2_payload = {
            **payload,
            "model": self.primary2_model
        }

        # Step 4: Check Primary 1's own token budget.

        use_primary1 = True

        if self.primary1_token_limit > 0:

            primary1_allowed = await asyncio.to_thread(
                self.rate_limiter.check_primary1_and_consume,
                estimated_tokens,
                self.primary1_token_limit,
                self.primary1_token_window_seconds
            )

            if not primary1_allowed:

                use_primary1 = False

                log.warning(
                    "Primary 1 token budget exhausted. "
                    "Switching to Primary 2."
                )

        # Step 5: Attempt Primary 1.

        if use_primary1:

            log.info(
                "Sending request to Primary 1. Model: %s",
                self.primary1_model
            )

            try:

                status, data = await asyncio.wait_for(
                    self._call_provider(
                        self.primary1_url,
                        primary1_payload,
                        PRIMARY_TIMEOUT_SECONDS,
                        self.primary1_api_key
                    ),
                    timeout=PRIMARY_TIMEOUT_SECONDS + 0.5
                )

                if self._should_fallback(status, data):

                    log.warning(
                        "Primary 1 returned HTTP %d. "
                        "Switching to Primary 2.",
                        status
                    )

                elif not 200 <= status <= 299:

                    raise GatewayError(
                        status,
                        "PRIMARY1_REQUEST_ERROR",
                        "Primary 1 rejected the request.",
                        reason=f"Primary 1 returned HTTP {status}."
                    )

                else:

                    log.info("Primary 1 succeeded.")

                    return {
                        "provider": "primary1",
                        "model": self.primary1_model,
                        "data": data
                    }

            except asyncio.TimeoutError:

                log.warning(
                    "Primary 1 timed out. Switching to Primary 2."
                )

            except GatewayError:

                raise

            except Exception as exc:

                log.warning(
                    "Primary 1 connection failed: %s. "
                    "Switching to Primary 2.",
                    type(exc).__name__
                )

        # Step 6: Attempt Primary 2.

        log.info(
            "Sending the same prompt to Primary 2. Model: %s",
            self.primary2_model
        )

        try:

            status, data = await asyncio.wait_for(
                self._call_provider(
                    self.primary2_url,
                    primary2_payload,
                    SECONDARY_TIMEOUT_SECONDS,
                    self.primary2_api_key
                ),
                timeout=SECONDARY_TIMEOUT_SECONDS + 0.5
            )

        except asyncio.TimeoutError as exc:

            raise GatewayError(
                502,
                "BOTH_PROVIDERS_UNAVAILABLE",
                "Primary 1 and Primary 2 could not complete the request.",
                reason="Primary 2 timed out."
            ) from exc

        except Exception as exc:

            log.error(
                "Primary 2 connection failed: %s",
                type(exc).__name__
            )

            raise GatewayError(
                502,
                "BOTH_PROVIDERS_UNAVAILABLE",
                "Primary 1 and Primary 2 could not complete the request.",
                reason=f"Primary 2 connection error: {type(exc).__name__}"
            ) from exc

        if not 200 <= status <= 299:

            raise GatewayError(
                502,
                "BOTH_PROVIDERS_UNAVAILABLE",
                "Primary 1 and Primary 2 could not complete the request.",
                reason=f"Primary 2 returned HTTP {status}."
            )

        log.info("Primary 2 succeeded.")

        return {
            "provider": "primary2",
            "model": self.primary2_model,
            "data": data
        }
