
import asyncio
import json
import logging
import os

from dotenv import load_dotenv

from llm_gateway import (
    SQLiteRateLimiter,
    LLMGatewayRouter,
    GatewayError
)


load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)


async def main():

    limiter = None

    try:

        # 1. Read configuration from .env.

        primary1_url = os.getenv("primary1_endpoint")
        primary2_url = os.getenv("primary2_endpoint")

        primary1_key = os.getenv("primary1_api_key")
        primary2_key = os.getenv("primary2_api_key")

        primary1_model = os.getenv("primary1_model")
        primary2_model = os.getenv("primary2_model")

        tenant_token_limit = int(
            os.getenv("tenant_token_limit", "50000")
        )

        tenant_window_seconds = int(
            os.getenv("tenant_window_seconds", "60")
        )

        primary1_token_limit = int(
            os.getenv("primary1_token_limit", "0")
        )

        primary1_token_window_seconds = int(
            os.getenv("primary1_token_window_seconds", "60")
        )

        # 2. Validate required configuration.

        required_settings = {
            "primary1_endpoint": primary1_url,
            "primary2_endpoint": primary2_url,
            "primary1_model": primary1_model,
            "primary2_model": primary2_model
        }

        missing = [
            name
            for name, value in required_settings.items()
            if not value or not value.strip()
        ]

        if missing:

            raise ValueError(
                "Missing .env settings: " + ", ".join(missing)
            )

        # 3. Initialize SQLite rate limiter.

        limiter = SQLiteRateLimiter("gateway_test.db")

        # 4. Initialize gateway with both providers.

        router = LLMGatewayRouter(
            primary1_url=primary1_url,
            primary2_url=primary2_url,

            primary1_model=primary1_model,
            primary2_model=primary2_model,

            rate_limiter=limiter,

            primary1_api_key=primary1_key,
            primary2_api_key=primary2_key,

            tenant_token_limit=tenant_token_limit,
            tenant_window_seconds=tenant_window_seconds,

            primary1_token_limit=primary1_token_limit,
            primary1_token_window_seconds=primary1_token_window_seconds
        )

        # Tenant identifier for this test.
        # In production, derive this from authenticated tenant identity.
        tenant_id = "my_personal_account"

        # 5. Ask for one common user prompt.

        print("\n========== LLM GATEWAY ==========")

        user_prompt = input(
            "\nEnter your prompt: "
        ).strip()

        if not user_prompt:

            print("Prompt cannot be empty.")
            return

        estimated_tokens = int(
            input("Enter estimated token usage: ").strip()
        )

        if estimated_tokens <= 0:

            print("Estimated token usage must be positive.")
            return

        # 6. One common payload.
        # Gateway inserts the appropriate model name.

        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            "stream": False
        }

        print("\n========== ROUTING CONFIGURATION ==========")

        print("Primary 1 model:", primary1_model)
        print("Primary 2 model:", primary2_model)

        print(
            "Tenant token limit:",
            tenant_token_limit,
            "tokens per",
            tenant_window_seconds,
            "seconds"
        )

        if primary1_token_limit > 0:

            print(
                "Primary 1 token budget:",
                primary1_token_limit,
                "tokens per",
                primary1_token_window_seconds,
                "seconds"
            )

        else:

            print(
                "Primary 1 local token budget: Not configured; "
                "upstream HTTP 429 will trigger fallback."
            )

        print("\nSubmitting one request to the gateway...")

        # 7. Submit once. Gateway handles all routing.

        response = await router.handle_completion(
            api_key=tenant_id,
            payload=payload,
            estimated_tokens=estimated_tokens
        )

        # 8. Display successful result.

        print("\n========== SUCCESS ==========")

        print("Provider selected:", response["provider"])
        print("Model selected:", response["model"])

        print("\nModel response:")

        print(
            json.dumps(
                response["data"],
                indent=2
            )
        )

    except GatewayError as ge:

        print("\n========== GATEWAY ERROR ==========")

        print("Status:", ge.status_code)
        print("Error code:", ge.error_code)
        print("Message:", ge.message)

        # Diagnostic detail for local testing only.
        print("Debug reason:", ge.reason)

    except ValueError as exc:

        print("\nINVALID INPUT OR CONFIGURATION:")
        print(str(exc))

    except Exception as exc:

        print("\nUNEXPECTED ERROR:")
        print(type(exc).__name__, str(exc))

    finally:

        if limiter is not None:
            limiter.close()


if __name__ == "__main__":
    asyncio.run(main())
