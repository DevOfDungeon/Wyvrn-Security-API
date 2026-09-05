import time
import uuid
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class WyvrnMiddleware(BaseHTTPMiddleware):

    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        start_time = time.perf_counter()

        request_id = str(uuid.uuid4())

        # ====================================================
        # CAPTURE REQUEST
        # ====================================================

        try:
            body_bytes = await request.body()

            if body_bytes:
                body = body_bytes.decode(
                    "utf-8",
                    errors="replace",
                )
            else:
                body = None

        except Exception:
            body = None

        request_event = {
            "request_id": request_id,

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "method": request.method,

            "path": request.url.path,

            "client_ip": (
                request.client.host
                if request.client
                else None
            ),

            "headers": dict(request.headers),

            "query_params": dict(
                request.query_params
            ),

            "body": body,
        }

        print()
        print("=" * 70)
        print("🐉 WYVRN SECURITY API — REQUEST")
        print("=" * 70)
        print(request_event)

        # ====================================================
        # CONTINUE REQUEST
        # ====================================================

        response = await call_next(request)

        # ====================================================
        # CAPTURE RESPONSE
        # ====================================================

        latency_ms = (
            time.perf_counter() - start_time
        ) * 1000

        response_event = {
            "request_id": request_id,
            "status_code": response.status_code,
            "latency_ms": round(latency_ms, 2),
        }

        print()
        print("=" * 70)
        print("🐉 WYVRN SECURITY API — RESPONSE")
        print("=" * 70)
        print(response_event)

        return response