import time
import uuid
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SentinelMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        start_time = time.time()

        request_id = str(uuid.uuid4())

        body = None

        try:
            body_bytes = await request.body()

            if body_bytes:
                body = body_bytes.decode("utf-8", errors="replace")

        except Exception:
            body = None

        request_event = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),

            "method": request.method,
            "path": request.url.path,

            "client_ip": request.client.host
            if request.client
            else None,

            "headers": dict(request.headers),
            "query_params": dict(request.query_params),
            "body": body,
        }

        request_event = {
            "request_id": request_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "path": request.url.path,
        }

        print("\n========== SENTINEL REQUEST ==========")
        print(request_event)

        response = await call_next(request)

        return response
