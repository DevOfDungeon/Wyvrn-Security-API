import time
import uuid
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SentinelMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        start_time = time.time()

        request_id = str(uuid.uuid4())

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
