import time
import uuid

from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from wyvrn.detectors.engine import run_detectors


class WyvrnMiddleware(BaseHTTPMiddleware):

    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        start_time = time.perf_counter()

        request_id = str(uuid.uuid4())

        # ====================================================
        # CAPTURE REQUEST BODY
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

        # ====================================================
        # NORMALIZE PATH FOR SECURITY DETECTION
        # ====================================================
        #
        # Incoming WYVRN request:
        #
        #     /proxy/users/1
        #
        # Actual target API path:
        #
        #     /users/1
        #
        # Detectors analyze the target API path.
        # ====================================================

        request_path = request.url.path

        if request_path.startswith("/proxy/"):
            security_path = request_path[len("/proxy"):]
        else:
            security_path = request_path

        # ====================================================
        # BUILD REQUEST EVENT
        # ====================================================

        request_event = {
            "request_id": request_id,

            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "method": request.method,

            "path": security_path,

            "client_ip": (
                request.client.host
                if request.client
                else None
            ),

            "headers": dict(
                request.headers
            ),

            "query_params": dict(
                request.query_params
            ),

            "body": body,
        }

        # ====================================================
        # RUN SECURITY DETECTORS
        # ====================================================

        findings = run_detectors(
            request_event
        )

        if findings:
            print()
            print("=" * 70)
            print("🚨 WYVRN SECURITY FINDINGS")
            print("=" * 70)

            for finding in findings:
                print(finding)

        # ====================================================
        # LOG REQUEST
        # ====================================================

        print()
        print("=" * 70)
        print("🐉 WYVRN SECURITY API — REQUEST")
        print("=" * 70)

        print(request_event)

        # ====================================================
        # CONTINUE REQUEST
        # ====================================================

        response = await call_next(
            request
        )

        # ====================================================
        # CAPTURE RESPONSE
        # ====================================================

        latency_ms = (
            time.perf_counter()
            - start_time
        ) * 1000

        response_event = {
            "request_id": request_id,
            "status_code": response.status_code,
            "latency_ms": round(
                latency_ms,
                2,
            ),
        }

        # ====================================================
        # LOG RESPONSE
        # ====================================================

        print()
        print("=" * 70)
        print("🐉 WYVRN SECURITY API — RESPONSE")
        print("=" * 70)

        print(response_event)

        return response