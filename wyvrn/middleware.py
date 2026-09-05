import time
import uuid

from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from wyvrn.detectors.engine import run_detectors
from wyvrn.detectors.sensitive_data import detect_sensitive_data


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
        # NORMALIZE PATH
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
        # REQUEST-SIDE DETECTORS
        # ====================================================

        findings = run_detectors(
            request_event
        )

        if findings:
            print()
            print("=" * 70)
            print("🚨 WYVRN REQUEST SECURITY FINDINGS")
            print("=" * 70)

            for finding in findings:
                print(finding)

        # ====================================================
        # CONTINUE REQUEST
        # ====================================================

        response = await call_next(
            request
        )

        # ====================================================
        # CAPTURE RESPONSE BODY
        # ====================================================

        response_body = b""

        async for chunk in response.body_iterator:
            response_body += chunk

        # ====================================================
        # RESPONSE-SIDE DETECTION
        # ====================================================

        try:
            response_text = response_body.decode(
                "utf-8",
                errors="replace",
            )
        except Exception:
            response_text = None

        response_findings = detect_sensitive_data(
            response_text
        )

        if response_findings:
            print()
            print("=" * 70)
            print("🚨 WYVRN RESPONSE SECURITY FINDINGS")
            print("=" * 70)

            for finding in response_findings:
                print(finding)

        # ====================================================
        # COMBINE FINDINGS
        # ====================================================

        all_findings = (
            findings
            + response_findings
        )

        # ====================================================
        # RESPONSE METADATA
        # ====================================================

        latency_ms = (
            time.perf_counter()
            - start_time
        ) * 1000

        response_event = {
            "request_id": request_id,

            "status_code": response.status_code,

            "response_size": len(
                response_body
            ),

            "latency_ms": round(
                latency_ms,
                2,
            ),
        }

        # ====================================================
        # LOG REQUEST
        # ====================================================

        print()
        print("=" * 70)
        print("🐉 WYVRN SECURITY API — REQUEST")
        print("=" * 70)

        print(request_event)

        # ====================================================
        # LOG RESPONSE
        # ====================================================

        print()
        print("=" * 70)
        print("🐉 WYVRN SECURITY API — RESPONSE")
        print("=" * 70)

        print(response_event)

        # ====================================================
        # REBUILD RESPONSE
        # ====================================================

        return Response(
            content=response_body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
            background=response.background,
        )