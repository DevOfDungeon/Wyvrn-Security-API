import time
import uuid

from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from wyvrn.detectors.engine import run_detectors
from wyvrn.detectors.sensitive_data import (
    detect_sensitive_data,
)
from wyvrn.detectors.excessive_data import (
    detect_excessive_data,
)
from wyvrn.detectors.anomaly import (
    detect_behavioral_anomaly,
)


class WyvrnMiddleware(BaseHTTPMiddleware):

    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        start_time = time.perf_counter()

        request_id = str(uuid.uuid4())

        # ============================================================
        # CAPTURE REQUEST BODY
        # ============================================================

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

        # ============================================================
        # NORMALIZE PATH
        # ============================================================

        request_path = request.url.path

        if request_path.startswith("/proxy/"):
            security_path = request_path[
                len("/proxy"):
            ]
        else:
            security_path = request_path

        # ============================================================
        # BUILD REQUEST EVENT
        # ============================================================

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
            "headers": dict(request.headers),
            "query_params": dict(
                request.query_params
            ),
            "body": body,
        }

        # ============================================================
        # REQUEST-SIDE DETECTORS
        # ============================================================

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

        # ============================================================
        # CONTINUE REQUEST
        # ============================================================

        response = await call_next(
            request
        )

        # ============================================================
        # CAPTURE RESPONSE BODY
        # ============================================================

        response_body = b""

        async for chunk in response.body_iterator:
            response_body += chunk

        # ============================================================
        # RESPONSE METADATA
        # ============================================================

        latency_ms = (
            time.perf_counter()
            - start_time
        ) * 1000

        latency_ms = round(
            latency_ms,
            2,
        )

        response_size = len(
            response_body
        )

        status_code = response.status_code

        # ============================================================
        # DECODE RESPONSE
        # ============================================================

        try:
            response_text = response_body.decode(
                "utf-8",
                errors="replace",
            )
        except Exception:
            response_text = None

        # ============================================================
        # RESPONSE-SIDE: SENSITIVE DATA
        # ============================================================

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

        # ============================================================
        # RESPONSE-SIDE: EXCESSIVE DATA
        # ============================================================

        excessive_data_findings = (
            detect_excessive_data(
                security_path,
                response_text,
            )
        )

        if excessive_data_findings:
            print()
            print("=" * 70)
            print("🚨 WYVRN EXCESSIVE DATA FINDINGS")
            print("=" * 70)

            for finding in excessive_data_findings:
                print(finding)

        # ============================================================
        # RESPONSE-SIDE: BEHAVIORAL ANOMALY
        # ============================================================

        anomaly_findings = (
            detect_behavioral_anomaly(
                path=security_path,
                response_size=response_size,
                latency_ms=latency_ms,
                status_code=status_code,
            )
        )

        if anomaly_findings:
            print()
            print("=" * 70)
            print("🚨 WYVRN BEHAVIORAL ANOMALY FINDINGS")
            print("=" * 70)

            for finding in anomaly_findings:
                print(finding)

        # ============================================================
        # COMBINE ALL FINDINGS
        # ============================================================

        all_findings = (
            findings
            + response_findings
            + excessive_data_findings
            + anomaly_findings
        )

        # ============================================================
        # RESPONSE EVENT
        # ============================================================

        response_event = {
            "request_id": request_id,
            "status_code": status_code,
            "response_size": response_size,
            "latency_ms": latency_ms,
        }

        # ============================================================
        # LOG REQUEST
        # ============================================================

        print()
        print("=" * 70)
        print("🐉 WYVRN SECURITY API — REQUEST")
        print("=" * 70)
        print(request_event)

        # ============================================================
        # LOG RESPONSE
        # ============================================================

        print()
        print("=" * 70)
        print("🐉 WYVRN SECURITY API — RESPONSE")
        print("=" * 70)
        print(response_event)

        # ============================================================
        # LOG COMBINED SECURITY RESULT
        # ============================================================

        if all_findings:
            print()
            print("=" * 70)
            print("🐉 WYVRN SECURITY API — ALL FINDINGS")
            print("=" * 70)

            for finding in all_findings:
                print(finding)

        # ============================================================
        # REBUILD RESPONSE
        # ============================================================

        return Response(
            content=response_body,
            status_code=status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
            background=response.background,
        )