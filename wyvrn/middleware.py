import json
import time
import uuid

from datetime import datetime, timezone

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from wyvrn.detectors.engine import run_detectors
from wyvrn.detectors.sensitive_data import detect_sensitive_data
from wyvrn.detectors.excessive_data import detect_excessive_data
from wyvrn.detectors.anomaly import detect_behavioral_anomaly

from wyvrn.risk import calculate_risk
from wyvrn.policy import evaluate_policy

from wyvrn.events import build_security_event
from wyvrn.store import store_event


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
            security_path = request_path[len("/proxy"):]
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
        # REQUEST-SIDE DETECTION
        # ============================================================

        request_findings = run_detectors(
            request_event
        )

        # ============================================================
        # REQUEST-SIDE RISK
        # ============================================================

        request_risk = calculate_risk(
            request_findings
        )

        request_policy = evaluate_policy(
            request_risk
        )

        # ============================================================
        # LOG REQUEST SECURITY DECISION
        # ============================================================

        print()
        print("=" * 70)
        print("🐉 WYVRN — REQUEST SECURITY DECISION")
        print("=" * 70)

        print(
            json.dumps(
                {
                    "request_id": request_id,
                    "path": security_path,
                    "risk": request_risk,
                    "policy": request_policy,
                },
                indent=2,
            )
        )

        # ============================================================
        # REQUEST-SIDE BLOCK
        # ============================================================

        if request_policy["action"] == "BLOCK":

            print()
            print("=" * 70)
            print("🛑 WYVRN BLOCKED REQUEST")
            print("=" * 70)

            print(
                f"Reason: {request_policy['reason']}"
            )

            # Store blocked request as an event
            security_event = build_security_event(
                request_event=request_event,
                response_event=None,
                findings=request_findings,
                risk_result=request_risk,
                policy_result=request_policy,
            )

            store_event(security_event)

            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by WYVRN",
                    "request_id": request_id,
                    "risk_score": request_risk["risk_score"],
                    "risk_level": request_risk["risk_level"],
                    "action": "BLOCK",
                    "detections": request_risk["detections"],
                },
            )

        # ============================================================
        # REQUEST-SIDE RATE LIMIT
        # ============================================================

        if request_policy["action"] == "RATE_LIMIT":

            print()
            print("=" * 70)
            print("⏳ WYVRN RATE LIMITED REQUEST")
            print("=" * 70)

            print(
                f"Reason: {request_policy['reason']}"
            )

            # Store rate-limited request as an event
            security_event = build_security_event(
                request_event=request_event,
                response_event=None,
                findings=request_findings,
                risk_result=request_risk,
                policy_result=request_policy,
            )

            store_event(security_event)

            return JSONResponse(
                status_code=429,
                content={
                    "error": "Request rate limited by WYVRN",
                    "request_id": request_id,
                    "risk_score": request_risk["risk_score"],
                    "risk_level": request_risk["risk_level"],
                    "action": "RATE_LIMIT",
                    "detections": request_risk["detections"],
                },
                headers={
                    "Retry-After": "10",
                },
            )

        # ============================================================
        # CONTINUE REQUEST TO TARGET API
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
        # RESPONSE-SIDE DETECTION
        # ============================================================

        sensitive_findings = detect_sensitive_data(
            response_text
        )

        excessive_findings = detect_excessive_data(
            security_path,
            response_text,
        )

        anomaly_findings = detect_behavioral_anomaly(
            path=security_path,
            response_size=response_size,
            latency_ms=latency_ms,
            status_code=status_code,
        )

        # ============================================================
        # COMBINE FINDINGS
        # ============================================================

        all_findings = (
            request_findings
            + sensitive_findings
            + excessive_findings
            + anomaly_findings
        )

        # ============================================================
        # FINAL RISK CALCULATION
        # ============================================================

        final_risk = calculate_risk(
            all_findings
        )

        final_policy = evaluate_policy(
            final_risk
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
        # BUILD + STORE SECURITY EVENT
        # ============================================================

        security_event = build_security_event(
            request_event=request_event,
            response_event=response_event,
            findings=all_findings,
            risk_result=final_risk,
            policy_result=final_policy,
        )

        store_event(
            security_event
        )

        # ============================================================
        # LOG FINAL SECURITY DECISION
        # ============================================================

        print()
        print("=" * 70)
        print("🐉 WYVRN — FINAL SECURITY DECISION")
        print("=" * 70)

        print(
            json.dumps(
                security_event,
                indent=2,
            )
        )

        # ============================================================
        # RESPONSE-SIDE BLOCK
        # ============================================================

        if final_policy["action"] == "BLOCK":

            print()
            print("=" * 70)
            print("🛑 WYVRN BLOCKED RESPONSE")
            print("=" * 70)

            print(
                f"Reason: {final_policy['reason']}"
            )

            return JSONResponse(
                status_code=403,
                content={
                    "error": "Response blocked by WYVRN",
                    "request_id": request_id,
                    "risk_score": final_risk["risk_score"],
                    "risk_level": final_risk["risk_level"],
                    "action": "BLOCK",
                    "detections": final_risk["detections"],
                },
            )

        # ============================================================
        # RESPONSE-SIDE RATE LIMIT
        # ============================================================

        if final_policy["action"] == "RATE_LIMIT":

            print()
            print("=" * 70)
            print("⏳ WYVRN RATE LIMITED RESPONSE")
            print("=" * 70)

            return JSONResponse(
                status_code=429,
                content={
                    "error": "Response rate limited by WYVRN",
                    "request_id": request_id,
                    "risk_score": final_risk["risk_score"],
                    "risk_level": final_risk["risk_level"],
                    "action": "RATE_LIMIT",
                    "detections": final_risk["detections"],
                },
                headers={
                    "Retry-After": "10",
                },
            )

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