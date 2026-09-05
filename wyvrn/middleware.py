import json
import time
import uuid

from datetime import datetime, timezone

from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from wyvrn.detectors.engine import run_detectors
from wyvrn.detectors.auth import detect_auth_abuse
from wyvrn.detectors.sensitive_data import (
    detect_sensitive_data,
)
from wyvrn.detectors.excessive_data import (
    detect_excessive_data,
)
from wyvrn.detectors.anomaly import (
    detect_behavioral_anomaly,
)


from wyvrn.risk import calculate_risk
from wyvrn.policy import evaluate_policy

from wyvrn.events import build_security_event
from wyvrn.store import store_event
from wyvrn.ws import broadcast_event


class WyvrnMiddleware(BaseHTTPMiddleware):

    async def dispatch(
        self,
        request: Request,
        call_next,
    ):

        start_time = time.perf_counter()

        request_id = str(
            uuid.uuid4()
        )

        # -------------------------------------------------------------------
        # Capture request body
        # -------------------------------------------------------------------

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

        # -------------------------------------------------------------------
        # Normalize request path
        # -------------------------------------------------------------------

        request_path = request.url.path

        if request_path.startswith(
            "/proxy/"
        ):

            security_path = request_path[
                len("/proxy") :
            ]

        else:

            security_path = request_path

        # -------------------------------------------------------------------
        # Build request event
        # -------------------------------------------------------------------

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

        # -------------------------------------------------------------------
        # WYVRN internal/control-plane routes
        #
        # These endpoints belong to WYVRN itself rather than the protected
        # target API. They should not be inspected as security events.
        #
        # This prevents dashboard responses containing words such as
        # SQL_INJECTION or detections from becoming false-positive findings.
        # -------------------------------------------------------------------

        internal_routes = (
            "/",
            "/health",
            "/api/",
            "/ws/",
            "/docs",
            "/redoc",
            "/openapi.json",
        )

        is_internal_route = (
            request_path == "/"
            or any(
                request_path.startswith(route)
                for route in internal_routes
                if route != "/"
            )
        )

        if is_internal_route:

            response = await call_next(
                request
            )

            response_body = b""

            async for chunk in response.body_iterator:

                response_body += chunk

            return Response(
                content=response_body,
                status_code=response.status_code,
                headers=dict(
                    response.headers
                ),
                media_type=response.media_type,
                background=response.background,
            )

        # -------------------------------------------------------------------
        # REQUEST-SIDE DETECTION
        # -------------------------------------------------------------------

        request_findings = run_detectors(
            request_event
        )

        # Authentication abuse detection.
        #
        # This catches things such as obviously invalid bearer tokens
        # before the request reaches the target API.
        auth_request_findings = detect_auth_abuse(
            request_event=request_event,
            response_status_code=None,
        )

        # Rate abuse detection.
        #
        # This maintains a rolling request history per client IP.
        

        request_findings = (
            request_findings
            + auth_request_findings
        )

        request_risk = calculate_risk(
            request_findings
        )

        request_policy = evaluate_policy(
            request_risk
        )

        print()
        print(
            "=" * 70
        )
        print(
            "🐉 WYVRN — REQUEST SECURITY DECISION"
        )
        print(
            "=" * 70
        )

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

        # -------------------------------------------------------------------
        # BLOCK request immediately
        # -------------------------------------------------------------------

        if request_policy[
            "action"
        ] == "BLOCK":

            print()
            print(
                "=" * 70
            )
            print(
                "🛑 WYVRN BLOCKED REQUEST"
            )
            print(
                "=" * 70
            )
            print(
                f"Reason: "
                f"{request_policy['reason']}"
            )

            security_event = build_security_event(
                request_event=request_event,
                response_event=None,
                findings=request_findings,
                risk_result=request_risk,
                policy_result=request_policy,
            )

            store_event(
                security_event
            )

            await broadcast_event(
                security_event
            )

            return JSONResponse(
                status_code=403,
                content={
                    "error": (
                        "Request blocked by WYVRN"
                    ),

                    "request_id": request_id,

                    "risk_score": (
                        request_risk[
                            "risk_score"
                        ]
                    ),

                    "risk_level": (
                        request_risk[
                            "risk_level"
                        ]
                    ),

                    "action": "BLOCK",

                    "detections": (
                        request_risk[
                            "detections"
                        ]
                    ),
                },
            )

        # -------------------------------------------------------------------
        # RATE_LIMIT request immediately
        # -------------------------------------------------------------------

        if request_policy[
            "action"
        ] == "RATE_LIMIT":

            print()
            print(
                "=" * 70
            )
            print(
                "⏳ WYVRN RATE LIMITED REQUEST"
            )
            print(
                "=" * 70
            )
            print(
                f"Reason: "
                f"{request_policy['reason']}"
            )

            security_event = build_security_event(
                request_event=request_event,
                response_event=None,
                findings=request_findings,
                risk_result=request_risk,
                policy_result=request_policy,
            )

            store_event(
                security_event
            )

            await broadcast_event(
                security_event
            )

            return JSONResponse(
                status_code=429,
                content={
                    "error": (
                        "Request rate limited by WYVRN"
                    ),

                    "request_id": request_id,

                    "risk_score": (
                        request_risk[
                            "risk_score"
                        ]
                    ),

                    "risk_level": (
                        request_risk[
                            "risk_level"
                        ]
                    ),

                    "action": "RATE_LIMIT",

                    "detections": (
                        request_risk[
                            "detections"
                        ]
                    ),
                },

                headers={
                    "Retry-After": "10",
                },
            )

        # -------------------------------------------------------------------
        # Request allowed through to target API
        # -------------------------------------------------------------------

        response = await call_next(
            request
        )

        # -------------------------------------------------------------------
        # Capture upstream response body
        # -------------------------------------------------------------------

        response_body = b""

        async for chunk in response.body_iterator:

            response_body += chunk

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

        status_code = (
            response.status_code
        )

        try:

            response_text = response_body.decode(
                "utf-8",
                errors="replace",
            )

        except Exception:

            response_text = None

        # -------------------------------------------------------------------
        # RESPONSE-SIDE DETECTION
        # -------------------------------------------------------------------

        # Authentication detector is response-aware for login endpoints.
        auth_response_findings = detect_auth_abuse(
            request_event=request_event,
            response_status_code=status_code,
        )

        # Sensitive data exposure.
        sensitive_findings = detect_sensitive_data(
            response_text
        )

        # Excessive data exposure.
        #
        # Status code is passed so that error responses such as 404 do not
        # get incorrectly classified as excessive data exposure.
        excessive_findings = detect_excessive_data(
            security_path,
            response_text,
            status_code,
        )

        # Behavioral anomaly detection.
        anomaly_findings = detect_behavioral_anomaly(
            path=security_path,
            response_size=response_size,
            latency_ms=latency_ms,
            status_code=status_code,
        )

        # -------------------------------------------------------------------
        # Combine every detector
        # -------------------------------------------------------------------

        all_findings = (
            request_findings
            + auth_response_findings
            + sensitive_findings
            + excessive_findings
            + anomaly_findings
        )

        # -------------------------------------------------------------------
        # Final risk calculation
        # -------------------------------------------------------------------

        final_risk = calculate_risk(
            all_findings
        )

        final_policy = evaluate_policy(
            final_risk
        )

        # -------------------------------------------------------------------
        # Build response event
        # -------------------------------------------------------------------

        response_event = {
            "request_id": request_id,

            "status_code": status_code,

            "response_size": response_size,

            "latency_ms": latency_ms,
        }

        # -------------------------------------------------------------------
        # Build security event
        # -------------------------------------------------------------------

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

        await broadcast_event(
            security_event
        )

        print()
        print(
            "=" * 70
        )
        print(
            "🐉 WYVRN — FINAL SECURITY DECISION"
        )
        print(
            "=" * 70
        )

        print(
            json.dumps(
                security_event,
                indent=2,
            )
        )

        # -------------------------------------------------------------------
        # BLOCK response
        # -------------------------------------------------------------------

        if final_policy[
            "action"
        ] == "BLOCK":

            print()
            print(
                "=" * 70
            )
            print(
                "🛑 WYVRN BLOCKED RESPONSE"
            )
            print(
                "=" * 70
            )

            print(
                f"Reason: "
                f"{final_policy['reason']}"
            )

            return JSONResponse(
                status_code=403,

                content={
                    "error": (
                        "Response blocked by WYVRN"
                    ),

                    "request_id": request_id,

                    "risk_score": (
                        final_risk[
                            "risk_score"
                        ]
                    ),

                    "risk_level": (
                        final_risk[
                            "risk_level"
                        ]
                    ),

                    "action": "BLOCK",

                    "detections": (
                        final_risk[
                            "detections"
                        ]
                    ),
                },
            )

        # -------------------------------------------------------------------
        # RATE_LIMIT response
        # -------------------------------------------------------------------

        if final_policy[
            "action"
        ] == "RATE_LIMIT":

            print()
            print(
                "=" * 70
            )
            print(
                "⏳ WYVRN RATE LIMITED RESPONSE"
            )
            print(
                "=" * 70
            )

            print(
                f"Reason: "
                f"{final_policy['reason']}"
            )

            return JSONResponse(
                status_code=429,

                content={
                    "error": (
                        "Response rate limited by WYVRN"
                    ),

                    "request_id": request_id,

                    "risk_score": (
                        final_risk[
                            "risk_score"
                        ]
                    ),

                    "risk_level": (
                        final_risk[
                            "risk_level"
                        ]
                    ),

                    "action": "RATE_LIMIT",

                    "detections": (
                        final_risk[
                            "detections"
                        ]
                    ),
                },

                headers={
                    "Retry-After": "10",
                },
            )

        # -------------------------------------------------------------------
        # Return original upstream response
        # -------------------------------------------------------------------

        return Response(
            content=response_body,

            status_code=status_code,

            headers=dict(
                response.headers
            ),

            media_type=response.media_type,

            background=response.background,
        )
