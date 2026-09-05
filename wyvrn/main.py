import json

import httpx

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import Response

from wyvrn.middleware import WyvrnMiddleware
from wyvrn.store import get_events, get_event_count
from wyvrn.policy import (
    get_policies,
    set_policies,
)


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="WYVRN Security API",
    description=(
        "Runtime API security, threat detection, "
        "and automated threat control."
    ),
    version="0.1.0",
)


app.add_middleware(
    WyvrnMiddleware
)


TARGET_API = "http://127.0.0.1:8000"


# ============================================================
# LIVE DASHBOARD CONNECTIONS
# ============================================================

ACTIVE_CONNECTIONS = set()


# ============================================================
# BASIC HEALTH
# ============================================================

@app.get("/")
async def home():

    return {
        "service": "WYVRN Security API",
        "status": "running",
        "mode": "monitor",
        "version": "0.1.0",
    }


@app.get("/health")
async def health():

    return {
        "service": "WYVRN Security API",
        "status": "healthy",
    }


# ============================================================
# SECURITY EVENTS
# ============================================================

@app.get("/api/events")
async def security_events(
    limit: int = 100,
):

    limit = max(
        1,
        min(limit, 1000),
    )

    events = get_events(
        limit
    )

    return {
        "events": events,
        "count": get_event_count(),
    }


@app.get("/api/events/{request_id}")
async def security_event(
    request_id: str,
):

    events = get_events(
        1000
    )

    for event in events:

        if event["request_id"] == request_id:

            return event

    return {
        "error": "Security event not found",
        "request_id": request_id,
    }


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.get("/api/stats")
async def security_stats():

    events = get_events(
        1000
    )

    total_requests = len(
        events
    )

    blocked = 0
    rate_limited = 0
    monitored = 0
    allowed = 0

    critical = 0
    high = 0
    medium = 0
    low = 0

    detections = {}

    for event in events:

        policy = event.get(
            "policy",
            {},
        )

        risk = event.get(
            "risk",
            {},
        )

        action = policy.get(
            "action"
        )

        risk_level = risk.get(
            "risk_level",
            "LOW",
        )

        if action == "BLOCK":
            blocked += 1

        elif action == "RATE_LIMIT":
            rate_limited += 1

        elif action == "MONITOR":
            monitored += 1

        else:
            allowed += 1

        if risk_level == "CRITICAL":
            critical += 1

        elif risk_level == "HIGH":
            high += 1

        elif risk_level == "MEDIUM":
            medium += 1

        else:
            low += 1

        for detection in risk.get(
            "detections",
            [],
        ):

            detections[detection] = (
                detections.get(
                    detection,
                    0,
                )
                + 1
            )

    return {
        "total_requests": total_requests,

        "actions": {
            "blocked": blocked,
            "rate_limited": rate_limited,
            "monitored": monitored,
            "allowed": allowed,
        },

        "risk_levels": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },

        "detections": detections,
    }


# ============================================================
# THREAT SUMMARY
# ============================================================

@app.get("/api/threats")
async def threats():

    events = get_events(
        1000
    )

    threats = []

    for event in events:

        risk = event.get(
            "risk",
            {},
        )

        if not risk.get(
            "detections"
        ):
            continue

        threats.append(
            {
                "request_id": event.get(
                    "request_id"
                ),
                "timestamp": event.get(
                    "timestamp"
                ),
                "path": event.get(
                    "path"
                ),
                "method": event.get(
                    "method"
                ),
                "risk_score": risk.get(
                    "risk_score",
                    0,
                ),
                "risk_level": risk.get(
                    "risk_level",
                    "LOW",
                ),
                "detections": risk.get(
                    "detections",
                    [],
                ),
                "policy": event.get(
                    "policy",
                    {},
                ),
            }
        )

    return {
        "threats": threats,
        "count": len(
            threats
        ),
    }


# ============================================================
# POLICY API
# ============================================================

@app.get("/api/policies")
async def policies():

    return {
        "policies": get_policies(),
    }


@app.put("/api/policies")
async def replace_policies(
    request: Request,
):

    try:

        payload = await request.json()

        policies = payload.get(
            "policies"
        )

        if not isinstance(
            policies,
            dict,
        ):

            return Response(
                content=(
                    '{"error":"policies must be an object"}'
                ),
                status_code=400,
                media_type="application/json",
            )

        updated = set_policies(
            policies
        )

        return {
            "status": "updated",
            "policies": updated,
        }

    except ValueError as exc:

        return Response(
            content=json.dumps(
                {
                    "error": str(exc)
                }
            ),
            status_code=400,
            media_type="application/json",
        )

    except Exception:

        return Response(
            content=(
                '{"error":"Invalid JSON payload"}'
            ),
            status_code=400,
            media_type="application/json",
        )


# ============================================================
# LIVE SECURITY EVENTS
# ============================================================

async def broadcast_event(
    event,
):

    disconnected = []

    for websocket in ACTIVE_CONNECTIONS:

        try:

            await websocket.send_json(
                event
            )

        except Exception:

            disconnected.append(
                websocket
            )

    for websocket in disconnected:

        ACTIVE_CONNECTIONS.discard(
            websocket
        )


@app.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket,
):

    await websocket.accept()

    ACTIVE_CONNECTIONS.add(
        websocket
    )

    try:

        await websocket.send_json(
            {
                "type": "connection",
                "message": (
                    "Connected to WYVRN "
                    "live security events."
                ),
            }
        )

        while True:

            await websocket.receive_text()

    except Exception:

        ACTIVE_CONNECTIONS.discard(
            websocket
        )


# ============================================================
# TARGET API PROXY
# ============================================================

@app.api_route(
    "/proxy/{path:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "HEAD",
    ],
)
async def proxy(
    path: str,
    request: Request,
):

    target_url = (
        f"{TARGET_API}/{path}"
    )

    if request.url.query:

        target_url += (
            f"?{request.url.query}"
        )

    body = await request.body()

    excluded_headers = {
        "host",
        "content-length",
    }

    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower()
        not in excluded_headers
    }

    try:

        async with httpx.AsyncClient(
            timeout=10.0
        ) as client:

            upstream_response = (
                await client.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body,
                )
            )

    except httpx.RequestError:

        return Response(
            content=(
                '{"error":"Target API unavailable"}'
            ),
            status_code=502,
            media_type="application/json",
        )

    excluded_response_headers = {
        "content-length",
        "transfer-encoding",
        "connection",
    }

    response_headers = {
        key: value
        for key, value
        in upstream_response.headers.items()
        if key.lower()
        not in excluded_response_headers
    }

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get(
            "content-type"
        ),
    )