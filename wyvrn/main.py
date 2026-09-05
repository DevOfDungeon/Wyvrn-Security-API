import httpx

from fastapi import FastAPI, Request
from fastapi.responses import Response

from wyvrn.middleware import WyvrnMiddleware
from wyvrn.store import get_events, get_event_count

from wyvrn.policy import (
    get_policies,
    set_policies,
)

app = FastAPI(
    title="WYVRN Security API",
    description=(
        "Runtime API security, threat detection, "
        "and automated threat control."
    ),
    version="0.1.0",
)


# ============================================================
# WYVRN MIDDLEWARE
# ============================================================

app.add_middleware(
    WyvrnMiddleware
)


# ============================================================
# TARGET API
# ============================================================

TARGET_API = "http://127.0.0.1:8000"


# ============================================================
# WYVRN ROOT
# ============================================================

@app.get("/")
async def home():
    return {
        "service": "WYVRN Security API",
        "status": "running",
        "mode": "monitor",
        "version": "0.1.0",
    }


# ============================================================
# WYVRN HEALTH
# ============================================================

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
    return {
        "events": get_events(limit),
        "count": get_event_count(),
    }


@app.get("/api/events/{request_id}")
async def security_event(
    request_id: str,
):
    events = get_events(1000)

    for event in events:
        if event["request_id"] == request_id:
            return event

    return {
        "error": "Security event not found",
        "request_id": request_id,
    }
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
            content=(
                '{"error":'
                f'"{str(exc)}"'
                "}"
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
# PROXY
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
    target_url = f"{TARGET_API}/{path}"

    # Forward query parameters
    if request.url.query:
        target_url += f"?{request.url.query}"

    # Capture request body
    body = await request.body()

    # Headers that should not be forwarded
    excluded_headers = {
        "host",
        "content-length",
    }

    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in excluded_headers
    }

    # ========================================================
    # FORWARD REQUEST TO TARGET API
    # ========================================================

    try:

        async with httpx.AsyncClient(
            timeout=10.0
        ) as client:

            upstream_response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
            )

    except httpx.RequestError:

        return Response(
            content='{"error":"Target API unavailable"}',
            status_code=502,
            media_type="application/json",
        )

    # ========================================================
    # RESPONSE HEADERS
    # ========================================================

    excluded_response_headers = {
        "content-length",
        "transfer-encoding",
        "connection",
    }

    response_headers = {
        key: value
        for key, value in upstream_response.headers.items()
        if key.lower() not in excluded_response_headers
    }

    # ========================================================
    # RETURN TARGET RESPONSE
    # ========================================================

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get(
            "content-type"
        ),
    )