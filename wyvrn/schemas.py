from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from wyvrn.middleware import proxy_request
from wyvrn.store import (
    get_event,
    get_events,
    get_stats,
)
from wyvrn.policy import DEFAULT_POLICIES
from wyvrn.ws import (
    add_connection,
    remove_connection,
)


app = FastAPI(
    title="WYVRN Security API",
    description=(
        "Real-time API security detection, "
        "risk scoring and policy enforcement."
    ),
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# BASIC ENDPOINTS
# ============================================================

@app.get("/")
async def root():

    return {
        "name": "WYVRN Security API",
        "status": "running",
        "version": "1.0.0",
    }


@app.get("/health")
async def health():

    return {
        "status": "healthy",
    }


# ============================================================
# DASHBOARD API
# ============================================================

@app.get("/api/events")
async def api_events():

    return {
        "events": get_events(),
    }


@app.get(
    "/api/events/{request_id}"
)
async def api_event(
    request_id: str,
):

    event = get_event(
        request_id
    )

    if event is None:

        return {
            "error": "Event not found."
        }

    return event


@app.get("/api/stats")
async def api_stats():

    return get_stats()


@app.get("/api/threats")
async def api_threats():

    events = get_events()

    threats = [
        event
        for event in events
        if event.get(
            "policy",
            {},
        ).get(
            "action"
        ) in {
            "BLOCK",
            "RATE_LIMIT",
        }
    ]

    return {
        "threats": threats,
    }


@app.get("/api/policies")
async def get_policies():

    return {
        "policies": DEFAULT_POLICIES,
    }


@app.put("/api/policies")
async def update_policies(
    policies: dict,
):

    DEFAULT_POLICIES.update(
        policies
    )

    return {
        "policies": DEFAULT_POLICIES,
    }


# ============================================================
# WEBSOCKET
# ============================================================

@app.websocket(
    "/ws/events"
)
async def websocket_events(
    websocket: WebSocket,
):

    await websocket.accept()

    add_connection(
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

        remove_connection(
            websocket
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
    request: Request,
    path: str,
):

    return await proxy_request(
        request,
        path,
    )