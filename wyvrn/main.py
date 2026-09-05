import httpx

from fastapi import FastAPI, Request
from fastapi.responses import Response

from wyvrn.middleware import WyvrnMiddleware


app = FastAPI(
    title="WYVRN Security API",
    description=(
        "Runtime API security, threat detection, "
        "and automated threat control."
    ),
    version="0.1.0",
)

app.add_middleware(WyvrnMiddleware)


TARGET_API = "http://127.0.0.1:8000"


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
async def proxy(path: str, request: Request):
    """
    Forward requests from WYVRN to the target API.
    """

    target_url = f"{TARGET_API}/{path}"

    if request.url.query:
        target_url += f"?{request.url.query}"

    body = await request.body()

    excluded_headers = {
        "host",
        "content-length",
    }

    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in excluded_headers
    }

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

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get(
            "content-type"
        ),
    )