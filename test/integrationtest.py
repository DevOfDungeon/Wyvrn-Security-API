import pytest

from httpx import ASGITransport, AsyncClient

import wyvrn.main as wyvrn_main


@pytest.mark.anyio
async def test_proxy_forwards_request(monkeypatch):

    # --------------------------------------------------
    # Fake response from the Target API
    # --------------------------------------------------

    class FakeResponse:

        status_code = 200

        content = b'{"id":1,"name":"Alice"}'

        headers = {
            "content-type": "application/json"
        }


    # --------------------------------------------------
    # Fake HTTP client
    # --------------------------------------------------

    class FakeAsyncClient:

        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(
            self,
            exc_type,
            exc_value,
            traceback
        ):
            pass

        async def request(
            self,
            method,
            url,
            headers,
            content
        ):

            # Check that Wyvrn forwarded
            # the correct HTTP method.

            assert method == "GET"

            # Check that Wyvrn forwarded
            # the correct endpoint.

            assert "/users/1" in url

            # Return fake Target API response.

            return FakeResponse()


    # --------------------------------------------------
    # Replace the real HTTP client with our fake client
    # --------------------------------------------------

    monkeypatch.setattr(
        wyvrn_main.httpx,
        "AsyncClient",
        FakeAsyncClient
    )


    # --------------------------------------------------
    # Create test transport for Wyvrn
    # --------------------------------------------------

    transport = ASGITransport(
        app=wyvrn_main.app
    )


    # --------------------------------------------------
    # Send request to Wyvrn
    # --------------------------------------------------

    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as client:

        response = await client.get(
            "/proxy/users/1"
        )


    # --------------------------------------------------
    # Verify response
    # --------------------------------------------------

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == 1

    assert data["name"] == "Alice"
