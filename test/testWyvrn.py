python
import pytest

from httpx import ASGITransport, AsyncClient

from wyvrn.main import app


@pytest.mark.anyio
async def test_wyvrn_home():

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as client:

        response = await client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "WYVRN Security API"
    assert data["status"] == "running"
    assert data["mode"] == "monitor"


@pytest.mark.anyio
async def test_wyvrn_health():

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as client:

        response = await client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "WYVRN Security API"
    assert data["status"] == "healthy"


@pytest.mark.anyio
async def test_proxy_route_exists():

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as client:

        response = await client.get(
            "/proxy/users/1"
        )

    # Target API does not need to be running
    # for this test.

    assert response.status_code != 404
