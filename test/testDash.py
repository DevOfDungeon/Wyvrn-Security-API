python
import pytest

from httpx import ASGITransport, AsyncClient

from target_api.main import app


@pytest.mark.anyio
async def test_home():

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as client:

        response = await client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["service"] == "WYVRN Target API"
    assert data["status"] == "running"


@pytest.mark.anyio
async def test_health():

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as client:

        response = await client.get("/health")

    assert response.status_code == 200

    assert response.json()["status"] == "healthy"


@pytest.mark.anyio
async def test_get_user():

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as client:

        response = await client.get("/users/1")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == 1
    assert data["name"] == "Alice"


@pytest.mark.anyio
async def test_missing_user():

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as client:

        response = await client.get("/users/9999")

    assert response.status_code == 404


@pytest.mark.anyio
async def test_products():

    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport,
        base_url="http://test"
    ) as client:

        response = await client.get(
            "/products?limit=5"
        )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 5
