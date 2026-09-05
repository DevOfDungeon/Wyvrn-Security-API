from fastapi import FastAPI, HTTPException

app = FastAPI(
    title="WYVRN Target API",
    description="Intentionally vulnerable API used to test WYVRN.",
    version="0.1.0",
)

USERS = {
    1: {
        "id": 1,
        "name": "Alice",
        "email": "alice@example.com",
        "role": "user",
        "phone": "+91-9000000001",
        "password_hash": "fake_hash_alice",
    },
    2: {
        "id": 2,
        "name": "Bob",
        "email": "bob@example.com",
        "role": "user",
        "phone": "+91-9000000002",
        "password_hash": "fake_hash_bob",
    },
    3: {
        "id": 3,
        "name": "Admin",
        "email": "admin@example.com",
        "role": "admin",
        "phone": "+91-9000000003",
        "password_hash": "fake_hash_admin",
    },
}

PRODUCTS = [
    {
        "id": i,
        "name": f"Product {i}",
        "price": i * 100,
    }
    for i in range(1, 101)
]


@app.get("/")
async def home():
    return {
        "service": "WYVRN Target API",
        "status": "running",
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
    }


@app.get("/profile")
async def get_profile():

    # INTENTIONALLY VULNERABLE:
    # This endpoint exposes sensitive user information.

    return USERS[1]


@app.get("/users/{user_id}")
async def get_user(user_id: int):

    # INTENTIONALLY VULNERABLE:
    # No authorization check is performed.

    user = USERS.get(user_id)

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    return user


@app.get("/products")
async def get_products(limit: int = 10):

    # INTENTIONALLY VULNERABLE:
    # No sensible upper limit.

    return PRODUCTS[:limit]


@app.get("/search")
async def search(q: str):

    # INTENTIONALLY ANOMALOUS:
    # Used by the WYVRN behavioral anomaly simulator.
    #
    # Normal searches return a small response.
    # The special test query creates an unusually large
    # response so WYVRN can detect the deviation.

    if q == "ANOMALY_TEST":
        return {
            "query": q,
            "results": [
                f"Anomalous result {i}"
                for i in range(100)
            ],
        }

    return {
        "query": q,
        "results": [
            "Result 1",
            "Result 2",
            "Result 3",
        ],
    }


@app.post("/login")
async def login(
    username: str,
    password: str,
):

    if (
        username == "alice"
        and password == "password123"
    ):
        return {
            "access_token": "fake-token-alice",
            "user_id": 1,
        }

    if (
        username == "bob"
        and password == "password123"
    ):
        return {
            "access_token": "fake-token-bob",
            "user_id": 2,
        }

    raise HTTPException(
        status_code=401,
        detail="Invalid credentials",
    )
