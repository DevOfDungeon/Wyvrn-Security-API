from fastapi import FastAPI, Header, HTTPException
from typing import Optional

app = FastAPI(title="Wyvrn Vulnerable API")

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

@app.get("/")
def home():
    return {
        "message": "Wyvrn vulnerable API",
        "status": "running"
    }


@app.get("/users/{user_id}")
def get_user(user_id: int):
    """ 
    Intentionally vulnerable to BOLA/IDOR.
    There is currently NO authorization check.
    """

    user = USERS.get(user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user


@app.get("/products")
def get_products(limit: int = 10):
    """
    Intentionally allows very large limits.
    Useful later for data-exfiltration detection.
    """

    products = [
        {"id": i, "name": f"Product {i}", "price": i * 100}
        for i in range(1, 101)
    ]

    return products[:limit]


@app.get("/search")
def search(q: str):
    """
    Intentionally simplistic search endpoint.
    We'll attack this later with injection-like payloads.
    """

    return {
        "query": q,
        "results": [
            "Result 1",
            "Result 2",
            "Result 3"
        ]
    }


@app.post("/login")
def login(username: str, password: str):
    """
    Fake login endpoint.
    No rate limiting yet.
    """

    if username == "alice" and password == "password123":
        return {
            "access_token": "fake-token-alice",
            "user_id": 1
        }

    if username == "bob" and password == "password123":
        return {
            "access_token": "fake-token-bob",
            "user_id": 2
        }

    raise HTTPException(
        status_code=401,
        detail="Invalid credentials"
    )
