from fastapi import FastAPI, Header, HTTPException
from typing import Optional

app = FastAPI(title="Sentinel Vulnerable API")

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