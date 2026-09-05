from typing import Any, Dict


ATTACKS: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "name": "SQL Injection",
        "method": "GET",
        "path": "/proxy/search",
        "query": {
            "q": "' OR 1=1 --"
        },
    },
    "bola_idor": {
        "name": "BOLA / IDOR",
        "method": "GET",
        "path": "/proxy/users/9999",
        "query": {},
    },
    "auth_abuse": {
        "name": "Authentication Abuse",
        "method": "GET",
        "path": "/proxy/admin",
        "query": {},
        "headers": {
            "authorization": "Bearer invalid-token"
        },
    },
    "sensitive_data": {
        "name": "Sensitive Data Exposure",
        "method": "GET",
        "path": "/proxy/users",
        "query": {},
    },
    "rate_abuse": {
        "name": "Rate Abuse",
        "method": "GET",
        "path": "/proxy/health",
        "query": {},
    },
    "anomaly": {import asyncio

import httpx


# ---------------------------------------------------------------------------
# Attack definitions
# ---------------------------------------------------------------------------

ATTACKS = {
    "sql_injection": {
        "name": "SQL Injection",
        "method": "GET",
        "path": "/proxy/search",
        "query": {"q": "' OR 1=1 --"},
    },

    "bola_idor": {
        "name": "BOLA / IDOR",
        "method": "GET",
        "path": "/proxy/users/9999",
        "query": {},
    },

    "auth_abuse": {
        "name": "Authentication Abuse",
        "method": "GET",
        "path": "/proxy/admin",
        "query": {},
        "headers": {
            "authorization": "Bearer invalid-token",
        },
    },

    "sensitive_data": {
        "name": "Sensitive Data Exposure",
        "method": "GET",
        "path": "/proxy/users",
        "query": {},
    },

    "rate_abuse": {
        "name": "Rate Abuse",
        "method": "GET",
        "path": "/proxy/health",
        "query": {},
    },

    "anomaly": {
        "name": "Behavioral Anomaly",
        "method": "POST",
        "path": "/proxy/search",
        "query": {},
        "body": {
            "payload": (
                "ANOMALOUS_REQUEST_"
                + ("X" * 5000)
            ),
        },
    },
}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WYVRN_URL = "http://127.0.0.1:9000"

RATE_ABUSE_REQUEST_COUNT = 15


def get_attack(
    attack_name: str,
):
    """
    Return a copy of a predefined attack configuration.
    """

    if attack_name not in ATTACKS:
        raise ValueError(
            f"Unknown attack: {attack_name}"
        )

    return dict(
        ATTACKS[attack_name]
    )


def list_attacks():
    """
    Return attack metadata for the dashboard.
    """

    return [
        {
            "id": attack_id,
            "name": attack["name"],
            "method": attack["method"],
            "path": attack["path"],
        }
        for attack_id, attack
        in ATTACKS.items()
    ]


async def run_rate_abuse():
    """
    Generate a burst of requests against WYVRN.

    The detector uses a rolling per-IP window.
    Sending more than MAX_REQUESTS_PER_WINDOW
    requests inside that window should cause
    WYVRN to return HTTP 429.
    """

    attack = ATTACKS[
        "rate_abuse"
    ]

    results = []

    async with httpx.AsyncClient(
        timeout=10.0
    ) as client:

        for index in range(
            RATE_ABUSE_REQUEST_COUNT
        ):

            try:

                response = await client.request(
                    method=attack["method"],
                    url=(
                        WYVRN_URL
                        + attack["path"]
                    ),
                    params=attack.get(
                        "query",
                        {},
                    ),
                )

                results.append(
                    {
                        "request_number": (
                            index + 1
                        ),
                        "status_code": (
                            response.status_code
                        ),
                        "body": (
                            response.text
                        ),
                    }
                )

            except Exception as exc:

                results.append(
                    {
                        "request_number": (
                            index + 1
                        ),
                        "status_code": None,
                        "body": str(exc),
                    }
                )

            # Yield control to the event loop without
            # introducing meaningful delay between requests.
            await asyncio.sleep(0)

    allowed = sum(
        1
        for result in results
        if result["status_code"] == 200
    )

    rate_limited = sum(
        1
        for result in results
        if result["status_code"] == 429
    )

    return {
        "success": True,
        "attack": "rate_abuse",
        "name": attack["name"],

        "request": {
            "method": attack["method"],
            "path": attack["path"],
            "query": attack.get(
                "query",
                {},
            ),
        },

        "burst": {
            "total_requests": (
                RATE_ABUSE_REQUEST_COUNT
            ),
            "allowed": allowed,
            "rate_limited": rate_limited,
        },

        "responses": results,
    }


async def run_attack(
    attack_name: str,
):
    """
    Run a simulator attack.

    Rate Abuse requires multiple requests,
    so it has a dedicated burst implementation.
    """

    if attack_name == "rate_abuse":

        return await run_rate_abuse()

    attack = get_attack(
        attack_name
    )

    url = (
        WYVRN_URL
        + attack["path"]
    )

    async with httpx.AsyncClient(
        timeout=10.0
    ) as client:

        response = await client.request(
            method=attack["method"],

            url=url,

            params=attack.get(
                "query",
                {},
            ),

            headers=attack.get(
                "headers",
                {},
            ),

            json=attack.get(
                "body"
            ),
        )

    return {
        "success": True,

        "attack": attack_name,

        "name": attack["name"],

        "request": {
            "method": attack["method"],
            "path": attack["path"],
            "query": attack.get(
                "query",
                {},
            ),
        },

        "response": {
            "status_code": (
                response.status_code
            ),
            "body": response.text,
        },
    }
