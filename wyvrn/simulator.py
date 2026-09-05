import asyncio

import httpx


ATTACKS = {
    "sql_injection": {
        "name": "SQL Injection",
        "method": "GET",
        "path": "/proxy/search",
        "query": {
            "q": "' OR 1=1 --",
        },
    },

    "bola_idor": {
        "name": "BOLA / IDOR",
        "method": "GET",
        "path": "/proxy/users/42",
        "query": {},
    },

    "auth_abuse": {
        "name": "Authentication Abuse",
        "method": "GET",
        "path": "/proxy/admin",
        "query": {},
        "headers": {
            "Authorization": "Bearer invalid-token",
        },
    },

    "sensitive_data": {
        "name": "Sensitive Data Exposure",
        "method": "GET",
        "path": "/proxy/profile",
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
        "method": "GET",
        "path": "/proxy/search",
        "query": {
            "q": "normal-search",
        },
    },
}


WYVRN_URL = "http://127.0.0.1:9000"

RATE_ABUSE_REQUEST_COUNT = 15
ANOMALY_BASELINE_REQUEST_COUNT = 5


def get_attack(attack_name: str):
    attack = ATTACKS.get(attack_name)

    if attack is None:
        raise ValueError(
            f"Unknown attack: {attack_name}"
        )

    return attack


def list_attacks():
    return [
        {
            "id": attack_name,
            **attack,
        }
        for attack_name, attack in ATTACKS.items()
    ]


async def run_rate_abuse():
    """
    Send a burst of requests from the same client so that
    the RATE_ABUSE detector can observe repeated traffic.
    """

    attack = ATTACKS["rate_abuse"]

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
                    headers=attack.get(
                        "headers",
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
                        "body": response.text,
                    }
                )

            except Exception as exc:
                results.append(
                    {
                        "request_number": (
                            index + 1
                        ),
                        "status_code": None,
                        "error": str(exc),
                    }
                )

            # Yield control so the burst remains
            # asynchronous without adding meaningful delay.
            await asyncio.sleep(0)

    allowed = sum(
        1
        for result in results
        if result.get("status_code") == 200
    )

    rate_limited = sum(
        1
        for result in results
        if result.get("status_code") == 429
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

async def run_anomaly():
    attack = ATTACKS["anomaly"]

    results = []

    async with httpx.AsyncClient(
        timeout=10.0
    ) as client:

        # Establish normal baseline
        for index in range(
            ANOMALY_BASELINE_REQUEST_COUNT
        ):
            try:
                response = await client.request(
                    method=attack["method"],
                    url=(
                        WYVRN_URL
                        + attack["path"]
                    ),
                    params={
                        "q": "normal-search"
                    },
                    headers=attack.get(
                        "headers",
                        {},
                    ),
                )

                results.append(
                    {
                        "request_number": index + 1,
                        "type": "baseline",
                        "status_code": response.status_code,
                        "body": response.text,
                    }
                )

            except Exception as exc:
                results.append(
                    {
                        "request_number": index + 1,
                        "type": "baseline",
                        "status_code": None,
                        "error": str(exc),
                    }
                )

            await asyncio.sleep(0)

        # Send anomalous request
        try:
            response = await client.request(
                method=attack["method"],
                url=(
                    WYVRN_URL
                    + attack["path"]
                ),
                params={
                    "q": "ANOMALY_TEST"
                },
                headers=attack.get(
                    "headers",
                    {},
                ),
            )

            results.append(
                {
                    "request_number": (
                        ANOMALY_BASELINE_REQUEST_COUNT
                        + 1
                    ),
                    "type": "anomaly",
                    "status_code": response.status_code,
                    "body": response.text,
                }
            )

            anomaly_response = {
                "status_code": response.status_code,
                "body": response.text,
            }

        except Exception as exc:
            anomaly_response = {
                "status_code": None,
                "error": str(exc),
            }

    return {
        "success": True,
        "attack": "anomaly",
        "name": attack["name"],
        "request": {
            "method": attack["method"],
            "path": attack["path"],
            "query": {
                "baseline": "normal-search",
                "anomaly": "ANOMALY_TEST",
            },
        },
        "baseline": {
            "requests": ANOMALY_BASELINE_REQUEST_COUNT,
        },
        "anomaly": {
            "query": "ANOMALY_TEST",
            "blocked": (
                anomaly_response.get("status_code")
                in (403, 429)
            ),
            "response": anomaly_response,
        },
        "responses": results,
    }

async def run_attack(
    attack_name: str,
):
    """
    Run a simulator attack.

    Rate abuse is special because it requires
    multiple requests. All other attacks use
    a single request.
    """

    if attack_name == "rate_abuse":
        return await run_rate_abuse()
    if attack_name == "anomaly":
        return await run_anomaly()

    attack = get_attack(
        attack_name
    )

    async with httpx.AsyncClient(
        timeout=10.0
    ) as client:

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
            headers=attack.get(
                "headers",
                {},
            ),
        )

    return {
        "success": (
            response.status_code
            < 400
        ),

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
