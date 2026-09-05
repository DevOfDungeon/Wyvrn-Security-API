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
    "anomaly": {
        "name": "Behavioral Anomaly",
        "method": "POST",
        "path": "/proxy/search",
        "query": {},
        "body": {
            "payload": "ANOMALOUS_REQUEST_" + ("X" * 5000)
        },
    },
}


def get_attack(attack_name: str) -> Dict[str, Any]:
    """
    Return a copy of a predefined attack configuration.
    """
    if attack_name not in ATTACKS:
        raise ValueError(f"Unknown attack: {attack_name}")

    return dict(ATTACKS[attack_name])


def list_attacks() -> list[Dict[str, Any]]:
    
    #Return attack metadata for the dashboard.
    
    return [
        {
            "id": attack_id,
            "name": attack["name"],
            "method": attack["method"],
            "path": attack["path"],
        }
        for attack_id, attack in ATTACKS.items()
    ]