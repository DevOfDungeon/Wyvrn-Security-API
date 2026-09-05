from typing import Any, Dict, List


def build_security_event(
    request_event: Dict[str, Any],
    response_event: Dict[str, Any] | None,
    findings: List[Dict[str, Any]],
    risk_result: Dict[str, Any],
    policy_result: Dict[str, Any],
) -> Dict[str, Any]:

    return {
        "request_id": request_event["request_id"],
        "timestamp": request_event["timestamp"],

        "request": {
            "method": request_event["method"],
            "path": request_event["path"],
            "client_ip": request_event.get("client_ip"),
        },

        "response": response_event,

        "findings": findings,

        "risk": {
            "score": risk_result["risk_score"],
            "level": risk_result["risk_level"],
            "finding_count": risk_result["finding_count"],
            "detections": risk_result["detections"],
        },

        "policy": {
            "action": policy_result["action"],
            "reason": policy_result["reason"],
        },
    }