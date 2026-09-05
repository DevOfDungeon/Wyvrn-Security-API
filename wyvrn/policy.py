from typing import Any, Dict


# ============================================================
# POLICY THRESHOLDS
# ============================================================

MONITOR_THRESHOLD = 30
RATE_LIMIT_THRESHOLD = 60
BLOCK_THRESHOLD = 80


# ============================================================
# POLICY DECISION
# ============================================================

def decide_action(risk_score: int) -> str:
    """
    Convert an overall risk score into a security action.
    """

    if risk_score >= BLOCK_THRESHOLD:
        return "BLOCK"

    if risk_score >= RATE_LIMIT_THRESHOLD:
        return "RATE_LIMIT"

    if risk_score >= MONITOR_THRESHOLD:
        return "MONITOR"

    return "ALLOW"


# ============================================================
# FULL POLICY EVALUATION
# ============================================================

def evaluate_policy(
    risk_result: Dict[str, Any],
) -> Dict[str, Any]:

    risk_score = risk_result.get(
        "risk_score",
        0,
    )

    action = decide_action(
        risk_score
    )

    return {
        "action": action,
        "risk_score": risk_score,
        "risk_level": risk_result.get(
            "risk_level",
            "LOW",
        ),
        "reason": get_policy_reason(
            action,
            risk_score,
        ),
    }


# ============================================================
# HUMAN-READABLE REASON
# ============================================================

def get_policy_reason(
    action: str,
    risk_score: int,
) -> str:

    if action == "BLOCK":
        return (
            f"Request blocked because the risk score "
            f"({risk_score}) exceeds the blocking threshold."
        )

    if action == "RATE_LIMIT":
        return (
            f"Request should be rate limited because the "
            f"risk score ({risk_score}) indicates significant abuse."
        )

    if action == "MONITOR":
        return (
            f"Request allowed under monitoring because the "
            f"risk score ({risk_score}) indicates suspicious activity."
        )

    return (
        f"Request allowed because the risk score "
        f"({risk_score}) is below the monitoring threshold."
    )