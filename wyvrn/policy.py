from typing import Any, Dict


# ============================================================
# POLICY THRESHOLDS
# ============================================================

MONITOR_THRESHOLD = 30
RATE_LIMIT_THRESHOLD = 60
BLOCK_THRESHOLD = 80


# ============================================================
# DETECTION-SPECIFIC POLICY OVERRIDES
# ============================================================

DETECTION_POLICIES = {
    "SQL_INJECTION": "BLOCK",
    "SENSITIVE_DATA_EXPOSURE": "BLOCK",
    "BOLA_IDOR": "MONITOR",
    "RATE_ABUSE": "RATE_LIMIT",
    "AUTH_ABUSE": "RATE_LIMIT",
}


# ============================================================
# VALID ACTIONS
# ============================================================

VALID_ACTIONS = {
    "ALLOW",
    "MONITOR",
    "RATE_LIMIT",
    "BLOCK",
}


# ============================================================
# RISK-BASED POLICY DECISION
# ============================================================

def decide_action(
    risk_score: int,
) -> str:
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
# DETECTION OVERRIDE
# ============================================================

def get_detection_override(
    detections,
) -> tuple[str | None, str | None]:
    """
    Check whether any detected threat has a
    detection-specific policy override.

    Returns:
        (action, detection)

    The first matching override is returned.
    """

    for detection in detections:
        action = DETECTION_POLICIES.get(
            detection
        )

        if action:
            return action, detection

    return None, None


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

    risk_level = risk_result.get(
        "risk_level",
        "LOW",
    )

    detections = risk_result.get(
        "detections",
        [],
    )

    # --------------------------------------------------------
    # First apply normal risk-score policy
    # --------------------------------------------------------

    risk_action = decide_action(
        risk_score
    )

    # --------------------------------------------------------
    # Then check detection-specific overrides
    # --------------------------------------------------------

    override_action, override_detection = (
        get_detection_override(
            detections
        )
    )

    if override_action:
        action = override_action

        reason = (
            f"Policy override triggered by "
            f"{override_detection}. "
            f"The configured action for this detection "
            f"is {override_action}."
        )

        policy_source = "DETECTION_OVERRIDE"

    else:
        action = risk_action

        reason = get_policy_reason(
            action,
            risk_score,
        )

        policy_source = "RISK_THRESHOLD"

    return {
        "action": action,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "policy_source": policy_source,
        "override_detection": override_detection,
        "reason": reason,
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
