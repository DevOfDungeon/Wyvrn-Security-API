from typing import Any, Dict


# ============================================================
# POLICY THRESHOLDS
# ============================================================

MONITOR_THRESHOLD = 30
RATE_LIMIT_THRESHOLD = 60
BLOCK_THRESHOLD = 80

# Confidence gates prevent low-confidence detections from immediately
# jumping to the most disruptive response.
BLOCK_CONFIDENCE_THRESHOLD = 0.75
RATE_LIMIT_CONFIDENCE_THRESHOLD = 0.55


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

VALID_ACTIONS = {"ALLOW", "MONITOR", "RATE_LIMIT", "BLOCK"}


# ============================================================
# POLICY CONFIGURATION
# ============================================================

def get_policies() -> Dict[str, str]:
    return DETECTION_POLICIES.copy()


def set_policies(policies: Dict[str, str]) -> Dict[str, str]:
    for detection, action in policies.items():
        if action not in VALID_ACTIONS:
            raise ValueError(
                f"Invalid policy action '{action}' for detection '{detection}'. "
                f"Valid actions: {sorted(VALID_ACTIONS)}"
            )

    DETECTION_POLICIES.clear()
    DETECTION_POLICIES.update(policies)
    return get_policies()


def update_policy(detection: str, action: str) -> Dict[str, str]:
    if action not in VALID_ACTIONS:
        raise ValueError(
            f"Invalid policy action '{action}'. "
            f"Valid actions: {sorted(VALID_ACTIONS)}"
        )

    DETECTION_POLICIES[detection] = action
    return get_policies()


def reset_policies() -> Dict[str, str]:
    DETECTION_POLICIES.clear()
    DETECTION_POLICIES.update({
        "SQL_INJECTION": "BLOCK",
        "SENSITIVE_DATA_EXPOSURE": "BLOCK",
        "BOLA_IDOR": "MONITOR",
        "RATE_ABUSE": "RATE_LIMIT",
        "AUTH_ABUSE": "RATE_LIMIT",
    })
    return get_policies()


# ============================================================
# RISK-BASED POLICY DECISION
# ============================================================

def decide_action(
    risk_score: int,
    confidence: float = 1.0,
) -> str:
    """
    Map risk + confidence to an enforcement action.

    Low-confidence high scores are deliberately stepped down one action
    rather than being blindly blocked.
    """

    try:
        score = max(0, min(100, int(risk_score)))
    except (TypeError, ValueError):
        score = 0

    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence = 1.0

    if score >= BLOCK_THRESHOLD:
        return "BLOCK" if confidence >= BLOCK_CONFIDENCE_THRESHOLD else "RATE_LIMIT"

    if score >= RATE_LIMIT_THRESHOLD:
        return "RATE_LIMIT" if confidence >= RATE_LIMIT_CONFIDENCE_THRESHOLD else "MONITOR"

    if score >= MONITOR_THRESHOLD:
        return "MONITOR"

    return "ALLOW"


# ============================================================
# DETECTION OVERRIDE
# ============================================================

def get_detection_override(detections) -> tuple[str | None, str | None]:
    for detection in detections:
        action = DETECTION_POLICIES.get(detection)
        if action:
            return action, detection
    return None, None


# ============================================================
# FULL POLICY EVALUATION
# ============================================================

def evaluate_policy(risk_result: Dict[str, Any]) -> Dict[str, Any]:
    risk_score = risk_result.get("risk_score", 0)
    risk_level = risk_result.get("risk_level", "LOW")
    confidence = risk_result.get("confidence", 1.0)
    detections = risk_result.get("detections", [])

    risk_action = decide_action(risk_score, confidence)
    override_action, override_detection = get_detection_override(detections)

    if override_action:
        action = override_action
        reason = (
            f"Policy override triggered by {override_detection}. "
            f"The configured action for this detection is {override_action}."
        )
        policy_source = "DETECTION_OVERRIDE"
    else:
        action = risk_action
        reason = get_policy_reason(action, risk_score, confidence)
        policy_source = "RISK_THRESHOLD"

    return {
        "action": action,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
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
    confidence: float = 1.0,
) -> str:
    confidence_percent = round(float(confidence) * 100)

    if action == "BLOCK":
        return (
            f"Request blocked because the risk score ({risk_score}) is critical "
            f"with {confidence_percent}% confidence."
        )

    if action == "RATE_LIMIT":
        if risk_score >= BLOCK_THRESHOLD and confidence < BLOCK_CONFIDENCE_THRESHOLD:
            return (
                f"Request rate limited because risk is critical ({risk_score}) "
                f"but detection confidence ({confidence_percent}%) is below the "
                f"blocking threshold."
            )
        return (
            f"Request should be rate limited because the risk score ({risk_score}) "
            f"indicates significant abuse with {confidence_percent}% confidence."
        )

    if action == "MONITOR":
        if risk_score >= RATE_LIMIT_THRESHOLD and confidence < RATE_LIMIT_CONFIDENCE_THRESHOLD:
            return (
                f"Request allowed under monitoring because risk is elevated ({risk_score}) "
                f"but confidence ({confidence_percent}%) is too low for rate limiting."
            )
        return (
            f"Request allowed under monitoring because the risk score ({risk_score}) "
            f"indicates suspicious activity."
        )

    return (
        f"Request allowed because the risk score ({risk_score}) is below the "
        f"monitoring threshold."
    )
