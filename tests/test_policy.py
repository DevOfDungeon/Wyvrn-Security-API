from wyvrn.policy import (
    decide_action,
    evaluate_policy,
    get_detection_override,
)


# ============================================================
# ACTION THRESHOLD TESTS
# ============================================================

def test_low_risk_is_allowed():
    assert decide_action(0) == "ALLOW"
    assert decide_action(29) == "ALLOW"


def test_medium_risk_is_monitored():
    assert decide_action(30) == "MONITOR"
    assert decide_action(59) == "MONITOR"


def test_high_risk_is_rate_limited():
    assert decide_action(60) == "RATE_LIMIT"
    assert decide_action(79) == "RATE_LIMIT"


def test_critical_risk_is_blocked():
    assert decide_action(80) == "BLOCK"
    assert decide_action(100) == "BLOCK"


# ============================================================
# POLICY EVALUATION TESTS
# ============================================================

def test_evaluate_allow_policy():
    risk_result = {
        "risk_score": 20,
        "risk_level": "LOW",
        "finding_count": 0,
        "detections": [],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "ALLOW"
    assert result["risk_score"] == 20
    assert result["risk_level"] == "LOW"
    assert result["policy_source"] == "RISK_THRESHOLD"


def test_evaluate_monitor_policy():
    risk_result = {
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "finding_count": 1,
        "detections": [],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "MONITOR"
    assert result["risk_score"] == 45


def test_evaluate_rate_limit_policy():
    risk_result = {
        "risk_score": 70,
        "risk_level": "HIGH",
        "finding_count": 1,
        "detections": [],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "RATE_LIMIT"
    assert result["risk_score"] == 70


def test_evaluate_block_policy():
    risk_result = {
        "risk_score": 91,
        "risk_level": "CRITICAL",
        "finding_count": 2,
        "detections": [],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "BLOCK"
    assert result["risk_score"] == 91
    assert result["risk_level"] == "CRITICAL"


# ============================================================
# DETECTION OVERRIDE TESTS
# ============================================================

def test_sql_injection_forces_block():
    risk_result = {
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "finding_count": 1,
        "detections": [
            "SQL_INJECTION",
        ],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "BLOCK"
    assert result["policy_source"] == "DETECTION_OVERRIDE"
    assert result["override_detection"] == "SQL_INJECTION"


def test_sensitive_data_forces_block():
    risk_result = {
        "risk_score": 35,
        "risk_level": "MEDIUM",
        "finding_count": 1,
        "detections": [
            "SENSITIVE_DATA_EXPOSURE",
        ],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "BLOCK"
    assert result["policy_source"] == "DETECTION_OVERRIDE"


def test_bola_override_is_monitor():
    risk_result = {
        "risk_score": 75,
        "risk_level": "HIGH",
        "finding_count": 1,
        "detections": [
            "BOLA_IDOR",
        ],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "MONITOR"
    assert result["policy_source"] == "DETECTION_OVERRIDE"
    assert result["override_detection"] == "BOLA_IDOR"


def test_rate_abuse_override():
    risk_result = {
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "finding_count": 1,
        "detections": [
            "RATE_ABUSE",
        ],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "RATE_LIMIT"
    assert result["policy_source"] == "DETECTION_OVERRIDE"


def test_auth_abuse_override():
    risk_result = {
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "finding_count": 1,
        "detections": [
            "AUTH_ABUSE",
        ],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "RATE_LIMIT"
    assert result["policy_source"] == "DETECTION_OVERRIDE"


# ============================================================
# OVERRIDE PRIORITY TESTS
# ============================================================

def test_detection_override_beats_risk_threshold():
    """
    BOLA normally has a high risk score here,
    but its explicit policy says MONITOR.
    """

    risk_result = {
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "finding_count": 1,
        "detections": [
            "BOLA_IDOR",
        ],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "MONITOR"
    assert result["policy_source"] == "DETECTION_OVERRIDE"


def test_sql_injection_override_beats_low_risk():
    """
    Even a low numerical risk score cannot weaken
    the explicit SQL injection BLOCK policy.
    """

    risk_result = {
        "risk_score": 25,
        "risk_level": "LOW",
        "finding_count": 1,
        "detections": [
            "SQL_INJECTION",
        ],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "BLOCK"


# ============================================================
# OVERRIDE HELPER TESTS
# ============================================================

def test_get_detection_override():
    action, detection = get_detection_override(
        ["BOLA_IDOR"]
    )

    assert action == "MONITOR"
    assert detection == "BOLA_IDOR"


def test_no_detection_override():
    action, detection = get_detection_override(
        ["UNKNOWN_DETECTION"]
    )

    assert action is None
    assert detection is None


# ============================================================
# REASON TESTS
# ============================================================

def test_policy_contains_reason():
    risk_result = {
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "finding_count": 1,
        "detections": [],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["reason"]
    assert "90" in result["reason"]


def test_override_reason_mentions_detection():
    risk_result = {
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "finding_count": 1,
        "detections": [
            "SQL_INJECTION",
        ],
    }

    result = evaluate_policy(
        risk_result
    )

    assert "SQL_INJECTION" in result["reason"]
    assert "BLOCK" in result["reason"]

