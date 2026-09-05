from wyvrn.policy import (
    decide_action,
    evaluate_policy,
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


def test_evaluate_monitor_policy():
    risk_result = {
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "finding_count": 1,
        "detections": ["BOLA_IDOR"],
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
        "detections": ["RATE_ABUSE"],
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
        "detections": [
            "BOLA_IDOR",
            "RATE_ABUSE",
        ],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["action"] == "BLOCK"
    assert result["risk_score"] == 91
    assert result["risk_level"] == "CRITICAL"


def test_policy_contains_reason():
    risk_result = {
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "finding_count": 1,
        "detections": ["RATE_ABUSE"],
    }

    result = evaluate_policy(
        risk_result
    )

    assert result["reason"]
    assert "90" in result["reason"]
