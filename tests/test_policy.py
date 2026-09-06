from wyvrn.policy import (
    decide_action,
    evaluate_policy,
    get_detection_override,
)


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


def test_low_confidence_critical_risk_is_rate_limited():
    assert decide_action(90, 0.60) == "RATE_LIMIT"


def test_low_confidence_high_risk_is_monitored():
    assert decide_action(70, 0.40) == "MONITOR"


def test_evaluate_allow_policy():
    result = evaluate_policy({
        "risk_score": 20,
        "risk_level": "LOW",
        "confidence": 1.0,
        "finding_count": 0,
        "detections": [],
    })
    assert result["action"] == "ALLOW"
    assert result["policy_source"] == "RISK_THRESHOLD"


def test_evaluate_monitor_policy():
    result = evaluate_policy({
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "confidence": 0.8,
        "finding_count": 1,
        "detections": [],
    })
    assert result["action"] == "MONITOR"
    assert result["risk_score"] == 45


def test_evaluate_rate_limit_policy():
    result = evaluate_policy({
        "risk_score": 70,
        "risk_level": "HIGH",
        "confidence": 0.8,
        "finding_count": 1,
        "detections": [],
    })
    assert result["action"] == "RATE_LIMIT"


def test_evaluate_block_policy():
    result = evaluate_policy({
        "risk_score": 91,
        "risk_level": "CRITICAL",
        "confidence": 0.95,
        "finding_count": 2,
        "detections": [],
    })
    assert result["action"] == "BLOCK"
    assert result["risk_level"] == "CRITICAL"


def test_sql_injection_forces_block():
    result = evaluate_policy({
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "confidence": 0.30,
        "finding_count": 1,
        "detections": ["SQL_INJECTION"],
    })
    assert result["action"] == "BLOCK"
    assert result["policy_source"] == "DETECTION_OVERRIDE"
    assert result["override_detection"] == "SQL_INJECTION"


def test_sensitive_data_forces_block():
    result = evaluate_policy({
        "risk_score": 35,
        "risk_level": "MEDIUM",
        "confidence": 0.50,
        "finding_count": 1,
        "detections": ["SENSITIVE_DATA_EXPOSURE"],
    })
    assert result["action"] == "BLOCK"


def test_bola_override_is_monitor():
    result = evaluate_policy({
        "risk_score": 75,
        "risk_level": "HIGH",
        "confidence": 1.0,
        "finding_count": 1,
        "detections": ["BOLA_IDOR"],
    })
    assert result["action"] == "MONITOR"
    assert result["policy_source"] == "DETECTION_OVERRIDE"


def test_rate_abuse_override():
    result = evaluate_policy({
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "confidence": 0.30,
        "finding_count": 1,
        "detections": ["RATE_ABUSE"],
    })
    assert result["action"] == "RATE_LIMIT"


def test_auth_abuse_override():
    result = evaluate_policy({
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "confidence": 0.30,
        "finding_count": 1,
        "detections": ["AUTH_ABUSE"],
    })
    assert result["action"] == "RATE_LIMIT"


def test_detection_override_beats_risk_threshold():
    result = evaluate_policy({
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "confidence": 1.0,
        "finding_count": 1,
        "detections": ["BOLA_IDOR"],
    })
    assert result["action"] == "MONITOR"


def test_sql_injection_override_beats_low_risk():
    result = evaluate_policy({
        "risk_score": 25,
        "risk_level": "LOW",
        "confidence": 0.2,
        "finding_count": 1,
        "detections": ["SQL_INJECTION"],
    })
    assert result["action"] == "BLOCK"


def test_get_detection_override():
    action, detection = get_detection_override(["BOLA_IDOR"])
    assert action == "MONITOR"
    assert detection == "BOLA_IDOR"


def test_no_detection_override():
    action, detection = get_detection_override(["UNKNOWN_DETECTION"])
    assert action is None
    assert detection is None


def test_policy_reason_contains_score_and_confidence():
    result = evaluate_policy({
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "confidence": 0.60,
        "finding_count": 1,
        "detections": [],
    })
    assert result["action"] == "RATE_LIMIT"
    assert "90" in result["reason"]
    assert "60%" in result["reason"]
