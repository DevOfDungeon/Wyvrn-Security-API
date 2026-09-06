import pytest

from wyvrn.risk import (
    calculate_risk,
    get_risk_level,
    reset_risk_history,
)


@pytest.fixture(autouse=True)
def clean_risk_state():
    reset_risk_history()
    yield
    reset_risk_history()


def test_low_risk():
    assert get_risk_level(0) == "LOW"
    assert get_risk_level(29) == "LOW"


def test_medium_risk():
    assert get_risk_level(30) == "MEDIUM"
    assert get_risk_level(59) == "MEDIUM"


def test_high_risk():
    assert get_risk_level(60) == "HIGH"
    assert get_risk_level(79) == "HIGH"


def test_critical_risk():
    assert get_risk_level(80) == "CRITICAL"
    assert get_risk_level(100) == "CRITICAL"


def test_no_findings_returns_low_risk():
    result = calculate_risk([])
    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["finding_count"] == 0
    assert result["detections"] == []
    assert result["correlations"] == []
    assert result["confidence"] == 1.0


def test_confidence_adjustment_reduces_but_does_not_erase_severity():
    high_confidence = calculate_risk([{
        "detection": "BOLA_IDOR",
        "confidence": 1.0,
        "risk_score": 60,
    }])
    low_confidence = calculate_risk([{
        "detection": "BOLA_IDOR",
        "confidence": 0.5,
        "risk_score": 60,
    }])

    assert high_confidence["risk_score"] == 60
    assert low_confidence["risk_score"] == 45
    assert low_confidence["risk_score"] < high_confidence["risk_score"]


def test_rate_abuse_remains_critical_when_confidence_is_high():
    result = calculate_risk([{
        "detection": "RATE_ABUSE",
        "confidence": 0.95,
        "risk_score": 85,
    }])

    assert result["risk_score"] == 83
    assert result["risk_level"] == "CRITICAL"
    assert result["confidence"] == 0.95


def test_multiple_findings_are_weighted_not_flatly_added():
    result = calculate_risk([
        {"detection": "BOLA_IDOR", "confidence": 0.7, "risk_score": 60},
        {"detection": "RATE_ABUSE", "confidence": 0.95, "risk_score": 85},
    ])

    assert result["risk_score"] == 96
    assert result["risk_level"] == "CRITICAL"
    assert result["finding_count"] == 2
    assert "BOLA_IDOR" in result["detections"]
    assert "RATE_ABUSE" in result["detections"]
    assert len(result["score_contributions"]) >= 2


def test_sql_injection_and_rate_abuse_are_correlated():
    result = calculate_risk([
        {"detection": "SQL_INJECTION", "confidence": 0.92, "risk_score": 90},
        {"detection": "RATE_ABUSE", "confidence": 0.95, "risk_score": 85},
    ])

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"
    assert result["correlations"][0]["name"] == "COORDINATED_INJECTION_ABUSE"


def test_bola_and_sensitive_data_are_correlated():
    result = calculate_risk([
        {"detection": "BOLA_IDOR", "confidence": 0.70, "risk_score": 60},
        {"detection": "SENSITIVE_DATA_EXPOSURE", "confidence": 0.98, "risk_score": 90},
    ])

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"
    assert result["correlations"][0]["name"] == "POTENTIAL_DATA_EXFILTRATION"


def test_multiple_attack_correlations_can_be_detected():
    result = calculate_risk([
        {"detection": "SQL_INJECTION", "confidence": 1.0, "risk_score": 90},
        {"detection": "RATE_ABUSE", "confidence": 1.0, "risk_score": 85},
        {"detection": "SENSITIVE_DATA_EXPOSURE", "confidence": 1.0, "risk_score": 90},
    ])

    names = {item["name"] for item in result["correlations"]}
    assert result["risk_score"] == 100
    assert names == {"COORDINATED_INJECTION_ABUSE", "INJECTION_WITH_DATA_EXPOSURE"}


def test_sensitive_endpoint_adds_contextual_risk():
    plain = calculate_risk([
        {"detection": "BOLA_IDOR", "confidence": 0.7, "risk_score": 60},
    ])
    contextual = calculate_risk(
        [{"detection": "BOLA_IDOR", "confidence": 0.7, "risk_score": 60}],
        context={"path": "/admin/users/42", "method": "GET"},
    )

    assert contextual["risk_score"] == plain["risk_score"] + 8
    assert any(item["factor"] == "ENDPOINT_SENSITIVITY" for item in contextual["score_contributions"])


def test_server_error_adds_contextual_risk():
    result = calculate_risk(
        [{"detection": "BEHAVIORAL_ANOMALY", "confidence": 0.88, "risk_score": 70}],
        context={"path": "/search", "method": "GET", "status_code": 500},
    )

    assert result["risk_score"] == 74
    assert any(item["factor"] == "SERVER_ERROR" for item in result["score_contributions"])


def test_temporal_risk_accumulates_and_decays():
    first = calculate_risk(
        [{"detection": "RATE_ABUSE", "confidence": 1.0, "risk_score": 70}],
        history_key="10.0.0.5",
        track_history=True,
    )
    second = calculate_risk(
        [{"detection": "RATE_ABUSE", "confidence": 1.0, "risk_score": 70}],
        history_key="10.0.0.5",
        track_history=True,
    )

    assert first["temporal_bonus"] == 0
    assert second["temporal_bonus"] > 0
    assert second["risk_score"] > first["risk_score"]


def test_temporal_history_is_isolated_by_source():
    calculate_risk(
        [{"detection": "RATE_ABUSE", "confidence": 1.0, "risk_score": 70}],
        history_key="attacker-a",
        track_history=True,
    )
    other = calculate_risk(
        [{"detection": "RATE_ABUSE", "confidence": 1.0, "risk_score": 70}],
        history_key="attacker-b",
        track_history=True,
    )

    assert other["temporal_bonus"] == 0


def test_risk_score_never_exceeds_100():
    result = calculate_risk([
        {"detection": "ATTACK_A", "confidence": 1.0, "risk_score": 100},
        {"detection": "ATTACK_B", "confidence": 1.0, "risk_score": 100},
        {"detection": "ATTACK_C", "confidence": 1.0, "risk_score": 100},
    ], context={"path": "/admin", "method": "POST", "status_code": 500})

    assert result["risk_score"] == 100
