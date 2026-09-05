from wyvrn.risk import (
    calculate_risk,
    get_risk_level,
)


# ============================================================
# RISK LEVEL TESTS
# ============================================================

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


# ============================================================
# BASIC RISK CALCULATION
# ============================================================

def test_no_findings_returns_low_risk():

    result = calculate_risk([])

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["finding_count"] == 0
    assert result["detections"] == []
    assert result["correlations"] == []


def test_bola_risk_is_confidence_adjusted():

    findings = [
        {
            "detection": "BOLA_IDOR",
            "confidence": 0.70,
            "risk_score": 60,
        }
    ]

    result = calculate_risk(
        findings
    )

    assert result["risk_score"] == 42
    assert result["risk_level"] == "MEDIUM"
    assert result["finding_count"] == 1
    assert result["correlations"] == []


def test_rate_abuse_can_be_critical():

    findings = [
        {
            "detection": "RATE_ABUSE",
            "confidence": 0.95,
            "risk_score": 85,
        }
    ]

    result = calculate_risk(
        findings
    )

    assert result["risk_score"] == 81
    assert result["risk_level"] == "CRITICAL"


# ============================================================
# GENERIC CORRELATION
# ============================================================

def test_multiple_findings_receive_generic_bonus():

    findings = [
        {
            "detection": "BOLA_IDOR",
            "confidence": 0.70,
            "risk_score": 60,
        },
        {
            "detection": "RATE_ABUSE",
            "confidence": 0.95,
            "risk_score": 85,
        },
    ]

    result = calculate_risk(
        findings
    )

    # Strongest:
    #
    # 85 * 0.95 = 80.75
    # rounded = 81
    #
    # Generic bonus:
    #
    # +5
    #
    # Final:
    #
    # 86

    assert result["risk_score"] == 86
    assert result["risk_level"] == "CRITICAL"
    assert result["finding_count"] == 2

    assert (
        "BOLA_IDOR"
        in result["detections"]
    )

    assert (
        "RATE_ABUSE"
        in result["detections"]
    )

    assert result["correlations"] == []


# ============================================================
# EXPLICIT ATTACK CORRELATION TESTS
# ============================================================

def test_sql_injection_and_rate_abuse_are_correlated():

    findings = [
        {
            "detection": "SQL_INJECTION",
            "confidence": 0.92,
            "risk_score": 90,
        },
        {
            "detection": "RATE_ABUSE",
            "confidence": 0.95,
            "risk_score": 85,
        },
    ]

    result = calculate_risk(
        findings
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"

    assert len(
        result["correlations"]
    ) == 1

    correlation = (
        result["correlations"][0]
    )

    assert (
        correlation["name"]
        == "COORDINATED_INJECTION_ABUSE"
    )

    assert (
        correlation["bonus"]
        == 20
    )


def test_bola_and_sensitive_data_are_correlated():

    findings = [
        {
            "detection": "BOLA_IDOR",
            "confidence": 0.70,
            "risk_score": 60,
        },
        {
            "detection": "SENSITIVE_DATA_EXPOSURE",
            "confidence": 0.98,
            "risk_score": 90,
        },
    ]

    result = calculate_risk(
        findings
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"

    assert len(
        result["correlations"]
    ) == 1

    correlation = (
        result["correlations"][0]
    )

    assert (
        correlation["name"]
        == "POTENTIAL_DATA_EXFILTRATION"
    )

    assert (
        "BOLA_IDOR"
        in correlation["detections"]
    )

    assert (
        "SENSITIVE_DATA_EXPOSURE"
        in correlation["detections"]
    )


def test_auth_abuse_and_rate_abuse_are_correlated():

    findings = [
        {
            "detection": "AUTH_ABUSE",
            "confidence": 0.95,
            "risk_score": 80,
        },
        {
            "detection": "RATE_ABUSE",
            "confidence": 0.95,
            "risk_score": 85,
        },
    ]

    result = calculate_risk(
        findings
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"

    assert len(
        result["correlations"]
    ) == 1

    assert (
        result["correlations"][0]["name"]
        == "CREDENTIAL_ATTACK"
    )


def test_sql_injection_and_sensitive_data_are_correlated():

    findings = [
        {
            "detection": "SQL_INJECTION",
            "confidence": 0.92,
            "risk_score": 90,
        },
        {
            "detection": "SENSITIVE_DATA_EXPOSURE",
            "confidence": 0.98,
            "risk_score": 90,
        },
    ]

    result = calculate_risk(
        findings
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"

    assert len(
        result["correlations"]
    ) == 1

    assert (
        result["correlations"][0]["name"]
        == "INJECTION_WITH_DATA_EXPOSURE"
    )


# ============================================================
# MULTIPLE CORRELATIONS
# ============================================================

def test_multiple_attack_correlations_can_be_detected():

    findings = [
        {
            "detection": "SQL_INJECTION",
            "confidence": 1.0,
            "risk_score": 90,
        },
        {
            "detection": "RATE_ABUSE",
            "confidence": 1.0,
            "risk_score": 85,
        },
        {
            "detection": "SENSITIVE_DATA_EXPOSURE",
            "confidence": 1.0,
            "risk_score": 90,
        },
    ]

    result = calculate_risk(
        findings
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"

    # SQL + RATE
    # SQL + SENSITIVE DATA
    #
    # Both correlations should be detected.

    assert len(
        result["correlations"]
    ) == 2

    correlation_names = {
        correlation["name"]
        for correlation
        in result["correlations"]
    }

    assert (
        "COORDINATED_INJECTION_ABUSE"
        in correlation_names
    )

    assert (
        "INJECTION_WITH_DATA_EXPOSURE"
        in correlation_names
    )


# ============================================================
# SCORE LIMIT
# ============================================================

def test_risk_score_never_exceeds_100():

    findings = [
        {
            "detection": "ATTACK_A",
            "confidence": 1.0,
            "risk_score": 100,
        },
        {
            "detection": "ATTACK_B",
            "confidence": 1.0,
            "risk_score": 100,
        },
        {
            "detection": "ATTACK_C",
            "confidence": 1.0,
            "risk_score": 100,
        },
    ]

    result = calculate_risk(
        findings
    )

    assert result["risk_score"] == 100
