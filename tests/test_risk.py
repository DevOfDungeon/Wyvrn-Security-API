from wyvrn.risk import calculate_risk, get_risk_level


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
# RISK CALCULATION TESTS
# ============================================================

def test_no_findings_returns_low_risk():
    result = calculate_risk([])

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["finding_count"] == 0
    assert result["detections"] == []


def test_bola_risk_is_confidence_adjusted():
    findings = [
        {
            "detection": "BOLA_IDOR",
            "confidence": 0.70,
            "risk_score": 60,
        }
    ]

    result = calculate_risk(findings)

    assert result["risk_score"] == 42
    assert result["risk_level"] == "MEDIUM"
    assert result["finding_count"] == 1


def test_rate_abuse_can_be_critical():
    findings = [
        {
            "detection": "RATE_ABUSE",
            "confidence": 0.95,
            "risk_score": 85,
        }
    ]

    result = calculate_risk(findings)

    assert result["risk_score"] == 81
    assert result["risk_level"] == "CRITICAL"


def test_multiple_findings_receive_correlation_bonus():
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

    result = calculate_risk(findings)

    # Strongest finding:
    # 85 * 0.95 = 80.75 -> 81
    #
    # One additional finding:
    # +10 correlation bonus
    #
    # Final = 91

    assert result["risk_score"] == 91
    assert result["risk_level"] == "CRITICAL"
    assert result["finding_count"] == 2

    assert "BOLA_IDOR" in result["detections"]
    assert "RATE_ABUSE" in result["detections"]


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

    result = calculate_risk(findings)

    assert result["risk_score"] == 100