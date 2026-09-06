import pytest

import wyvrn.risk as risk


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def finding(
    detection="TEST",
    risk_score=50,
    confidence=1.0,
):
    return {
        "detection": detection,
        "risk_score": risk_score,
        "confidence": confidence,
        "reason": "test finding",
        "metadata": {},
    }


@pytest.fixture(autouse=True)
def clean_history():
    risk.RISK_HISTORY.clear()

    yield

    risk.RISK_HISTORY.clear()


# ---------------------------------------------------------------------------
# Basic scoring
# ---------------------------------------------------------------------------

def test_no_findings_is_low_risk():
    result = risk.calculate_risk([])

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["finding_count"] == 0
    assert result["detections"] == []


def test_single_high_confidence_finding_preserves_severity():
    result = risk.calculate_risk(
        [
            finding(
                detection="SQL_INJECTION",
                risk_score=85,
                confidence=1.0,
            )
        ]
    )

    assert result["risk_score"] == 85
    assert result["risk_level"] == "CRITICAL"
    assert result["finding_count"] == 1
    assert result["detections"] == ["SQL_INJECTION"]


def test_confidence_reduces_but_does_not_erase_severity():
    result = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=60,
                confidence=0.50,
            )
        ]
    )

    # 60 * (0.85 + (0.15 * 0.50))
    #
    # = 60 * 0.925
    # = 55.5
    #
    # Conventional security-score rounding:
    # 55.5 -> 56
    assert result["risk_score"] == 56
    assert result["risk_level"] == "MEDIUM"


def test_zero_confidence_does_not_erase_finding():
    result = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=80,
                confidence=0.0,
            )
        ]
    )

    # 80 * 0.85 = 68
    assert result["risk_score"] == 68
    assert result["risk_score"] > 0


# ---------------------------------------------------------------------------
# Multiple findings
# ---------------------------------------------------------------------------

def test_multiple_findings_increase_risk():
    single = risk.calculate_risk(
        [
            finding(
                detection="BOLA_IDOR",
                risk_score=60,
                confidence=0.70,
            )
        ]
    )

    risk.RISK_HISTORY.clear()

    multiple = risk.calculate_risk(
        [
            finding(
                detection="BOLA_IDOR",
                risk_score=60,
                confidence=0.70,
            ),
            finding(
                detection="RATE_ABUSE",
                risk_score=85,
                confidence=0.95,
            ),
        ]
    )

    assert multiple["risk_score"] > single["risk_score"]
    assert multiple["finding_count"] == 2
    assert "BOLA_IDOR" in multiple["detections"]
    assert "RATE_ABUSE" in multiple["detections"]


def test_secondary_findings_have_diminishing_influence():
    one = risk.calculate_risk(
        [
            finding(
                detection="A",
                risk_score=80,
                confidence=1.0,
            )
        ]
    )

    risk.RISK_HISTORY.clear()

    two = risk.calculate_risk(
        [
            finding(
                detection="A",
                risk_score=80,
                confidence=1.0,
            ),
            finding(
                detection="B",
                risk_score=80,
                confidence=1.0,
            ),
        ]
    )

    assert two["risk_score"] > one["risk_score"]

    # The second finding must not simply add another 80 points.
    assert two["risk_score"] < 100


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

def test_sensitive_endpoint_adds_contextual_risk():
    plain = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=50,
                confidence=1.0,
            )
        ],
        request_event={
            "method": "GET",
            "path": "/search",
        },
    )

    risk.RISK_HISTORY.clear()

    sensitive = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=50,
                confidence=1.0,
            )
        ],
        request_event={
            "method": "GET",
            "path": "/admin/users/42",
        },
    )

    assert sensitive["risk_score"] == plain["risk_score"] + 5


def test_mutating_request_adds_contextual_risk():
    plain = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=60,
                confidence=1.0,
            )
        ],
        request_event={
            "method": "GET",
            "path": "/search",
        },
    )

    risk.RISK_HISTORY.clear()

    mutating = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=60,
                confidence=1.0,
            )
        ],
        request_event={
            "method": "DELETE",
            "path": "/search",
        },
    )

    assert mutating["risk_score"] == plain["risk_score"] + 3


def test_sensitive_mutating_endpoint_gets_both_context_signals():
    plain = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=60,
                confidence=1.0,
            )
        ],
        request_event={
            "method": "GET",
            "path": "/search",
        },
    )

    risk.RISK_HISTORY.clear()

    contextual = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=60,
                confidence=1.0,
            )
        ],
        request_event={
            "method": "DELETE",
            "path": "/users/42",
        },
    )

    # /users/42:
    #
    # sensitive endpoint = +5
    # DELETE            = +3
    #
    # total = +8
    assert contextual["risk_score"] == plain["risk_score"] + 8


def test_server_error_adds_contextual_risk():
    plain = risk.calculate_risk(
        [
            finding(
                detection="BEHAVIORAL_ANOMALY",
                risk_score=70,
                confidence=0.88,
            )
        ],
        request_event={
            "method": "GET",
            "path": "/search",
        },
        response_event={
            "status_code": 200,
        },
    )

    risk.RISK_HISTORY.clear()

    server_error = risk.calculate_risk(
        [
            finding(
                detection="BEHAVIORAL_ANOMALY",
                risk_score=70,
                confidence=0.88,
            )
        ],
        request_event={
            "method": "GET",
            "path": "/search",
        },
        response_event={
            "status_code": 500,
        },
    )

    assert server_error["risk_score"] == plain["risk_score"] + 5


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def test_correlation_adds_risk():
    plain = risk.calculate_risk(
        [
            finding(
                detection="SQL_INJECTION",
                risk_score=80,
                confidence=1.0,
            )
        ]
    )

    # Remove the baseline event from temporal history so that the comparison
    # isolates correlation risk.
    risk.RISK_HISTORY.clear()

    correlated = risk.calculate_risk(
        [
            finding(
                detection="SQL_INJECTION",
                risk_score=80,
                confidence=1.0,
            )
        ],
        correlations=[
            {
                "type": "ATTACK_CAMPAIGN",
                "severity": "HIGH",
            }
        ],
    )

    assert correlated["risk_score"] == plain["risk_score"] + 10


def test_multiple_correlations_are_capped():
    plain = risk.calculate_risk(
        [
            finding(
                detection="SQL_INJECTION",
                risk_score=70,
                confidence=1.0,
            )
        ]
    )

    # Clear the history generated by the baseline calculation.
    #
    # Otherwise the correlated calculation can receive a temporal bonus and
    # the test would no longer isolate the correlation behaviour.
    risk.RISK_HISTORY.clear()

    result = risk.calculate_risk(
        [
            finding(
                detection="SQL_INJECTION",
                risk_score=70,
                confidence=1.0,
            )
        ],
        correlations=[
            {"type": "A"},
            {"type": "B"},
            {"type": "C"},
            {"type": "D"},
        ],
    )

    # 70-point finding at 100% confidence:
    #
    # 70 * 1.0 = 70
    #
    # Correlation bonus:
    #
    # 4 correlations * 10 = 40
    # capped at 20
    #
    # final = 90
    assert result["risk_score"] == min(
        plain["risk_score"] + 20,
        100,
    )


# ---------------------------------------------------------------------------
# Temporal behaviour
# ---------------------------------------------------------------------------

def test_temporal_activity_accumulates():
    results = []

    for _ in range(4):
        result = risk.calculate_risk(
            [
                finding(
                    detection="RATE_ABUSE",
                    risk_score=70,
                    confidence=1.0,
                )
            ]
        )

        results.append(result["risk_score"])

    # Repeated suspicious activity should increase risk.
    assert results[-1] >= 80
    assert results[-1] > results[0]


def test_old_history_decays_away():
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)

    risk.RISK_HISTORY.extend(
        [
            {
                "timestamp": now - timedelta(seconds=120),
                "score": 90,
            },
            {
                "timestamp": now - timedelta(seconds=180),
                "score": 90,
            },
        ]
    )

    result = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=50,
                confidence=1.0,
            )
        ]
    )

    # Old events should not produce temporal bonus.
    assert result["risk_score"] == 50


def test_zero_score_history_does_not_create_temporal_bonus():
    from datetime import datetime, timezone

    risk.RISK_HISTORY.append(
        {
            "timestamp": datetime.now(timezone.utc),
            "score": 0,
        }
    )

    result = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=50,
                confidence=1.0,
            )
        ]
    )

    assert result["risk_score"] == 50


# ---------------------------------------------------------------------------
# Score boundaries
# ---------------------------------------------------------------------------

def test_score_never_exceeds_100():
    result = risk.calculate_risk(
        [
            finding(
                detection="A",
                risk_score=100,
                confidence=1.0,
            ),
            finding(
                detection="B",
                risk_score=100,
                confidence=1.0,
            ),
            finding(
                detection="C",
                risk_score=100,
                confidence=1.0,
            ),
        ],
        request_event={
            "method": "DELETE",
            "path": "/admin/users/42",
        },
        response_event={
            "status_code": 500,
        },
        correlations=[
            {"type": "A"},
            {"type": "B"},
            {"type": "C"},
        ],
    )

    assert result["risk_score"] <= 100


def test_score_never_goes_below_zero():
    result = risk.calculate_risk([])

    assert result["risk_score"] >= 0


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "score,expected_level",
    [
        (0, "LOW"),
        (29, "LOW"),
        (30, "MEDIUM"),
        (59, "MEDIUM"),
        (60, "HIGH"),
        (79, "HIGH"),
        (80, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_risk_level_boundaries(score, expected_level):
    assert risk._risk_level(score) == expected_level


# ---------------------------------------------------------------------------
# Confidence aggregation
# ---------------------------------------------------------------------------

def test_overall_confidence_is_between_zero_and_one():
    result = risk.calculate_risk(
        [
            finding(
                detection="A",
                risk_score=80,
                confidence=0.90,
            ),
            finding(
                detection="B",
                risk_score=50,
                confidence=0.40,
            ),
        ]
    )

    assert 0 <= result["confidence"] <= 1


def test_single_finding_confidence_is_preserved():
    result = risk.calculate_risk(
        [
            finding(
                detection="TEST",
                risk_score=50,
                confidence=0.80,
            )
        ]
    )

    assert result["confidence"] == 0.80


def test_detections_are_preserved_in_output():
    result = risk.calculate_risk(
        [
            finding(
                detection="SQL_INJECTION",
                risk_score=90,
                confidence=1.0,
            ),
            finding(
                detection="BOLA_IDOR",
                risk_score=70,
                confidence=1.0,
            ),
        ]
    )

    assert result["detections"] == [
        "SQL_INJECTION",
        "BOLA_IDOR",
    ]


def test_duplicate_detections_are_not_removed():
    result = risk.calculate_risk(
        [
            finding(
                detection="SENSITIVE_DATA_PATTERN",
                risk_score=45,
                confidence=0.90,
            ),
            finding(
                detection="SENSITIVE_DATA_PATTERN",
                risk_score=45,
                confidence=0.90,
            ),
        ]
    )

    assert result["finding_count"] == 2

    assert result["detections"] == [
        "SENSITIVE_DATA_PATTERN",
        "SENSITIVE_DATA_PATTERN",
    ]


# ---------------------------------------------------------------------------
# Convenience helper
# ---------------------------------------------------------------------------

def test_calculate_risk_score_returns_numeric_score():
    score = risk.calculate_risk_score(
        [
            finding(
                detection="SQL_INJECTION",
                risk_score=85,
                confidence=1.0,
            )
        ]
    )

    assert isinstance(score, int)
    assert score == 85