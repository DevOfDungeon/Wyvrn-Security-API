from wyvrn.detectors.anomaly import (
    ENDPOINT_HISTORY,
    detect_behavioral_anomaly,
)


def setup_function():
    ENDPOINT_HISTORY.clear()


def test_anomaly_needs_baseline():

    for _ in range(4):

        findings = detect_behavioral_anomaly(
            path="/products",
            response_size=200,
            latency_ms=10,
            status_code=200,
        )

    assert findings == []


def test_normal_behavior_is_not_flagged():

    for _ in range(10):

        findings = detect_behavioral_anomaly(
            path="/products",
            response_size=200,
            latency_ms=10,
            status_code=200,
        )

    assert findings == []


def test_large_response_is_detected():

    for _ in range(10):

        detect_behavioral_anomaly(
            path="/users/1",
            response_size=200,
            latency_ms=10,
            status_code=200,
        )

    findings = detect_behavioral_anomaly(
        path="/users/1",
        response_size=1500,
        latency_ms=10,
        status_code=200,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding["detection"]
        == "BEHAVIORAL_ANOMALY"
    )

    assert (
        finding["metadata"]["response_ratio"]
        >= 5
    )


def test_high_latency_is_detected():

    for _ in range(10):

        detect_behavioral_anomaly(
            path="/search",
            response_size=200,
            latency_ms=10,
            status_code=200,
        )

    findings = detect_behavioral_anomaly(
        path="/search",
        response_size=200,
        latency_ms=100,
        status_code=200,
    )

    assert len(findings) == 1

    assert (
        findings[0]["detection"]
        == "BEHAVIORAL_ANOMALY"
    )


def test_server_error_is_detected():

    for _ in range(10):

        detect_behavioral_anomaly(
            path="/login",
            response_size=200,
            latency_ms=10,
            status_code=200,
        )

    findings = detect_behavioral_anomaly(
        path="/login",
        response_size=200,
        latency_ms=10,
        status_code=500,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding["detection"]
        == "BEHAVIORAL_ANOMALY"
    )

    assert (
        finding["metadata"]["status_code"]
        == 500
    )