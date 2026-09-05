import time
from collections import defaultdict, deque

from wyvrn.detectors.engine import make_finding


# How many recent observations we keep per endpoint.
MAX_HISTORY = 100


# endpoint -> recent observations
ENDPOINT_HISTORY = defaultdict(
    lambda: deque(maxlen=MAX_HISTORY)
)


def record_observation(
    path,
    response_size,
    latency_ms,
    status_code,
):
    """
    Store an observation for an endpoint.
    """

    ENDPOINT_HISTORY[path].append(
        {
            "timestamp": time.time(),
            "response_size": response_size,
            "latency_ms": latency_ms,
            "status_code": status_code,
        }
    )


def calculate_average(
    observations,
    field,
):
    if not observations:
        return 0

    return sum(
        observation[field]
        for observation in observations
    ) / len(observations)


def detect_behavioral_anomaly(
    path,
    response_size,
    latency_ms,
    status_code,
):
    findings = []

    history = ENDPOINT_HISTORY[path]

    # We need enough observations to establish
    # a meaningful baseline.
    if len(history) < 5:
        record_observation(
            path,
            response_size,
            latency_ms,
            status_code,
        )
        return findings

    average_response_size = calculate_average(
        history,
        "response_size",
    )

    average_latency = calculate_average(
        history,
        "latency_ms",
    )

    # Avoid division by zero.
    response_ratio = (
        response_size / average_response_size
        if average_response_size > 0
        else 1
    )

    latency_ratio = (
        latency_ms / average_latency
        if average_latency > 0
        else 1
    )

    anomaly_reasons = []

    # Response is dramatically larger than normal.
    if response_ratio >= 5:
        anomaly_reasons.append(
            f"response size is {response_ratio:.1f}x "
            f"above the endpoint baseline"
        )

    # Response latency is dramatically higher.
    if latency_ratio >= 5:
        anomaly_reasons.append(
            f"latency is {latency_ratio:.1f}x "
            f"above the endpoint baseline"
        )

    # Unexpected server error.
    if status_code >= 500:
        anomaly_reasons.append(
            f"endpoint returned HTTP {status_code}"
        )

    if anomaly_reasons:

        severity_score = 70

        if response_ratio >= 10:
            severity_score = 85

        if latency_ratio >= 10:
            severity_score = max(
                severity_score,
                85,
            )

        findings.append(
            make_finding(
                detection="BEHAVIORAL_ANOMALY",
                confidence=0.88,
                risk_score=severity_score,
                reason=(
                    "Unusual endpoint behavior detected: "
                    + "; ".join(anomaly_reasons)
                ),
                metadata={
                    "endpoint": path,
                    "response_size": response_size,
                    "baseline_response_size": round(
                        average_response_size,
                        2,
                    ),
                    "response_ratio": round(
                        response_ratio,
                        2,
                    ),
                    "latency_ms": latency_ms,
                    "baseline_latency_ms": round(
                        average_latency,
                        2,
                    ),
                    "latency_ratio": round(
                        latency_ratio,
                        2,
                    ),
                    "status_code": status_code,
                    "baseline_samples": len(history),
                },
            )
        )

    # Always record the latest observation so
    # the baseline evolves over time.
    record_observation(
        path,
        response_size,
        latency_ms,
        status_code,
    )

    return findings