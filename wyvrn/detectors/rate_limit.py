import time

from collections import defaultdict, deque

from wyvrn.detectors.engine import make_finding


# ---------------------------------------------------------------------------
# Rate abuse configuration
# ---------------------------------------------------------------------------

RATE_LIMIT_WINDOW_SECONDS = 10

# Number of requests allowed inside the rolling window
# before WYVRN considers the client abusive.
MAX_REQUESTS_PER_WINDOW = 10


# Track request timestamps per client IP.
#
# Key:
#     client_ip
#
# Value:
#     deque of request timestamps
#
REQUEST_HISTORY = defaultdict(deque)


def _remove_expired_requests(history, now):
    """
    Remove requests that have fallen outside the
    configured rolling time window.
    """

    while (
        history
        and now - history[0]
        > RATE_LIMIT_WINDOW_SECONDS
    ):
        history.popleft()


def detect_rate_abuse(
    request_event,
):
    """
    Detect excessive request rates from a single client.

    The detector maintains a rolling request history
    for each client IP.

    Example:

        10 requests / 10 seconds -> allowed
        11+ requests / 10 seconds -> RATE_ABUSE

    The detector returns a security finding once the
    configured threshold has been exceeded.
    """

    findings = []

    client_ip = (
        request_event.get(
            "client_ip"
        )
        or "unknown"
    )

    now = time.time()

    history = REQUEST_HISTORY[
        client_ip
    ]

    # Remove timestamps outside the
    # rolling window.
    _remove_expired_requests(
        history,
        now,
    )

    # Record this request.
    history.append(now)

    request_count = len(history)

    # -----------------------------------------------------------------------
    # Rate threshold exceeded
    # -----------------------------------------------------------------------

    if request_count > MAX_REQUESTS_PER_WINDOW:

        findings.append(
            make_finding(
                detection="RATE_ABUSE",
                confidence=0.95,
                risk_score=70,
                reason=(
                    f"Client {client_ip} generated "
                    f"{request_count} requests within "
                    f"{RATE_LIMIT_WINDOW_SECONDS} seconds, "
                    f"exceeding the configured limit of "
                    f"{MAX_REQUESTS_PER_WINDOW} requests."
                ),
                metadata={
                    "client_ip": client_ip,
                    "request_count": request_count,
                    "window_seconds": (
                        RATE_LIMIT_WINDOW_SECONDS
                    ),
                    "max_requests": (
                        MAX_REQUESTS_PER_WINDOW
                    ),
                },
            )
        )

    return findings