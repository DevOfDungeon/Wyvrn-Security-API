import time
from collections import defaultdict, deque

from wyvrn.detectors.engine import make_finding


REQUEST_WINDOW_SECONDS = 10
MAX_REQUESTS = 20

REQUEST_HISTORY = defaultdict(deque)


def detect_rate_abuse(request_event):
    findings = []

    client_ip = request_event.get("client_ip") or "unknown"
    path = request_event["path"]

    now = time.time()

    history = REQUEST_HISTORY[(client_ip, path)]

    # Remove requests outside the sliding window.
    while history and now - history[0] > REQUEST_WINDOW_SECONDS:
        history.popleft()

    history.append(now)

    request_count = len(history)

    if request_count > MAX_REQUESTS:
        findings.append(
            make_finding(
                detection="RATE_ABUSE",
                confidence=0.95,
                risk_score=85,
                reason=(
                    f"Excessive requests to {path}: "
                    f"{request_count} requests in "
                    f"{REQUEST_WINDOW_SECONDS} seconds"
                ),
                metadata={
                    "client_ip": client_ip,
                    "path": path,
                    "request_count": request_count,
                    "window_seconds": REQUEST_WINDOW_SECONDS,
                },
            )
        )

    return findings