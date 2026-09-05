import json
import time

from collections import defaultdict, deque

from wyvrn.detectors.engine import make_finding


# ---------------------------------------------------------------------------
# Authentication abuse configuration
# ---------------------------------------------------------------------------

AUTH_FAILURE_WINDOW_SECONDS = 60
MAX_FAILED_ATTEMPTS = 5


# Track failed authentication timestamps.
#
# Key:
#     (client_ip, username)
#
# Value:
#     deque of timestamps
#
FAILED_ATTEMPTS = defaultdict(deque)


def extract_username(request_event):
    """
    Extract the username involved in an authentication request.

    Supports:
    - query parameters
    - JSON request bodies
    """

    query_params = request_event.get(
        "query_params",
        {},
    )

    username = query_params.get("username")

    if username:
        return str(username)

    body = request_event.get("body")

    if not body:
        return None

    # Body may already be a dictionary.
    if isinstance(body, dict):
        username = body.get("username")

        if username:
            return str(username)

        return None

    # Try JSON body.
    try:
        parsed_body = json.loads(body)

        if isinstance(parsed_body, dict):
            username = parsed_body.get("username")

            if username:
                return str(username)

    except (
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        pass

    return None


def _get_failure_history(client_ip, username):
    """
    Return the failure history for an IP + username pair.
    """

    return FAILED_ATTEMPTS[
        (client_ip, username)
    ]


def _remove_expired_attempts(history, now):
    """
    Remove authentication failures outside
    the configured rolling window.
    """

    while (
        history
        and now - history[0]
        > AUTH_FAILURE_WINDOW_SECONDS
    ):
        history.popleft()


def detect_auth_abuse(
    request_event,
    response_status_code=None,
):
    """
    Detect repeated failed authentication attempts.

    IMPORTANT:
    This detector is response-aware.

    A request only counts as an authentication failure
    when the upstream API actually returns HTTP 401.

    Successful authentication clears the failure history
    for that IP + username pair.
    """

    findings = []

    path = request_event.get("path")
    method = request_event.get("method")

    # Only inspect login endpoints.
    if method != "POST":
        return findings

    if path not in {
        "/login",
        "/auth/login",
    }:
        return findings

    # We cannot determine whether authentication failed
    # until we know the upstream response.
    if response_status_code is None:
        return findings

    client_ip = (
        request_event.get("client_ip")
        or "unknown"
    )

    username = extract_username(
        request_event
    )

    # If the username is unavailable, fall back to
    # IP-based tracking.
    username_key = (
        username
        if username
        else "unknown"
    )

    history = _get_failure_history(
        client_ip,
        username_key,
    )

    now = time.time()

    _remove_expired_attempts(
        history,
        now,
    )

    # -----------------------------------------------------------------------
    # Failed authentication
    # -----------------------------------------------------------------------

    if response_status_code == 401:

        history.append(now)

        attempts = len(history)

        if attempts >= MAX_FAILED_ATTEMPTS:

            findings.append(
                make_finding(
                    detection="AUTH_ABUSE",
                    confidence=0.95,
                    risk_score=80,
                    reason=(
                        f"Repeated failed authentication "
                        f"attempts detected from {client_ip}"
                        f" for username "
                        f"'{username_key}': "
                        f"{attempts} failures within "
                        f"{AUTH_FAILURE_WINDOW_SECONDS} seconds."
                    ),
                    metadata={
                        "client_ip": client_ip,
                        "username": username_key,
                        "attempts": attempts,
                        "window_seconds": (
                            AUTH_FAILURE_WINDOW_SECONDS
                        ),
                        "status_code": (
                            response_status_code
                        ),
                    },
                )
            )

        return findings

    # -----------------------------------------------------------------------
    # Successful authentication
    # -----------------------------------------------------------------------

    if 200 <= response_status_code < 300:

        history.clear()

    return findings