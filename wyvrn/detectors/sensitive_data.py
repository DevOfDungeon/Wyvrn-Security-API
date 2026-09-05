import json
import re

from wyvrn.detectors.engine import make_finding


# ============================================================
# SENSITIVE FIELD NAMES
# ============================================================

SENSITIVE_FIELDS = {
    "password",
    "password_hash",
    "passwd",
    "secret",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "credit_card",
    "card_number",
    "cvv",
    "ssn",
}


# ============================================================
# SENSITIVE VALUE PATTERNS
# ============================================================

SENSITIVE_PATTERNS = [
    (
        "EMAIL_ADDRESS",
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
        35,
    ),
    (
        "PHONE_NUMBER",
        re.compile(
            r"\+?\d[\d\s().-]{8,}\d"
        ),
        30,
    ),
]


# ============================================================
# JSON WALKER
# ============================================================

def find_sensitive_fields(
    data,
    path="",
):
    """
    Recursively inspect JSON-like response data.

    Returns:
        list of (field_path, field_name)
    """

    findings = []

    if isinstance(data, dict):

        for key, value in data.items():

            field_path = (
                f"{path}.{key}"
                if path
                else key
            )

            if key.lower() in SENSITIVE_FIELDS:
                findings.append(
                    (
                        field_path,
                        key,
                    )
                )

            findings.extend(
                find_sensitive_fields(
                    value,
                    field_path,
                )
            )

    elif isinstance(data, list):

        for index, item in enumerate(data):

            field_path = (
                f"{path}[{index}]"
            )

            findings.extend(
                find_sensitive_fields(
                    item,
                    field_path,
                )
            )

    return findings


# ============================================================
# RESPONSE DATA PARSER
# ============================================================

def parse_response_body(response_body):
    if response_body is None:
        return None

    if isinstance(response_body, (dict, list)):
        return response_body

    try:
        return json.loads(
            response_body
        )
    except (json.JSONDecodeError, TypeError):
        return None


# ============================================================
# SENSITIVE DATA DETECTOR
# ============================================================

def detect_sensitive_data(
    response_body,
):
    findings = []

    data = parse_response_body(
        response_body
    )

    if data is None:
        return findings

    # --------------------------------------------------------
    # Sensitive field names
    # --------------------------------------------------------

    sensitive_fields = find_sensitive_fields(
        data
    )

    for field_path, field_name in sensitive_fields:

        findings.append(
            make_finding(
                detection="SENSITIVE_DATA_EXPOSURE",
                confidence=0.98,
                risk_score=90,
                reason=(
                    f"Response contains a sensitive field: "
                    f"{field_name}"
                ),
                metadata={
                    "field": field_name,
                    "field_path": field_path,
                },
            )
        )

    # --------------------------------------------------------
    # Sensitive value patterns
    # --------------------------------------------------------

    response_text = json.dumps(
        data
    )

    for pattern_name, pattern, risk_score in SENSITIVE_PATTERNS:

        if pattern.search(response_text):

            findings.append(
                make_finding(
                    detection="SENSITIVE_DATA_PATTERN",
                    confidence=0.80,
                    risk_score=risk_score,
                    reason=(
                        f"Response contains a value matching "
                        f"a sensitive data pattern: "
                        f"{pattern_name}"
                    ),
                    metadata={
                        "pattern": pattern_name,
                    },
                )
            )

    return findings