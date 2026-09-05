import json

from wyvrn.detectors.engine import make_finding


# ============================================================
# EXPECTED RESPONSE FIELDS
# ============================================================

EXPECTED_FIELDS = {
    "/users/{id}": {
        "id",
        "name",
        "email",
    },
}


# ============================================================
# PATH NORMALIZATION
# ============================================================

def normalize_endpoint(path):
    parts = path.strip("/").split("/")

    if len(parts) == 2 and parts[0] == "users":
        if parts[1].isdigit():
            return "/users/{id}"

    return path


# ============================================================
# RESPONSE PARSER
# ============================================================

def parse_response(response_body):

    if response_body is None:
        return None

    if isinstance(response_body, (dict, list)):
        return response_body

    try:
        return json.loads(response_body)

    except (json.JSONDecodeError, TypeError):
        return None


# ============================================================
# EXCESSIVE DATA DETECTOR
# ============================================================

def detect_excessive_data(
    path,
    response_body,
):
    findings = []

    endpoint = normalize_endpoint(path)

    expected_fields = EXPECTED_FIELDS.get(
        endpoint
    )

    if expected_fields is None:
        return findings

    data = parse_response(
        response_body
    )

    if not isinstance(data, dict):
        return findings

    observed_fields = set(
        data.keys()
    )

    unexpected_fields = (
        observed_fields
        - expected_fields
    )

    if not unexpected_fields:
        return findings

    # --------------------------------------------------------
    # Calculate exposure ratio
    # --------------------------------------------------------

    total_fields = len(
        observed_fields
    )

    excessive_count = len(
        unexpected_fields
    )

    exposure_ratio = (
        excessive_count / total_fields
        if total_fields
        else 0
    )

    # --------------------------------------------------------
    # Risk depends on how much extra data was returned.
    # --------------------------------------------------------

    if exposure_ratio >= 0.50:
        risk_score = 75
        confidence = 0.90

    elif exposure_ratio >= 0.25:
        risk_score = 60
        confidence = 0.82

    else:
        risk_score = 45
        confidence = 0.75

    findings.append(
        make_finding(
            detection="EXCESSIVE_DATA_EXPOSURE",
            confidence=confidence,
            risk_score=risk_score,
            reason=(
                f"Endpoint returned {excessive_count} "
                f"fields outside its expected response schema."
            ),
            metadata={
                "endpoint": endpoint,
                "expected_fields": sorted(
                    expected_fields
                ),
                "observed_fields": sorted(
                    observed_fields
                ),
                "unexpected_fields": sorted(
                    unexpected_fields
                ),
                "exposure_ratio": round(
                    exposure_ratio,
                    2,
                ),
            },
        )
    )

    return findings