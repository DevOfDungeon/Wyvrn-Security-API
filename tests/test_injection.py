from wyvrn.detectors.injection import detect_injection


# ============================================================
# SQL INJECTION
# ============================================================

def test_detects_sql_injection():
    request_event = {
        "path": "/search",
        "method": "GET",
        "query_params": {
            "q": "' OR 1=1 --",
        },
        "body": None,
    }

    findings = detect_injection(
        request_event
    )

    detections = [
        finding["detection"]
        for finding in findings
    ]

    assert "SQL_INJECTION" in detections


# ============================================================
# COMMAND INJECTION
# ============================================================

def test_detects_command_injection():
    request_event = {
        "path": "/search",
        "method": "GET",
        "query_params": {
            "q": "test; whoami",
        },
        "body": None,
    }

    findings = detect_injection(
        request_event
    )

    detections = [
        finding["detection"]
        for finding in findings
    ]

    assert "COMMAND_INJECTION" in detections


# ============================================================
# XSS
# ============================================================

def test_detects_xss_payload():
    request_event = {
        "path": "/search",
        "method": "GET",
        "query_params": {
            "q": "<script>alert(1)</script>",
        },
        "body": None,
    }

    findings = detect_injection(
        request_event
    )

    detections = [
        finding["detection"]
        for finding in findings
    ]

    assert "XSS_PAYLOAD" in detections


# ============================================================
# CLEAN REQUEST
# ============================================================

def test_clean_request_has_no_injection_findings():
    request_event = {
        "path": "/search",
        "method": "GET",
        "query_params": {
            "q": "laptop computers",
        },
        "body": None,
    }

    findings = detect_injection(
        request_event
    )

    assert findings == []


# ============================================================
# BODY ANALYSIS
# ============================================================

def test_detects_injection_in_body():
    request_event = {
        "path": "/search",
        "method": "POST",
        "query_params": {},
        "body": '{"username": "\' OR 1=1 --"}',
    }

    findings = detect_injection(
        request_event
    )

    detections = [
        finding["detection"]
        for finding in findings
    ]

    assert "SQL_INJECTION" in detections
