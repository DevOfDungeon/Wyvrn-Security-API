import pytest

from wyvrn.detectors.auth import detect_auth_abuse
from wyvrn.detectors.bola import detect_bola
from wyvrn.detectors.engine import run_detectors
from wyvrn.detectors.rate_limit import (
    detect_rate_abuse,
    REQUEST_HISTORY,
)


# ============================================================
# BOLA / IDOR TESTS
# ============================================================

def test_bola_detects_user_object_access():
    request_event = {
        "path": "/users/1",
        "method": "GET",
        "client_ip": "127.0.0.1",
    }

    findings = detect_bola(request_event)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["detection"] == "BOLA_IDOR"
    assert finding["confidence"] == 0.70
    assert finding["risk_score"] == 60
    assert finding["metadata"]["object_type"] == "user"
    assert finding["metadata"]["object_id"] == 1


def test_bola_ignores_non_user_paths():
    request_event = {
        "path": "/products",
        "method": "GET",
        "client_ip": "127.0.0.1",
    }

    findings = detect_bola(request_event)

    assert findings == []


def test_bola_ignores_non_get_requests():
    request_event = {
        "path": "/users/1",
        "method": "POST",
        "client_ip": "127.0.0.1",
    }

    findings = detect_bola(request_event)

    assert findings == []


# ============================================================
# RATE ABUSE TESTS
# ============================================================

def test_rate_abuse_detects_excessive_requests():
    client_ip = "10.0.0.50"
    path = "/products"

    # Make sure this test starts clean.
    REQUEST_HISTORY[(client_ip, path)].clear()

    request_event = {
        "path": path,
        "method": "GET",
        "client_ip": client_ip,
    }

    for _ in range(21):
        findings = detect_rate_abuse(request_event)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["detection"] == "RATE_ABUSE"
    assert finding["confidence"] == 0.95
    assert finding["risk_score"] == 85
    assert finding["metadata"]["request_count"] == 21


def test_rate_abuse_allows_normal_request_volume():
    client_ip = "10.0.0.51"
    path = "/products"

    REQUEST_HISTORY[(client_ip, path)].clear()

    request_event = {
        "path": path,
        "method": "GET",
        "client_ip": client_ip,
    }

    for _ in range(5):
        findings = detect_rate_abuse(request_event)

    assert findings == []


# ============================================================
# AUTHENTICATION ABUSE TESTS
# ============================================================
'''
def test_auth_abuse_detects_repeated_login_attempts():
    client_ip = "10.0.0.60"

    request_event = {
        "path": "/login",
        "method": "POST",
        "client_ip": client_ip,
    }

    findings = []

    for _ in range(5):
        findings = detect_auth_abuse(request_event)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["detection"] == "AUTH_ABUSE"
    assert finding["confidence"] == 0.90
    assert finding["risk_score"] == 75
    assert finding["metadata"]["attempts"] == 5

'''
def test_auth_abuse_ignores_normal_get_request():
    request_event = {
        "path": "/login",
        "method": "GET",
        "client_ip": "10.0.0.61",
    }

    findings = detect_auth_abuse(request_event)

    assert findings == []


def test_auth_abuse_ignores_non_login_endpoint():
    request_event = {
        "path": "/products",
        "method": "POST",
        "client_ip": "10.0.0.62",
    }

    findings = detect_auth_abuse(request_event)

    assert findings == []


# ============================================================
# DETECTOR ENGINE TESTS
# ============================================================

def test_engine_runs_bola_detector():
    request_event = {
        "path": "/users/42",
        "method": "GET",
        "client_ip": "10.0.0.70",
    }

    findings = run_detectors(request_event)

    detections = [
        finding["detection"]
        for finding in findings
    ]

    assert "BOLA_IDOR" in detections


def test_engine_returns_no_findings_for_normal_request():
    request_event = {
        "path": "/health",
        "method": "GET",
        "client_ip": "10.0.0.71",
    }

    findings = run_detectors(request_event)

    assert findings == []
