# WYVRN Security API

> Runtime API Security, Threat Detection & Automated Threat Control

WYVRN is a runtime API security layer that sits between clients and an API to detect, assess, and respond to security threats in real time.

Instead of relying only on static vulnerability detection, WYVRN analyzes API requests and responses, calculates contextual risk, applies automated security policies, correlates related events, and streams security activity to a live dashboard.

---

## What WYVRN Detects

WYVRN currently detects:

- SQL Injection
- BOLA / IDOR
- Authentication Abuse
- Rate Abuse
- Sensitive Data Exposure
- Excessive Data Exposure
- Behavioral Anomalies

Security decisions are based on contextual risk and can result in:

```text
ALLOW
MONITOR
RATE_LIMIT
BLOCK
```

---

## Architecture

```text
                    CLIENT
                       │
                       ▼
              ┌─────────────────┐
              │ WYVRN MIDDLEWARE│
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │    DETECTORS    │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │   RISK ENGINE   │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  POLICY ENGINE  │
              └────────┬────────┘
                       │
              ALLOW / MONITOR /
             RATE_LIMIT / BLOCK
                       │
                       ▼
                ┌─────────────┐
                │  TARGET API │
                └──────┬──────┘
                       │
                       ▼
                   RESPONSE
                       │
                       ▼
              RESPONSE DETECTORS
                       │
                       ▼
                RISK + CORRELATION
                       │
             ┌─────────┼─────────┐
             ▼         ▼         ▼
         EVENT STORE  CAMPAIGN  WEBSOCKET
                                  │
                                  ▼
                              DASHBOARD
```

---

## Key Features

### Runtime Threat Detection

Analyzes API traffic in real time for common API security threats.

### Risk-Based Decisions

Multiple findings are combined with confidence and contextual factors to produce a risk score from 0–100.

### Automated Protection

The policy engine converts risk into an enforcement action:

```text
ALLOW → MONITOR → RATE_LIMIT → BLOCK
```

### Behavioral Analysis

WYVRN builds endpoint-level baselines and detects unusual response size, latency, and server behavior.

### Attack Correlation

Multiple suspicious events from the same client can be correlated into a larger `ATTACK_CAMPAIGN`.

### Real-Time Dashboard

Security events are exposed through REST APIs and a WebSocket stream for live dashboard updates.

---

## Project Structure

```text
Trojan-Horses/
│
├── target_api/
│   └── main.py
│
├── wyvrn/
│   ├── main.py
│   ├── middleware.py
│   ├── risk.py
│   ├── policy.py
│   ├── events.py
│   ├── store.py
│   ├── ws.py
│   ├── correlation.py
│   │
│   └── detectors/
│       ├── auth.py
│       ├── bola.py
│       ├── injection.py
│       ├── rate_limit.py
│       ├── sensitive_data.py
│       ├── excessive_data.py
│       └── anomaly.py
│
├── dashboard/
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── tests/
├── requirements.txt
├── pytest.ini
├── README.md
└── LICENSE
```

---

# Setup

## Requirements

- Python 3.10+
- pip

---

## 1. Clone the Repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd Trojan-Horses
```

---

## 2. Create a Virtual Environment

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Running WYVRN

WYVRN uses two local services.

### Terminal 1 — Target API

```bash
uvicorn target_api.main:app --host 127.0.0.1 --port 8000
```

### Terminal 2 — WYVRN

```bash
uvicorn wyvrn.main:app --host 127.0.0.1 --port 9000
```

---

## Dashboard

Open:

```text
http://127.0.0.1:9000/dashboard/
```

The dashboard provides:

- live security events
- risk scores
- detection statistics
- policy actions
- attack campaigns
- attack simulator controls

---

## API Documentation

Interactive API documentation:

```text
http://127.0.0.1:9000/docs
```

Alternative documentation:

```text
http://127.0.0.1:9000/redoc
```

---

# Quick Demo

Once both services are running, traffic can be sent through the WYVRN proxy.

### Normal Traffic

```bash
curl http://127.0.0.1:9000/proxy/health
```

### SQL Injection

```bash
curl "http://127.0.0.1:9000/proxy/search?q=%27%20OR%201%3D1%20--"
```

### BOLA / IDOR

```bash
curl http://127.0.0.1:9000/proxy/users/1
```

### Sensitive Data Exposure

```bash
curl http://127.0.0.1:9000/proxy/profile
```

### Authentication Abuse

```bash
curl -X POST "http://127.0.0.1:9000/proxy/login?username=alice&password=wrong-password"
```

Repeated failed attempts can trigger authentication-abuse detection.

The dashboard can also be used to trigger the built-in attack simulator.

---

# Testing

Run the complete test suite with:

```bash
pytest -q
```

Tests cover the detector, risk, policy, integration, anomaly, sensitive-data, and dashboard/API components.

---

# Security Note

The `target_api` application is **intentionally vulnerable**.

It exists only as a controlled target for demonstrating WYVRN's detection and response capabilities.

Do not expose the vulnerable target API directly to the public internet.

---

# Why WYVRN?

Traditional API security often focuses on identifying individual vulnerabilities.

WYVRN focuses on the **runtime security decision**:

```text
DETECT
   ↓
ASSESS
   ↓
DECIDE
   ↓
CORRELATE
   ↓
RESPOND
```

A suspicious request is not treated in isolation.

WYVRN combines detector findings, confidence, behavioral context, endpoint context, recent activity, and correlated events to determine what should happen next.

---

## Team

### Trojan Horses

Cybersecurity project focused on runtime API protection, automated threat detection, risk-based enforcement, behavioral analysis, and real-time security observability.

---

## License

See `LICENSE` for license information.

---

# WYVRN

```text
Runtime API Security

Detect → Score → Decide → Correlate → Respond
```
