# Trojan-Horses
# WYVRN Security API

> Runtime API Security, Threat Detection & Automated Threat Control

WYVRN is a runtime API security layer designed to detect, score, correlate, and respond to API security threats in real time.

It sits between a client and an API, observes requests and responses, runs multiple security detectors, calculates a contextual risk score, applies an automated security policy, stores the resulting security event, and streams live events to the dashboard.

---

## What WYVRN Does

WYVRN continuously analyzes API traffic and detects threats including:

- SQL Injection
- BOLA / IDOR
- Authentication Abuse
- Rate Abuse
- Sensitive Data Exposure
- Excessive Data Exposure
- Behavioral Anomalies

Each request passes through a security pipeline:

text
Client
  │
  ▼
WYVRN Security Layer
  │
  ├── Request Detection
  │
  ├── Risk Scoring
  │
  ├── Policy Decision
  │
  ├── Target API
  │       │
  │       ▼
  │   Response
  │
  ├── Response Detection
  │
  ├── Risk Recalculation
  │
  ├── Attack Correlation
  │
  ├── Event Store
  │
  └── WebSocket Event Stream
          │
          ▼
      Dashboard
