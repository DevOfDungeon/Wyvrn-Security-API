const API_BASE = "";

let events = [];
let stats = {};
let detectionCounts = {};

const DETECTIONS = [
    "SQL_INJECTION",
    "BOLA_IDOR",
    "AUTH_ABUSE",
    "RATE_ABUSE",
    "SENSITIVE_DATA_EXPOSURE",
    "SENSITIVE_DATA_PATTERN",
    "EXCESSIVE_DATA_EXPOSURE",
    "BEHAVIORAL_ANOMALY"
];


// =========================================================
// DOM
// =========================================================

const $ = (selector) =>
    document.querySelector(selector);

