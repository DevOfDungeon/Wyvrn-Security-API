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

// =========================================================
// INITIALISE
// =========================================================

document.addEventListener(
    "DOMContentLoaded",
    async () => {

        renderDetectionCards();

        await loadStats();

        await loadEvents();

        await loadThreats();

        await loadAttacks();

        connectWebSocket();

    }
);


// =========================================================
// STATS
// =========================================================

async function loadStats() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/stats`
            );

        if (!response.ok) {
            throw new Error(
                "Stats request failed"
            );
        }

        stats =
            await response.json();

        updateStats();

    } catch (error) {

        console.error(
            "Could not load stats:",
            error
        );

    }

}


function updateStats() {

    const total =
        stats.total_events ??
        stats.total_requests ??
        0;

    const blocked =
        stats.blocked ??
        stats.blocked_requests ??
        0;

    const rateLimited =
        stats.rate_limited ??
        stats.rate_limit ??
        stats.rate_limited_requests ??
        0;

    const threats =
        stats.threats ??
        stats.total_threats ??
        0;

    $("#totalRequests").textContent =
        formatNumber(total);

    $("#blockedRequests").textContent =
        formatNumber(blocked);

    $("#rateLimited").textContent =
        formatNumber(rateLimited);

    $("#threatCount").textContent =
        formatNumber(threats);

    calculateOverallRisk();

}


// =========================================================
// EVENTS
// =========================================================

async function loadEvents() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/events`
            );

        if (!response.ok) {
            throw new Error(
                "Events request failed"
            );
        }

        const data =
            await response.json();

        events =
            Array.isArray(data)
                ? data
                : data.events ?? [];

        events =
            events.slice(-100);

        calculateDetectionCounts();

        renderEvents();

        calculateOverallRisk();

        updateCampaign();

    } catch (error) {

        console.error(
            "Could not load events:",
            error
        );

    }

}


// =========================================================
// THREATS
// =========================================================

async function loadThreats() {

    try {

        const response =
            await fetch(
                `${API_BASE}/api/threats`
            );

        if (!response.ok) {
            return;
        }

        const data =
            await response.json();

        if (
            data &&
            Array.isArray(data.threats)
        ) {

            $("#threatCount").textContent =
                data.threats.length;

        }

    } catch (error) {

        console.error(
            "Could not load threats:",
            error
        );

    }

}
