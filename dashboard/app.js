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


// =========================================================
// DETECTION COUNTS
// =========================================================

function calculateDetectionCounts() {

    detectionCounts = {};

    DETECTIONS.forEach(
        detection => {
            detectionCounts[detection] = 0;
        }
    );

    events.forEach(event => {

        const detections =
            event.risk?.detections ??
            event.findings?.map(
                finding =>
                    finding.detection
            ) ??
            [];

        detections.forEach(
            detection => {

                if (
                    detectionCounts[detection]
                    !== undefined
                ) {

                    detectionCounts[
                        detection
                    ]++;

                }

            }
        );

    });

}


function renderDetectionCards() {

    const grid =
        $("#detectionGrid");

    grid.innerHTML = "";

    DETECTIONS.forEach(
        (detection, index) => {

            const card =
                document.createElement(
                    "div"
                );

            card.className =
                "detection-card";

            const count =
                detectionCounts[detection] || 0;

            if (count > 0) {

                card.classList.add(
                    "active"
                );

            }

            card.innerHTML = `
                <div class="detection-icon">
                    ${String(index + 1).padStart(2, "0")}
                </div>

                <div class="detection-name">
                    ${formatDetection(detection)}
                </div>

                <div class="detection-count">
                    ${count}
                </div>
            `;

            grid.appendChild(card);

        }
    );

}


// =========================================================
// EVENT STREAM
// =========================================================

function renderEvents() {

    const container =
        $("#eventStream");

    if (!events.length) {

        container.innerHTML = `
            <div class="empty-state">
                <span>WAITING FOR TRAFFIC</span>

                <small>
                    Security events will appear here.
                </small>
            </div>
        `;

        return;
    }


    const recent =
        [...events]
            .reverse()
            .slice(0, 12);


    container.innerHTML = "";


    recent.forEach(event => {

        const element =
            document.createElement(
                "article"
            );

        element.className =
            "event";


        const detections =
            event.risk?.detections ??
            event.findings?.map(
                finding =>
                    finding.detection
            ) ??
            [];


        const detection =
            detections[0] ??
            "TRAFFIC";


        const request =
            event.request ?? {};


        const risk =
            event.risk?.score ??
            event.risk?.risk_score ??
            0;


        const action =
            event.policy?.action ??
            "ALLOW";


        const timestamp =
            event.timestamp
                ? formatTime(
                    event.timestamp
                )
                : "NOW";


        element.innerHTML = `

            <div class="event-top">

                <div class="event-detection">
                    ${formatDetection(detection)}
                </div>

                <div class="event-time">
                    ${timestamp}
                </div>

            </div>


            <div class="event-path">

                ${request.method ?? "GET"}
                &nbsp;
                ${request.path ?? "/"}

            </div>


            <div class="event-bottom">

                <div
                    class="event-action action-${action}"
                >
                    ${action}
                </div>

                <div class="event-score">
                    ${risk}
                </div>

            </div>
        `;


        container.appendChild(
            element
        );

    });

}
