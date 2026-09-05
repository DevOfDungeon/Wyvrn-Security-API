/*
SENTINEL API SECURITY DASHBOARD
Vanilla JavaScript
*/

/* ==========================================
SAMPLE SECURITY DATA
========================================== */

let threats = [
{
endpoint: "/api/users",
threat: "SQL Injection",
ip: "185.22.91.42",
severity: "critical",
action: "BLOCKED",
time: "12 sec ago",
confidence: 96,
reason: "Suspicious SQL operators were detected in request parameters. The request pattern matches a known injection technique."
},


{
    endpoint: "/api/auth/login",
    threat: "Brute Force",
    ip: "91.204.17.88",
    severity: "high",
    action: "RATE LIMITED",
    time: "38 sec ago",
    confidence: 91,
    reason: "More than 120 authentication attempts were observed from the same source within a 60 second window."
},

{
    endpoint: "/api/admin/users",
    threat: "Broken Authentication",
    ip: "45.132.66.21",
    severity: "critical",
    action: "BLOCKED",
    time: "1 min ago",
    confidence: 98,
    reason: "An expired authentication token was used to access an administrative endpoint."
},

{
    endpoint: "/api/orders",
    threat: "Rate Abuse",
    ip: "103.84.19.77",
    severity: "medium",
    action: "RATE LIMITED",
    time: "2 min ago",
    confidence: 87,
    reason: "Request volume exceeded the configured threshold for this endpoint."
},

{
    endpoint: "/api/products",
    threat: "Data Exposure",
    ip: "172.16.4.23",
    severity: "low",
    action: "ALLOWED",
    time: "4 min ago",
    confidence: 72,
    reason: "Response contained more fields than normally requested by this client."
},

{
    endpoint: "/api/payments",
    threat: "IDOR Attempt",
    ip: "66.91.33.10",
    severity: "high",
    action: "BLOCKED",
    time: "6 min ago",
    confidence: 94,
    reason: "User attempted to access an object belonging to another account."
}


];

const endpoints = [
{
path: "/api/admin/users",
method: "GET",
risk: 94,
status: "Critical",
requests: "42K/day"
},


{
    path: "/api/auth/login",
    method: "POST",
    risk: 81,
    status: "High",
    requests: "183K/day"
},

{
    path: "/api/orders",
    method: "GET",
    risk: 67,
    status: "Medium",
    requests: "421K/day"
},

{
    path: "/api/payments",
    method: "POST",
    risk: 48,
    status: "Medium",
    requests: "82K/day"
},

{
    path: "/api/users",
    method: "GET",
    risk: 39,
    status: "Low",
    requests: "328K/day"
},

{
    path: "/api/products",
    method: "GET",
    risk: 18,
    status: "Protected",
    requests: "512K/day"
}


];

let activities = [
{
icon: "🛡",
title: "Threat automatically blocked",
description: "SQL Injection from 185.22.91.42",
time: "12 seconds ago"
},


{
    icon: "⚡",
    title: "Rate limit triggered",
    description: "/api/auth/login exceeded threshold",
    time: "38 seconds ago"
},

{
    icon: "🔐",
    title: "Authentication anomaly detected",
    description: "Expired token used against /api/admin/users",
    time: "1 minute ago"
},

{
    icon: "◉",
    title: "Security policy updated",
    description: "Automatic threat blocking enabled",
    time: "14 minutes ago"
},

{
    icon: "✓",
    title: "Endpoint security scan completed",
    description: "18 endpoints analyzed",
    time: "31 minutes ago"
}


];

/* ==========================================
DOM ELEMENTS
========================================== */

const navItems = document.querySelectorAll(".nav-item");

const pages = {
dashboard: document.getElementById("dashboardPage"),
threats: document.getElementById("threatsPage"),
endpoints: document.getElementById("endpointsPage"),
activity: document.getElementById("activityPage"),
controls: document.getElementById("controlsPage")
};

const pageTitle = document.getElementById("pageTitle");

/* ==========================================
NAVIGATION
========================================== */

navItems.forEach(button => {


button.addEventListener("click", () => {

    const page = button.dataset.page;

    navItems.forEach(item => {
        item.classList.remove("active");
    });

    button.classList.add("active");

    Object.values(pages).forEach(section => {
        section.classList.remove("active-page");
    });

    pages[page].classList.add("active-page");

    const titles = {
        dashboard: "Security Overview",
        threats: "Threat Detection Center",
        endpoints: "API Endpoint Inventory",
        activity: "Security Activity",
        controls: "Protection Controls"
    };

    pageTitle.textContent = titles[page];

});


});

/* ==========================================
THREAT TABLE
========================================== */

function renderThreatTable() {


const table = document.getElementById("threatTable");

table.innerHTML = "";

threats.slice(0, 6).forEach((threat, index) => {

    const row = document.createElement("tr");

    row.innerHTML = `
        <td>${threat.endpoint}</td>

        <td>${threat.threat}</td>

        <td>${threat.ip}</td>

        <td>
            <span class="severity ${threat.severity}">
                ${threat.severity.toUpperCase()}
            </span>
        </td>

        <td>
            <span class="action ${
                threat.action === "BLOCKED"
                    ? "blocked"
                    : threat.action === "ALLOWED"
                        ? "allowed"
                        : "rate"
            }">
                ${threat.action}
            </span>
        </td>

        <td>${threat.time}</td>
    `;

    row.style.cursor = "pointer";

    row.addEventListener("click", () => {
        openThreatModal(threat);
    });

    table.appendChild(row);

});


}

/* ==========================================
THREAT CARDS
========================================== */

function renderThreatCards() {


const container = document.getElementById("threatCards");

container.innerHTML = "";

threats.forEach(threat => {

    const card = document.createElement("div");

    card.className = "threat-card";

    card.innerHTML = `

        <div class="threat-card-top">

            <span class="severity ${threat.severity}">
                ${threat.severity.toUpperCase()}
            </span>

            <span style="color:#596579;font-size:9px">
                ${threat.time}
            </span>

        </div>

        <h3>${threat.threat}</h3>

        <p>
            ${threat.endpoint}
            <br>
            Source: ${threat.ip}
        </p>

        <div class="threat-meta">
            <span>Confidence: ${threat.confidence}%</span>
            <strong>${threat.action}</strong>
        </div>

    `;

    card.addEventListener("click", () => {
        openThreatModal(threat);
    });

    container.appendChild(card);

});


}

/* ==========================================
ENDPOINTS
========================================== */

function renderEndpoints() {


const container = document.getElementById("endpointGrid");

container.innerHTML = "";

endpoints.forEach(endpoint => {

    let color = "#4ade80";

    if (endpoint.risk >= 90) {
        color = "#ef4444";
    } else if (endpoint.risk >= 70) {
        color = "#f97316";
    } else if (endpoint.risk >= 40) {
        color = "#f59e0b";
    }

    const card = document.createElement("div");

    card.className = "endpoint-card";

    card.innerHTML = `

        <span class="method">
            ${endpoint.method}
        </span>

        <br>

        <code>${endpoint.path}</code>

        <div class="risk">
            <span
                style="
                    width:${endpoint.risk}%;
                    background:${color};
                "
            ></span>
        </div>

        <div class="card-footer">
            <span>${endpoint.status}</span>
            <span>Risk ${endpoint.risk}</span>
        </div>

        <div class="card-footer">
            <span>Traffic</span>
            <span>${endpoint.requests}</span>
        </div>

    `;

    container.appendChild(card);

});


}

/* ==========================================
ACTIVITY
========================================== */

function renderActivity() {


const container = document.getElementById("activityList");

container.innerHTML = "";

activities.forEach(item => {

    const div = document.createElement("div");

    div.className = "activity-item";

    div.innerHTML = `

        <div class="activity-icon">
            ${item.icon}
        </div>

        <div class="activity-info">

            <strong>${item.title}</strong>

            <span>${item.description}</span>

        </div>

        <div class="activity-time">
            ${item.time}
        </div>

    `;

    container.appendChild(div);

});


}

/* ==========================================
THREAT MODAL
========================================== */

const modal = document.getElementById("modal");

const modalTitle = document.getElementById("modalTitle");
const modalEndpoint = document.getElementById("modalEndpoint");
const modalIP = document.getElementById("modalIP");
const modalSeverity = document.getElementById("modalSeverity");
const modalAction = document.getElementById("modalAction");
const modalReason = document.getElementById("modalReason");
const modalConfidence = document.getElementById("modalConfidence");
const confidenceFill = document.getElementById("confidenceFill");

let selectedThreat = null;

function openThreatModal(threat) {


selectedThreat = threat;

modalTitle.textContent = threat.threat;
modalEndpoint.textContent = threat.endpoint;
modalIP.textContent = threat.ip;
modalSeverity.textContent = threat.severity.toUpperCase();
modalAction.textContent = threat.action;
modalReason.textContent = threat.reason;

modalConfidence.textContent = `${threat.confidence}%`;

confidenceFill.style.width = `${threat.confidence}%`;

modal.classList.add("show");

}

document.getElementById("modalClose").addEventListener("click", () => {


modal.classList.remove("show");


});

modal.addEventListener("click", event => {


if (event.target === modal) {
    modal.classList.remove("show");
}


});

/* ==========================================
BLOCK IP
========================================== */

document.getElementById("blockIP").addEventListener("click", () => {


if (!selectedThreat) return;

selectedThreat.action = "BLOCKED";

activities.unshift({
    icon: "🚫",
    title: "Source IP blocked",
    description: `${selectedThreat.ip} blocked by administrator`,
    time: "Just now"
});

renderThreatTable();
renderThreatCards();
renderActivity();

modalAction.textContent = "BLOCKED";

alert(`IP ${selectedThreat.ip} has been blocked.`);


});

/* ==========================================
FALSE POSITIVE
========================================== */

document.getElementById("falsePositive").addEventListener("click", () => {


if (!selectedThreat) return;

activities.unshift({
    icon: "✓",
    title: "Threat marked as false positive",
    description: `${selectedThreat.threat} on ${selectedThreat.endpoint}`,
    time: "Just now"
});

renderActivity();

modal.classList.remove("show");

alert("Threat marked as a false positive.");


});

/* ==========================================
SIMULATE NEW ATTACK
========================================== */

const attackTypes = [


{
    threat: "SQL Injection",
    severity: "critical",
    reason: "Suspicious SQL syntax detected in query parameters."
},

{
    threat: "Brute Force",
    severity: "high",
    reason: "Authentication request frequency exceeded the configured threshold."
},

{
    threat: "IDOR Attempt",
    severity: "high",
    reason: "User attempted to access a resource belonging to another account."
},

{
    threat: "Rate Abuse",
    severity: "medium",
    reason: "Client request volume exceeded the API rate limit."
},

{
    threat: "Data Exposure",
    severity: "low",
    reason: "API response contained fields not normally requested by the client."
}


];

function simulateAttack() {


const attack =
    attackTypes[
        Math.floor(Math.random() * attackTypes.length)
    ];

const endpoint =
    endpoints[
        Math.floor(Math.random() * endpoints.length)
    ];

const ip =
    `${Math.floor(Math.random() * 220) + 10}.` +
    `${Math.floor(Math.random() * 220) + 10}.` +
    `${Math.floor(Math.random() * 220) + 10}.` +
    `${Math.floor(Math.random() * 220) + 10}`;

const confidence =
    Math.floor(Math.random() * 12) + 85;

let action = "ALLOWED";

if (attack.severity === "critical") {
    action = "BLOCKED";
} else if (attack.severity === "high") {
    action = Math.random() > .3
        ? "BLOCKED"
        : "RATE LIMITED";
} else if (attack.severity === "medium") {
    action = "RATE LIMITED";
}

const newThreat = {

    endpoint: endpoint.path,

    threat: attack.threat,

    ip,

    severity: attack.severity,

    action,

    time: "Just now",

    confidence,

    reason: attack.reason

};

threats.unshift(newThreat);

document.getElementById("threatCount").textContent =
    247 + threats.length - 6;

if (action === "BLOCKED") {

    document.getElementById("blockedCount").textContent =
        183 + threats.filter(t => t.action === "BLOCKED").length - 3;

}

activities.unshift({

    icon: "⚠",

    title: `${attack.threat} detected`,

    description: `${endpoint.path} from ${ip}`,

    time: "Just now"

});

renderThreatTable();
renderThreatCards();
renderActivity();

openThreatModal(newThreat);


}

document.getElementById("simulateAttack")
.addEventListener("click", simulateAttack);

/* ==========================================
SEARCH
========================================== */

document.getElementById("threatSearch")
.addEventListener("input", event => {


    const query =
        event.target.value.toLowerCase();

    const cards =
        document.querySelectorAll(".threat-card");

    cards.forEach((card, index) => {

        const threat =
            threats[index];

        const text =
            `${threat.threat}
             ${threat.endpoint}
             ${threat.ip}`.toLowerCase();

        card.style.display =
            text.includes(query)
                ? ""
                : "none";

    });

});


document.getElementById("endpointSearch")
.addEventListener("input", event => {


    const query =
        event.target.value.toLowerCase();

    const cards =
        document.querySelectorAll(".endpoint-card");

    cards.forEach((card, index) => {

        const endpoint =
            endpoints[index];

        card.style.display =
            endpoint.path
                .toLowerCase()
                .includes(query)
                ? ""
                : "none";

    });

});


/* ==========================================
SEVERITY FILTER
========================================== */

document.getElementById("severityFilter")
.addEventListener("change", event => {


    const filter = event.target.value;

    const cards =
        document.querySelectorAll(".threat-card");

    cards.forEach((card, index) => {

        const threat =
            threats[index];

        card.style.display =
            filter === "all" ||
            threat.severity === filter
                ? ""
                : "none";

    });

});


/* ==========================================
VIEW ALL THREATS
========================================== */

document.getElementById("viewThreats")
.addEventListener("click", () => {


    document.querySelector('[data-page="threats"]')
        .click();

});


/* ==========================================
TRAFFIC CHART
========================================== */

function drawChart() {


const canvas =
    document.getElementById("trafficChart");

const ctx =
    canvas.getContext("2d");

const width =
    canvas.width =
    canvas.offsetWidth * 2;

const height =
    canvas.height =
    canvas.offsetHeight * 2;

ctx.scale(2, 2);

const w = canvas.offsetWidth;
const h = canvas.offsetHeight;

ctx.clearRect(0, 0, w, h);

/* Grid */

ctx.strokeStyle = "#1c2431";
ctx.lineWidth = 1;

for (let i = 0; i < 5; i++) {

    const y =
        20 + i * ((h - 40) / 4);

    ctx.beginPath();

    ctx.moveTo(0, y);
    ctx.lineTo(w, y);

    ctx.stroke();

}


/* Data */

const requests = [
    32, 40, 36, 48, 52, 46,
    58, 65, 61, 70, 68, 76,
    72, 81, 78, 88, 83, 91,
    87, 79, 85, 92, 89, 96
];

const threatsData = [
    5, 7, 4, 9, 6, 11,
    8, 13, 10, 17, 12, 15,
    11, 20, 16, 19, 14, 23,
    17, 21, 19, 26, 22, 29
];


function drawLine(data, color, fill) {

    ctx.beginPath();

    data.forEach((value, index) => {

        const x =
            index * (w / (data.length - 1));

        const y =
            h - 25 -
            (value / 100) * (h - 50);

        if (index === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }

    });

    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();


    /* Gradient fill */

    if (fill) {

        ctx.lineTo(w, h);
        ctx.lineTo(0, h);
        ctx.closePath();

        const gradient =
            ctx.createLinearGradient(0, 0, 0, h);

        gradient.addColorStop(
            0,
            "rgba(59,130,246,.18)"
        );

        gradient.addColorStop(
            1,
            "rgba(59,130,246,0)"
        );

        ctx.fillStyle = gradient;
        ctx.fill();

    }

}


drawLine(requests, "#3b82f6", true);
drawLine(threatsData, "#ef4444", false);


/* Labels */

ctx.fillStyle = "#566276";
ctx.font = "9px Inter";

const labels = [
    "00:00",
    "04:00",
    "08:00",
    "12:00",
    "16:00",
    "20:00"
];

labels.forEach((label, index) => {

    const x =
        index * (w / (labels.length - 1));

    ctx.fillText(label, x, h - 5);

});


}

/* ==========================================
LIVE TRAFFIC SIMULATION
========================================== */

function liveUpdate() {


const requestElement =
    document.getElementById("requestCount");

const current =
    parseInt(
        requestElement.textContent.replace(/,/g, "")
    );

requestElement.textContent =
    (current + Math.floor(Math.random() * 8))
        .toLocaleString();


}

/* ==========================================
NOTIFICATION
========================================== */

document.getElementById("notificationButton")
.addEventListener("click", () => {


    alert(
        "3 new security events detected.\n\n" +
        "• SQL Injection blocked\n" +
        "• Brute force attempt rate limited\n" +
        "• Suspicious API access detected"
    );

});


/* ==========================================
INITIALIZE
========================================== */

renderThreatTable();
renderThreatCards();
renderEndpoints();
renderActivity();

drawChart();

window.addEventListener("resize", drawChart);

/* Update traffic every 3 seconds */

setInterval(liveUpdate, 3000);

/* Randomly simulate security events */

setInterval(() => {


if (Math.random() > .65) {
    simulateAttack();
}


}, 10000);
