// AUTH CHECK

const role =
    localStorage.getItem("wyvrnRole");

if (!role) {
    window.location.href = "login.html";
}

// SHOW ROLE

document.getElementById("userRole").textContent =
    role.toUpperCase();

// DASHBOARD METRICS

document.getElementById("totalApis").textContent = "128";
document.getElementById("alerts").textContent = "17";
document.getElementById("activeThreats").textContent = "4";
document.getElementById("blockedRequests").textContent = "342";

document.getElementById("riskScore").textContent = "78";
document.getElementById("riskLabel").textContent = "HIGH RISK";

// THREAT FEED

document.getElementById("threatList").innerHTML = `
<div class="threat-item">
⚠️ BOLA Attack Detected
</div>

<div class="threat-item">
⚠️ Brute Force Attempts
</div>

<div class="threat-item">
⚠️ Excessive Data Exposure
</div>
`;

// HIGH RISK ENDPOINTS

document.getElementById("endpointList").innerHTML = `
<div class="endpoint-item">
GET /api/users
</div>

<div class="endpoint-item">
POST /api/login
</div>

<div class="endpoint-item">
GET /api/orders
</div>
`;

// LIVE THREAT COUNTER

setInterval(() => {

    const threats =
        Math.floor(Math.random() * 10) + 1;

    document.getElementById(
        "activeThreats"
    ).textContent = threats;

}, 3000);

// TOAST NOTIFICATIONS

function showThreatNotification(message) {

    const container =
        document.getElementById("toastContainer");

    if (!container) return;

    const toast =
        document.createElement("div");

    toast.classList.add("toast");

    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4000);
}

// RANDOM ALERTS

setInterval(() => {

    const alerts = [

        "⚠️ Brute Force Attempt Detected",

        "⚠️ BOLA Risk Identified",

        "⚠️ Excessive Data Exposure",

        "⚠️ Suspicious API Activity"

    ];

    const randomAlert =
        alerts[Math.floor(
            Math.random() * alerts.length
        )];

    showThreatNotification(randomAlert);

}, 10000);

// LOGOUT

function logout() {

    localStorage.removeItem(
        "wyvrnRole"
    );

    window.location.href =
        "login.html";

}