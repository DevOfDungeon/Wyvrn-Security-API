const role =
localStorage.getItem("wyvrnRole") || "user";

document.getElementById(
    "userRole"
).textContent =
role.toUpperCase();
document.getElementById("userRole").textContent = "ADMIN";

document.getElementById("totalApis").textContent = "128";
document.getElementById("alerts").textContent = "17";
document.getElementById("activeThreats").textContent = "4";
document.getElementById("blockedRequests").textContent = "342";

document.getElementById("riskScore").textContent = "78";
document.getElementById("riskLabel").textContent = "HIGH RISK";

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

setInterval(() => {

    const threats =
        Math.floor(Math.random() * 10) + 1;

    document.getElementById("activeThreats").textContent =
        threats;

}, 3000);

function showThreatNotification(message){

    const toast =
        document.createElement("div");

    toast.classList.add("toast");

    toast.textContent = message;

    document
        .getElementById("toastContainer")
        .appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4000);
}

setInterval(() => {

    const alerts = [

        "⚠️ Brute Force Attempt Detected",

        "⚠️ BOLA Risk Identified",

        "⚠️ Excessive Data Exposure",

        "⚠️ Suspicious API Activity"

    ];

    const randomAlert =
        alerts[Math.floor(Math.random()*alerts.length)];

    showThreatNotification(randomAlert);

}, 10000);