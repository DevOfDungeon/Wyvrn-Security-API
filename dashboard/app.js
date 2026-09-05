const state = {
    events: [],
    paused: false,
    filter: "ALL",
    socket: null,
    reconnectTimer: null,
    reconnectAttempt: 0,
    maxEvents: 150,
    simulatorRunning: false,
    detectionCounts: {},
    stats: {
        requests: 0,
        threats: 0,
        blocked: 0,
        rateLimited: 0
    }
};

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

const $ = selector => document.querySelector(selector);

document.addEventListener("DOMContentLoaded", init);

async function init() {
    DETECTIONS.forEach(name => {
        state.detectionCounts[name] = 0;
    });

    setupNavigation();
    setupCampaignActions();
    setupKeyboard();
    setupStreamControls();
    startClock();

    await Promise.all([
        loadStats(),
        loadEvents(),
        loadAttacks()
    ]);

    connectWebSocket();
    setInterval(loadStats, 10000);
}

function setupNavigation() {
    const nav = document.querySelector("#mainNav");
    const links = [...document.querySelectorAll(".nav-item")];
    const highlight = document.querySelector("#navHighlight");
    const sections = links.map(link => document.querySelector(link.getAttribute("href"))).filter(Boolean);

    function moveHighlight(link, animate = true) {
        if (!highlight || !link || !nav) return;
        const navRect = nav.getBoundingClientRect();
        const linkRect = link.getBoundingClientRect();
        highlight.style.transitionDuration = animate ? "220ms" : "0ms";
        highlight.style.transform = `translateY(${linkRect.top - navRect.top}px)`;
        highlight.style.height = `${linkRect.height}px`;
    }

    function activate(link, animate = true) {
        if (!link) return;
        links.forEach(item => item.classList.toggle("active", item === link));
        moveHighlight(link, animate);
    }

    links.forEach(link => {
        link.addEventListener("click", event => {
            const target = document.querySelector(link.getAttribute("href"));
            if (!target) return;
            event.preventDefault();
            activate(link);
            target.scrollIntoView({ behavior: "smooth", block: "start" });
            history.replaceState(null, "", link.getAttribute("href"));
        });
    });

    let ticking = false;
    window.addEventListener("scroll", () => {
        if (ticking) return;
        ticking = true;
        requestAnimationFrame(() => {
            const marker = window.scrollY + window.innerHeight * 0.30;
            let current = sections[0];
            sections.forEach(section => { if (section.offsetTop <= marker) current = section; });
            const link = links.find(item => item.getAttribute("href") === `#${current.id}`);
            if (link) activate(link, true);
            ticking = false;
        });
    }, { passive: true });

    const initial = links.find(link => link.getAttribute("href") === location.hash) || links[0];
    activate(initial, false);
    window.addEventListener("resize", () => moveHighlight(document.querySelector(".nav-item.active"), false));
}

function setupKeyboard() {
    document.addEventListener("keydown", event => {
        if (event.target.matches("input, textarea, select")) return;

        if (event.key.toLowerCase() === "p") {
            state.paused = !state.paused;
            showToast(
                state.paused ? "Live stream paused" : "Live stream resumed",
                state.paused ? "warning" : "success"
            );
        }

        if (event.key.toLowerCase() === "r") {
            refreshAll();
        }

        if (event.key === "Escape") {
            closeDrawer();
        }
    });
}

function setupStreamControls() {
    const header = document.querySelector("#events .section-header");
    if (!header) return;

    const controls = document.createElement("div");
    controls.className = "stream-controls";
    controls.innerHTML = `
        <button class="stream-button" id="pauseStream">PAUSE</button>
        <button class="stream-button" id="clearStream">CLEAR</button>
        <select class="stream-select" id="eventFilter">
            <option value="ALL">ALL</option>
            ${DETECTIONS.map(d => `<option value="${d}">${formatDetection(d)}</option>`).join("")}
        </select>
    `;

    header.appendChild(controls);

    const style = document.createElement("style");
    style.textContent = `
        .stream-controls {
            display: flex;
            gap: 6px;
            align-items: center;
        }
        .stream-button,
        .stream-select {
            height: 27px;
            border: 1px solid var(--border-light);
            border-radius: 5px;
            background: var(--surface-2);
            color: var(--muted);
            padding: 0 8px;
            font: 6px "DM Mono", monospace;
            letter-spacing: .5px;
            cursor: pointer;
        }
        .stream-button:hover,
        .stream-select:hover {
            color: var(--text);
            border-color: rgba(201,242,125,.3);
        }
        .stream-button.active {
            color: var(--warning);
        }
    `;
    document.head.appendChild(style);

    $("#pauseStream").addEventListener("click", () => {
        state.paused = !state.paused;
        $("#pauseStream").textContent = state.paused ? "RESUME" : "PAUSE";
        $("#pauseStream").classList.toggle("active", state.paused);
        showToast(state.paused ? "Live stream paused" : "Live stream resumed",
            state.paused ? "warning" : "success");
    });

    $("#clearStream").addEventListener("click", () => {
        state.events = [];
        state.detectionCounts = {};
        DETECTIONS.forEach(d => state.detectionCounts[d] = 0);
        state.stats.threats = 0;
        state.stats.blocked = 0;
        state.stats.rateLimited = 0;
        renderAll();
        showToast("Local event view cleared");
    });

    $("#eventFilter").addEventListener("change", event => {
        state.filter = event.target.value;
        renderEvents();
    });
}

function startClock() {
    updateClock();
    setInterval(updateClock, 1000);
}

function updateClock() {
    const clock = $("#lastUpdated");
    if (!clock) return;

    clock.textContent = new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
}

async function loadStats() {
    try {
        const response = await fetch("/api/stats", { cache: "no-store" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();

        state.stats.requests = Number(
            data.total_events ??
            data.total_requests ??
            data.requests ??
            data.event_count ??
            state.events.length
        );

        state.stats.threats = Number(
            data.threats ??
            data.total_threats ??
            countThreats()
        );

        state.stats.blocked = Number(
            data.blocked ??
            data.blocked_requests ??
            countAction("BLOCK")
        );

        state.stats.rateLimited = Number(
            data.rate_limited ??
            data.rate_limited_requests ??
            data.rate_limit ??
            countAction("RATE_LIMIT")
        );

        renderStats();
    } catch (error) {
        console.error("Stats:", error);
    }
}

async function loadEvents() {
    try {
        const response = await fetch("/api/events", { cache: "no-store" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        state.events = (
            Array.isArray(data) ? data : data.events ?? []
        ).slice(-state.maxEvents);

        recalculate();
        renderAll();
    } catch (error) {
        console.error("Events:", error);
    }
}

async function refreshAll() {
    await Promise.all([loadStats(), loadEvents()]);
    showToast("Console refreshed");
}

function connectWebSocket() {
    if (
        state.socket &&
        (
            state.socket.readyState === WebSocket.OPEN ||
            state.socket.readyState === WebSocket.CONNECTING
        )
    ) return;

    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${location.host}/ws/events`);

    state.socket = socket;
    setConnection("CONNECTING");

    socket.onopen = () => {
        state.reconnectAttempt = 0;
        setConnection("LIVE");
    };

    socket.onmessage = message => {
        try {
            const event = JSON.parse(message.data);

            if (event.type === "connection") return;
            if (!event.request) return;
            if (state.paused) return;

            state.events.push(event);

            if (state.events.length > state.maxEvents) {
                state.events = state.events.slice(-state.maxEvents);
            }

            processLiveEvent(event);
            renderAll();

            if (getDetections(event).length) {
                flashRisk();
            }

            const action = event.policy?.action;
            const detection = getDetections(event)[0];

            if (action === "BLOCK") {
                showToast(`BLOCKED · ${formatDetection(detection || "THREAT")}`, "danger");
            } else if (action === "RATE_LIMIT") {
                showToast(`RATE LIMITED · ${formatDetection(detection || "THREAT")}`, "warning");
            }
        } catch (error) {
            console.error("Socket event:", error);
        }
    };

    socket.onerror = error => console.error("WebSocket:", error);

    socket.onclose = () => {
        setConnection("RECONNECTING");
        scheduleReconnect();
    };
}

function scheduleReconnect() {
    if (state.reconnectTimer) return;

    const delay = Math.min(
        1000 * Math.pow(1.5, state.reconnectAttempt),
        10000
    );

    state.reconnectAttempt++;

    state.reconnectTimer = setTimeout(() => {
        state.reconnectTimer = null;
        connectWebSocket();
    }, delay);
}

function setConnection(status) {
    const text = $("#connectionText");
    const sidebar = $("#sidebarStatus");
    const dots = document.querySelectorAll(".live-dot");

    if (text) text.textContent = status;
    if (sidebar) sidebar.textContent = status === "LIVE" ? "OPERATIONAL" : status;

    dots.forEach(dot => {
        dot.style.background = status === "LIVE"
            ? "var(--accent)"
            : "var(--warning)";

        dot.style.boxShadow = status === "LIVE"
            ? "0 0 9px rgba(201,242,125,.45)"
            : "0 0 9px rgba(230,198,109,.35)";
    });
}

function processLiveEvent(event) {
    const action = event.policy?.action;

    if (action === "BLOCK") state.stats.blocked++;
    if (action === "RATE_LIMIT") state.stats.rateLimited++;

    const detections = getDetections(event);
    state.stats.threats += detections.length;

    detections.forEach(detection => {
        state.detectionCounts[detection] =
            (state.detectionCounts[detection] || 0) + 1;
    });

    state.stats.requests++;
}

function recalculate() {
    state.detectionCounts = {};
    DETECTIONS.forEach(d => state.detectionCounts[d] = 0);

    let threats = 0;
    let blocked = 0;
    let rateLimited = 0;

    state.events.forEach(event => {
        const action = event.policy?.action;

        if (action === "BLOCK") blocked++;
        if (action === "RATE_LIMIT") rateLimited++;

        const detections = getDetections(event);
        threats += detections.length;

        detections.forEach(detection => {
            state.detectionCounts[detection] =
                (state.detectionCounts[detection] || 0) + 1;
        });
    });

    state.stats.requests = Math.max(state.stats.requests, state.events.length);
    state.stats.threats = threats;
    state.stats.blocked = blocked;
    state.stats.rateLimited = rateLimited;
}

function renderAll() {
    renderStats();
    renderEvents();
    renderDetections();
    renderRisk();
    renderCampaign();
}

function renderStats() {
    animateNumber($("#totalRequests"), state.stats.requests);
    animateNumber($("#threatCount"), state.stats.threats);
    animateNumber($("#blockedRequests"), state.stats.blocked);
    animateNumber($("#rateLimited"), state.stats.rateLimited);
}

function renderEvents() {
    const container = $("#eventStream");
    if (!container) return;

    const events = state.filter === "ALL"
        ? state.events
        : state.events.filter(event =>
            getDetections(event).includes(state.filter)
        );

    $("#streamCount").textContent = state.events.length;

    if (!events.length) {
        container.innerHTML = `
            <div class="empty">
                <div class="empty-symbol">—</div>
                <div>${state.events.length ? "NO MATCHING EVENTS" : "WAITING FOR SECURITY EVENTS"}</div>
                <small>${state.events.length ? "Try another detection filter." : "Traffic inspected by WYVRN will appear here."}</small>
            </div>
        `;
        return;
    }

    container.innerHTML = "";

    events.slice().reverse().slice(0, 35).forEach(event => {
        container.appendChild(createEvent(event));
    });
}

function createEvent(event) {
    const request = event.request || {};
    const risk = Number(event.risk?.score ?? event.risk?.risk_score ?? 0);
    const action = event.policy?.action ?? "ALLOW";
    const detections = getDetections(event);
    const detection = detections[0] || "TRAFFIC";

    const row = document.createElement("div");
    row.className = "event interactive-event";
    row.dataset.requestId = event.request_id || "";
    row.tabIndex = 0;
    row.innerHTML = `
        <div class="event-time">${formatTime(event.timestamp)}</div>
        <div class="event-detection">${escapeHTML(formatDetection(detection))}</div>
        <div class="event-path">${escapeHTML(request.method || "GET")} &nbsp; ${escapeHTML(request.path || "/")}</div>
        <div class="event-action action-${escapeHTML(action)}">${escapeHTML(action)}</div>
        <div class="event-score">${risk}</div>
        <div class="event-expand">+</div>
    `;
    const toggle = () => toggleEventDetails(row, event);
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", e => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
    });
    return row;
}

function toggleEventDetails(row, event) {
    const existing = row.querySelector(".event-details");
    if (existing) {
        existing.remove();
        row.classList.remove("expanded");
        row.querySelector(".event-expand").textContent = "+";
        return;
    }
    const request = event.request || {};
    const risk = event.risk || {};
    const policy = event.policy || {};
    const response = event.response || {};
    const detections = getDetections(event);
    const details = document.createElement("div");
    details.className = "event-details";
    details.innerHTML = `
        <div class="event-detail-grid">
            <div><span>DETECTIONS</span><strong>${detections.length ? detections.map(d => escapeHTML(formatDetection(d))).join(" · ") : "NONE"}</strong></div>
            <div><span>CONFIDENCE</span><strong>${formatConfidence(event)}%</strong></div>
            <div><span>RISK LEVEL</span><strong>${escapeHTML(risk.level || risk.risk_level || "LOW")}</strong></div>
            <div><span>POLICY REASON</span><strong>${escapeHTML(policy.reason || "No policy override")}</strong></div>
            <div><span>RESPONSE</span><strong>${response.status_code ?? "—"} · ${response.response_size ?? response.size ?? "—"} bytes</strong></div>
            <div><span>CLIENT</span><strong>${escapeHTML(request.client_ip || "unknown")}</strong></div>
        </div>
        <button class="event-investigate">OPEN FULL INSPECTOR →</button>
    `;
    details.querySelector(".event-investigate").addEventListener("click", e => { e.stopPropagation(); openDrawer(event); });
    row.appendChild(details);
    row.classList.add("expanded");
    row.querySelector(".event-expand").textContent = "−";
}

function formatConfidence(event) {
    const findings = event.findings || [];
    if (!findings.length) return "—";
    return Math.round(Math.max(...findings.map(f => Number(f.confidence || 0))) * 100);
}

function renderDetections() {
    const grid = $("#detectionGrid");
    if (!grid) return;

    grid.innerHTML = "";

    DETECTIONS.forEach((detection, index) => {
        const count = state.detectionCounts[detection] || 0;
        const card = document.createElement("article");

        card.className = `detection-card ${count ? "active" : ""}`;
        card.tabIndex = 0;

        card.innerHTML = `
            <div class="detection-index">${String(index + 1).padStart(2, "0")}</div>
            <div class="detection-name">${escapeHTML(formatDetection(detection))}</div>
            <div class="detection-count">${count}</div>
        `;

        card.addEventListener("click", () => {
            state.filter = state.filter === detection ? "ALL" : detection;
            const select = $("#eventFilter");
            if (select) select.value = state.filter;
            renderEvents();
            document.querySelector("#events").scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        });

        grid.appendChild(card);
    });
}

function renderRisk() {
    if (!state.events.length) {
        setRisk(0, "LOW");
        return;
    }

    const recent = state.events.slice(-20);
    const highest = Math.max(
        ...recent.map(event =>
            Number(event.risk?.score ?? event.risk?.risk_score ?? 0)
        )
    );

    let level = "LOW";
    if (highest >= 80) level = "CRITICAL";
    else if (highest >= 60) level = "HIGH";
    else if (highest >= 40) level = "MEDIUM";

    setRisk(highest, level);
}

function setRisk(score, level) {
    const scoreEl = $("#riskScore");
    const levelEl = $("#riskLevel");
    const bar = $("#riskBar");

    if (scoreEl) scoreEl.textContent = Math.round(score);
    if (levelEl) levelEl.textContent = level;

    const value = level === "CRITICAL"
        ? "var(--danger)"
        : level === "HIGH" || level === "MEDIUM"
            ? "var(--warning)"
            : "var(--accent)";

    if (levelEl) levelEl.style.color = value;
    if (bar) {
        bar.style.width = `${Math.min(score, 100)}%`;
        bar.style.background = value;
    }
    drawRiskChart();
}

function renderCampaign() {
    const section = $("#campaignSection");
    const campaign = findCampaign();

    if (!section) return;

    if (!campaign) {
        section.classList.add("hidden");
        return;
    }

    section.classList.remove("hidden");

    $("#campaignScore").textContent = campaign.correlation_score ?? 0;
    $("#campaignSeverity").textContent = campaign.severity ?? "HIGH";
    $("#campaignIP").textContent = campaign.client_ip ?? "UNKNOWN";
    $("#campaignEvents").textContent = campaign.event_count ?? 0;

    const detections = campaign.unique_detections ?? [];

    $("#campaignDetections").innerHTML = detections.map(detection => `
        <span class="detection-pill">${escapeHTML(formatDetection(detection))}</span>
    `).join("");

    $("#campaignDescription").textContent =
        `${detections.length} different threat signals were correlated from the same source.`;
}

function setupCampaignActions() {
    const button = document.querySelector("#investigateCampaign");
    if (!button) return;
    button.addEventListener("click", () => {
        const campaign = findCampaign();
        if (!campaign) return;
        state.filter = "ALL";
        const select = document.querySelector("#eventFilter");
        if (select) select.value = "ALL";
        document.querySelector("#events")?.scrollIntoView({ behavior: "smooth", block: "start" });
        setTimeout(() => {
            const ids = new Set((campaign.events || []).map(item => item.request_id));
            document.querySelectorAll(".event").forEach(row => row.classList.remove("campaign-focus"));
            state.events.forEach(event => {
                if (!ids.has(event.request_id)) return;
                const rows = [...document.querySelectorAll(".event")];
                const row = rows.find(r => r.dataset.requestId === event.request_id);
                if (row) row.classList.add("campaign-focus");
            });
            showToast("Campaign events isolated", "warning");
        }, 500);
    });
}

function findCampaign() {
    for (let i = state.events.length - 1; i >= 0; i--) {
        const correlation = state.events[i].correlation;

        if (
            correlation &&
            correlation.type === "ATTACK_CAMPAIGN"
        ) return correlation;
    }

    return null;
}

async function loadAttacks() {
    const container = $("#attackButtons");
    if (!container) return;

    try {
        const response = await fetch("/api/simulator/attacks", { cache: "no-store" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        const attacks = Array.isArray(data) ? data : data.attacks ?? [];

        renderAttackButtons(attacks);
    } catch (error) {
        console.error("Attacks:", error);

        renderAttackButtons([
            { id: "sql_injection", name: "SQL INJECTION" },
            { id: "bola_idor", name: "BOLA / IDOR" },
            { id: "auth_abuse", name: "AUTH ABUSE" },
            { id: "rate_abuse", name: "RATE ABUSE" },
            { id: "sensitive_data", name: "SENSITIVE DATA" },
            { id: "anomaly", name: "BEHAVIORAL ANOMALY" }
        ]);
    }
}

function renderAttackButtons(attacks) {
    const container = $("#attackButtons");
    container.innerHTML = "";

    attacks.forEach(attack => {
        const button = document.createElement("button");
        button.className = "attack-button";
        button.dataset.attack = attack.id;
        button.textContent = attack.name || formatDetection(attack.id);

        button.addEventListener("click", () =>
            runAttack(attack.id, button)
        );

        container.appendChild(button);
    });
}

async function runAttack(attackName, clickedButton) {
    if (state.simulatorRunning) return;

    state.simulatorRunning = true;

    const buttons = document.querySelectorAll(".attack-button");
    buttons.forEach(button => {
        button.disabled = true;
        button.classList.add("running");
    });

    const original = clickedButton.textContent;
    clickedButton.textContent = "RUNNING...";

    showToast(`Launching ${formatDetection(attackName)}`, "warning");
    showSimulationProgress(attackName);

    try {
        const response = await fetch(
            `/api/simulator/run/${encodeURIComponent(attackName)}`,
            { method: "POST" }
        );

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const result = await response.json();
        showSimulatorResult(result);

        await loadEvents();
        await loadStats();

        const securityResult = result.security_result;

        if (securityResult === "BLOCKED") {
            showToast("Attack blocked by WYVRN", "danger");
        } else if (securityResult === "RATE_LIMITED") {
            showToast("Attack rate limited by WYVRN", "warning");
        } else {
            showToast("Attack completed");
        }
    } catch (error) {
        console.error("Simulator:", error);
        showToast(`Attack failed: ${error.message}`, "danger");
    } finally {
        state.simulatorRunning = false;

        buttons.forEach(button => {
            button.disabled = false;
            button.classList.remove("running");
        });

        clickedButton.textContent = original;
    }
}

function showSimulationProgress(attackName) {
    const panel = document.querySelector("#simulatorResult");
    if (!panel) return;
    panel.classList.remove("hidden");
    panel.innerHTML = `
        <div class="sim-progress">
            <div class="sim-progress-top"><span>EXECUTING SCENARIO</span><strong>${escapeHTML(formatDetection(attackName))}</strong></div>
            <div class="sim-progress-track"><div class="sim-progress-fill"></div></div>
            <div class="sim-progress-steps"><span>REQUEST</span><span>DETECT</span><span>RISK</span><span>POLICY</span></div>
        </div>`;
}

function showSimulatorResult(result) {
    const panel = $("#simulatorResult");
    if (!panel) return;

    panel.classList.remove("hidden");

    const status = result.security_result || "UNKNOWN";

    const statusClass =
        status === "BLOCKED"
            ? "blocked"
            : status === "RATE_LIMITED"
                ? "limited"
                : "allowed";

    panel.innerHTML = `
        <div class="sim-result-top">
            <div>
                <div class="sim-result-label">LAST SIMULATION</div>
                <div class="sim-result-name">${escapeHTML(
                    formatDetection(result.name || result.attack || "ATTACK")
                )}</div>
            </div>

            <div class="sim-result-status ${statusClass}">
                ${escapeHTML(status)}
            </div>
        </div>

        <div class="sim-result-details">
            <div><span>METHOD</span>${escapeHTML(result.request?.method || "GET")}</div>
            <div><span>PATH</span>${escapeHTML(result.request?.path || "—")}</div>
            <div><span>HTTP</span>${result.response?.status_code ?? "—"}</div>
        </div>
    `;
}

function openDrawer(event) {
    let drawer = $("#eventDrawer");

    if (!drawer) {
        drawer = document.createElement("div");
        drawer.id = "eventDrawer";
        drawer.className = "event-drawer";

        drawer.innerHTML = `
            <div class="drawer-backdrop"></div>
            <aside class="drawer-panel">
                <div id="drawerContent"></div>
            </aside>
        `;

        document.body.appendChild(drawer);

        drawer.querySelector(".drawer-backdrop")
            .addEventListener("click", closeDrawer);
    }

    const request = event.request || {};
    const response = event.response || {};
    const risk = event.risk || {};
    const policy = event.policy || {};
    const detections = getDetections(event);

    drawer.querySelector("#drawerContent").innerHTML = `
        <button class="drawer-close">ESC / CLOSE</button>

        <div class="drawer-title">
            ${escapeHTML(formatDetection(detections[0] || "TRAFFIC EVENT"))}
        </div>

        <div class="drawer-subtitle">
            REQUEST ${escapeHTML(event.request_id || "UNKNOWN")}
        </div>

        <div class="drawer-section">
            <div class="drawer-label">REQUEST</div>
            <div class="drawer-value">
                ${escapeHTML(request.method || "—")}
                &nbsp;
                ${escapeHTML(request.path || "—")}
                <br>
                CLIENT: ${escapeHTML(request.client_ip || "unknown")}
            </div>
        </div>

        <div class="drawer-section">
            <div class="drawer-label">SECURITY DECISION</div>
            <div class="drawer-value">
                ACTION: ${escapeHTML(policy.action || "ALLOW")}<br>
                RISK: ${risk.score ?? risk.risk_score ?? 0}<br>
                LEVEL: ${escapeHTML(risk.level || risk.risk_level || "LOW")}
            </div>
        </div>

        <div class="drawer-section">
            <div class="drawer-label">DETECTIONS</div>
            <div class="drawer-value">
                ${
                    detections.length
                        ? detections.map(d => `• ${escapeHTML(d)}`).join("<br>")
                        : "No detections"
                }
            </div>
        </div>

        <div class="drawer-section">
            <div class="drawer-label">RESPONSE</div>
            <div class="drawer-value">
                STATUS: ${response.status_code ?? "—"}<br>
                SIZE: ${response.response_size ?? response.size ?? "—"} bytes<br>
                LATENCY: ${response.latency_ms ?? "—"} ms
            </div>
        </div>

        <div class="drawer-section">
            <div class="drawer-label">RAW EVENT</div>
            <div class="drawer-json">${escapeHTML(
                JSON.stringify(event, null, 2)
            )}</div>
        </div>
    `;

    drawer.querySelector(".drawer-close")
        .addEventListener("click", closeDrawer);

    requestAnimationFrame(() => drawer.classList.add("open"));
}

function closeDrawer() {
    const drawer = $("#eventDrawer");
    if (drawer) drawer.classList.remove("open");
}

function flashRisk() {
    const panel = document.querySelector(".risk-panel");
    if (!panel) return;

    panel.animate([
        {
            transform: "translateY(0)",
            borderColor: "rgba(201,242,125,.55)"
        },
        {
            transform: "translateY(-2px)",
            borderColor: "rgba(201,242,125,.15)"
        },
        {
            transform: "translateY(0)",
            borderColor: "var(--border)"
        }
    ], { duration: 450 });
}

const numberTargets = new WeakMap();

function animateNumber(element, target) {
    if (!element) return;

    target = Number(target) || 0;

    const previous = numberTargets.get(element) ??
        (Number(element.textContent.replace(/,/g, "")) || 0);

    if (previous === target) {
        element.textContent = target.toLocaleString();
        return;
    }

    const start = performance.now();
    const duration = 350;

    function tick(now) {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(previous + (target - previous) * eased);

        element.textContent = value.toLocaleString();

        if (progress < 1) requestAnimationFrame(tick);
    }

    numberTargets.set(element, target);
    requestAnimationFrame(tick);
}

function showToast(message, type = "success") {
    const container = $("#toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast ${type === "danger" ? "danger" : type === "warning" ? "warning" : ""}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.animate([
            { opacity: 1, transform: "translateY(0)" },
            { opacity: 0, transform: "translateY(6px)" }
        ], { duration: 180 }).onfinish = () => toast.remove();
    }, 2600);
}

function countThreats() {
    return state.events.reduce(
        (sum, event) => sum + getDetections(event).length,
        0
    );
}

function countAction(action) {
    return state.events.filter(
        event => event.policy?.action === action
    ).length;
}

function getDetections(event) {
    const detections =
        event.risk?.detections ??
        event.findings?.map(finding => finding.detection) ??
        [];

    return [...new Set(detections.filter(Boolean))];
}

function formatDetection(value) {
    return String(value || "UNKNOWN").replaceAll("_", " ");
}

function formatTime(timestamp) {
    if (!timestamp) return "—";

    try {
        return new Date(timestamp).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
    } catch {
        return "—";
    }
}

function escapeHTML(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
