// Master Application Orchestrator

let socket = null;

document.addEventListener("DOMContentLoaded", () => {
    initPetroCharts();
    connectWebSocket();
    loadPhishTemplates();
    loadQuarantineVault();
    setupNavigation();
    setupAnomalyControls();
});

// --- Tab Navigation ---
function setupNavigation() {
    const tabs = document.querySelectorAll(".nav-tabs .tab-btn");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active", "shield-active"));
            tab.classList.add("active");
            if (tab.dataset.target === "viewPhish") {
                tab.classList.add("shield-active");
            }
            
            document.querySelectorAll(".view-section").forEach(view => {
                view.classList.remove("active-view");
            });
            const targetView = document.getElementById(tab.dataset.target);
            if (targetView) targetView.classList.add("active-view");
        });
    });
}

// --- WebSocket Connection ---
function connectWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;
    
    socket = new WebSocket(wsUrl);
    
    socket.onopen = () => {
        console.log("[WebSocket] Connected to Telemetry Stream");
        const dot = document.getElementById("streamStatusDot");
        if (dot) dot.style.background = "#10b981";
    };
    
    socket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.event === "TELEMETRY_STREAM" || msg.event === "INITIAL_STATE") {
                updatePetroTelemetryView(msg.data);
            }
        } catch (err) {
            console.error("[WebSocket Parse Error]", err);
        }
    };
    
    socket.onclose = () => {
        console.warn("[WebSocket] Disconnected. Retrying in 3s...");
        const dot = document.getElementById("streamStatusDot");
        if (dot) dot.style.background = "#ef4444";
        setTimeout(connectWebSocket, 3000);
    };
}

// --- Anomaly Controls ---
function setupAnomalyControls() {
    document.querySelectorAll(".anomaly-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
            const anomalyType = btn.dataset.anomaly;
            const targetUnit = currentSelectedUnit || "FCC-01";
            try {
                const res = await fetch("/api/v1/petro/inject-anomaly", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        anomaly_type: anomalyType,
                        severity: 0.85,
                        target_unit: targetUnit
                    })
                });
                const data = await res.json();
                showNotification(`⚠️ Anomaly Injected: ${anomalyType} on ${targetUnit}`, "danger");
            } catch (err) {
                console.error(err);
            }
        });
    });

    const clearBtn = document.getElementById("btnClearAnomalies");
    if (clearBtn) {
        clearBtn.addEventListener("click", async () => {
            try {
                await fetch("/api/v1/petro/clear-anomalies", { method: "POST" });
                showNotification("✅ Telemetry Restored to Nominal Baseline", "success");
            } catch (err) {
                console.error(err);
            }
        });
    }
}

function showNotification(msg, type) {
    const banner = document.getElementById("globalAlertBanner");
    if (!banner) return;
    banner.textContent = msg;
    banner.style.display = "block";
    banner.style.background = type === "danger" ? "rgba(239, 68, 68, 0.9)" : "rgba(16, 185, 129, 0.9)";
    setTimeout(() => {
        banner.style.display = "none";
    }, 4000);
}

// --- API Sandbox Runner ---
async function runApiSandbox(endpoint, method, bodyText) {
    const respBox = document.getElementById("sandboxResponseOutput");
    if (!respBox) return;
    respBox.textContent = "Sending API Request...";

    try {
        const opts = {
            method: method,
            headers: { "Content-Type": "application/json" }
        };
        if (method === "POST" && bodyText) {
            opts.body = bodyText;
        }
        const res = await fetch(endpoint, opts);
        const data = await res.json();
        respBox.textContent = JSON.stringify(data, null, 2);
    } catch (e) {
        respBox.textContent = `Error: ${e.message}`;
    }
}
