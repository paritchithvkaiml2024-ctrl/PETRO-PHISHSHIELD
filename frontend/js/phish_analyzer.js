// PhishShield AI Threat Protection Frontend Controller

let loadedTemplates = [];

async function loadPhishTemplates() {
    try {
        const res = await fetch('/api/v1/phish/templates');
        if (!res.ok) return;
        loadedTemplates = await res.json();
        renderTemplatePills(loadedTemplates);
    } catch (e) {
        console.error("Failed to load phish templates", e);
    }
}

function renderTemplatePills(templates) {
    const container = document.getElementById("templatePillsContainer");
    if (!container) return;
    container.innerHTML = "";
    
    templates.forEach(tpl => {
        const badge = document.createElement("span");
        badge.className = "template-badge";
        badge.innerHTML = `⚡ ${tpl.name}`;
        badge.onclick = () => applyTemplate(tpl);
        container.appendChild(badge);
    });
}

function applyTemplate(tpl) {
    if (tpl.type === "URL") {
        switchPhishInputMode("URL");
        document.getElementById("inputPhishUrl").value = tpl.url;
    } else {
        switchPhishInputMode("EMAIL");
        document.getElementById("inputEmailSender").value = tpl.sender;
        document.getElementById("inputEmailSubject").value = tpl.subject;
        document.getElementById("inputEmailBody").value = tpl.body;
    }
}

function switchPhishInputMode(mode) {
    const isUrl = mode === "URL";
    document.getElementById("urlInputGroup").style.display = isUrl ? "block" : "none";
    document.getElementById("emailInputGroup").style.display = isUrl ? "none" : "block";
    
    document.getElementById("btnModeUrl").classList.toggle("active", isUrl);
    document.getElementById("btnModeEmail").classList.toggle("active", !isUrl);
}

async function executePhishScan() {
    const isUrlMode = document.getElementById("btnModeUrl").classList.contains("active");
    const scanBtn = document.getElementById("btnExecuteScan");
    const originalText = scanBtn.innerHTML;
    scanBtn.innerHTML = `<span>⏳ Analyzing with Scikit-Learn Ensemble...</span>`;
    scanBtn.disabled = true;

    try {
        let endpoint = "";
        let payload = {};

        if (isUrlMode) {
            const urlVal = document.getElementById("inputPhishUrl").value.trim();
            if (!urlVal) {
                alert("Please enter a URL to scan.");
                return;
            }
            endpoint = "/api/v1/phish/scan-url";
            payload = { url: urlVal };
        } else {
            const sender = document.getElementById("inputEmailSender").value.trim();
            const subject = document.getElementById("inputEmailSubject").value.trim();
            const body = document.getElementById("inputEmailBody").value.trim();
            if (!body && !subject) {
                alert("Please enter email details.");
                return;
            }
            endpoint = "/api/v1/phish/scan-email";
            payload = { sender, subject, body };
        }

        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            throw new Error(`HTTP Error: ${res.status}`);
        }

        const result = await res.json();
        renderScanResults(result);
        loadQuarantineVault(); // Refresh vault table
    } catch (err) {
        alert(`Scan failed: ${err.message}`);
    } finally {
        scanBtn.innerHTML = originalText;
        scanBtn.disabled = false;
    }
}

function renderScanResults(data) {
    const resultsPanel = document.getElementById("phishResultsPanel");
    if (!resultsPanel) return;
    resultsPanel.style.display = "block";

    // Risk Meter & Threat Badge
    const meterVal = document.getElementById("resRiskScore");
    const badgeEl = document.getElementById("resThreatBadge");
    const actionEl = document.getElementById("resActionBadge");
    const targetEl = document.getElementById("resTargetDisplay");
    
    if (meterVal) meterVal.textContent = `${data.risk_score}%`;
    if (targetEl) targetEl.textContent = data.target;
    
    if (badgeEl) {
        badgeEl.textContent = `${data.threat_level} (${data.confidence}% Confidence)`;
        badgeEl.className = `threat-badge ${data.threat_level === 'MALICIOUS' ? 'threat-malicious' : (data.threat_level === 'SUSPICIOUS' ? 'threat-suspicious' : 'threat-safe')}`;
    }

    if (actionEl) {
        actionEl.textContent = `SOC Action: ${data.recommended_action}`;
    }

    // SHAP Explainability Waterfall
    const shapContainer = document.getElementById("shapFeaturesContainer");
    if (shapContainer) {
        shapContainer.innerHTML = "";
        data.shap_contributions.forEach(item => {
            const row = document.createElement("div");
            row.className = "shap-item";
            const pillClass = item.type === "critical" ? "shap-pill-critical" : (item.type === "risk" ? "shap-pill-risk" : "shap-pill-safe");
            row.innerHTML = `
                <span>${item.feature}</span>
                <span class="${pillClass}">${item.impact}</span>
            `;
            shapContainer.appendChild(row);
        });
    }

    // Remediation list
    const remContainer = document.getElementById("remediationStepsContainer");
    if (remContainer) {
        remContainer.innerHTML = data.remediation_steps.map(step => `<li>${step}</li>`).join("");
    }

    // Lexical Indicators Tags
    const indContainer = document.getElementById("iocIndicatorsContainer");
    if (indContainer) {
        indContainer.innerHTML = (data.detected_indicators || []).map(tag => 
            `<span class="template-badge" style="background: rgba(239,68,68,0.15); color: #fca5a5; border-color: rgba(239,68,68,0.3)">⚠️ ${tag}</span>`
        ).join("") || `<span class="template-badge" style="color: #6ee7b7">✅ CLEAN REPUTATION</span>`;
    }
}

async function loadQuarantineVault() {
    try {
        const res = await fetch('/api/v1/phish/vault');
        if (!res.ok) return;
        const vault = await res.json();
        const tbody = document.getElementById("quarantineVaultBody");
        if (!tbody) return;
        tbody.innerHTML = "";

        vault.slice(0, 6).forEach(item => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="font-family: var(--font-mono); color: #38bdf8">${item.id}</td>
                <td style="color: var(--text-muted); font-size: 0.72rem">${item.timestamp}</td>
                <td><span style="max-width: 200px; display: inline-block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">${item.threat_vector}</span></td>
                <td><span class="threat-badge threat-malicious" style="font-size: 0.7rem; padding: 2px 8px">${item.risk_score}%</span></td>
                <td><code style="font-size: 0.7rem; color: #a78bfa">${item.mitre_technique}</code></td>
                <td><span style="color: #6ee7b7; font-size: 0.75rem">${item.action_taken}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed to load vault", e);
    }
}
