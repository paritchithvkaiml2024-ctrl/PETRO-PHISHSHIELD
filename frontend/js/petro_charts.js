// PetroPulse AI Charting & Telemetry Visualizer Engine

let petroChart = null;
let currentSelectedUnit = "FCC-01";

function initPetroCharts() {
    const ctx = document.getElementById("petroTelemetryChart");
    if (!ctx) return;
    
    // Create Chart.js line chart for real-time telemetry + LSTM multi-step forecast
    petroChart = new Chart(ctx.getContext("2d"), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Actual Temperature (°C)',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.08)',
                    borderWidth: 2.5,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 2,
                    pointHoverRadius: 6
                },
                {
                    label: 'LSTM Predicted Forecast (t+1..t+15)',
                    data: [],
                    borderColor: '#06b6d4',
                    borderDash: [5, 5],
                    borderWidth: 2,
                    fill: false,
                    tension: 0.35,
                    pointRadius: 3,
                    pointBackgroundColor: '#06b6d4'
                },
                {
                    label: 'Pressure (bar x10)',
                    data: [],
                    borderColor: '#8b5cf6',
                    borderWidth: 1.5,
                    fill: false,
                    tension: 0.3,
                    pointRadius: 1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 350 },
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    position: 'top',
                    labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleColor: '#f1f5f9',
                    bodyColor: '#cbd5e1',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 10 }
                },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                }
            }
        }
    });
}

function updatePetroTelemetryView(data) {
    if (!data || !data.units) return;
    
    const unit = data.units[currentSelectedUnit];
    if (!unit) return;
    
    // 1. Update Gauge Badges
    const tempEl = document.getElementById("gaugeTemp");
    const pressEl = document.getElementById("gaugePress");
    const flowEl = document.getElementById("gaugeFlow");
    const vibEl = document.getElementById("gaugeVib");
    const catEl = document.getElementById("gaugeCat");
    const viscEl = document.getElementById("gaugeVisc");
    const h2El = document.getElementById("gaugeH2");
    const sulfurEl = document.getElementById("gaugeSulfur");
    
    if (tempEl) tempEl.textContent = `${unit.temperature_c} °C`;
    if (pressEl) pressEl.textContent = `${unit.pressure_bar} bar`;
    if (flowEl) flowEl.textContent = `${unit.feed_flow_m3h} m³/h`;
    if (vibEl) vibEl.textContent = `${unit.vibration_mms} mm/s`;
    if (catEl) catEl.textContent = `${unit.catalyst_activity_pct} %`;
    if (viscEl) viscEl.textContent = `${unit.viscosity_cp} cP`;
    if (h2El) h2El.textContent = `${unit.h2_purity_pct} %`;
    if (sulfurEl) sulfurEl.textContent = `${unit.sulfur_ppm} ppm`;
    
    // 2. Update Top KPI Banner Cards
    const kpiRul = document.getElementById("kpiRulHours");
    const kpiYield = document.getElementById("kpiYieldLgbm");
    const kpiAnomaly = document.getElementById("kpiAnomalyScore");
    const kpiStatus = document.getElementById("kpiUnitStatus");
    
    if (kpiRul) kpiRul.textContent = `${unit.rul_hours_xgboost} hrs`;
    if (kpiYield) kpiYield.textContent = `${unit.yield_predicted_lgbm}%`;
    if (kpiAnomaly) {
        kpiAnomaly.textContent = (unit.anomaly_score * 100).toFixed(1) + "%";
        if (unit.anomaly_score > 0.6) {
            kpiAnomaly.className = "card-value text-danger";
        } else if (unit.anomaly_score > 0.3) {
            kpiAnomaly.className = "card-value text-petro";
        } else {
            kpiAnomaly.className = "card-value text-shield";
        }
    }
    if (kpiStatus) {
        kpiStatus.textContent = unit.anomaly_status;
        kpiStatus.className = `threat-badge ${unit.anomaly_status === 'CRITICAL' ? 'threat-malicious' : (unit.anomaly_status === 'WARNING' ? 'threat-suspicious' : 'threat-safe')}`;
    }
    
    // 3. Update Chart Stream
    if (petroChart && data.recent_stream) {
        const filtered = data.recent_stream.filter(item => item.unit_id === currentSelectedUnit);
        const labels = filtered.map(item => item.timestamp);
        const tempData = filtered.map(item => item.temperature_c);
        const pressData = filtered.map(item => item.pressure_bar * (currentSelectedUnit === "HDT-02" ? 1 : 10));
        
        // LSTM Forecast series: map actuals up to latest, then project t+1, t+5, t+15
        const forecastData = new Array(tempData.length - 1).fill(null);
        if (tempData.length > 0) {
            forecastData.push(tempData[tempData.length - 1]);
            // Future forecast points
            labels.push("+1m", "+5m", "+15m");
            forecastData.push(unit.forecast_lstm_t1, unit.forecast_lstm_t5, unit.forecast_lstm_t15);
        }
        
        petroChart.data.labels = labels;
        petroChart.data.datasets[0].data = tempData;
        petroChart.data.datasets[1].data = forecastData;
        petroChart.data.datasets[2].data = pressData;
        petroChart.update('none');
    }
}

function selectEquipmentUnit(unitId) {
    currentSelectedUnit = unitId;
    document.querySelectorAll(".unit-chip-btn").forEach(btn => {
        btn.classList.toggle("active-unit", btn.dataset.unit === unitId);
    });
}
