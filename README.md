# ⚡ PetroPulse AI & PhishShield Enterprise
### Unified Industrial IoT Telemetry Analytics & AI-Driven Cyber Threat Defense Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![XGBoost](https://img.shields.io/badge/XGBoost-v2.0+-eb6024.svg)](https://xgboost.readthedocs.io)
[![LightGBM](https://img.shields.io/badge/LightGBM-v4.3+-ff5722.svg)](https://lightgbm.readthedocs.io)
[![PyTorch](https://img.shields.io/badge/PyTorch-v2.2+-ee4c2c.svg?logo=pytorch&logoColor=white)](https://pytorch.org)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-v1.4+-f7931e.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-326CE5.svg?logo=kubernetes&logoColor=white)](https://kubernetes.io)

---

## 🌟 Executive Summary

This repository delivers a production-grade dual-platform suite combining high-throughput **Industrial IoT Predictive Telemetry Analytics** for petrochemical refineries with **Enterprise AI Phishing Threat Defense & Explainable Security Intelligence**.

```
+---------------------------------------------------------------------------------------------------+
|                           APEX INDUSTRIAL & CYBER DEFENSE PORTAL                                  |
|                                                                                                   |
|   [⛽ PetroPulse AI Platform]                                [🛡️ PhishShield Enterprise]           |
|   • Streaming OPC-UA Telemetry                               • Lexical & Syntactic URL Analyzer   |
|   • Apache Kafka & Spark Streaming                           • NLP Urgency & Impersonation Engine |
|   • TimescaleDB & Feast Feature Store                        • Scikit-Learn Ensemble Classifier   |
|   • Real-Time ML: XGBoost, LightGBM, PyTorch LSTM            • SHAP-Style Explainable AI (XAI)    |
|   • Anomaly Injection & Automated Mitigation                 • Quarantine Vault & MITRE ATT&CK    |
+---------------------------------------------------------------------------------------------------+
```

---

## 🔬 Core System Architecture

### 1. PetroPulse AI — Petrochemical Predictive Engine
1. **OPC-UA Telemetry Ingestion**: Continuous high-frequency multi-sensor streaming for Catalytic Crackers (FCC-01), Hydrotreaters (HDT-02), Crude Distillation (CDU-03), and Heat Exchangers (HEX-04).
2. **Kafka + Spark Streaming Pipeline**: Real-time event deduplication, windowed aggregations, and sub-5ms low-latency transfer into TimescaleDB hypertables.
3. **Feast Feature Store**: Dual-tier storage with in-memory Redis online cache for sub-2ms feature retrieval during inference.
4. **Machine Learning Model Trio**:
   - **XGBoost Regressor**: Predicts Remaining Useful Life (RUL) in hours based on thermal, vibration, and catalyst degradation dynamics.
   - **LightGBM Regressor**: Optimizes hydrocarbon yield efficiency percentage given dynamic feed flow, hydrogen purity, and sulfur load.
   - **PyTorch LSTM Network**: Multi-step ahead temporal forecasting ($t+1, t+5, t+15$) with reconstruction error-based anomaly scoring.
5. **Interactive Anomaly Injection**: Live testing of thermal runaway surges, compressor cavitation, catalyst poisoning, and sensor drift.

---

### 2. PhishShield Enterprise — Phishing Threat Intelligence
1. **Multi-Vector Feature Extraction**:
   - *Lexical & Structural*: Shannon entropy calculation, punycode/homoglyph detection (`xn--`), subdomain hierarchy depth, IP-literal host detection, suspicious TLD matching (`.xyz`, `.top`, `.ru`, `.buzz`, etc.).
   - *NLP & Semantic Analysis*: TF-IDF vectorization, urgency coercion markers ("Account suspended in 2 hours", "Wire transfer pending"), brand spoofing detection.
2. **Scikit-Learn Ensemble Engine**:
   - Random Forest & Gradient Boosting classifiers with calibrated probabilities (0.0% to 100.0%).
3. **Explainable AI (XAI)**:
   - SHAP-style attribution waterfall quantifying individual positive/negative risk contributors.
4. **Quarantine Vault & MITRE ATT&CK Mapping**:
   - Automated incident logging with SHA-256 IOC extraction, SOC playbook dispatch, and DNS sinkhole recommendations.

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.10+ (Recommended: Python 3.12)
- Or Docker & Docker Compose

### 1. Local Run
```bash
# Install dependencies
pip install -r requirements.txt

# Start FastAPI server with live WebSocket telemetry
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Open your browser at **`http://localhost:8000`**.

### 2. Docker Compose Deployment
```bash
docker-compose up --build -d
```

---

## ⚡ REST API Specifications

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/petro/telemetry` | Returns real-time snapshot of refinery sensors, RUL, and LSTM forecasts |
| `POST` | `/api/v1/petro/inject-anomaly` | Injects synthetic anomalies (`thermal_runaway`, `compressor_surge`, etc.) |
| `POST` | `/api/v1/petro/clear-anomalies` | Restores all telemetry streams to nominal baseline |
| `GET` | `/api/v1/petro/mlops-registry` | Inspects MLflow model versions and Feast feature store status |
| `POST` | `/api/v1/phish/scan-url` | Scans target URL with Scikit-learn ensemble + SHAP attribution |
| `POST` | `/api/v1/phish/scan-email` | Inspects email headers and message body with NLP + URL ensemble |
| `GET` | `/api/v1/phish/templates` | Retrieves curated adversarial test scenarios |
| `GET` | `/api/v1/phish/vault` | Returns MITRE ATT&CK incident log and quarantined threats |
| `GET` | `/api/v1/health` | Returns platform and WebSocket cluster health |

---

## 🏛️ Kubernetes Deployment

The platform is designed with cloud-native deployment manifests:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: petro-phish-platform
  namespace: prod-petro-shield
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: petro-app
        image: petro-phish-platform:latest
        resources:
          limits: { cpu: "1000m", memory: "1Gi" }
          requests: { cpu: "200m", memory: "256Mi" }
        ports:
        - containerPort: 8000
```
