import os
import asyncio
import json
from contextlib import asynccontextmanager
from typing import List, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from backend.data_models import (
    URLScanRequest,
    EmailScanRequest,
    AnomalyInjectionRequest,
    ModelRetrainRequest
)
from backend.petro_engine import PetrochemicalPredictiveEngine
from backend.phish_engine import PhishShieldEngine

# Initialize Engines
petro_engine = PetrochemicalPredictiveEngine()
phish_engine = PhishShieldEngine()

# Connected WebSocket clients for real-time telemetry streaming
active_ws_connections: List[WebSocket] = []

async def telemetry_background_publisher():
    """Simulates real-time OPC-UA streaming via Kafka/Spark into TimescaleDB every 1.5s"""
    while True:
        try:
            batch = petro_engine.produce_next_telemetry_batch()
            if active_ws_connections:
                payload = json.dumps({
                    "event": "TELEMETRY_STREAM",
                    "data": petro_engine.get_latest_telemetry()
                })
                # Broadcast to all connected clients
                for ws in list(active_ws_connections):
                    try:
                        await ws.send_text(payload)
                    except Exception:
                        if ws in active_ws_connections:
                            active_ws_connections.remove(ws)
        except Exception as e:
            print(f"[Telemetry Publisher Error] {e}")
        await asyncio.sleep(1.5)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: launch background telemetry publisher task
    pub_task = asyncio.create_task(telemetry_background_publisher())
    yield
    # Shutdown
    pub_task.cancel()

app = FastAPI(
    title="Industrial AI & Threat Defense Platform",
    description="Unified AI-Powered Petrochemical Predictive Analytics & PhishShield Threat Platform",
    version="2.5.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- WebSocket Stream Endpoint ---
@app.websocket("/ws/telemetry")
async def websocket_telemetry_stream(websocket: WebSocket):
    await websocket.accept()
    active_ws_connections.append(websocket)
    try:
        # Send initial full snapshot
        init_snapshot = json.dumps({
            "event": "INITIAL_STATE",
            "data": petro_engine.get_latest_telemetry()
        })
        await websocket.send_text(init_snapshot)
        while True:
            # Keep alive and listen for any client triggers
            msg = await websocket.receive_text()
            try:
                data = json.loads(msg)
                if data.get("action") == "INJECT_ANOMALY":
                    petro_engine.inject_anomaly(
                        data.get("unit_id", "FCC-01"),
                        data.get("anomaly_type", "thermal_runaway"),
                        float(data.get("severity", 0.8))
                    )
                elif data.get("action") == "CLEAR_ANOMALIES":
                    petro_engine.clear_anomalies()
            except Exception:
                pass
    except WebSocketDisconnect:
        if websocket in active_ws_connections:
            active_ws_connections.remove(websocket)
    except Exception:
        if websocket in active_ws_connections:
            active_ws_connections.remove(websocket)

# --- Petrochemical Analytics REST Endpoints ---
@app.get("/api/v1/petro/telemetry")
async def get_petro_telemetry():
    return petro_engine.get_latest_telemetry()

@app.post("/api/v1/petro/inject-anomaly")
async def inject_anomaly(req: AnomalyInjectionRequest):
    petro_engine.inject_anomaly(req.target_unit, req.anomaly_type, req.severity)
    return {
        "status": "ANOMALY_INJECTED",
        "target_unit": req.target_unit,
        "anomaly_type": req.anomaly_type,
        "severity": req.severity,
        "message": f"Injected {req.anomaly_type} into unit {req.target_unit} (severity: {req.severity})"
    }

@app.post("/api/v1/petro/clear-anomalies")
async def clear_anomalies():
    petro_engine.clear_anomalies()
    return {"status": "ANOMALIES_CLEARED", "message": "All equipment telemetry restored to nominal baseline."}

@app.get("/api/v1/petro/mlops-registry")
async def get_mlops_registry():
    return {
        "models": petro_engine.model_metadata,
        "feast_feature_store": petro_engine.feast_features
    }

# --- PhishShield Detection REST Endpoints ---
@app.post("/api/v1/phish/scan-url")
async def scan_url(req: URLScanRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL parameter cannot be empty.")
    result = phish_engine.scan_url(req.url)
    return result

@app.post("/api/v1/phish/scan-email")
async def scan_email(req: EmailScanRequest):
    result = phish_engine.scan_email(req.sender, req.subject, req.body, req.headers)
    return result

@app.get("/api/v1/phish/templates")
async def get_phish_templates():
    return phish_engine.get_templates()

@app.get("/api/v1/phish/vault")
async def get_quarantine_vault():
    return phish_engine.get_quarantine_vault()

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "platform": "PetroPulse AI & PhishShield Enterprise",
        "active_ws_clients": len(active_ws_connections)
    }

# --- Serve Frontend Static Files ---
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
async def serve_index():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse(content={"message": "Frontend building..."})
