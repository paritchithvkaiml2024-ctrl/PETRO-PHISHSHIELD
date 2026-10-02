from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

# --- Petrochemical Telemetry Models ---
class TelemetryDataPoint(BaseModel):
    timestamp: str
    unit_id: str
    unit_name: str
    temperature_c: float
    pressure_bar: float
    feed_flow_m3h: float
    catalyst_activity_pct: float
    vibration_mms: float
    viscosity_cp: float
    h2_purity_pct: float
    sulfur_ppm: float
    anomaly_score: float
    anomaly_status: str # "NORMAL", "WARNING", "CRITICAL"
    rul_hours_xgboost: float
    yield_predicted_lgbm: float
    forecast_lstm_t1: float
    forecast_lstm_t5: float
    forecast_lstm_t15: float

class AnomalyInjectionRequest(BaseModel):
    anomaly_type: str # "thermal_runaway", "compressor_surge", "valve_cavitation", "catalyst_poisoning", "sensor_drift"
    severity: float = Field(default=0.8, ge=0.1, le=1.0)
    target_unit: str = "FCC-01" # "FCC-01", "HDT-02", "CDU-03", "HEX-04"

class ModelRetrainRequest(BaseModel):
    model_name: str # "XGBoost_RUL", "LightGBM_Yield", "LSTM_Forecaster"
    epochs_or_estimators: int = 50
    learning_rate: float = 0.05

# --- PhishShield Detection Models ---
class URLScanRequest(BaseModel):
    url: str

class EmailScanRequest(BaseModel):
    sender: str
    subject: str
    body: str
    headers: Optional[Dict[str, str]] = None

class LexicalFeatures(BaseModel):
    url_length: int
    num_dots: int
    num_hyphens: int
    num_subdomains: int
    has_ip_address: bool
    is_https: bool
    shannon_entropy: float
    has_punycode: bool
    suspicious_tld: bool
    suspicious_keywords: List[str]

class PhishAnalysisResult(BaseModel):
    target: str
    scan_type: str # "URL" or "EMAIL"
    is_phishing: bool
    risk_score: float # 0.0 to 100.0
    threat_level: str # "SAFE", "SUSPICIOUS", "MALICIOUS"
    confidence: float
    lexical_features: Dict[str, Any]
    content_nlp_features: Dict[str, Any]
    shap_contributions: List[Dict[str, Any]]
    detected_indicators: List[str]
    ioc_records: Dict[str, Any]
    recommended_action: str
    remediation_steps: List[str]
