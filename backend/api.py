"""
==================================================
NetShield-NIDS — FastAPI REST API Backend
==================================================
backend/api.py

Provides a high-performance RESTful interface for the NetShield NIDS
live monitoring engine, delivering real-time metrics, traffic time-series,
threat analytics, incident alerts, and network adapter control to
modern web dashboards.

Architecture:
Network -> Scapy (capture.py) -> FlowManager (flow_manager.py)
        -> FeatureExtractor (feature_extractor.py) -> LiveDetector (detector.py)
        -> RealtimeMonitorEngine (monitor.py) -> FastAPI (backend/api.py)
        -> Web Dashboard
"""

import os
import sys
import time
import uuid
import hashlib
import platform
import threading
from collections import deque, Counter
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
from contextlib import asynccontextmanager

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.responses import FileResponse
from backend.database import init_db, get_db_session
from backend.models import Sensor, Alert, TrafficMetric, Report
from backend.report_generator import (
    fetch_report_data,
    generate_pdf_report,
    generate_csv_report,
    generate_json_report,
    REPORTS_DIR,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ── Configure Container & Production Logging ─────────────────────────
LOG_LEVEL_STR = os.getenv("LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, LOG_LEVEL_STR, logging.INFO)

logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("netshield")

# ── Ensure Project Root is in sys.path ──────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from live.capture import get_available_network_interfaces
from live.monitor import RealtimeMonitorEngine
from live.detector import (
    LiveDetector,
    get_severity_for_class,
    get_attack_explanation,
    get_confidence_category,
    get_operational_status,
    SEVERITY_MAPPING,
    ATTACK_EXPLANATIONS,
)

# ── Component Paths ─────────────────────────────────────────────────
ET_MODEL_PATH = os.path.join(PROJECT_ROOT, "extra_trees_model.pkl")
RF_MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "random_forest_model.pkl")
SCALER_PATH = os.path.join(PROJECT_ROOT, "models", "scaler.pkl")
ENCODER_PATH = os.path.join(PROJECT_ROOT, "models", "label_encoder.pkl")


# ── Global Engine & Traffic State Manager ────────────────────────────
class NIDSServiceManager:
    """Manages the lifecycle of ML components, monitor engine, and time-series traffic stats."""

    def __init__(self):
        self.server_start_time: float = time.time()
        self.monitor_start_time: Optional[float] = None
        self.model: Any = None
        self.scaler: Any = None
        self.encoder: Any = None
        self.model_name: str = "None"
        self.model_loaded: bool = False
        self.model_error: Optional[str] = None
        
        self.engine: Optional[RealtimeMonitorEngine] = None
        self._lock = threading.Lock()
        
        # Lightweight time-series circular buffer (stores up to 300 data points @ 1/sec)
        self.traffic_history: deque = deque(maxlen=300)
        self.total_bytes_tracked: int = 0
        self._last_packet_count: int = 0
        self._last_bytes_count: int = 0
        self._last_sample_time: float = time.time()
        
        # Sensor Architecture Telemetry State
        self.latest_sensor_data: Optional[Dict[str, Any]] = None
        self.last_sensor_update_time: Optional[float] = None
        self.sensor_timeout_seconds: float = 15.0
        
        # Background collector thread
        self._collector_stop_event = threading.Event()
        self._collector_thread: Optional[threading.Thread] = None
        
        # Initialize components
        self.load_components()

    def load_components(self):
        """Loads Extra Trees (or fallback Random Forest) model, scaler, and encoder."""
        with self._lock:
            model_path = ET_MODEL_PATH if os.path.exists(ET_MODEL_PATH) else RF_MODEL_PATH
            logger.info(f"Loading ML detector artifacts from: {model_path}")
            
            if not os.path.exists(model_path):
                self.model_loaded = False
                self.model_error = f"Model artifact missing at {ET_MODEL_PATH} and {RF_MODEL_PATH}"
                logger.error(self.model_error)
                return
            if not os.path.exists(SCALER_PATH):
                self.model_loaded = False
                self.model_error = f"StandardScaler missing at {SCALER_PATH}"
                logger.error(self.model_error)
                return
            if not os.path.exists(ENCODER_PATH):
                self.model_loaded = False
                self.model_error = f"LabelEncoder missing at {ENCODER_PATH}"
                logger.error(self.model_error)
                return

            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(SCALER_PATH)
                self.encoder = joblib.load(ENCODER_PATH)
                self.model_name = type(self.model).__name__
                self.model_loaded = True
                self.model_error = None
                
                # Instantiate continuous monitoring engine
                self.engine = RealtimeMonitorEngine(
                    model=self.model,
                    scaler=self.scaler,
                    encoder=self.encoder,
                    active_timeout=5.0,
                    inactivity_timeout=3.0
                )
                logger.info(f"ML Model '{self.model_name}' loaded successfully. RealtimeMonitorEngine initialized.")
            except Exception as e:
                self.model_loaded = False
                self.model_error = f"Failed to initialize components: {str(e)}"
                logger.error(self.model_error, exc_info=True)

    def start_traffic_collector(self):
        """Starts background periodic sampling for traffic time-series charts."""
        self._collector_stop_event.clear()
        self._collector_thread = threading.Thread(target=self._traffic_collector_loop, daemon=True)
        self._collector_thread.start()
        logger.info("Background traffic statistics collector thread started.")

    def stop_traffic_collector(self):
        """Stops background traffic sampling."""
        self._collector_stop_event.set()
        if self._collector_thread and self._collector_thread.is_alive():
            self._collector_thread.join(timeout=1.5)
        logger.info("Background traffic statistics collector thread stopped.")

    def _traffic_collector_loop(self):
        """Samples engine state once every second to build smooth frontend chart metrics."""
        while not self._collector_stop_event.is_set():
            time.sleep(1.0)
            now = time.time()
            dt = max(0.1, now - self._last_sample_time)
            
            if self.engine:
                snap = self.engine.get_snapshot()
                pkts = snap.get("packets_captured", 0)
                
                # Calculate bytes from recent detections if available
                total_bytes = sum(d.get("Bytes", 0) for d in snap.get("recent_detections", []))
                
                delta_pkts = max(0, pkts - self._last_packet_count)
                delta_bytes = max(0, total_bytes - self._last_bytes_count) if total_bytes >= self._last_bytes_count else total_bytes
                
                pps = round(delta_pkts / dt, 2)
                bps = round(delta_bytes / dt, 2)
                
                self._last_packet_count = pkts
                self._last_bytes_count = total_bytes
                self._last_sample_time = now
                
                point = {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "timestamp_iso": datetime.now().isoformat(),
                    "timestamp_epoch": round(now, 3),
                    "packets": pkts,
                    "packets_per_sec": pps,
                    "bytes": total_bytes,
                    "bytes_per_sec": bps,
                    "active_flows": snap.get("active_flows", 0),
                    "completed_flows": snap.get("completed_flows", 0),
                    "classified_flows": snap.get("classified_flows", 0),
                    "normal_count": snap.get("normal_count", 0),
                    "threat_count": snap.get("threat_count", 0),
                    "review_count": snap.get("review_count", 0),
                    "uncertain_count": snap.get("uncertain_count", 0)
                }
                
                with self._lock:
                    self.traffic_history.append(point)

    def get_active_telemetry(self) -> Dict[str, Any]:
        """Returns remote sensor telemetry if active, otherwise local engine snapshot."""
        now = time.time()
        with self._lock:
            if self.latest_sensor_data and self.last_sensor_update_time and (now - self.last_sensor_update_time <= self.sensor_timeout_seconds):
                return {
                    "source": "remote_sensor",
                    "data": self.latest_sensor_data
                }

        if self.engine:
            snap = self.engine.get_snapshot()
            sanitized_detections = [sanitize_detection_record(d) for d in snap.get("recent_detections", [])]
            sanitized_incidents = [sanitize_incident_record(inc) for inc in snap.get("incidents_list", [])]

            high_risk_count = sum(
                1 for d in sanitized_detections
                if d.get("Severity") in ["HIGH", "CRITICAL"] and not d.get("Is_Benign", True)
            )
            protocol_dist = calculate_protocol_breakdown(sanitized_detections)
            top_ips = calculate_top_source_ips(sanitized_detections, limit=5)

            return {
                "source": "local_engine",
                "data": {
                    "state": snap.get("state", "STOPPED"),
                    "interface": snap.get("interface", ""),
                    "packets_captured": snap.get("packets_captured", 0),
                    "active_flows": snap.get("active_flows", 0),
                    "completed_flows": snap.get("completed_flows", 0),
                    "classified_flows": snap.get("classified_flows", 0),
                    "skipped_flows": snap.get("skipped_flows", 0),
                    "normal_count": snap.get("normal_count", 0),
                    "threat_count": snap.get("threat_count", 0),
                    "review_count": snap.get("review_count", 0),
                    "uncertain_count": snap.get("uncertain_count", 0),
                    "high_risk_threat_count": high_risk_count,
                    "attack_rate": round(snap.get("attack_rate", 0.0), 2),
                    "attack_breakdown": snap.get("attack_breakdown", {}),
                    "protocol_breakdown": protocol_dist,
                    "recent_detections": sanitized_detections,
                    "recent_incidents": sanitized_incidents,
                    "top_source_ips": top_ips
                }
            }

        return {"source": "idle", "data": {}}


# Singleton Service Manager
service_manager = NIDSServiceManager()


# ── Lifespan Context Manager ─────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize SQLite DB schema, then start background traffic collector
    logger.info("Initializing NetShield-NIDS REST API Service...")
    try:
        init_db()
        logger.info("SQLite database initialized (netshield.db).")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)
    service_manager.start_traffic_collector()
    yield
    # Shutdown: Stop traffic collector and cleanly stop monitoring if running
    logger.info("Container shutdown signal (SIGTERM/SIGINT) received. Initiating graceful shutdown...")
    service_manager.stop_traffic_collector()
    if service_manager.engine and service_manager.engine.state == "RUNNING":
        logger.info("Stopping Scapy live packet capture thread and flushing active flows...")
        service_manager.engine.stop_monitoring()
    logger.info("NetShield-NIDS REST API Service stopped cleanly.")


# ── FastAPI App Declaration ──────────────────────────────────────────
app = FastAPI(
    title="NetShield-NIDS REST API",
    description="High-Performance Machine Learning Network Intrusion Detection System API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# ── CORS Configuration ───────────────────────────────────────────────
# Allows local development frontends (Vite, React, Next.js, etc.) and reverse proxies to access API
cors_env = os.getenv("CORS_ORIGINS", "*")
origins = [o.strip() for o in cors_env.split(",")] if cors_env != "*" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ────────────────────────────────────────
class MonitorStartRequest(BaseModel):
    interface: Optional[str] = Field(None, description="Interface display name or substring identifier. If omitted, the best active adapter is automatically selected.")

class APIResponse(BaseModel):
    status: str
    message: str
    data: Optional[Dict[str, Any]] = None

class SensorDataPayload(BaseModel):
    sensor_id: str = Field(..., description="Unique sensor instance identifier")
    timestamp: str = Field(..., description="ISO 8601 timestamp of telemetry snapshot")
    state: Optional[str] = "RUNNING"
    interface: Optional[str] = ""
    packets_captured: int = 0
    active_flows: int = 0
    completed_flows: int = 0
    classified_flows: int = 0
    skipped_flows: int = 0
    normal_count: int = 0
    threat_count: int = 0
    review_count: int = 0
    uncertain_count: int = 0
    high_risk_threat_count: int = 0
    attack_rate: float = 0.0
    attack_breakdown: Dict[str, int] = {}
    protocol_breakdown: Dict[str, int] = {}
    recent_detections: List[Dict[str, Any]] = []
    recent_incidents: List[Dict[str, Any]] = []
    top_source_ips: List[Dict[str, Any]] = []


class SensorHeartbeatPayload(BaseModel):
    sensor_id: str = Field(..., description="Unique sensor instance identifier")
    name: Optional[str] = None
    hostname: Optional[str] = None
    platform: Optional[str] = None
    version: Optional[str] = "1.0.0"
    packets_captured: int = 0
    active_flows: int = 0
    threat_count: int = 0


# ── Serialization & Helper Utilities ─────────────────────────────────
def sanitize_detection_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures detection dictionary is 100% JSON-serializable (removes DataFrame / ndarrays)."""
    clean = {}
    for k, v in rec.items():
        if k in ["Proba_DF", "Scaled_Features", "Raw_Features"]:
            continue  # Skip heavy internal machine learning objects
        elif isinstance(v, (np.floating, float)):
            clean[k] = float(v)
        elif isinstance(v, (np.integer, int)):
            clean[k] = int(v)
        elif isinstance(v, (np.bool_, bool)):
            clean[k] = bool(v)
        else:
            clean[k] = v
    return clean

def sanitize_incident_record(inc: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures incident alert dictionary is clean and standardized for REST clients."""
    clean = {}
    for k, v in inc.items():
        if k in ["Proba_DF", "Scaled_Features", "Raw_Features"]:
            continue
        elif isinstance(v, (np.floating, float)):
            clean[k] = float(v)
        elif isinstance(v, (np.integer, int)):
            clean[k] = int(v)
        elif isinstance(v, (np.bool_, bool)):
            clean[k] = bool(v)
        else:
            clean[k] = v
    return clean

def calculate_top_source_ips(recent_detections: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    """Calculates top source IP activity and threat associations safely from detection records."""
    ip_stats: Dict[str, Dict[str, int]] = {}
    for det in recent_detections:
        src = det.get("Source", "Unknown")
        if src == "Unknown":
            continue
        if src not in ip_stats:
            ip_stats[src] = {"total_flows": 0, "threat_flows": 0}
        ip_stats[src]["total_flows"] += 1
        if not det.get("Is_Benign", True):
            ip_stats[src]["threat_flows"] += 1

    sorted_ips = sorted(ip_stats.items(), key=lambda item: (item[1]["threat_flows"], item[1]["total_flows"]), reverse=True)
    return [
        {
            "ip": ip,
            "total_flows": stats["total_flows"],
            "threat_flows": stats["threat_flows"],
            "threat_rate": round((stats["threat_flows"] / stats["total_flows"] * 100.0), 1) if stats["total_flows"] > 0 else 0.0
        }
        for ip, stats in sorted_ips[:limit]
    ]

def calculate_protocol_breakdown(recent_detections: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calculates protocol distribution from recent traffic flows."""
    counts: Dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    for det in recent_detections:
        proto = str(det.get("Protocol", "Other")).upper()
        if "TCP" in proto:
            counts["TCP"] += 1
        elif "UDP" in proto:
            counts["UDP"] += 1
        elif "ICMP" in proto:
            counts["ICMP"] += 1
        else:
            counts["Other"] += 1
    return counts

def calculate_severity_distribution(recent_detections: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calculates severity counts across recent events."""
    counts: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for det in recent_detections:
        sev = str(det.get("Severity", "LOW")).upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["LOW"] += 1
    return counts


# ── REST API ENDPOINTS ───────────────────────────────────────────────

@app.get("/", summary="Root Health & API Info")
def root_info():
    """Returns basic API service metadata and documentation links."""
    return {
        "service": "NetShield-NIDS REST API",
        "version": "1.0.0",
        "status": "online",
        "docs_url": "/docs",
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "python": platform.python_version()
        }
    }


@app.get("/api/status", summary="Engine Status & System Info")
def get_status(response: Response):
    """
    Returns the real-time operational status of NetShield NIDS:
    - Running state (STOPPED, STARTING, RUNNING, STOPPING, ERROR)
    - Active network interface
    - Server and monitoring uptime
    - Machine learning model status
    """
    server_uptime = round(time.time() - service_manager.server_start_time, 1)
    monitor_uptime = 0.0
    if service_manager.monitor_start_time and service_manager.engine and service_manager.engine.state == "RUNNING":
        monitor_uptime = round(time.time() - service_manager.monitor_start_time, 1)

    engine_state = "UNINITIALIZED"
    interface_name = ""
    error_msg = service_manager.model_error

    if service_manager.engine:
        snap = service_manager.engine.get_snapshot()
        engine_state = snap.get("state", "STOPPED")
        interface_name = snap.get("interface", "")
        if snap.get("error"):
            error_msg = snap.get("error")

    # Health check condition: Model must be loaded and engine not in ERROR state
    healthy = service_manager.model_loaded and (engine_state != "ERROR")
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    sensor_active = False
    sensor_id = ""
    if service_manager.last_sensor_update_time:
        if (time.time() - service_manager.last_sensor_update_time) <= service_manager.sensor_timeout_seconds:
            sensor_active = True
            if service_manager.latest_sensor_data:
                sensor_id = service_manager.latest_sensor_data.get("sensor_id", "")

    return {
        "status": "ok" if healthy else "error",
        "health": "healthy" if healthy else "unhealthy",
        "monitoring_running": (engine_state == "RUNNING" or sensor_active),
        "state": "RUNNING" if sensor_active else engine_state,
        "interface": interface_name,
        "sensor_connected": sensor_active,
        "sensor_id": sensor_id,
        "server_uptime_seconds": server_uptime,
        "monitor_uptime_seconds": monitor_uptime,
        "model_loaded": service_manager.model_loaded,
        "model_name": service_manager.model_name,
        "error": error_msg,
        "system_info": {
            "os": platform.system(),
            "os_release": platform.release(),
            "machine": platform.machine(),
            "python_version": platform.python_version()
        }
    }


@app.get("/api/dashboard", summary="Comprehensive Dashboard Snapshot")
def get_dashboard():
    """
    Returns a unified dashboard snapshot containing all essential metrics:
    - Packet and flow counts
    - Classification breakdown (Normal, Threat, Review, Uncertain)
    - High-risk threat count
    - Attack category breakdown
    - Protocol breakdown
    - Recent detections & incidents
    - Top source IPs by threat activity
    """
    active = service_manager.get_active_telemetry()
    source = active.get("source")
    data = active.get("data", {})

    if source == "idle" or not data:
        return {
            "status": "idle",
            "state": "STOPPED",
            "message": "Monitoring engine not active and no sensor connected",
            "packets_captured": 0,
            "active_flows": 0,
            "completed_flows": 0,
            "classified_flows": 0,
            "normal_count": 0,
            "threat_count": 0,
            "review_count": 0,
            "uncertain_count": 0,
            "high_risk_threat_count": 0,
            "attack_rate": 0.0,
            "attack_breakdown": {},
            "protocol_breakdown": {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
            "recent_detections": [],
            "recent_incidents": [],
            "top_source_ips": []
        }

    return {
        "status": "ok",
        "state": data.get("state", "RUNNING" if source == "remote_sensor" else "STOPPED"),
        "interface": data.get("interface", ""),
        "sensor_id": data.get("sensor_id", "local"),
        "sensor_mode": (source == "remote_sensor"),
        "packets_captured": data.get("packets_captured", 0),
        "active_flows": data.get("active_flows", 0),
        "completed_flows": data.get("completed_flows", 0),
        "classified_flows": data.get("classified_flows", 0),
        "skipped_flows": data.get("skipped_flows", 0),
        "normal_count": data.get("normal_count", 0),
        "threat_count": data.get("threat_count", 0),
        "review_count": data.get("review_count", 0),
        "uncertain_count": data.get("uncertain_count", 0),
        "high_risk_threat_count": data.get("high_risk_threat_count", 0),
        "attack_rate": data.get("attack_rate", 0.0),
        "attack_breakdown": data.get("attack_breakdown", {}),
        "protocol_breakdown": data.get("protocol_breakdown", {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}),
        "recent_detections": data.get("recent_detections", [])[:20],
        "recent_incidents": data.get("recent_incidents", [])[:20],
        "top_source_ips": data.get("top_source_ips", [])
    }


@app.get("/api/traffic", summary="Traffic Time-Series Statistics")
def get_traffic(limit: int = Query(60, ge=5, le=300, description="Number of recent time-series points to return")):
    """
    Returns lightweight in-memory time-series statistics for frontend charting:
    - timestamp (HH:MM:SS & ISO)
    - packets & packets per second
    - bytes & bytes per second
    - active & completed flows
    - current rate summary
    """
    with service_manager._lock:
        history_list = list(service_manager.traffic_history)

    trimmed = history_list[-limit:] if len(history_list) > limit else history_list
    
    current_pps = trimmed[-1]["packets_per_sec"] if trimmed else 0.0
    current_bps = trimmed[-1]["bytes_per_sec"] if trimmed else 0.0
    total_pkts = trimmed[-1]["packets"] if trimmed else 0
    total_bytes = trimmed[-1]["bytes"] if trimmed else 0

    return {
        "status": "ok",
        "points_count": len(trimmed),
        "current_rate": {
            "packets_per_sec": current_pps,
            "bytes_per_sec": current_bps,
            "total_packets": total_pkts,
            "total_bytes": total_bytes
        },
        "time_series": trimmed
    }


@app.get("/api/threats", summary="Threat Analytics & Attack Breakdown")
def get_threats():
    """
    Returns threat analytics from active local engine or remote sensor.
    """
    active = service_manager.get_active_telemetry()
    data = active.get("data", {})
    if not data:
        return {
            "status": "ok",
            "total_threats": 0,
            "confirmed_threats": 0,
            "review_threats": 0,
            "uncertain_threats": 0,
            "threats_by_type": {},
            "severity_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "recent_threat_events": []
        }

    sanitized_detections = data.get("recent_detections", [])
    threat_events = [d for d in sanitized_detections if not d.get("Is_Benign", True)]
    sev_dist = calculate_severity_distribution(sanitized_detections)

    return {
        "status": "ok",
        "total_threats": data.get("threat_count", 0) + data.get("review_count", 0),
        "confirmed_threats": data.get("threat_count", 0),
        "review_threats": data.get("review_count", 0),
        "uncertain_threats": data.get("uncertain_count", 0),
        "threats_by_type": data.get("attack_breakdown", {}),
        "severity_distribution": sev_dist,
        "recent_threat_events": threat_events[:25]
    }


@app.get("/api/alerts", summary="Recent Incident Alerts")
def get_alerts(limit: int = Query(25, ge=1, le=100, description="Max number of alerts to return"), source: str = Query("db", description="'db' for persistent history, 'live' for in-memory only")):
    """
    Returns security incident alerts.
    - source=db (default): Queries persistent SQLite history (survives container restarts).
    - source=live: Returns in-memory recent incidents from the current sensor session.
    """
    # ── DB-backed persistent alerts (default) ──────────────────────────
    if source == "db":
        try:
            with get_db_session() as db:
                rows = db.query(Alert).order_by(Alert.timestamp.desc()).limit(limit).all()
                formatted = []
                for row in rows:
                    d = row.to_dict()
                    formatted.append({
                        "id": str(d.get("id", "NIDS-UNKNOWN")),
                        "timestamp": d.get("timestamp", ""),
                        "source_ip": d.get("source_ip", ""),
                        "destination_ip": d.get("destination_ip", ""),
                        "source_port": d.get("source_port", 0),
                        "destination_port": d.get("destination_port", 0),
                        "protocol": d.get("protocol", "TCP"),
                        "attack_type": d.get("attack_type", "Unknown"),
                        "confidence": d.get("confidence", "0.0%"),
                        "confidence_level": "HIGH",
                        "severity": d.get("severity", "HIGH"),
                        "operational_status": "THREAT",
                        "status": d.get("status", "New"),
                        "flow_duration_sec": 0.0,
                        "packets": 0,
                        "bytes": 0,
                        "explanation": d.get("explanation", "")
                    })
            return {"status": "ok", "total_alerts": len(formatted), "alerts": formatted}
        except Exception as e:
            logger.error(f"Failed to query alerts from DB: {e}", exc_info=True)
            return {"status": "error", "total_alerts": 0, "alerts": []}

    # ── Live in-memory fallback ────────────────────────────────────────
    active = service_manager.get_active_telemetry()
    data = active.get("data", {})
    if not data:
        return {"status": "ok", "total_alerts": 0, "alerts": []}

    sanitized_incidents = data.get("recent_incidents", [])
    formatted_alerts = []
    for inc in sanitized_incidents[:limit]:
        formatted_alerts.append({
            "id": inc.get("Incident ID", "NIDS-UNKNOWN"),
            "timestamp": inc.get("Timestamp", ""),
            "source_ip": inc.get("Source IP", ""),
            "destination_ip": inc.get("Destination IP", ""),
            "source_port": inc.get("Source Port", 0),
            "destination_port": inc.get("Destination Port", 0),
            "protocol": inc.get("Protocol", "TCP"),
            "attack_type": inc.get("Attack", "Unknown"),
            "confidence": inc.get("Confidence", "0.0%"),
            "confidence_level": inc.get("Confidence Level", "LOW"),
            "severity": inc.get("Severity", "HIGH"),
            "operational_status": inc.get("Operational Status", "THREAT"),
            "status": inc.get("Status", "New"),
            "flow_duration_sec": inc.get("Flow Duration", 0.0),
            "packets": inc.get("Packets", 0),
            "bytes": inc.get("Bytes", 0),
            "explanation": inc.get("Explanation", "")
        })
    return {"status": "ok", "total_alerts": len(formatted_alerts), "alerts": formatted_alerts}


@app.post("/api/sensor/heartbeat", summary="Receive Sensor Heartbeat")
def receive_sensor_heartbeat(payload: SensorHeartbeatPayload):
    """
    Accepts a lightweight heartbeat from a native sensor.
    Upserts the sensor record in SQLite and marks status as ONLINE.
    Sensors not seen within 15 seconds will be reported OFFLINE by GET /api/sensors.
    """
    now_dt = datetime.utcnow()
    try:
        with get_db_session() as db:
            sensor = db.query(Sensor).filter(Sensor.sensor_id == payload.sensor_id).first()
            if sensor is None:
                sensor = Sensor(
                    sensor_id=payload.sensor_id,
                    name=payload.name or payload.sensor_id,
                    hostname=payload.hostname,
                    platform=payload.platform,
                    version=payload.version,
                    first_seen=now_dt,
                    last_seen=now_dt,
                    status="ONLINE",
                    packets_captured=payload.packets_captured,
                    active_flows=payload.active_flows,
                    threat_count=payload.threat_count,
                )
                db.add(sensor)
                logger.info(f"New sensor registered: {payload.sensor_id}")
            else:
                sensor.last_seen = now_dt
                sensor.status = "ONLINE"
                sensor.packets_captured = payload.packets_captured
                sensor.active_flows = payload.active_flows
                sensor.threat_count = payload.threat_count
                if payload.name:
                    sensor.name = payload.name
                if payload.hostname:
                    sensor.hostname = payload.hostname
                if payload.platform:
                    sensor.platform = payload.platform
                if payload.version:
                    sensor.version = payload.version
    except Exception as e:
        logger.error(f"Heartbeat DB error for sensor '{payload.sensor_id}': {e}", exc_info=True)

    logger.debug(f"Heartbeat received from '{payload.sensor_id}'")
    return {"status": "ok", "message": f"Heartbeat recorded for {payload.sensor_id}"}


@app.get("/api/sensors", summary="List Registered Sensors")
def list_sensors():
    """
    Returns all registered sensors from SQLite, dynamically evaluating
    ONLINE vs OFFLINE status based on a 15-second heartbeat timeout.
    """
    TIMEOUT_SECONDS = service_manager.sensor_timeout_seconds
    now_dt = datetime.utcnow()
    results = []
    try:
        with get_db_session() as db:
            sensors = db.query(Sensor).order_by(Sensor.last_seen.desc()).all()
            for s in sensors:
                # Dynamically evaluate online status — DB 'status' may be stale after container restart
                if s.last_seen:
                    delta = (now_dt - s.last_seen).total_seconds()
                    computed_status = "ONLINE" if delta <= TIMEOUT_SECONDS else "OFFLINE"
                else:
                    computed_status = "OFFLINE"
                row = s.to_dict()
                row["status"] = computed_status
                results.append(row)
    except Exception as e:
        logger.error(f"Failed to query sensors: {e}", exc_info=True)

    return {
        "status": "ok",
        "count": len(results),
        "sensors": results
    }


@app.post("/api/sensor/data", summary="Receive Sensor Telemetry Data")
def receive_sensor_data(payload: SensorDataPayload):
    """
    Receives real-time intrusion monitoring telemetry from a NetShield native sensor.
    Updates the central in-memory state for web dashboards.
    Persists new alerts (with deduplication) and traffic snapshots to SQLite.
    """
    data_dict = payload.model_dump()
    now = time.time()
    now_dt = datetime.utcnow()

    with service_manager._lock:
        service_manager.latest_sensor_data = data_dict
        service_manager.last_sensor_update_time = now

        # Update time-series traffic point
        dt = max(0.1, now - service_manager._last_sample_time)
        delta_pkts = max(0, payload.packets_captured - service_manager._last_packet_count)
        pps = round(delta_pkts / dt, 2)

        service_manager._last_packet_count = payload.packets_captured
        service_manager._last_sample_time = now

        point = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "timestamp_iso": datetime.now().isoformat(),
            "timestamp_epoch": round(now, 3),
            "packets": payload.packets_captured,
            "packets_per_sec": pps,
            "bytes": 0,
            "bytes_per_sec": 0.0,
            "active_flows": payload.active_flows,
            "completed_flows": payload.completed_flows,
            "classified_flows": payload.classified_flows,
            "normal_count": payload.normal_count,
            "threat_count": payload.threat_count,
            "review_count": payload.review_count,
            "uncertain_count": payload.uncertain_count
        }
        service_manager.traffic_history.append(point)

    # ── Persist to SQLite ──────────────────────────────────────────────
    try:
        with get_db_session() as db:
            # 1. Persist traffic snapshot every call
            metric = TrafficMetric(
                sensor_id=payload.sensor_id,
                timestamp=now_dt,
                packets=payload.packets_captured,
                packets_per_sec=pps,
                active_flows=payload.active_flows,
                completed_flows=payload.completed_flows,
                classified_flows=payload.classified_flows,
                normal_count=payload.normal_count,
                threat_count=payload.threat_count,
                review_count=payload.review_count,
                uncertain_count=payload.uncertain_count,
            )
            db.add(metric)

            # 2. Persist new alert incidents (deduplicated by dedup_hash)
            for inc in payload.recent_incidents:
                # Build dedup key from: sensor + source_ip + dest_ip + attack_type + timestamp(minute)
                raw_key = f"{payload.sensor_id}|{inc.get('Source IP','?')}|{inc.get('Destination IP','?')}|{inc.get('Attack','?')}|{inc.get('Timestamp','?')[:16]}"
                dedup_hash = hashlib.sha256(raw_key.encode()).hexdigest()[:64]

                exists = db.query(Alert).filter(Alert.dedup_hash == dedup_hash).first()
                if not exists:
                    alert = Alert(
                        sensor_id=payload.sensor_id,
                        timestamp=now_dt,
                        source_ip=inc.get("Source IP") or inc.get("Source", ""),
                        destination_ip=inc.get("Destination IP") or inc.get("Destination", ""),
                        source_port=inc.get("Source Port", 0),
                        destination_port=inc.get("Destination Port", 0),
                        protocol=inc.get("Protocol", "TCP"),
                        attack_type=inc.get("Attack", "Unknown"),
                        confidence=inc.get("Confidence", "0.0%"),
                        severity=inc.get("Severity", "HIGH"),
                        status="New",
                        explanation=inc.get("Explanation", ""),
                        dedup_hash=dedup_hash,
                    )
                    db.add(alert)
    except Exception as e:
        logger.error(f"Database persistence error for sensor '{payload.sensor_id}': {e}", exc_info=True)

    logger.info(f"Received sensor telemetry from '{payload.sensor_id}' (Packets: {payload.packets_captured}, Flows: {payload.classified_flows})")
    return {"status": "ok", "message": f"Telemetry received from {payload.sensor_id}"}


@app.get("/api/interfaces", summary="List Available Network Adapters")
def list_interfaces():
    """
    Discovers available host network interfaces via Scapy.
    Prioritizes active physical adapters with assigned IP addresses (Wi-Fi, Ethernet).
    """
    iface_dict = get_available_network_interfaces()
    interface_list = []
    
    for idx, (display_name, iface_obj) in enumerate(iface_dict.items()):
        friendly = getattr(iface_obj, "name", str(iface_obj))
        desc = getattr(iface_obj, "description", "")
        ip = getattr(iface_obj, "ip", "") or ""
        
        interface_list.append({
            "id": str(iface_obj),
            "display_name": display_name,
            "name": friendly,
            "description": desc,
            "ip_address": ip,
            "is_default": (idx == 0)
        })

    return {
        "status": "ok",
        "count": len(interface_list),
        "interfaces": interface_list
    }


@app.post("/api/monitor/start", summary="Start Live Monitoring Engine")
def start_monitor(req: Optional[MonitorStartRequest] = None):
    """
    Starts real-time Scapy packet capture and flow classification on the selected adapter.
    If no interface is specified, automatically selects the highest-priority active adapter.
    """
    if not service_manager.model_loaded or not service_manager.engine:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot start monitoring: ML components not loaded. ({service_manager.model_error})"
        )

    if service_manager.engine.state == "RUNNING":
        return {
            "status": "already_running",
            "message": f"Monitoring is already running on adapter: {service_manager.engine.selected_iface_name}",
            "interface": service_manager.engine.selected_iface_name,
            "state": "RUNNING"
        }

    # Discover network interfaces
    ifaces = get_available_network_interfaces()
    if not ifaces:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No network interfaces could be detected on the host."
        )

    target_name = None
    target_obj = None

    # Interface selection logic
    req_iface = req.interface if req and req.interface else None
    if req_iface:
        for name, obj in ifaces.items():
            if req_iface.lower() in name.lower() or req_iface.lower() in str(obj).lower():
                target_name = name
                target_obj = obj
                break

    if target_obj is None:
        # Pick the top prioritized adapter (Wi-Fi / Ethernet with IP)
        target_name, target_obj = list(ifaces.items())[0]

    success = service_manager.engine.start_monitoring(iface_obj=target_obj, iface_name=target_name)
    if not success:
        err = service_manager.engine.error_message or "Failed to start Scapy capture worker"
        logger.error(f"Failed to start live monitoring on interface '{target_name}': {err}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start monitoring on '{target_name}': {err}"
        )

    service_manager.monitor_start_time = time.time()
    logger.info(f"Live NIDS monitoring started successfully on adapter '{target_name}'.")

    return {
        "status": "started",
        "message": f"Successfully started live NIDS monitoring on {target_name}",
        "interface": target_name,
        "state": "RUNNING"
    }


@app.get("/api/monitor/stop", summary="Stop Live Monitoring Engine (GET compatibility)")
@app.post("/api/monitor/stop", summary="Stop Live Monitoring Engine")
def stop_monitor():
    """
    Safely stops packet sniffing and background detection worker.
    Flushes remaining active flows.
    """
    if not service_manager.engine:
        return {"status": "stopped", "message": "Engine not active", "state": "STOPPED"}

    if service_manager.engine.state == "STOPPED":
        return {"status": "already_stopped", "message": "Monitoring is already stopped", "state": "STOPPED"}

    logger.info("Stopping live NIDS monitoring engine...")
    service_manager.engine.stop_monitoring()
    service_manager.monitor_start_time = None
    logger.info("Live NIDS monitoring stopped. Active flows flushed.")

    return {
        "status": "stopped",
        "message": "Live monitoring stopped cleanly. Active flows flushed.",
        "state": "STOPPED"
    }


@app.post("/api/monitor/reset", summary="Reset Session Metrics")
def reset_monitor():
    """
    Resets captured session counts, active/completed flows, and detection history.
    """
    if service_manager.engine:
        service_manager.engine.reset_session()
    with service_manager._lock:
        service_manager.traffic_history.clear()
        service_manager._last_packet_count = 0
        service_manager._last_bytes_count = 0

    return {
        "status": "reset",
        "message": "Session metrics and history reset successfully."
    }


# ─── Report Generation & Download Endpoints ─────────────────────────────────


class ReportGenerateRequest(BaseModel):
    format: str = Field("pdf", description="Report format: pdf, csv, or json")
    time_range: str = Field("24h", description="Time range: 24h, 7d, 30d, or custom")
    start_time: Optional[str] = Field(None, description="ISO 8601 start time (for custom range)")
    end_time: Optional[str] = Field(None, description="ISO 8601 end time (for custom range)")
    sensor_id: Optional[str] = Field(None, description="Filter by sensor ID (optional)")


def _parse_report_time(value: Optional[str], fallback: datetime) -> datetime:
    """Parse an ISO 8601 datetime string or return fallback."""
    if not value:
        return fallback
    try:
        if value.endswith("Z"):
            value = value.replace("Z", "+00:00")
        return datetime.fromisoformat(value)
    except Exception:
        return fallback


@app.get("/api/reports", summary="List Generated Reports")
def list_reports(limit: int = Query(25, ge=1, le=200)):
    """
    Returns metadata for all previously generated reports, newest first.
    """
    try:
        with get_db_session() as db:
            rows = db.query(Report).order_by(Report.generated_at.desc()).limit(limit).all()
            serialized = [r.to_dict() for r in rows]
        return {"status": "ok", "count": len(serialized), "reports": serialized}
    except Exception as e:
        logger.error(f"Failed to list reports: {e}", exc_info=True)
        return {"status": "error", "count": 0, "reports": [], "error": str(e)}


@app.get("/api/reports/{report_id}", summary="Get Report Detail")
def get_report_detail(report_id: str):
    """
    Returns full metadata for a single report including all stored fields.
    """
    try:
        with get_db_session() as db:
            record = db.query(Report).filter(Report.report_id == report_id).first()
            if not record:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found")
            return {"status": "ok", "report": record.to_dict()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get report '{report_id}': {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


@app.post("/api/reports/generate", summary="Generate a Security Investigation Report")
def generate_report(req: ReportGenerateRequest):
    """
    Generates a Security Investigation Report in the requested format (PDF/CSV/JSON)
    from real NetShield database records within the specified time window.

    The report is persisted to /app/data/reports/ and its metadata is stored in SQLite.
    """
    report_id = f"NIDS-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.utcnow()
    valid_formats = {"pdf", "csv", "json"}
    fmt = req.format.lower() if req.format.lower() in valid_formats else "pdf"
    valid_ranges = {"24h": 1, "7d": 7, "30d": 30}
    time_range = req.time_range.lower() if req.time_range.lower() in valid_ranges else "24h"

    end_time = _parse_report_time(req.end_time, now)
    if req.time_range in valid_ranges:
        start_time = end_time - timedelta(days=valid_ranges[req.time_range])
    else:
        start_time = _parse_report_time(req.start_time, end_time - timedelta(days=1))

    sensor_filter = req.sensor_id if req.sensor_id else None

    logger.info(f"Generating {fmt.upper()} report '{report_id}' from {start_time.isoformat()} to {end_time.isoformat()}")

    # Fetch real data from database
    try:
        data = fetch_report_data(start_time, end_time, sensor_filter)
    except Exception as e:
        logger.error(f"Failed to fetch report data: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Data fetch failed: {e}")

    data["report_id"] = report_id

    # Generate file
    ext = fmt
    filename = f"{report_id}.{ext}"
    file_path = os.path.join(REPORTS_DIR, filename)

    try:
        if fmt == "csv":
            size, sha = generate_csv_report(data, file_path)
        elif fmt == "json":
            size, sha = generate_json_report(data, file_path)
        else:
            data["sha256"] = ""  # filled after PDF write
            size, sha = generate_pdf_report(data, file_path)
            data["sha256"] = sha  # update for DB record
    except Exception as e:
        logger.error(f"Report file generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Report generation failed: {e}")

    # Persist metadata to SQLite
    try:
        with get_db_session() as db:
            report_record = Report(
                report_id=report_id,
                report_type="security_investigation",
                sensor_id=sensor_filter,
                start_time=start_time,
                end_time=end_time,
                generated_at=now,
                incident_count=data["summary"].get("total_incidents", 0),
                format=fmt,
                file_path=file_path,
                file_size_bytes=size,
                sha256=sha,
                status="GENERATED",
            )
            db.add(report_record)
        logger.info(f"Report '{report_id}' generated: {size:,} bytes, SHA256={sha[:16]}...")
    except Exception as e:
        logger.error(f"Failed to save report record to DB: {e}", exc_info=True)

    return {
        "status": "ok",
        "report_id": report_id,
        "format": fmt,
        "file_path": file_path,
        "file_size_bytes": size,
        "sha256": sha,
        "incident_count": data["summary"].get("total_incidents", 0),
        "message": f"{fmt.upper()} report generated successfully",
    }


@app.get("/api/reports/{report_id}/download", summary="Download a Report File")
def download_report(report_id: str, response: Response):
    """
    Downloads the report file for the given report_id.
    Uses path-safe lookup from the database (no user-supplied path).
    """
    try:
        with get_db_session() as db:
            record = db.query(Report).filter(Report.report_id == report_id).first()
            if record:
                # Capture all needed attributes while session is alive
                record_snapshot = {
                    "report_id": record.report_id,
                    "format": record.format,
                    "file_path": record.file_path,
                    "file_size_bytes": record.file_size_bytes,
                }
            else:
                record_snapshot = None
    except Exception as e:
        logger.error(f"DB lookup failed for report '{report_id}': {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error")

    if not record_snapshot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found")

    # Defensive: resolve real path only from DB record
    real_path = os.path.normpath(record_snapshot["file_path"])
    if not real_path.startswith(os.path.normpath(REPORTS_DIR)):
        logger.error(f"Path traversal attempt blocked: {real_path}")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    if not os.path.exists(real_path):
        logger.error(f"Report file not found on disk: {real_path}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found on server")

    content_type_map = {"pdf": "application/pdf", "csv": "text/csv", "json": "application/json"}
    media_type = content_type_map.get(record_snapshot["format"], "application/octet-stream")
    disposition = f"attachment; filename=\"{record_snapshot['report_id']}.{record_snapshot['format']}\""

    response.headers["Content-Disposition"] = disposition
    logger.info(f"Serving report download: {record_snapshot['report_id']}.{record_snapshot['format']} ({record_snapshot['file_size_bytes']:,} bytes)")

    return FileResponse(
        path=real_path,
        media_type=media_type,
        filename=f"{record_snapshot['report_id']}.{record_snapshot['format']}",
    )
