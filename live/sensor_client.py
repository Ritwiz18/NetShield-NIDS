"""
==================================================
NetShield-NIDS — Sensor Client
==================================================
live/sensor_client.py

Runs alongside the native NetShield RealtimeMonitorEngine on the host machine.
Periodically extracts summarized snapshot metrics, threat detections, and
flow statistics, posting them to the FastAPI server via HTTP/JSON.

Architecture:
Scapy (Host Network) -> FlowManager -> 53-Feature Extractor -> ML Detector
                    -> RealtimeMonitorEngine -> NetShieldSensorClient
                    -> HTTP POST /api/sensor/data -> FastAPI -> React Dashboard
"""

import os
import sys
import time
import socket
import logging
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime

import requests

# Ensure Project Root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from live.capture import get_available_network_interfaces
from live.monitor import RealtimeMonitorEngine
from live.detector import (
    get_severity_for_class,
    get_attack_explanation,
    get_confidence_category,
    get_operational_status
)

logger = logging.getLogger("netshield.sensor")


# ── Serialization Helper Utilities ───────────────────────────────────
def sanitize_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures dictionary records are JSON-serializable."""
    clean = {}
    for k, v in rec.items():
        if k in ["Proba_DF", "Scaled_Features", "Raw_Features"]:
            continue
        elif hasattr(v, "item"):  # numpy scalars
            clean[k] = v.item()
        elif isinstance(v, (float, int, bool, str)):
            clean[k] = v
        else:
            clean[k] = str(v)
    return clean


def calculate_top_source_ips(recent_detections: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    """Calculates top source IP threat statistics."""
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
    """Calculates protocol distribution."""
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


class NetShieldSensorClient:
    """
    Periodically pulls snapshot telemetry from local RealtimeMonitorEngine
    and transmits it via HTTP POST to the central FastAPI REST server.
    """

    def __init__(
        self,
        engine: RealtimeMonitorEngine,
        api_url: Optional[str] = None,
        sensor_id: Optional[str] = None,
        interval_seconds: float = 2.5
    ):
        self.engine = engine
        self.api_url = (api_url or os.getenv("NETSHIELD_API_URL", "http://localhost:8000")).rstrip("/")
        self.sensor_id = sensor_id or os.getenv("NETSHIELD_SENSOR_ID", f"sensor-{socket.gethostname()}")
        self.interval_seconds = max(1.0, interval_seconds)

        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self.is_connected: bool = False
        self.last_sync_time: Optional[float] = None
        self.sync_count: int = 0
        self.last_error: Optional[str] = None

    def start(self):
        """Starts background sensor telemetry reporter thread."""
        if self._worker_thread and self._worker_thread.is_alive():
            return

        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._telemetry_loop, daemon=True)
        self._worker_thread.start()
        logger.info(f"SensorClient [{self.sensor_id}] started. Target API: {self.api_url}/api/sensor/data")

    def stop(self):
        """Stops background reporter thread."""
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info(f"SensorClient [{self.sensor_id}] stopped.")

    def _telemetry_loop(self):
        """Periodic telemetry sync loop."""
        endpoint = f"{self.api_url}/api/sensor/data"

        while not self._stop_event.is_set():
            try:
                self.send_telemetry(endpoint)
            except Exception as e:
                self.is_connected = False
                self.last_error = str(e)
                logger.warning(f"Failed to post sensor telemetry to {endpoint}: {e}. Retrying in {self.interval_seconds}s...")

            time.sleep(self.interval_seconds)

    def send_telemetry(self, endpoint: str):
        """Extracts engine snapshot, formats payload, and posts to FastAPI endpoint."""
        snap = self.engine.get_snapshot()

        sanitized_detections = [sanitize_record(d) for d in snap.get("recent_detections", [])]
        sanitized_incidents = [sanitize_record(inc) for inc in snap.get("incidents_list", [])]
        
        high_risk_count = sum(
            1 for d in sanitized_detections
            if d.get("Severity") in ["HIGH", "CRITICAL"] and not d.get("Is_Benign", True)
        )
        protocol_dist = calculate_protocol_breakdown(sanitized_detections)
        top_ips = calculate_top_source_ips(sanitized_detections, limit=5)

        payload = {
            "sensor_id": self.sensor_id,
            "timestamp": datetime.now().isoformat(),
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
            "recent_detections": sanitized_detections[:20],
            "recent_incidents": sanitized_incidents[:20],
            "top_source_ips": top_ips
        }

        resp = requests.post(endpoint, json=payload, timeout=4.0)
        if resp.status_code == 200:
            self.is_connected = True
            self.last_sync_time = time.time()
            self.sync_count += 1
            self.last_error = None
        else:
            self.is_connected = False
            self.last_error = f"HTTP {resp.status_code}: {resp.text}"
            logger.warning(f"Sensor POST returned status {resp.status_code}: {resp.text}")


# ── Standalone Native Windows Sensor Launcher ─────────────────────────
def main():
    import joblib

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [netshield.sensor] %(message)s"
    )

    print("=" * 65)
    print("NETSHIELD-NIDS NATIVE SENSOR LAUNCHER")
    print("=" * 65)

    ET_MODEL_PATH = os.path.join(PROJECT_ROOT, "extra_trees_model.pkl")
    RF_MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "random_forest_model.pkl")
    SCALER_PATH = os.path.join(PROJECT_ROOT, "models", "scaler.pkl")
    ENCODER_PATH = os.path.join(PROJECT_ROOT, "models", "label_encoder.pkl")

    model_path = ET_MODEL_PATH if os.path.exists(ET_MODEL_PATH) else RF_MODEL_PATH
    if not os.path.exists(model_path):
        print(f"[ERROR] ML Model missing at {model_path}")
        sys.exit(1)

    print(f"[*] Loading ML artifacts from {model_path}...")
    model = joblib.load(model_path)
    scaler = joblib.load(SCALER_PATH)
    encoder = joblib.load(ENCODER_PATH)
    print(f"[+] Loaded model: {type(model).__name__}")

    # Discover network interface
    ifaces = get_available_network_interfaces()
    if not ifaces:
        print("[ERROR] No network interfaces found.")
        sys.exit(1)

    target_name, target_obj = list(ifaces.items())[0]
    print(f"[*] Selected network adapter: {target_name}")

    # Initialize Engine & Start Packet Capture
    engine = RealtimeMonitorEngine(model, scaler, encoder)
    started = engine.start_monitoring(iface_obj=target_obj, iface_name=target_name)
    if not started:
        print(f"[ERROR] Failed to start packet capture on {target_name}: {engine.error_message}")
        sys.exit(1)

    print(f"[+] Scapy packet capture running on {target_name}!")

    # Start Sensor Client
    api_url = os.getenv("NETSHIELD_API_URL", "http://localhost:8000")
    sensor_id = os.getenv("NETSHIELD_SENSOR_ID", f"win-{socket.gethostname()}")

    client = NetShieldSensorClient(engine=engine, api_url=api_url, sensor_id=sensor_id)
    client.start()

    print(f"[+] Sensor telemetry transmitting to {api_url}/api/sensor/data every 2.5 seconds.")
    print("[*] Press Ctrl+C to stop sensor.\n")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Stopping NetShield Sensor...")
        client.stop()
        engine.stop_monitoring()
        print("[+] Sensor cleanly stopped.")


if __name__ == "__main__":
    main()
