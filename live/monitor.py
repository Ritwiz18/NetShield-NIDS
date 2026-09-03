"""
==================================================
NetShield-NIDS — Real-Time Monitoring Engine
==================================================
live/monitor.py

Coordinates the end-to-end continuous monitoring pipeline:
PacketCaptureWorker -> FlowManager -> LiveDetector -> Metrics & Snapshot.
Thread-safe, bounded memory, and clean lifecycle management (START/STOP/RESTART).
"""

import time
import threading
from typing import Dict, List, Any, Optional

from live.capture import PacketCaptureWorker
from live.flow_manager import FlowManager
from live.detector import LiveDetector


class RealtimeMonitorEngine:
    """Continuous NIDS monitoring engine with robust lifecycle controls."""

    def __init__(self, model, scaler, encoder, active_timeout: float = 5.0, inactivity_timeout: float = 3.0):
        self.flow_manager = FlowManager(active_timeout_sec=active_timeout, inactivity_timeout_sec=inactivity_timeout)
        self.detector = LiveDetector(model, scaler, encoder)
        
        self.capture_worker: Optional[PacketCaptureWorker] = None
        self.state: str = "STOPPED"  # STOPPED, STARTING, RUNNING, STOPPING, ERROR
        self.selected_iface_name: str = ""
        self.error_message: Optional[str] = None
        
        self._lock = threading.Lock()
        self._monitor_loop_thread: Optional[threading.Thread] = None
        self._stop_loop_event = threading.Event()
        
        # Bounded session metrics & history
        self.packets_captured: int = 0
        self.active_flows_count: int = 0
        self.completed_flows_count: int = 0
        self.classified_flows_count: int = 0
        self.skipped_flows_count: int = 0
        self.normal_count: int = 0
        self.threat_count: int = 0
        self.review_count: int = 0
        self.uncertain_count: int = 0
        
        self.recent_detections: List[Dict[str, Any]] = []
        self.incidents_list: List[Dict[str, Any]] = []
        self.attack_breakdown: Dict[str, int] = {}
        
        self.max_detections_history: int = 100
        self.max_incidents_history: int = 100

    def start_monitoring(self, iface_obj: Any, iface_name: str) -> bool:
        """Starts real-time monitoring on the specified network adapter."""
        with self._lock:
            # If already running on the SAME interface and worker is healthy, no-op
            if self.state == "RUNNING" and self.selected_iface_name == iface_name:
                if self.capture_worker and self.capture_worker.is_running():
                    return True

        # Stop any active capture on previous adapter first
        self.stop_monitoring()

        with self._lock:
            self.state = "STARTING"
            self.selected_iface_name = iface_name
            self.error_message = None

        try:
            self.capture_worker = PacketCaptureWorker(
                iface_obj=iface_obj,
                packet_callback=self._on_packet_received
            )
            self.capture_worker.start()

            self._stop_loop_event.clear()
            self._monitor_loop_thread = threading.Thread(target=self._processing_loop, daemon=True)
            self._monitor_loop_thread.start()

            with self._lock:
                self.state = "RUNNING"
            return True
        except Exception as e:
            with self._lock:
                self.state = "ERROR"
                self.error_message = str(e)
            return False

    def stop_monitoring(self):
        """Stops the capture worker and background processing loop cleanly."""
        with self._lock:
            if self.state in ["STOPPED", "STOPPING"]:
                return
            self.state = "STOPPING"

        self._stop_loop_event.set()
        if self.capture_worker:
            self.capture_worker.stop()

        if self._monitor_loop_thread and self._monitor_loop_thread.is_alive():
            self._monitor_loop_thread.join(timeout=1.5)

        # Flush any remaining flows
        self._flush_and_classify_all()

        with self._lock:
            self.state = "STOPPED"


    def _on_packet_received(self, pkt):
        self.packets_captured += 1
        self.flow_manager.process_packet(pkt)

    def _processing_loop(self):
        """Background periodic flow expiry and detection worker."""
        while not self._stop_loop_event.is_set():
            time.sleep(0.5)
            self._flush_and_classify_all()

    def _flush_and_classify_all(self):
        # 1. Flush timed-out flows
        self.flow_manager.flush_expired_flows()
        # 2. Retrieve completed flows
        flows_to_classify = self.flow_manager.pop_completed_flows()

        for flow in flows_to_classify:
            det_record, inc_record, err = self.detector.classify_flow(flow)
            with self._lock:
                self.completed_flows_count += 1
                if err:
                    self.skipped_flows_count += 1
                elif det_record:
                    self.classified_flows_count += 1
                    op_status = det_record["Operational Status"]
                    if op_status == "NORMAL":
                        self.normal_count += 1
                    elif op_status == "THREAT":
                        self.threat_count += 1
                    elif op_status == "REVIEW":
                        self.review_count += 1
                    elif op_status == "UNCERTAIN":
                        self.uncertain_count += 1

                    pred_class = det_record["Prediction"]
                    if not det_record["Is_Benign"]:
                        self.attack_breakdown[pred_class] = self.attack_breakdown.get(pred_class, 0) + 1

                    self.recent_detections.insert(0, det_record)
                    if len(self.recent_detections) > self.max_detections_history:
                        self.recent_detections.pop()

                    if inc_record:
                        self.incidents_list.insert(0, inc_record)
                        if len(self.incidents_list) > self.max_incidents_history:
                            self.incidents_list.pop()

    def get_snapshot(self) -> Dict[str, Any]:
        """Thread-safe point-in-time snapshot for Streamlit dashboard rendering."""
        with self._lock:
            # Sync worker errors if any occurred in the capture thread
            if self.capture_worker and self.capture_worker.error_msg:
                self.error_message = self.capture_worker.error_msg
                self.state = "ERROR"
            elif self.capture_worker and not self.capture_worker.is_running() and self.state == "RUNNING":
                if self.capture_worker.error_msg:
                    self.error_message = self.capture_worker.error_msg
                    self.state = "ERROR"

            total_classified = self.classified_flows_count
            threats_total = self.threat_count + self.review_count
            attack_rate = (threats_total / total_classified * 100.0) if total_classified > 0 else 0.0

            return {
                "state": self.state,
                "interface": self.selected_iface_name,
                "error": self.error_message,
                "packets_captured": self.packets_captured,
                "active_flows": len(self.flow_manager.active_flows),
                "completed_flows": self.completed_flows_count,
                "classified_flows": self.classified_flows_count,
                "skipped_flows": self.skipped_flows_count,
                "normal_count": self.normal_count,
                "threat_count": self.threat_count,
                "review_count": self.review_count,
                "uncertain_count": self.uncertain_count,
                "attack_rate": attack_rate,
                "recent_detections": list(self.recent_detections),
                "incidents_list": list(self.incidents_list),
                "attack_breakdown": dict(self.attack_breakdown)
            }

    def reset_session(self):
        """Resets counters, flow manager, and detection history."""
        with self._lock:
            self.packets_captured = 0
            self.completed_flows_count = 0
            self.classified_flows_count = 0
            self.skipped_flows_count = 0
            self.normal_count = 0
            self.threat_count = 0
            self.review_count = 0
            self.uncertain_count = 0
            self.recent_detections.clear()
            self.incidents_list.clear()
            self.attack_breakdown.clear()
            self.flow_manager.reset()
