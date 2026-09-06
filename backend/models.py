"""
==================================================
NetShield-NIDS — Database Models
==================================================
backend/models.py

SQLAlchemy ORM models for sensors, security incident alerts, and summarized
traffic metrics.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, BigInteger, Float, String, Text, DateTime
from backend.database import Base


class Sensor(Base):
    """Stores sensor metadata, registration, heartbeat state, and current counters."""
    __tablename__ = "sensors"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    sensor_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(128), nullable=True)
    hostname = Column(String(128), nullable=True)
    platform = Column(String(128), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(32), default="ONLINE")
    packets_captured = Column(BigInteger, default=0)
    active_flows = Column(Integer, default=0)
    threat_count = Column(Integer, default=0)
    version = Column(String(32), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "sensor_id": self.sensor_id,
            "name": self.name or self.sensor_id,
            "hostname": self.hostname or "",
            "platform": self.platform or "",
            "first_seen": self.first_seen.isoformat() if self.first_seen else "",
            "last_seen": self.last_seen.isoformat() if self.last_seen else "",
            "status": self.status,
            "packets_captured": self.packets_captured or 0,
            "active_flows": self.active_flows or 0,
            "threat_count": self.threat_count or 0,
            "version": self.version or "1.0.0"
        }


class Alert(Base):
    """Stores persistent security incident alerts with deduplication support."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    sensor_id = Column(String(64), index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source_ip = Column(String(64), nullable=True)
    destination_ip = Column(String(64), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    attack_type = Column(String(64), nullable=True)
    confidence = Column(String(32), nullable=True)
    severity = Column(String(32), nullable=True)
    status = Column(String(32), default="New")
    explanation = Column(Text, nullable=True)
    dedup_hash = Column(String(64), unique=True, index=True, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "sensor_id": self.sensor_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else "",
            "source_ip": self.source_ip or "0.0.0.0",
            "destination_ip": self.destination_ip or "0.0.0.0",
            "source_port": self.source_port or 0,
            "destination_port": self.destination_port or 0,
            "protocol": self.protocol or "TCP",
            "attack_type": self.attack_type or "Unknown",
            "confidence": self.confidence or "0.0%",
            "severity": self.severity or "HIGH",
            "status": self.status or "New",
            "explanation": self.explanation or ""
        }


class Report(Base):
    """Stores metadata for generated security investigation reports (PDF/CSV/JSON)."""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    report_id = Column(String(64), unique=True, index=True, nullable=False)
    report_type = Column(String(32), nullable=False)  # e.g. "security_investigation"
    sensor_id = Column(String(64), index=True, nullable=True)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow, index=True)
    incident_count = Column(Integer, default=0)
    format = Column(String(16), nullable=False)  # "pdf", "csv", "json"
    file_path = Column(String(512), nullable=False)
    file_size_bytes = Column(BigInteger, default=0)
    sha256 = Column(String(64), nullable=True)
    status = Column(String(32), default="GENERATED")  # GENERATED, FAILED

    def to_dict(self):
        return {
            "id": self.id,
            "report_id": self.report_id,
            "report_type": self.report_type,
            "sensor_id": self.sensor_id or "all",
            "start_time": self.start_time.isoformat() if self.start_time else "",
            "end_time": self.end_time.isoformat() if self.end_time else "",
            "generated_at": self.generated_at.isoformat() if self.generated_at else "",
            "incident_count": self.incident_count or 0,
            "format": self.format,
            "file_path": self.file_path,
            "file_size_bytes": self.file_size_bytes or 0,
            "sha256": self.sha256 or "",
            "status": self.status or "GENERATED"
        }


class TrafficMetric(Base):
    """Stores summarized time-series traffic flow statistics for historical reporting."""
    __tablename__ = "traffic_metrics"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    sensor_id = Column(String(64), index=True, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    packets = Column(BigInteger, default=0)
    packets_per_sec = Column(Float, default=0.0)
    active_flows = Column(Integer, default=0)
    completed_flows = Column(Integer, default=0)
    classified_flows = Column(Integer, default=0)
    normal_count = Column(Integer, default=0)
    threat_count = Column(Integer, default=0)
    review_count = Column(Integer, default=0)
    uncertain_count = Column(Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "sensor_id": self.sensor_id or "local",
            "timestamp": self.timestamp.strftime("%H:%M:%S") if self.timestamp else "",
            "timestamp_iso": self.timestamp.isoformat() if self.timestamp else "",
            "packets": self.packets or 0,
            "packets_per_sec": self.packets_per_sec or 0.0,
            "active_flows": self.active_flows or 0,
            "completed_flows": self.completed_flows or 0,
            "classified_flows": self.classified_flows or 0,
            "normal_count": self.normal_count or 0,
            "threat_count": self.threat_count or 0,
            "review_count": self.review_count or 0,
            "uncertain_count": self.uncertain_count or 0
        }
