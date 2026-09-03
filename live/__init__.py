"""
NetShield-NIDS Live Pipeline Module
"""

from live.feature_extractor import (
    FEATURE_NAMES,
    NUM_FEATURES,
    FlowData,
    PacketRecord,
    extract_53_features,
    validate_feature_vector,
    convert_scapy_packet_to_record
)
from live.capture import (
    PacketCaptureWorker,
    get_available_network_interfaces
)
from live.flow_manager import FlowManager
from live.detector import (
    LiveDetector,
    get_severity_for_class,
    get_attack_explanation,
    get_confidence_category,
    get_operational_status,
    SEVERITY_MAPPING,
    ATTACK_EXPLANATIONS
)
from live.monitor import RealtimeMonitorEngine

__all__ = [
    "FEATURE_NAMES",
    "NUM_FEATURES",
    "FlowData",
    "PacketRecord",
    "extract_53_features",
    "validate_feature_vector",
    "convert_scapy_packet_to_record",
    "PacketCaptureWorker",
    "get_available_network_interfaces",
    "FlowManager",
    "LiveDetector",
    "get_severity_for_class",
    "get_attack_explanation",
    "get_confidence_category",
    "get_operational_status",
    "SEVERITY_MAPPING",
    "ATTACK_EXPLANATIONS",
    "RealtimeMonitorEngine"
]
