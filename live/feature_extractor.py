"""
==================================================
NetShield-NIDS — Live Flow Feature Extractor
==================================================
live/feature_extractor.py

Implements rigorous, authentic network flow statistical extraction
producing the exact 53 features required by the CICIDS2017 training schema.

CRITICAL SPECIFICATIONS:
- Maintains strict 53-feature naming and canonical training sequence.
- Precise units: microsecond (µs) resolution for Duration and IATs, Bytes for lengths.
- Flow directionality determined by initial packet initiation (Forward = Client -> Server).
- Zero hallucinated features: every metric is computed from packet headers/timestamps.
"""

import math
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd

# ─────────────────────────────────────────────────────────────
# EXACT 53 FEATURES IN STRICT CANONICAL ORDER
# ─────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "Destination Port",             # 0
    "Flow Duration",                # 1
    "Total Fwd Packets",            # 2
    "Total Length of Fwd Packets",  # 3
    "Fwd Packet Length Max",        # 4
    "Fwd Packet Length Min",        # 5
    "Fwd Packet Length Mean",       # 6
    "Bwd Packet Length Max",        # 7
    "Bwd Packet Length Min",        # 8
    "Bwd Packet Length Mean",       # 9
    "Bwd Packet Length Std",        # 10
    "Flow Bytes/s",                 # 11
    "Flow Packets/s",               # 12
    "Flow IAT Mean",                # 13
    "Flow IAT Std",                 # 14
    "Flow IAT Max",                 # 15
    "Flow IAT Min",                 # 16
    "Fwd IAT Mean",                 # 17
    "Fwd IAT Std",                  # 18
    "Fwd IAT Min",                  # 19
    "Bwd IAT Total",                # 20
    "Bwd IAT Mean",                 # 21
    "Bwd IAT Std",                  # 22
    "Bwd IAT Max",                  # 23
    "Bwd IAT Min",                  # 24
    "Fwd PSH Flags",                # 25
    "Fwd URG Flags",                # 26
    "Fwd Header Length",            # 27
    "Bwd Header Length",            # 28
    "Bwd Packets/s",                # 29
    "Min Packet Length",            # 30
    "Max Packet Length",            # 31
    "Packet Length Mean",           # 32
    "Packet Length Variance",       # 33
    "FIN Flag Count",               # 34
    "SYN Flag Count",               # 35
    "RST Flag Count",               # 36
    "PSH Flag Count",               # 37
    "ACK Flag Count",               # 38
    "URG Flag Count",               # 39
    "CWE Flag Count",               # 40
    "ECE Flag Count",               # 41
    "Down/Up Ratio",                # 42
    "Average Packet Size",          # 43
    "Init_Win_bytes_forward",       # 44
    "Init_Win_bytes_backward",      # 45
    "act_data_pkt_fwd",             # 46
    "min_seg_size_forward",         # 47
    "Active Mean",                  # 48
    "Active Std",                   # 49
    "Active Max",                   # 50
    "Active Min",                   # 51
    "Idle Std",                     # 52
]

NUM_FEATURES = len(FEATURE_NAMES)  # 53


class PacketRecord:
    """Lightweight representation of packet metadata without payload storage."""
    __slots__ = (
        "timestamp", "length", "direction",
        "header_length", "payload_length",
        "tcp_flags", "window_size", "tcp_header_len"
    )

    def __init__(
        self,
        timestamp: float,
        length: int,
        direction: str,  # 'fwd' or 'bwd'
        header_length: int = 0,
        payload_length: int = 0,
        tcp_flags: Optional[Dict[str, int]] = None,
        window_size: int = -1,
        tcp_header_len: int = 20
    ):
        self.timestamp = timestamp
        self.length = length
        self.direction = direction
        self.header_length = header_length
        self.payload_length = payload_length
        self.tcp_flags = tcp_flags or {}
        self.window_size = window_size
        self.tcp_header_len = tcp_header_len


class FlowData:
    """Maintains bidirectional packet streams for a single flow conversation."""
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, start_time: float):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.start_time = start_time
        self.last_time = start_time
        self.packets: List[PacketRecord] = []

    def add_packet(self, pkt: PacketRecord):
        self.packets.append(pkt)
        if pkt.timestamp > self.last_time:
            self.last_time = pkt.timestamp


def _calculate_stats(values: List[float]) -> Tuple[float, float, float, float, float]:
    """Calculates min, max, mean, std, and variance."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    arr = np.array(values, dtype=np.float64)
    min_v = float(np.min(arr))
    max_v = float(np.max(arr))
    mean_v = float(np.mean(arr))
    std_v = float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0
    var_v = float(np.var(arr, ddof=1)) if len(arr) > 1 else 0.0
    return min_v, max_v, mean_v, std_v, var_v


def _calculate_iats(timestamps: List[float]) -> List[float]:
    """Computes inter-arrival times in microseconds (µs)."""
    if len(timestamps) < 2:
        return []
    sorted_ts = sorted(timestamps)
    return [(sorted_ts[i] - sorted_ts[i - 1]) * 1_000_000.0 for i in range(1, len(sorted_ts))]


def _calculate_active_idle(timestamps: List[float], idle_threshold_sec: float = 5.0) -> Tuple[List[float], List[float]]:
    """
    Computes Active and Idle times in microseconds based on standard idle threshold.
    """
    if len(timestamps) < 2:
        return [0.0], [0.0]

    sorted_ts = sorted(timestamps)
    active_periods = []
    idle_periods = []

    cur_active_start = sorted_ts[0]
    last_pkt_time = sorted_ts[0]

    for t in sorted_ts[1:]:
        gap = t - last_pkt_time
        if gap > idle_threshold_sec:
            # End of an active sub-flow
            active_periods.append((last_pkt_time - cur_active_start) * 1_000_000.0)
            idle_periods.append(gap * 1_000_000.0)
            cur_active_start = t
        last_pkt_time = t

    active_periods.append((last_pkt_time - cur_active_start) * 1_000_000.0)

    return active_periods, (idle_periods if idle_periods else [0.0])


def extract_53_features(flow: FlowData) -> Dict[str, float]:
    """
    Extracts the canonical 53 network statistical features from a completed FlowData object.
    Returns a dictionary mapping each of the 53 feature names to its computed float value.
    """
    if not flow.packets:
        return {feat: 0.0 for feat in FEATURE_NAMES}

    fwd_pkts = [p for p in flow.packets if p.direction == "fwd"]
    bwd_pkts = [p for p in flow.packets if p.direction == "bwd"]

    # Basic Counts
    num_fwd = len(fwd_pkts)
    num_bwd = len(bwd_pkts)
    total_pkts = len(flow.packets)

    # Duration in microseconds (µs)
    dur_sec = max(0.0, flow.last_time - flow.start_time)
    flow_dur_us = dur_sec * 1_000_000.0

    # Destination Port
    dest_port = float(flow.dst_port)

    # Length statistics
    fwd_lengths = [float(p.length) for p in fwd_pkts]
    bwd_lengths = [float(p.length) for p in bwd_pkts]
    all_lengths = [float(p.length) for p in flow.packets]

    fwd_min, fwd_max, fwd_mean, fwd_std, fwd_var = _calculate_stats(fwd_lengths)
    bwd_min, bwd_max, bwd_mean, bwd_std, bwd_var = _calculate_stats(bwd_lengths)
    all_min, all_max, all_mean, all_std, all_var = _calculate_stats(all_lengths)

    total_fwd_len = sum(fwd_lengths)
    total_bwd_len = sum(bwd_lengths)
    total_bytes = total_fwd_len + total_bwd_len

    # Flow Rates (seconds denominator)
    safe_dur_sec = dur_sec if dur_sec > 0.0 else 0.000001
    flow_bytes_s = total_bytes / safe_dur_sec
    flow_pkts_s = total_pkts / safe_dur_sec
    bwd_pkts_s = num_bwd / safe_dur_sec

    # Inter-Arrival Times (IAT in µs)
    all_ts = [p.timestamp for p in flow.packets]
    fwd_ts = [p.timestamp for p in fwd_pkts]
    bwd_ts = [p.timestamp for p in bwd_pkts]

    all_iats = _calculate_iats(all_ts)
    fwd_iats = _calculate_iats(fwd_ts)
    bwd_iats = _calculate_iats(bwd_ts)

    flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std, _ = _calculate_stats(all_iats)
    fwd_iat_min, fwd_iat_max, fwd_iat_mean, fwd_iat_std, _ = _calculate_stats(fwd_iats)
    bwd_iat_min, bwd_iat_max, bwd_iat_mean, bwd_iat_std, _ = _calculate_stats(bwd_iats)
    bwd_iat_total = sum(bwd_iats)

    # TCP Flag Counts across whole flow
    fin_cnt = sum(p.tcp_flags.get("FIN", 0) for p in flow.packets)
    syn_cnt = sum(p.tcp_flags.get("SYN", 0) for p in flow.packets)
    rst_cnt = sum(p.tcp_flags.get("RST", 0) for p in flow.packets)
    psh_cnt = sum(p.tcp_flags.get("PSH", 0) for p in flow.packets)
    ack_cnt = sum(p.tcp_flags.get("ACK", 0) for p in flow.packets)
    urg_cnt = sum(p.tcp_flags.get("URG", 0) for p in flow.packets)
    cwe_cnt = sum(p.tcp_flags.get("CWE", 0) for p in flow.packets)
    ece_cnt = sum(p.tcp_flags.get("ECE", 0) for p in flow.packets)

    # Forward specific TCP flags
    fwd_psh = sum(p.tcp_flags.get("PSH", 0) for p in fwd_pkts)
    fwd_urg = sum(p.tcp_flags.get("URG", 0) for p in fwd_pkts)

    # Header Lengths
    fwd_hdr_len = sum(p.header_length for p in fwd_pkts)
    bwd_hdr_len = sum(p.header_length for p in bwd_pkts)

    # Segment / Window Parameters
    init_win_fwd = -1.0
    for p in fwd_pkts:
        if p.window_size >= 0:
            init_win_fwd = float(p.window_size)
            break

    init_win_bwd = -1.0
    for p in bwd_pkts:
        if p.window_size >= 0:
            init_win_bwd = float(p.window_size)
            break

    act_data_fwd = sum(1.0 for p in fwd_pkts if p.payload_length > 0)
    min_seg_fwd = min([p.tcp_header_len for p in fwd_pkts]) if fwd_pkts else 20.0

    # Ratios and Sizes
    down_up_ratio = float(num_bwd) / float(num_fwd) if num_fwd > 0 else 0.0
    avg_pkt_size = total_bytes / float(total_pkts) if total_pkts > 0 else 0.0

    # Active / Idle Statistics
    active_times, idle_times = _calculate_active_idle(all_ts)
    act_min, act_max, act_mean, act_std, _ = _calculate_stats(active_times)
    _, _, _, idle_std, _ = _calculate_stats(idle_times)

    # Assembling exact dictionary
    features = {
        "Destination Port": dest_port,
        "Flow Duration": flow_dur_us,
        "Total Fwd Packets": float(num_fwd),
        "Total Length of Fwd Packets": float(total_fwd_len),
        "Fwd Packet Length Max": fwd_max,
        "Fwd Packet Length Min": fwd_min,
        "Fwd Packet Length Mean": fwd_mean,
        "Bwd Packet Length Max": bwd_max,
        "Bwd Packet Length Min": bwd_min,
        "Bwd Packet Length Mean": bwd_mean,
        "Bwd Packet Length Std": bwd_std,
        "Flow Bytes/s": flow_bytes_s,
        "Flow Packets/s": flow_pkts_s,
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Flow IAT Min": flow_iat_min,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": bwd_iat_total,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": float(fwd_psh),
        "Fwd URG Flags": float(fwd_urg),
        "Fwd Header Length": float(fwd_hdr_len),
        "Bwd Header Length": float(bwd_hdr_len),
        "Bwd Packets/s": bwd_pkts_s,
        "Min Packet Length": all_min,
        "Max Packet Length": all_max,
        "Packet Length Mean": all_mean,
        "Packet Length Variance": all_var,
        "FIN Flag Count": float(fin_cnt),
        "SYN Flag Count": float(syn_cnt),
        "RST Flag Count": float(rst_cnt),
        "PSH Flag Count": float(psh_cnt),
        "ACK Flag Count": float(ack_cnt),
        "URG Flag Count": float(urg_cnt),
        "CWE Flag Count": float(cwe_cnt),
        "ECE Flag Count": float(ece_cnt),
        "Down/Up Ratio": down_up_ratio,
        "Average Packet Size": avg_pkt_size,
        "Init_Win_bytes_forward": init_win_fwd,
        "Init_Win_bytes_backward": init_win_bwd,
        "act_data_pkt_fwd": float(act_data_fwd),
        "min_seg_size_forward": float(min_seg_fwd),
        "Active Mean": act_mean,
        "Active Std": act_std,
        "Active Max": act_max,
        "Active Min": act_min,
        "Idle Std": idle_std,
    }

    return features


def validate_feature_vector(feature_dict: Dict[str, float]) -> Tuple[bool, List[str], List[float]]:
    """
    Validates that a feature dictionary satisfies exact 53-feature requirements.
    Returns: (is_valid, error_list, ordered_values)
    """
    errors = []
    ordered_values = []

    for idx, name in enumerate(FEATURE_NAMES):
        if name not in feature_dict:
            errors.append(f"Missing feature #{idx}: '{name}'")
            continue
        val = feature_dict[name]
        if not isinstance(val, (int, float, np.number)):
            errors.append(f"Feature '{name}' has non-numeric type: {type(val)}")
            continue
        if math.isnan(val):
            errors.append(f"Feature '{name}' has NaN value")
            continue
        if math.isinf(val):
            errors.append(f"Feature '{name}' has Infinite (Inf) value")
            continue
        ordered_values.append(float(val))

    if len(ordered_values) != NUM_FEATURES:
        errors.append(f"Expected {NUM_FEATURES} features, got {len(ordered_values)}")

    is_valid = len(errors) == 0
    return is_valid, errors, ordered_values


def convert_scapy_packet_to_record(pkt, forward_tuple: Tuple[str, str, int, int, str]) -> Tuple[Optional[PacketRecord], Optional[Tuple]]:
    """
    Parses a raw Scapy packet into a PacketRecord, determining forward or backward direction.
    """
    try:
        from scapy.all import IP, TCP, UDP, ICMP
    except ImportError:
        return None, None

    if IP not in pkt:
        return None, None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto_num = pkt[IP].proto
    ts = pkt.time if hasattr(pkt, "time") else 0.0
    pkt_len = len(pkt)

    ip_hdr_len = getattr(pkt[IP], "ihl", 5) * 4

    src_port = 0
    dst_port = 0
    proto_str = "OTHER"
    tcp_flags = {}
    win_size = -1
    trans_hdr_len = 0

    if TCP in pkt:
        proto_str = "TCP"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        trans_hdr_len = getattr(pkt[TCP], "dataofs", 5) * 4
        win_size = int(pkt[TCP].window)
        # Parse TCP flags
        flags = pkt[TCP].flags
        tcp_flags = {
            "FIN": 1 if "F" in flags else 0,
            "SYN": 1 if "S" in flags else 0,
            "RST": 1 if "R" in flags else 0,
            "PSH": 1 if "P" in flags else 0,
            "ACK": 1 if "A" in flags else 0,
            "URG": 1 if "U" in flags else 0,
            "ECE": 1 if "E" in flags else 0,
            "CWE": 1 if "C" in flags else 0,
        }
    elif UDP in pkt:
        proto_str = "UDP"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
        trans_hdr_len = 8
    elif ICMP in pkt:
        proto_str = "ICMP"
        trans_hdr_len = 8

    total_hdr_len = ip_hdr_len + trans_hdr_len
    payload_len = max(0, pkt_len - total_hdr_len)

    # Direction matching
    fwd_src_ip, fwd_dst_ip, fwd_src_port, fwd_dst_port, fwd_proto = forward_tuple
    if (src_ip == fwd_src_ip and dst_ip == fwd_dst_ip and 
        src_port == fwd_src_port and dst_port == fwd_dst_port and proto_str == fwd_proto):
        direction = "fwd"
    else:
        direction = "bwd"

    record = PacketRecord(
        timestamp=ts,
        length=pkt_len,
        direction=direction,
        header_length=total_hdr_len,
        payload_length=payload_len,
        tcp_flags=tcp_flags,
        window_size=win_size,
        tcp_header_len=trans_hdr_len
    )

    conv_key = (src_ip, dst_ip, src_port, dst_port, proto_str)
    return record, conv_key
