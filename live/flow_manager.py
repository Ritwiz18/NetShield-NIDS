"""
==================================================
NetShield-NIDS — Live Flow Manager
==================================================
live/flow_manager.py

Aggregates raw packet metadata into bidirectional network conversations (Flows).
Handles active timeout, FIN/RST completion, and bounded flow capacity.
"""

import time
import threading
from typing import Dict, List, Tuple, Optional
from live.feature_extractor import FlowData, PacketRecord, convert_scapy_packet_to_record


class FlowManager:
    """Thread-safe flow aggregation and lifecycle management."""
    
    def __init__(
        self,
        active_timeout_sec: float = 5.0,
        inactivity_timeout_sec: float = 3.0,
        max_active_flows: int = 500,
        max_completed_flows: int = 500
    ):
        self.active_timeout_sec = active_timeout_sec
        self.inactivity_timeout_sec = inactivity_timeout_sec
        self.max_active_flows = max_active_flows
        self.max_completed_flows = max_completed_flows

        self._lock = threading.Lock()
        # Active flows key -> FlowData
        self.active_flows: Dict[Tuple, FlowData] = {}
        # Mapping: (src, dst, sport, dport, proto) -> (canon_key, "fwd" or "bwd")
        self.flow_map: Dict[Tuple, Tuple[Tuple, str]] = {}
        # Completed flows ready for feature extraction & classification
        self.completed_flows: List[FlowData] = []
        self.total_flows_created = 0

    def process_packet(self, pkt):
        """Ingests a packet and maps to forward/backward flow record."""
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP
        except ImportError:
            return

        src_ip = None
        dst_ip = None
        ip_hdr_len = 20

        if IP in pkt:
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
            ip_hdr_len = getattr(pkt[IP], "ihl", 5) * 4
        elif IPv6 in pkt:
            src_ip = str(pkt[IPv6].src)
            dst_ip = str(pkt[IPv6].dst)
            ip_hdr_len = 40
        else:
            return

        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        pkt_len = len(pkt)

        src_port = 0
        dst_port = 0
        proto_str = "OTHER"
        tcp_flags = {}
        win_size = -1
        trans_hdr_len = 0
        is_fin_rst = False

        if TCP in pkt:
            proto_str = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            trans_hdr_len = getattr(pkt[TCP], "dataofs", 5) * 4
            win_size = int(pkt[TCP].window)
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
            if "F" in flags or "R" in flags:
                is_fin_rst = True
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

        cand = (src_ip, dst_ip, src_port, dst_port, proto_str)
        rev_cand = (dst_ip, src_ip, dst_port, src_port, proto_str)

        with self._lock:
            if cand in self.flow_map:
                canon_key, direction = self.flow_map[cand]
            else:
                # Bounded memory: if capacity exceeded, retire oldest
                if len(self.active_flows) >= self.max_active_flows:
                    oldest_key = min(self.active_flows.keys(), key=lambda k: self.active_flows[k].start_time)
                    self._complete_flow_internal(oldest_key)

                canon_key = cand
                self.flow_map[cand] = (canon_key, "fwd")
                self.flow_map[rev_cand] = (canon_key, "bwd")
                direction = "fwd"
                self.active_flows[canon_key] = FlowData(src_ip, dst_ip, src_port, dst_port, proto_str, ts)
                self.total_flows_created += 1

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
            self.active_flows[canon_key].add_packet(record)

            if is_fin_rst:
                self._complete_flow_internal(canon_key)

    def flush_expired_flows(self, current_time: Optional[float] = None) -> List[FlowData]:
        """Flushes flows that exceeded active or inactivity timeouts."""
        now = current_time if current_time is not None else time.time()
        flushed = []
        with self._lock:
            keys_to_flush = []
            for key, flow in self.active_flows.items():
                dur = now - flow.start_time
                idle = now - flow.last_time
                if dur >= self.active_timeout_sec or idle >= self.inactivity_timeout_sec:
                    keys_to_flush.append(key)

            for key in keys_to_flush:
                f = self._complete_flow_internal(key)
                if f:
                    flushed.append(f)
        return flushed

    def _complete_flow_internal(self, canon_key: Tuple) -> Optional[FlowData]:
        if canon_key in self.active_flows:
            completed_f = self.active_flows.pop(canon_key)
            # Remove from flow_map
            fwd_key = (completed_f.src_ip, completed_f.dst_ip, completed_f.src_port, completed_f.dst_port, completed_f.proto)
            rev_key = (completed_f.dst_ip, completed_f.src_ip, completed_f.dst_port, completed_f.src_port, completed_f.proto)
            self.flow_map.pop(fwd_key, None)
            self.flow_map.pop(rev_key, None)

            self.completed_flows.append(completed_f)
            if len(self.completed_flows) > self.max_completed_flows:
                self.completed_flows.pop(0)
            return completed_f
        return None

    def pop_completed_flows(self) -> List[FlowData]:
        with self._lock:
            flows = list(self.completed_flows)
            self.completed_flows.clear()
            return flows

    def reset(self):
        with self._lock:
            self.active_flows.clear()
            self.flow_map.clear()
            self.completed_flows.clear()
            self.total_flows_created = 0

