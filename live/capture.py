"""
==================================================
NetShield-NIDS — Live Packet Capture Engine
==================================================
live/capture.py

Thread-safe, bounded packet sniffer using Scapy + Npcap.
Privacy Guarantee: Zero raw packet payload content is captured or retained.
"""

import threading
import time
from typing import Callable, Optional, Dict, Any

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, IFACES, get_if_list
except ImportError:
    pass


def get_available_network_interfaces() -> Dict[str, Any]:
    """
    Detects available network interface adapters on the host.
    Prioritizes active physical adapters with assigned IP addresses (Wi-Fi, Ethernet).
    """
    try:
        from scapy.all import IFACES, get_if_list
        raw_items = []
        for key, iface in IFACES.data.items():
            friendly = getattr(iface, "name", None) or str(iface)
            desc = getattr(iface, "description", "")
            ip = getattr(iface, "ip", "") or ""
            display_name = f"{friendly} ({desc})" if desc and desc != friendly else friendly
            
            # Prioritization score: higher is better
            score = 0
            if ip and not ip.startswith("169.254.") and ip != "127.0.0.1":
                score += 100
                display_name += f" [{ip}]"
            elif ip == "127.0.0.1":
                score += 10
            
            lower_name = friendly.lower() + " " + desc.lower()
            if "wi-fi" in lower_name or "wifi" in lower_name or "wireless" in lower_name:
                score += 50
            elif "ethernet" in lower_name and "virtual" not in lower_name:
                score += 40
            if "miniport" in lower_name:
                score -= 30

            raw_items.append((score, display_name, iface))

        # Sort descending by score
        raw_items.sort(key=lambda x: x[0], reverse=True)

        iface_dict = {name: iface for _, name, iface in raw_items}

        if not iface_dict:
            for if_name in get_if_list():
                iface_dict[str(if_name)] = if_name

        return iface_dict
    except Exception:
        return {}


class PacketCaptureWorker:
    """Threaded packet sniffer with clean start, stop, and packet metadata callback."""
    
    def __init__(self, iface_obj: Any, packet_callback: Callable[[Any], None], max_packets: int = 10000):
        self.iface_obj = iface_obj
        self.packet_callback = packet_callback
        self.max_packets = max_packets
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.packet_count = 0
        self.error_msg: Optional[str] = None

    def start(self):
        self._stop_event.clear()
        self.packet_count = 0
        self.error_msg = None
        self._thread = threading.Thread(target=self._run_sniff, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    def _run_sniff(self):
        try:
            def _pkt_handler(pkt):
                self.packet_count += 1
                try:
                    self.packet_callback(pkt)
                except Exception:
                    pass
                # Must return None so Scapy does not print callback return value to console
                return None

            sniff(
                iface=self.iface_obj,
                prn=_pkt_handler,
                stop_filter=lambda p: self._stop_event.is_set() or self.packet_count >= self.max_packets,
                store=False
            )
        except Exception as e:
            self.error_msg = str(e)

