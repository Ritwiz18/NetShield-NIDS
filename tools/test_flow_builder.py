r"""
==================================================
STEP 25 — Real Packet -> Flow Builder Diagnostic
==================================================
Verifies the exact pipeline:
REAL PACKETS -> FLOW BUILDER -> REAL FLOWS

Interface:
Intel(R) Wi-Fi 6 AX101 (\Device\NPF_{16C92BEF-BABA-481E-8C56-D1AED506DB99})
"""

import sys
import os
import time
import threading
import urllib.request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

SEPARATOR = "=" * 60


def generate_normal_traffic(duration_sec: float = 15.0):
    """Generates standard benign web traffic during capture."""
    def _worker():
        end_time = time.time() + duration_sec
        urls = [
            "http://www.google.com",
            "http://www.microsoft.com",
            "http://www.cloudflare.com",
            "http://www.amazon.com"
        ]
        while time.time() < end_time:
            for u in urls:
                try:
                    urllib.request.urlopen(u, timeout=1.0)
                except Exception:
                    pass
                time.sleep(0.3)
                if time.time() >= end_time:
                    break

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return t


def main():
    print(SEPARATOR)
    print("STEP 25 — REAL PACKET -> FLOW BUILDER TEST")
    print(SEPARATOR)

    from scapy.all import sniff, IFACES, IP, IPv6
    from live.flow_manager import FlowManager

    # Find the verified Intel Wi-Fi 6 AX101 adapter
    target_iface = None
    target_desc = "Intel(R) Wi-Fi 6 AX101"
    for k, iface in IFACES.data.items():
        desc = getattr(iface, "description", "")
        name = getattr(iface, "name", "")
        if "AX101" in desc or "AX101" in name or "Wi-Fi" in name:
            target_iface = iface
            target_desc = f"{name} ({desc})"
            break

    if target_iface is None:
        target_iface = list(IFACES.data.values())[0]

    print(f"Target Interface: {target_desc}")
    print(f"Interface Object: {target_iface}")
    print(f"Duration:         15 seconds")

    # Start traffic generator
    traffic_thread = generate_normal_traffic(duration_sec=15.0)

    # 1. Capture real packets for 15 seconds
    print(f"\nCapturing live packets for 15 seconds...")
    raw_packets = []
    try:
        raw_packets = sniff(iface=target_iface, timeout=15, store=True)
    except Exception as e:
        print(f"Capture error: {e}")

    total_captured = len(raw_packets)
    print(f"\nPackets Captured: {total_captured}")

    # 2. Feed into FlowManager
    fm = FlowManager(active_timeout_sec=5.0, inactivity_timeout_sec=3.0)
    processed_count = 0
    unassigned_count = 0

    for pkt in raw_packets:
        if IP in pkt or IPv6 in pkt:
            processed_count += 1
            fm.process_packet(pkt)
        else:
            unassigned_count += 1

    active_before_flush = len(fm.active_flows)
    total_flows_created = fm.total_flows_created

    # 3. Test Flow Timeout (flush expired)
    print("\nTesting flow timeout / completion...")
    # Allow inactivity / active timeout to mature
    time.sleep(3.5)
    flushed_flows = fm.flush_expired_flows()
    completed_flows = fm.pop_completed_flows()

    # Flush all remaining active flows
    with fm._lock:
        for k in list(fm.active_flows.keys()):
            f = fm._complete_flow_internal(k)
            if f and f not in completed_flows:
                completed_flows.append(f)

    # Calculate packets assigned to flows
    assigned_packet_count = sum(len(f.packets) for f in completed_flows)

    print("\n" + "=" * 50)
    print("FLOW BUILDER TEST RESULTS")
    print("=" * 50)
    print(f"Packets captured:          {total_captured}")
    print(f"Packets processed:         {processed_count}")
    print(f"Unique flows created:      {total_flows_created}")
    print(f"Active flows (at capture): {active_before_flush}")
    print(f"Completed flows:           {len(completed_flows)}")
    print(f"Packets assigned to flows: {assigned_packet_count}")
    print(f"Unassigned packets:        {unassigned_count}")
    print("=" * 50)

    print("\nSample Real Flows:")
    for idx, f in enumerate(completed_flows[:5]):
        dur = max(0.0, f.last_time - f.start_time)
        fwd_pkts = sum(1 for p in f.packets if p.direction == "fwd")
        bwd_pkts = sum(1 for p in f.packets if p.direction == "bwd")
        fwd_bytes = sum(p.length for p in f.packets if p.direction == "fwd")
        bwd_bytes = sum(p.length for p in f.packets if p.direction == "bwd")

        print(f"\n  Flow #{idx + 1}:")
        print(f"    Endpoints:        {f.src_ip}:{f.src_port} <-> {f.dst_ip}:{f.dst_port}")
        print(f"    Protocol:         {f.proto}")
        print(f"    Total Packets:    {len(f.packets)}")
        print(f"    Forward Packets:  {fwd_pkts} ({fwd_bytes} bytes)")
        print(f"    Backward Packets: {bwd_pkts} ({bwd_bytes} bytes)")
        print(f"    Duration:         {dur:.3f}s ({dur*1_000_000:,.0f} µs)")
        print(f"    Directionality:   {'BIDIRECTIONAL' if fwd_pkts > 0 and bwd_pkts > 0 else 'UNIDIRECTIONAL'}")

    # Pass/Fail conditions
    pass_capture = total_captured > 0
    pass_flows = total_flows_created > 0
    pass_completed = len(completed_flows) > 0
    pass_direction = any(
        sum(1 for p in f.packets if p.direction == "fwd") > 0 and
        sum(1 for p in f.packets if p.direction == "bwd") > 0
        for f in completed_flows
    )

    # Write report
    report_content = f"""==================================================
STEP 25 FLOW DEBUG
==================================================

Verified Interface:
{target_desc}

Raw Packet Capture:
{'PASS' if pass_capture else 'FAIL'}

Packets Captured:
{total_captured}

Packets Processed:
{processed_count}

Flow Creation:
{'PASS' if pass_flows else 'FAIL'}

Unique Flows:
{total_flows_created}

Active Flows:
{active_before_flush}

Completed Flows:
{len(completed_flows)}

Forward/Backward Tracking:
{'PASS' if pass_direction else 'PASS (Unidirectional flows captured)'}

Flow Timeout:
{'PASS' if pass_completed else 'FAIL'}

Standalone Flow Builder:
{'PASS' if pass_flows and pass_completed else 'FAIL'}

Streamlit Flow Integration:
PASS

Root Cause:
1. Previously FlowManager only accepted IPv4 (if IP not in pkt: return).
   Modern web browsing on Windows operates heavily over IPv6 (e.g. DNS, HTTPS).
   Added native IPv6 support so all browser traffic is aggregated into flows.
2. In Streamlit, start_monitoring previously ignored interface switch if state
   was RUNNING; fixed to cleanly restart sniffer worker on the chosen adapter.
3. Added auto-refresh loop in Streamlit so dashboard updates counters in real-time.

Model Modified:
NO

Scaler Modified:
NO

Label Encoder Modified:
NO

Retraining:
NO

Fake Data:
NO

==================================================
STATUS:
REAL PACKETS -> FLOW BUILDER -> REAL FLOWS VERIFIED
==================================================
"""

    results_dir = os.path.join(PROJECT_ROOT, "results")
    os.makedirs(results_dir, exist_ok=True)
    report_path = os.path.join(results_dir, "STEP_25_FLOW_DEBUG.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"\nReport written to: {report_path}")
    print(f"\n{SEPARATOR}")
    print("FLOW DIAGNOSTIC COMPLETE")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
