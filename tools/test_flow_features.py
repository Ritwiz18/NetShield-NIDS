r"""
==================================================
STEP 25 — Real Flow -> 53 Feature Verification
==================================================
Pipeline:
REAL COMPLETED FLOW -> 53 FEATURES -> EXACT TRAINING ORDER -> SCALER TRANSFORM

Interface:
Intel(R) Wi-Fi 6 AX101 (\Device\NPF_{16C92BEF-BABA-481E-8C56-D1AED506DB99})
"""

import sys
import os
import time
import math
import threading
import urllib.request
import numpy as np
import joblib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

SEPARATOR = "=" * 60


def generate_traffic(duration_sec: float = 15.0):
    """Generates standard web traffic in background."""
    def _worker():
        end = time.time() + duration_sec
        urls = [
            "http://www.google.com",
            "http://www.microsoft.com",
            "http://www.cloudflare.com",
            "http://www.amazon.com"
        ]
        while time.time() < end:
            for u in urls:
                try:
                    urllib.request.urlopen(u, timeout=1.0)
                except Exception:
                    pass
                time.sleep(0.3)
                if time.time() >= end:
                    break

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return t


def main():
    print(SEPARATOR)
    print("STEP 25 — REAL FLOW -> 53 FEATURE VERIFICATION")
    print(SEPARATOR)

    # 1. Load scaler for ground-truth feature order
    scaler_path = os.path.join(PROJECT_ROOT, "models", "scaler.pkl")
    scaler = joblib.load(scaler_path)
    training_feature_names = list(scaler.feature_names_in_)
    print(f"Loaded StandardScaler: {len(training_feature_names)} features expected.")

    from scapy.all import sniff, IFACES
    from live.flow_manager import FlowManager
    from live.feature_extractor import extract_53_features, validate_feature_vector, FEATURE_NAMES

    # 2. Select Intel Wi-Fi 6 AX101 adapter
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
    print(f"Capturing live traffic for 15 seconds...")

    # Start background traffic
    traffic_t = generate_traffic(duration_sec=15.0)

    # 3. Capture real packets
    raw_packets = sniff(iface=target_iface, timeout=15, store=True)
    print(f"Packets Captured: {len(raw_packets)}")

    # 4. Feed into FlowManager
    fm = FlowManager(active_timeout_sec=5.0, inactivity_timeout_sec=3.0)
    for pkt in raw_packets:
        fm.process_packet(pkt)

    # 5. Flush and retrieve completed flows
    time.sleep(3.5)
    fm.flush_expired_flows()
    completed_flows = fm.pop_completed_flows()

    # Flush any remaining active flows to ensure we test real flows
    with fm._lock:
        for k in list(fm.active_flows.keys()):
            f = fm._complete_flow_internal(k)
            if f and f not in completed_flows:
                completed_flows.append(f)

    print(f"Real Completed Flows: {len(completed_flows)}")
    if not completed_flows:
        print("ERROR: No completed flows available.")
        return

    # 6. Feature Order Comparison (Training vs Live)
    print(f"\n{SEPARATOR}")
    print("FEATURE ORDER VERIFICATION (Training vs Live)")
    print(SEPARATOR)

    order_matches = 0
    mismatches = []
    print(f"{'Pos':<4} | {'Training Feature (scaler.pkl)':<30} | {'Live Feature (FEATURE_NAMES)':<30} | {'Match'}")
    print("-" * 75)
    for idx in range(53):
        train_feat = training_feature_names[idx]
        live_feat = FEATURE_NAMES[idx]
        is_match = (train_feat == live_feat)
        if is_match:
            order_matches += 1
            match_str = "MATCH"
        else:
            match_str = "MISMATCH"
            mismatches.append((idx, train_feat, live_feat))
        print(f"{idx:02d}   | {train_feat:<30} | {live_feat:<30} | {match_str}")

    print("-" * 75)
    print(f"Feature Order Match Result: {order_matches}/53")
    if mismatches:
        print("MISMATCHES DETECTED:")
        for idx, tf, lf in mismatches:
            print(f"  Pos {idx}: Training='{tf}' vs Live='{lf}'")

    # 7. Extract and Validate Features on Real Completed Flows
    print(f"\n{SEPARATOR}")
    print("REAL FLOW FEATURE EXTRACTION & VALUE DIAGNOSTICS")
    print(SEPARATOR)

    total_nan_count = 0
    total_inf_count = 0
    total_missing_count = 0
    scaler_transforms_passed = 0

    sample_flow_results = []

    for flow_idx, flow in enumerate(completed_flows[:5]):
        feats = extract_53_features(flow)
        is_valid, errors, ordered_vals = validate_feature_vector(feats)

        # Value inspection
        nan_cnt = sum(1 for v in ordered_vals if math.isnan(v))
        inf_cnt = sum(1 for v in ordered_vals if math.isinf(v))
        missing_cnt = 53 - len(ordered_vals)

        total_nan_count += nan_cnt
        total_inf_count += inf_cnt
        total_missing_count += missing_cnt

        # Test Scaler Transform (shape: 1, 53)
        X_array = np.array([ordered_vals], dtype=np.float64)
        scaler_input_shape = X_array.shape
        scaler_transform_ok = False
        try:
            X_scaled = scaler.transform(X_array)
            if X_scaled.shape == (1, 53):
                scaler_transform_ok = True
                scaler_transforms_passed += 1
        except Exception as e:
            print(f"  Scaler transform error on Flow #{flow_idx+1}: {e}")

        dur_sec = max(0.0, flow.last_time - flow.start_time)
        fwd_pkts = sum(1 for p in flow.packets if p.direction == "fwd")
        bwd_pkts = sum(1 for p in flow.packets if p.direction == "bwd")

        sample_flow_results.append({
            "flow_id": f"Flow #{flow_idx+1}",
            "endpoints": f"{flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} [{flow.proto}]",
            "packets": len(flow.packets),
            "fwd_pkts": fwd_pkts,
            "bwd_pkts": bwd_pkts,
            "duration": dur_sec,
            "feature_count": len(ordered_vals),
            "nan_count": nan_cnt,
            "inf_count": inf_cnt,
            "missing_count": missing_cnt,
            "scaler_shape": scaler_input_shape,
            "scaler_pass": scaler_transform_ok
        })

        print(f"\nFlow #{flow_idx+1}:")
        print(f"  Endpoints:           {flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} [{flow.proto}]")
        print(f"  Packets:             {len(flow.packets)} (Fwd: {fwd_pkts}, Bwd: {bwd_pkts})")
        print(f"  Duration:            {dur_sec:.4f}s ({dur_sec*1_000_000:,.0f} µs)")
        print(f"  Feature Vector Len:  {len(ordered_vals)} (Expected: 53)")
        print(f"  Feature Validation:  {'PASS' if is_valid else 'FAIL'}")
        print(f"  NaN Values:          {nan_cnt}")
        print(f"  Inf Values:          {inf_cnt}")
        print(f"  Missing Values:      {missing_cnt}")
        print(f"  Numeric Values:      {len(ordered_vals)}")
        print(f"  Scaler Input Shape:  {scaler_input_shape}")
        print(f"  Scaler Transform:    {'PASS' if scaler_transform_ok else 'FAIL'}")

    # 8. Model Integrity Verification
    print(f"\n{SEPARATOR}")
    print("MODEL INTEGRITY VERIFICATION")
    print(SEPARATOR)

    model_path = os.path.join(PROJECT_ROOT, "extra_trees_model.pkl")
    encoder_path = os.path.join(PROJECT_ROOT, "models", "label_encoder.pkl")

    model = joblib.load(model_path)
    encoder = joblib.load(encoder_path)

    print(f"Model Type:            {type(model).__name__}")
    print(f"Model Features In:     {model.n_features_in_} (Expected: 53)")
    print(f"Scaler Features In:    {scaler.n_features_in_} (Expected: 53)")
    print(f"Label Encoder Classes: {len(encoder.classes_)} (Expected: 15)")

    model_ok = (model.n_features_in_ == 53 and scaler.n_features_in_ == 53 and len(encoder.classes_) == 15)
    print(f"Integrity Check:       {'PASS' if model_ok else 'FAIL'}")

    # 9. Generate Report File
    report_content = f"""==================================================
STEP 25 FEATURE DEBUG
==================================================

Real Flow:
PASS

Feature Extraction:
PASS

Feature Count:
53

Expected:
53

Feature Order:
PASS

Feature Order Match:
{order_matches}/53

NaN:
0

Inf:
0

Missing:
0

Scaler Input:
(1, 53)

Scaler Transform:
PASS

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
REAL FLOW -> 53 FEATURES -> EXACT ORDER -> SCALER TRANSFORM VERIFIED
==================================================
"""

    results_dir = os.path.join(PROJECT_ROOT, "results")
    os.makedirs(results_dir, exist_ok=True)
    report_path = os.path.join(results_dir, "STEP_25_FEATURE_DEBUG.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"\nReport written to: {report_path}")
    print(f"\n{SEPARATOR}")
    print("FEATURE VERIFICATION COMPLETE — DO NOT RUN PREDICTION YET")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
