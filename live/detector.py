"""
==================================================
NetShield-NIDS — Live Detection Engine
==================================================
live/detector.py

Extracts 53 features, validates input vectors, applies pre-trained StandardScaler,
and executes Extra Trees inference to generate live verdicts and incident records.
"""

from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
import pandas as pd

from live.feature_extractor import (
    FEATURE_NAMES,
    NUM_FEATURES,
    FlowData,
    extract_53_features,
    validate_feature_vector
)

SEVERITY_MAPPING = {
    "BENIGN": "LOW",
    "DDoS": "HIGH",
    "PortScan": "MEDIUM",
    "DoS Hulk": "HIGH",
    "DoS GoldenEye": "HIGH",
    "DoS slowloris": "HIGH",
    "DoS Slowhttptest": "HIGH",
    "FTP-Patator": "MEDIUM",
    "SSH-Patator": "HIGH",
    "Bot": "CRITICAL",
    "Web Attack \x96 Brute Force": "HIGH",
    "Web Attack \x96 XSS": "HIGH",
    "Web Attack \x96 Sql Injection": "CRITICAL",
    "Web Attack ? Brute Force": "HIGH",
    "Web Attack ? XSS": "HIGH",
    "Web Attack ? Sql Injection": "CRITICAL",
    "Infiltration": "CRITICAL",
    "Heartbleed": "CRITICAL",
}

ATTACK_EXPLANATIONS = {
    "BENIGN": "Normal communication activity; traffic characteristics are consistent with standard benign network behaviors.",
    "DDoS": "High volume or concentrated traffic patterns that may indicate a distributed denial-of-service attempt.",
    "PortScan": "Rapid or sequential connection probing that may indicate network reconnaissance or port scanning.",
    "DoS Hulk": "HTTP request flooding patterns that may indicate an attempt to exhaust web server application resources.",
    "DoS GoldenEye": "HTTP Keep-Alive and Cache-Control abuse that may indicate resource exhaustion attack patterns.",
    "DoS slowloris": "Slow, persistent HTTP header transmissions that may indicate an attempt to hold server connections open indefinitely.",
    "DoS Slowhttptest": "Slow HTTP request payloads that may indicate slow-rate denial-of-service probing.",
    "FTP-Patator": "Repeated FTP connection or authentication attempts that may indicate brute-force password guessing.",
    "SSH-Patator": "Repeated SSH connection or authentication attempts that may indicate automated brute-force attacks.",
    "Bot": "Periodic or synchronized network communications that may indicate command-and-control (C2) botnet traffic.",
    "Web Attack \x96 Brute Force": "Multiple rapid web login requests that may indicate dictionary-based authentication attempts.",
    "Web Attack \x96 XSS": "Web requests containing suspicious script tags or encoded characters that may indicate Cross-Site Scripting.",
    "Web Attack \x96 Sql Injection": "Web requests containing SQL keywords or syntax that may indicate relational database query manipulation.",
    "Web Attack ? Brute Force": "Multiple rapid web login requests that may indicate dictionary-based authentication attempts.",
    "Web Attack ? XSS": "Web requests containing suspicious script tags or encoded characters that may indicate Cross-Site Scripting.",
    "Web Attack ? Sql Injection": "Web requests containing SQL keywords or syntax that may indicate relational database query manipulation.",
    "Infiltration": "Anomalous internal lateral movement patterns that may indicate unauthorized network infiltration.",
    "Heartbleed": "TLS Heartbeat request anomalies that may indicate exploitation attempts targeting OpenSSL memory leakage.",
}


def get_severity_for_class(class_name: str) -> str:
    return SEVERITY_MAPPING.get(class_name, "HIGH" if class_name.upper() != "BENIGN" else "LOW")


def get_attack_explanation(class_name: str) -> str:
    if class_name in ATTACK_EXPLANATIONS:
        return ATTACK_EXPLANATIONS[class_name]
    norm_name = class_name.replace("\x96", "?").replace("\ufffd", "?")
    if norm_name in ATTACK_EXPLANATIONS:
        return ATTACK_EXPLANATIONS[norm_name]
    for key, desc in ATTACK_EXPLANATIONS.items():
        if "Brute Force" in class_name and "Brute Force" in key:
            return desc
        if "XSS" in class_name and "XSS" in key:
            return desc
        if "Sql Injection" in class_name and "Sql" in key:
            return desc
    return "Traffic characteristics classified by model as anomalous."


def get_confidence_category(conf_pct: float) -> str:
    if conf_pct >= 80.0:
        return "HIGH"
    elif conf_pct >= 50.0:
        return "MEDIUM"
    else:
        return "LOW"


def get_operational_status(pred_class: str, conf_pct: float) -> str:
    is_benign = (pred_class.upper() == "BENIGN")
    conf_cat = get_confidence_category(conf_pct)
    if is_benign:
        return "NORMAL" if conf_cat in ["HIGH", "MEDIUM"] else "UNCERTAIN"
    else:
        if conf_cat == "HIGH":
            return "THREAT"
        elif conf_cat == "MEDIUM":
            return "REVIEW"
        else:
            return "UNCERTAIN"


class LiveDetector:
    """Performs inference on completed network flows and manages detection state."""
    
    def __init__(self, model, scaler, encoder):
        self.model = model
        self.scaler = scaler
        self.encoder = encoder
        self.incident_seq = 0

    def classify_flow(self, flow: FlowData) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[str]]:
        """
        Classifies a FlowData object.
        Returns: (detection_record, incident_record_if_attack, error_message)
        """
        raw_features = extract_53_features(flow)
        is_valid, errors, ordered_vals = validate_feature_vector(raw_features)
        
        if not is_valid:
            return None, None, f"Flow skipped — {errors[0]}"

        # Apply StandardScaler
        X_df = pd.DataFrame([ordered_vals], columns=FEATURE_NAMES)
        try:
            X_scaled = self.scaler.transform(X_df)
        except Exception as e:
            return None, None, f"Scaler transformation failed: {str(e)}"

        # Predict using Extra Trees model
        try:
            y_pred = self.model.predict(X_scaled)
            pred_label = self.encoder.inverse_transform(y_pred)[0].encode("ascii", errors="replace").decode("ascii")
            probas = self.model.predict_proba(X_scaled)
            conf_val = float(probas[0, y_pred[0]] * 100.0)
            
            class_names = [c.encode("ascii", errors="replace").decode("ascii") for c in self.encoder.classes_]
            proba_df = pd.DataFrame(probas, columns=class_names)
        except Exception as e:
            return None, None, f"Inference execution failed: {str(e)}"

        is_benign = (pred_label.upper() == "BENIGN")
        severity_val = get_severity_for_class(pred_label)
        conf_level = get_confidence_category(conf_val)
        op_status = get_operational_status(pred_label, conf_val)
        dur = max(0.0, flow.last_time - flow.start_time)
        time_str = datetime.fromtimestamp(flow.start_time).strftime("%H:%M:%S")

        # Top 3 summary
        sorted_p = proba_df.iloc[0].sort_values(ascending=False).head(3)
        top3_summary = "\n".join([f"  {idx+1}. {k}: {v*100:.1f}%" for idx, (k, v) in enumerate(sorted_p.items())])

        detection_record = {
            "Timestamp": time_str,
            "Source": flow.src_ip,
            "Destination": flow.dst_ip,
            "Source Port": flow.src_port,
            "Destination Port": flow.dst_port,
            "Protocol": flow.proto,
            "Prediction": pred_label,
            "Confidence": f"{conf_val:.1f}%",
            "Conf_Num": conf_val,
            "Confidence Level": conf_level,
            "Operational Status": op_status,
            "Severity": severity_val,
            "Is_Benign": is_benign,
            "Packets": len(flow.packets),
            "Bytes": sum(p.length for p in flow.packets),
            "Duration (s)": round(dur, 3),
            "Proba_DF": proba_df,
            "Top_3_Summary": top3_summary,
            "Raw_Features": raw_features,
            "Scaled_Features": X_scaled[0],
            "Explanation": get_attack_explanation(pred_label)
        }

        incident_record = None
        if not is_benign:
            self.incident_seq += 1
            inc_id = f"NIDS-{datetime.now().strftime('%Y%m%d')}-{self.incident_seq:04d}"
            incident_record = {
                "Incident ID": inc_id,
                "Timestamp": time_str,
                "Source IP": flow.src_ip,
                "Destination IP": flow.dst_ip,
                "Source Port": flow.src_port,
                "Destination Port": flow.dst_port,
                "Protocol": flow.proto,
                "Attack": pred_label,
                "Confidence": f"{conf_val:.1f}%",
                "Conf_Num": conf_val,
                "Confidence Level": conf_level,
                "Severity": severity_val,
                "Operational Status": op_status,
                "Status": "New",
                "Flow Duration": round(dur, 3),
                "Packets": len(flow.packets),
                "Bytes": sum(p.length for p in flow.packets),
                "Top_3_Summary": top3_summary,
                "Proba_DF": proba_df,
                "Raw_Features": raw_features,
                "Scaled_Features": X_scaled[0],
                "Explanation": get_attack_explanation(pred_label)
            }

        return detection_record, incident_record, None
