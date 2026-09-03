"""
==================================================
NetShield-NIDS — Streamlit Web Application
==================================================
Machine Learning-Based Network Intrusion Detection System
Production-ready dashboard for network traffic flow inspection,
batch traffic analysis, threat analytics, session history,
and live traffic flow 53-feature extraction prototype.

CRITICAL INFERENCE ARCHITECTURE:
- Uses trained Extra Trees classifier, StandardScaler, and LabelEncoder.
- Strictly maintains the exact 53-feature input vector and training sequence.
- Live Traffic Mode performs 53-feature extraction and validation without ML execution.
"""

import os
import sys
import warnings
import io
import time
import threading
from datetime import datetime
from collections import defaultdict

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import streamlit as st

# ── Ensure the project root (D:\NetShield-NIDS) is on sys.path ──────────────
# Streamlit adds the *script* directory (app/) to sys.path, not the project root.
# The live/ package lives at the project root, so we add it explicitly.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Import modular 53-feature extraction & real-time monitoring engine
_LIVE_IMPORT_ERROR = None
try:
    from live import (
        FlowData,
        PacketRecord,
        extract_53_features,
        validate_feature_vector,
        convert_scapy_packet_to_record,
        PacketCaptureWorker,
        get_available_network_interfaces,
        FlowManager,
        LiveDetector,
        RealtimeMonitorEngine,
        get_severity_for_class,
        get_attack_explanation,
        get_confidence_category,
        get_operational_status,
        SEVERITY_MAPPING,
        ATTACK_EXPLANATIONS
    )
except Exception as _e:
    _LIVE_IMPORT_ERROR = str(_e)
    # Provide typed stubs so references don't raise NameError before the UI error is shown
    FlowData = None
    PacketRecord = None
    extract_53_features = None
    validate_feature_vector = None
    convert_scapy_packet_to_record = None
    PacketCaptureWorker = None
    get_available_network_interfaces = lambda: {}
    FlowManager = None
    LiveDetector = None
    RealtimeMonitorEngine = None
    get_severity_for_class = lambda c: "HIGH"
    get_attack_explanation = lambda c: ""
    get_confidence_category = lambda v: "HIGH" if v >= 80 else ("MEDIUM" if v >= 50 else "LOW")
    get_operational_status = lambda c, v: "NORMAL" if c.upper() == "BENIGN" else "THREAT"
    SEVERITY_MAPPING = {}
    ATTACK_EXPLANATIONS = {}

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────
# PAGE CONFIGURATION & STYLING
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetShield-NIDS — Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    /* Global Typography & Font Consistency */
    html, body, [class*="css"] {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    /* Header & Branding */
    .brand-container {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 2px;
    }
    .brand-logo {
        width: 44px;
        height: 44px;
        background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
        color: #ffffff;
        border-radius: 10px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.5rem;
        font-weight: 900;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .main-title {
        font-size: 2.0rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        color: #0f172a;
        margin: 0;
        line-height: 1.2;
    }
    .main-subtitle {
        font-size: 0.95rem;
        color: #64748b;
        font-weight: 500;
        margin-top: 2px;
        margin-bottom: 12px;
    }
    .status-badge-online {
        display: inline-block;
        background-color: #ecfdf5;
        color: #059669;
        font-weight: 700;
        font-size: 0.82rem;
        padding: 6px 14px;
        border-radius: 9999px;
        border: 1px solid #a7f3d0;
        letter-spacing: 0.5px;
    }

    /* Result Cards */
    .card-benign {
        background-color: #f0fdf4;
        border: 1.5px solid #86efac;
        border-left: 8px solid #16a34a;
        padding: 22px 26px;
        border-radius: 8px;
        margin: 16px 0;
    }
    .card-threat {
        background-color: #fef2f2;
        border: 1.5px solid #fca5a5;
        border-left: 8px solid #dc2626;
        padding: 22px 26px;
        border-radius: 8px;
        margin: 16px 0;
    }
    .verdict-header-benign {
        color: #15803d;
        font-size: 1.7rem;
        font-weight: 800;
        margin: 0;
    }
    .verdict-header-threat {
        color: #b91c1c;
        font-size: 1.7rem;
        font-weight: 800;
        margin: 0;
    }
    .verdict-body {
        font-size: 1.15rem;
        color: #1e293b;
        margin: 8px 0 0 0;
    }
    .verdict-explanation {
        font-size: 0.95rem;
        color: #475569;
        margin-top: 8px;
    }

    /* Traffic & Risk Info Cards */
    .info-card {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 12px 14px;
        margin-bottom: 10px;
    }
    .info-card-label {
        font-size: 0.75rem;
        font-weight: 700;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .info-card-value {
        font-size: 1.15rem;
        font-weight: 700;
        color: #0f172a;
        margin-top: 2px;
    }

    /* Threat Alert Panel */
    .threat-alert-box {
        background-color: #fff1f2;
        border: 1px solid #fecdd3;
        border-left: 5px solid #e11d48;
        border-radius: 6px;
        padding: 12px 16px;
        margin: 14px 0;
    }

    /* Prototype Banner */
    .prototype-banner {
        background-color: #f0f9ff;
        border: 1px solid #bae6fd;
        border-left: 5px solid #0284c7;
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 18px;
        color: #0369a1;
        font-size: 0.95rem;
    }

    /* Sidebar Clean Styling */
    .sidebar-section-title {
        font-size: 0.82rem;
        font-weight: 700;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 8px;
    }
    .sidebar-info-label {
        font-size: 0.82rem;
        color: #64748b;
        font-weight: 600;
        text-transform: uppercase;
        margin-top: 8px;
        margin-bottom: 2px;
    }
    .sidebar-info-value {
        font-size: 1.0rem;
        font-weight: 700;
        color: #0f172a;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ─────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(_HERE, ".."))

MODELS_DIR    = os.path.join(PROJECT_ROOT, "models")
ET_MODEL_PATH = os.path.join(PROJECT_ROOT, "extra_trees_model.pkl")
SCALER_PATH   = os.path.join(MODELS_DIR,   "scaler.pkl")
ENCODER_PATH  = os.path.join(MODELS_DIR,   "label_encoder.pkl")
SAMPLE_CSV    = os.path.join(PROJECT_ROOT, "inference", "sample_batch.csv")

# ─────────────────────────────────────────────────────────────
# EXACT 53 FEATURES — strict dataset & training order
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

# Logical groups for advanced manual feature inspection
FEATURE_GROUPS = {
    "FLOW INFORMATION": [
        "Destination Port", "Flow Duration", "Flow Bytes/s",
        "Flow Packets/s", "Down/Up Ratio"
    ],
    "FORWARD PACKET INFORMATION": [
        "Total Fwd Packets", "Total Length of Fwd Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Min",
        "Fwd Packet Length Mean", "Fwd Header Length"
    ],
    "BACKWARD PACKET INFORMATION": [
        "Bwd Packet Length Max", "Bwd Packet Length Min",
        "Bwd Packet Length Mean", "Bwd Packet Length Std",
        "Bwd Header Length", "Bwd Packets/s"
    ],
    "IAT INFORMATION": [
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Min",
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
        "Bwd IAT Max", "Bwd IAT Min"
    ],
    "TCP FLAGS": [
        "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
        "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
        "CWE Flag Count", "ECE Flag Count",
        "Fwd PSH Flags", "Fwd URG Flags"
    ],
    "PACKET STATISTICS": [
        "Min Packet Length", "Max Packet Length",
        "Packet Length Mean", "Packet Length Variance",
        "Average Packet Size"
    ],
    "WINDOW / SEGMENT INFORMATION": [
        "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        "act_data_pkt_fwd", "min_seg_size_forward"
    ],
    "ACTIVE / IDLE INFORMATION": [
        "Active Mean", "Active Std", "Active Max",
        "Active Min", "Idle Std"
    ]
}

# ─────────────────────────────────────────────────────────────
# AUTHENTIC PRESET FLOW VECTORS (Benchmark Tested 53 Features)
# ─────────────────────────────────────────────────────────────
PRESET_BENIGN = {
    "Destination Port": 80.0, "Flow Duration": 1500000.0, "Total Fwd Packets": 10.0,
    "Total Length of Fwd Packets": 1200.0, "Fwd Packet Length Max": 300.0, "Fwd Packet Length Min": 60.0,
    "Fwd Packet Length Mean": 120.0, "Bwd Packet Length Max": 400.0, "Bwd Packet Length Min": 80.0,
    "Bwd Packet Length Mean": 200.0, "Bwd Packet Length Std": 80.0, "Flow Bytes/s": 1200.0,
    "Flow Packets/s": 8.0, "Flow IAT Mean": 150000.0, "Flow IAT Std": 50000.0, "Flow IAT Max": 500000.0,
    "Flow IAT Min": 10000.0, "Fwd IAT Mean": 180000.0, "Fwd IAT Std": 60000.0, "Fwd IAT Min": 5000.0,
    "Bwd IAT Total": 800000.0, "Bwd IAT Mean": 200000.0, "Bwd IAT Std": 80000.0, "Bwd IAT Max": 500000.0,
    "Bwd IAT Min": 50000.0, "Fwd PSH Flags": 1.0, "Fwd URG Flags": 0.0, "Fwd Header Length": 200.0,
    "Bwd Header Length": 160.0, "Bwd Packets/s": 3.0, "Min Packet Length": 60.0, "Max Packet Length": 400.0,
    "Packet Length Mean": 180.0, "Packet Length Variance": 5000.0, "FIN Flag Count": 1.0, "SYN Flag Count": 0.0,
    "RST Flag Count": 0.0, "PSH Flag Count": 1.0, "ACK Flag Count": 1.0, "URG Flag Count": 0.0,
    "CWE Flag Count": 0.0, "ECE Flag Count": 0.0, "Down/Up Ratio": 1.0, "Average Packet Size": 180.0,
    "Init_Win_bytes_forward": 8192.0, "Init_Win_bytes_backward": 5840.0, "act_data_pkt_fwd": 8.0,
    "min_seg_size_forward": 20.0, "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0,
    "Active Min": 0.0, "Idle Std": 0.0
}

PRESET_DDOS = {
    "Destination Port": 80.0, "Flow Duration": 1293792.0, "Total Fwd Packets": 3.0,
    "Total Length of Fwd Packets": 26.0, "Fwd Packet Length Max": 20.0, "Fwd Packet Length Min": 0.0,
    "Fwd Packet Length Mean": 8.6667, "Bwd Packet Length Max": 5840.0, "Bwd Packet Length Min": 0.0,
    "Bwd Packet Length Mean": 1658.1429, "Bwd Packet Length Std": 2137.2971, "Flow Bytes/s": 8991.3989,
    "Flow Packets/s": 7.7292, "Flow IAT Mean": 143754.6667, "Flow IAT Std": 430865.8067, "Flow IAT Max": 1292730.0,
    "Flow IAT Min": 2.0, "Fwd IAT Mean": 373.5, "Fwd IAT Std": 523.9661, "Fwd IAT Min": 3.0,
    "Bwd IAT Total": 1293746.0, "Bwd IAT Mean": 215624.3333, "Bwd IAT Std": 527671.9348, "Bwd IAT Max": 1292730.0,
    "Bwd IAT Min": 2.0, "Fwd PSH Flags": 0.0, "Fwd URG Flags": 0.0, "Fwd Header Length": 72.0,
    "Bwd Header Length": 152.0, "Bwd Packets/s": 5.4105, "Min Packet Length": 0.0, "Max Packet Length": 5840.0,
    "Packet Length Mean": 1057.5455, "Packet Length Variance": 3435230.673, "FIN Flag Count": 0.0, "SYN Flag Count": 0.0,
    "RST Flag Count": 0.0, "PSH Flag Count": 1.0, "ACK Flag Count": 0.0, "URG Flag Count": 0.0,
    "CWE Flag Count": 0.0, "ECE Flag Count": 0.0, "Down/Up Ratio": 2.0, "Average Packet Size": 1163.3,
    "Init_Win_bytes_forward": 8192.0, "Init_Win_bytes_backward": 229.0, "act_data_pkt_fwd": 2.0,
    "min_seg_size_forward": 20.0, "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0,
    "Active Min": 0.0, "Idle Std": 0.0
}

PRESET_PORTSCAN = {
    "Destination Port": 80.0, "Flow Duration": 5021059.0, "Total Fwd Packets": 6.0,
    "Total Length of Fwd Packets": 703.0, "Fwd Packet Length Max": 356.0, "Fwd Packet Length Min": 0.0,
    "Fwd Packet Length Mean": 117.1667, "Bwd Packet Length Max": 1050.0, "Bwd Packet Length Min": 0.0,
    "Bwd Packet Length Mean": 282.8, "Bwd Packet Length Std": 456.9236, "Flow Bytes/s": 421.6242,
    "Flow Packets/s": 2.1908, "Flow IAT Mean": 502105.9, "Flow IAT Std": 1568379.157, "Flow IAT Max": 4965658.0,
    "Flow IAT Min": 19.0, "Fwd IAT Mean": 11080.2, "Fwd IAT Std": 17612.667, "Fwd IAT Min": 19.0,
    "Bwd IAT Total": 5020928.0, "Bwd IAT Mean": 1255232.0, "Bwd IAT Std": 2499939.593, "Bwd IAT Max": 5005133.0,
    "Bwd IAT Min": 1053.0, "Fwd PSH Flags": 0.0, "Fwd URG Flags": 0.0, "Fwd Header Length": 200.0,
    "Bwd Header Length": 168.0, "Bwd Packets/s": 0.9958, "Min Packet Length": 0.0, "Max Packet Length": 1050.0,
    "Packet Length Mean": 176.4167, "Packet Length Variance": 100787.9015, "FIN Flag Count": 0.0, "SYN Flag Count": 0.0,
    "RST Flag Count": 0.0, "PSH Flag Count": 1.0, "ACK Flag Count": 0.0, "URG Flag Count": 0.0,
    "CWE Flag Count": 0.0, "ECE Flag Count": 0.0, "Down/Up Ratio": 0.0, "Average Packet Size": 192.4545,
    "Init_Win_bytes_forward": 29200.0, "Init_Win_bytes_backward": 243.0, "act_data_pkt_fwd": 2.0,
    "min_seg_size_forward": 32.0, "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0,
    "Active Min": 0.0, "Idle Std": 0.0
}

PRESET_SSH_BRUTEFORCE = {
    "Destination Port": 22.0, "Flow Duration": 5808851.0, "Total Fwd Packets": 15.0,
    "Total Length of Fwd Packets": 1496.0, "Fwd Packet Length Max": 640.0, "Fwd Packet Length Min": 0.0,
    "Fwd Packet Length Mean": 99.7333, "Bwd Packet Length Max": 976.0, "Bwd Packet Length Min": 0.0,
    "Bwd Packet Length Mean": 127.6111, "Bwd Packet Length Std": 288.1713, "Flow Bytes/s": 652.9691,
    "Flow Packets/s": 5.6810, "Flow IAT Mean": 181526.5938, "Flow IAT Std": 534015.4383, "Flow IAT Max": 1978974.0,
    "Flow IAT Min": 18.0, "Fwd IAT Mean": 414917.9286, "Fwd IAT Std": 796605.2643, "Fwd IAT Min": 434.0,
    "Bwd IAT Total": 5707732.0, "Bwd IAT Mean": 335748.9412, "Bwd IAT Std": 706064.5178, "Bwd IAT Max": 1978974.0,
    "Bwd IAT Min": 18.0, "Fwd PSH Flags": 0.0, "Fwd URG Flags": 0.0, "Fwd Header Length": 488.0,
    "Bwd Header Length": 584.0, "Bwd Packets/s": 3.0987, "Min Packet Length": 0.0, "Max Packet Length": 976.0,
    "Packet Length Mean": 111.5588, "Packet Length Variance": 55147.9510, "FIN Flag Count": 0.0, "SYN Flag Count": 0.0,
    "RST Flag Count": 0.0, "PSH Flag Count": 1.0, "ACK Flag Count": 0.0, "URG Flag Count": 0.0,
    "CWE Flag Count": 0.0, "ECE Flag Count": 0.0, "Down/Up Ratio": 1.0, "Average Packet Size": 114.9394,
    "Init_Win_bytes_forward": 29200.0, "Init_Win_bytes_backward": 257.0, "act_data_pkt_fwd": 10.0,
    "min_seg_size_forward": 32.0, "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0,
    "Active Min": 0.0, "Idle Std": 0.0
}

SCENARIO_PRESETS = {
    "Normal Web Traffic": PRESET_BENIGN,
    "DDoS Attack Traffic": PRESET_DDOS,
    "PortScan Traffic": PRESET_PORTSCAN,
    "SSH Brute Force Traffic": PRESET_SSH_BRUTEFORCE,
}

# ─────────────────────────────────────────────────────────────
# LOAD ARTIFACTS (CACHED)
# ─────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner="Loading NIDS model and preprocessing components...")
def load_nids_components():
    """Load and cache Extra Trees model, scaler, and label encoder."""
    errors = []
    if not os.path.exists(ET_MODEL_PATH):
        errors.append(f"Model artifact missing: {ET_MODEL_PATH}")
    if not os.path.exists(SCALER_PATH):
        errors.append(f"Scaler artifact missing: {SCALER_PATH}")
    if not os.path.exists(ENCODER_PATH):
        errors.append(f"Label encoder artifact missing: {ENCODER_PATH}")

    if errors:
        return None, None, None, errors

    try:
        model = joblib.load(ET_MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        encoder = joblib.load(ENCODER_PATH)
        return model, scaler, encoder, []
    except Exception as e:
        return None, None, None, [f"Failed to load components: {str(e)}"]


# ─────────────────────────────────────────────────────────────
# VALIDATION & INFERENCE ENGINE
# ─────────────────────────────────────────────────────────────
def validate_and_preprocess_input(df_input: pd.DataFrame, scaler, allow_label=True) -> tuple:
    """
    Validate input DataFrame against strict 53-feature requirements.
    Returns: (X_scaled, error_message)
    """
    if df_input is None or df_input.empty:
        return None, "Unable to analyze this data. The input network flow table is empty."

    # Verify missing columns
    missing_cols = [col for col in FEATURE_NAMES if col not in df_input.columns]
    if missing_cols:
        return None, f"Required network-flow feature is missing: {missing_cols[0]} (and {len(missing_cols)-1} other features)" if len(missing_cols) > 1 else f"Required network-flow feature is missing: {missing_cols[0]}"

    # Verify unexpected/extra columns
    allowed = set(FEATURE_NAMES)
    if allow_label:
        allowed.add("Label")
    extra_cols = [col for col in df_input.columns if col not in allowed]
    if extra_cols:
        return None, f"Found {len(extra_cols)} unexpected column(s): {', '.join(extra_cols[:3])}. Expected only the 53 standard NIDS network features."

    # Extract exactly the 53 features in required order
    X = df_input[FEATURE_NAMES].copy()

    # Numeric conversion validation
    try:
        X = X.apply(pd.to_numeric, errors="coerce")
    except Exception as e:
        return None, f"Feature values must be numeric. Encountered non-numeric error: {str(e)}"

    # Check for NaN / Inf
    if X.isnull().values.any():
        nan_cols = X.columns[X.isnull().any()].tolist()
        return None, f"Feature values must be numeric. Column '{nan_cols[0]}' contains empty (NaN) or unparseable values."
    if np.isinf(X.values).any():
        inf_cols = X.columns[np.isinf(X.values).any(axis=0)].tolist()
        return None, f"Feature values must be finite numbers. Column '{inf_cols[0]}' contains Infinite (Inf) values."

    try:
        X_array = X.values.astype(np.float64)
        X_scaled = scaler.transform(X_array)
        return X_scaled, None
    except Exception as e:
        return None, f"Feature standardization failed: {str(e)}"


def execute_nids_inference(X_scaled, model, encoder):
    """
    Runs Extra Trees model inference and returns labels, confidence, and class probabilities.
    """
    y_pred = model.predict(X_scaled)
    y_labels = encoder.inverse_transform(y_pred)
    probas = model.predict_proba(X_scaled)

    class_names = [c.encode("ascii", errors="replace").decode("ascii") for c in encoder.classes_]
    confidences = probas[np.arange(len(y_pred)), y_pred]
    proba_df = pd.DataFrame(probas, columns=class_names)

    return y_labels, confidences, proba_df


# ─────────────────────────────────────────────────────────────
# LIVE TRAFFIC CAPTURE & 53-FEATURE EXTRACTION ENGINE
# (get_available_network_interfaces imported from live.capture)
# ─────────────────────────────────────────────────────────────

def live_packet_sniffer_and_extractor(iface_obj, duration_sec, max_packets=1000):
    """
    Runs packet capture and live 53-feature extraction on bidirectional flows.
    Returns: (stats_dict, flows_list, features_by_flow, error_msg)
    """
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
    except ImportError as e:
        return None, None, None, f"Scapy packet capture library is not available: {str(e)}"

    stats = {
        "total_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "icmp_packets": 0,
        "other_packets": 0,
        "start_time": time.time(),
        "end_time": time.time()
    }
    
    # Track bidirectional FlowData objects
    # Forward Key: (src_ip, dst_ip, src_port, dst_port, proto)
    flow_objects: Dict[Tuple, FlowData] = {}
    forward_keys: Dict[Tuple, Tuple] = {}  # mapping (A, B) and (B, A) to canonical forward tuple

    def packet_callback(pkt):
        if stats["total_packets"] >= max_packets:
            return True  # stop sniffing
        
        stats["total_packets"] += 1

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto
            pkt_len = len(pkt)
            ts = pkt.time if hasattr(pkt, "time") else time.time()
            ip_hdr_len = getattr(pkt[IP], "ihl", 5) * 4

            if TCP in pkt:
                proto_str = "TCP"
                stats["tcp_packets"] += 1
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
            elif UDP in pkt:
                proto_str = "UDP"
                stats["udp_packets"] += 1
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                trans_hdr_len = 8
                win_size = -1
                tcp_flags = {}
            elif ICMP in pkt:
                proto_str = "ICMP"
                stats["icmp_packets"] += 1
                src_port = 0
                dst_port = 0
                trans_hdr_len = 8
                win_size = -1
                tcp_flags = {}
            else:
                proto_str = f"IP({proto_num})"
                stats["other_packets"] += 1
                src_port = 0
                dst_port = 0
                trans_hdr_len = 0
                win_size = -1
                tcp_flags = {}

            total_hdr_len = ip_hdr_len + trans_hdr_len
            payload_len = max(0, pkt_len - total_hdr_len)

            fwd_candidate = (src_ip, dst_ip, src_port, dst_port, proto_str)
            rev_candidate = (dst_ip, src_ip, dst_port, src_port, proto_str)

            if fwd_candidate in forward_keys:
                canon_key = forward_keys[fwd_candidate]
                direction = "fwd"
            elif rev_candidate in forward_keys:
                canon_key = forward_keys[rev_candidate]
                direction = "bwd"
            else:
                canon_key = fwd_candidate
                forward_keys[fwd_candidate] = canon_key
                forward_keys[rev_candidate] = canon_key
                direction = "fwd"
                flow_objects[canon_key] = FlowData(src_ip, dst_ip, src_port, dst_port, proto_str, ts)

            # Record packet into flow
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
            flow_objects[canon_key].add_packet(record)
        else:
            stats["other_packets"] += 1

    try:
        sniff(iface=iface_obj, timeout=duration_sec, prn=packet_callback, store=False)
        stats["end_time"] = time.time()
    except Exception as e:
        return None, None, None, str(e)

    # Process and extract 53 features for each detected flow
    flows_list = []
    features_by_flow = []

    for flow_id, (key, flow_obj) in enumerate(flow_objects.items(), 1):
        dur = max(0.0, flow_obj.last_time - flow_obj.start_time)
        flows_list.append({
            "Flow ID": flow_id,
            "Time": datetime.fromtimestamp(flow_obj.start_time).strftime("%H:%M:%S"),
            "Source IP": flow_obj.src_ip,
            "Destination IP": flow_obj.dst_ip,
            "Protocol": flow_obj.proto,
            "Source Port": flow_obj.src_port,
            "Destination Port": flow_obj.dst_port,
            "Packets": len(flow_obj.packets),
            "Bytes": sum(p.length for p in flow_obj.packets),
            "Duration (s)": round(dur, 3)
        })

        # Extract 53 features
        f53 = extract_53_features(flow_obj)
        is_valid, val_errs, ordered_vals = validate_feature_vector(f53)
        features_by_flow.append({
            "Flow ID": flow_id,
            "Valid": is_valid,
            "Feature_Count": len(ordered_vals),
            "Features": f53,
            "Errors": val_errs
        })

    return stats, flows_list, features_by_flow, None


# ─────────────────────────────────────────────────────────────
# UI COMPONENTS
# ─────────────────────────────────────────────────────────────

def render_header():
    """Render clean professional header with offline text-based branding and status badge."""
    c_title, c_status = st.columns([3, 1])
    with c_title:
        st.markdown(
            """
            <div class='brand-container'>
                <div class='brand-logo'>N</div>
                <div>
                    <h1 class='main-title'>NetShield-NIDS</h1>
                    <div class='main-subtitle'>Machine Learning-Based Network Intrusion Detection System</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with c_status:
        st.markdown(
            """
            <div style='text-align: right; padding-top: 14px;'>
                <span class='status-badge-online'>● SYSTEM ONLINE</span>
            </div>
            """,
            unsafe_allow_html=True
        )
    st.markdown("---")


def render_sidebar():
    """Render concise sidebar navigation and technical summary."""
    st.sidebar.markdown("### ANALYSIS MODE")
    mode = st.sidebar.radio(
        "Select Mode:",
        options=["Single Flow Analysis", "Batch Traffic Analysis", "Live Traffic Monitor (Prototype)"],
        index=0,
        label_visibility="collapsed"
    )
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("<div class='sidebar-section-title'>SYSTEM SUMMARY</div>", unsafe_allow_html=True)
    
    st.sidebar.markdown("<div class='sidebar-info-label'>Model</div>", unsafe_allow_html=True)
    st.sidebar.markdown("<div class='sidebar-info-value'>Extra Trees</div>", unsafe_allow_html=True)
    
    st.sidebar.markdown("<div class='sidebar-info-label'>Detection Classes</div>", unsafe_allow_html=True)
    st.sidebar.markdown("<div class='sidebar-info-value'>15 Categories</div>", unsafe_allow_html=True)

    st.sidebar.markdown("---")
    if st.sidebar.button("CLEAR SESSION", use_container_width=True):
        st.session_state.detection_history = []
        st.session_state.single_flow_result = None
        st.session_state.batch_df = None
        st.session_state.batch_source = None
        st.session_state.batch_results = None
        st.session_state.scenario_loaded_msg = False
        st.session_state.live_capture_data = None
        st.session_state.live_capture_status = "READY"
        st.rerun()

    return mode


def render_detection_history():
    """Render session-based detection history and summary metrics."""
    if "detection_history" not in st.session_state or not st.session_state.detection_history:
        return

    st.markdown("---")
    st.markdown("### Session Detection History")
    
    hist = st.session_state.detection_history
    hist_df = pd.DataFrame(hist)

    # Session Summary Metrics
    total_analyses = len(hist_df)
    normal_count = sum(hist_df["Risk"] == "LOW")
    threat_count = total_analyses - normal_count
    attack_rate = (threat_count / total_analyses) * 100.0 if total_analyses > 0 else 0.0

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Analyses", total_analyses)
    with m2:
        st.metric("Normal Traffic", normal_count)
    with m3:
        st.metric("Threats Detected", threat_count)
    with m4:
        st.metric("Attack Rate", f"{attack_rate:.1f}%")

    col_tbl, col_clr = st.columns([5, 1])
    with col_tbl:
        st.dataframe(hist_df, use_container_width=True, height=180)
    with col_clr:
        st.markdown("<div style='padding-top: 10px;'></div>", unsafe_allow_html=True)
        if st.button("CLEAR HISTORY", use_container_width=True):
            st.session_state.detection_history = []
            st.rerun()


def render_single_flow_interface(model, scaler, encoder):
    """Render single flow analysis interface with clear scenario workflow and model independence."""
    st.markdown("## Single Flow Analysis")

    # Session state initialization
    if "single_flow_data" not in st.session_state:
        st.session_state.single_flow_data = dict(PRESET_BENIGN)
    if "scenario_loaded_msg" not in st.session_state:
        st.session_state.scenario_loaded_msg = False
    if "single_flow_result" not in st.session_state:
        st.session_state.single_flow_result = None
    if "detection_history" not in st.session_state:
        st.session_state.detection_history = []

    # Step 1: Scenario Selector
    st.markdown("### Test Traffic Scenario")
    st.caption("Select a predefined traffic pattern to load its network flow features. These presets load predefined network-flow features for testing. The final classification is produced by the trained ML model.")

    col_sel, col_load = st.columns([3, 1])
    with col_sel:
        selected_preset_name = st.selectbox(
            "Select Scenario:",
            options=list(SCENARIO_PRESETS.keys()),
            index=0,
            label_visibility="collapsed"
        )
    with col_load:
        if st.button("LOAD SCENARIO", use_container_width=True):
            # Load 53 features into state
            loaded_feats = dict(SCENARIO_PRESETS[selected_preset_name])
            st.session_state.single_flow_data = loaded_feats
            # Sync individual widget keys if present
            for f in FEATURE_NAMES:
                st.session_state[f"input_{f}"] = float(loaded_feats[f])
            st.session_state.scenario_loaded_msg = True
            st.session_state.single_flow_result = None
            st.rerun()

    if st.session_state.scenario_loaded_msg:
        st.success("Traffic scenario loaded successfully.")

    st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)

    # Step 2: Primary Prediction Action
    if st.button("ANALYZE TRAFFIC", type="primary", use_container_width=True):
        st.session_state.scenario_loaded_msg = False
        
        # Build 53-feature row strictly from current state values
        df_single = pd.DataFrame([{f: float(st.session_state.single_flow_data.get(f, 0.0)) for f in FEATURE_NAMES}])
        
        # Validate & standardize through scaler
        X_scaled, err = validate_and_preprocess_input(df_single, scaler, allow_label=False)
        if err:
            st.error(f"Input validation failed: {err}")
            return

        with st.spinner("Analyzing traffic..."):
            y_labels, confidences, proba_df = execute_nids_inference(X_scaled, model, encoder)

        pred_label = y_labels[0].encode("ascii", errors="replace").decode("ascii")
        conf_val = confidences[0] * 100.0
        is_benign = (pred_label.upper() == "BENIGN")
        risk_level = "LOW" if is_benign else "HIGH"

        st.session_state.single_flow_result = {
            "pred_label": pred_label,
            "conf_val": conf_val,
            "is_benign": is_benign,
            "risk_level": risk_level,
            "proba_df": proba_df,
            "flow_feats": dict(st.session_state.single_flow_data)
        }

        # Append to session detection history
        st.session_state.detection_history.insert(0, {
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Mode": "Single Flow",
            "Predicted Class": pred_label,
            "Confidence": f"{conf_val:.1f}%",
            "Risk": risk_level
        })

    # Step 3: Prominent Prediction Result
    if st.session_state.single_flow_result is not None:
        res = st.session_state.single_flow_result
        pred_label = res["pred_label"]
        conf_val = res["conf_val"]
        is_benign = res["is_benign"]
        risk_level = res["risk_level"]
        proba_df = res["proba_df"]
        flow_feats = res["flow_feats"]

        if is_benign:
            st.markdown(
                f"""
                <div class='card-benign'>
                    <div class='verdict-header-benign'>SAFE</div>
                    <div class='verdict-body'><strong>Classification:</strong> Normal Traffic &nbsp;|&nbsp; <strong>Confidence:</strong> {conf_val:.1f}% &nbsp;|&nbsp; <strong>Risk Level:</strong> <span style='color:#16a34a; font-weight:800;'>{risk_level}</span></div>
                    <div class='verdict-explanation'>The analyzed network flow was classified as normal traffic.</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f"""
                <div class='card-threat'>
                    <div class='verdict-header-threat'>THREAT DETECTED</div>
                    <div class='verdict-body'><strong>Classification:</strong> {pred_label} &nbsp;|&nbsp; <strong>Confidence:</strong> {conf_val:.1f}% &nbsp;|&nbsp; <strong>Risk Level:</strong> <span style='color:#dc2626; font-weight:800;'>{risk_level}</span></div>
                    <div class='verdict-explanation'>Potential malicious network activity was detected.</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Useful Flow Information Cards (Reliably mapped directly from 53 features)
        st.markdown("#### Traffic Flow Information")
        f1, f2, f3, f4, f5 = st.columns(5)
        with f1:
            dest_port = int(flow_feats.get("Destination Port", 0))
            st.markdown(f"<div class='info-card'><div class='info-card-label'>Destination Port</div><div class='info-card-value'>{dest_port}</div></div>", unsafe_allow_html=True)
        with f2:
            duration = float(flow_feats.get("Flow Duration", 0))
            st.markdown(f"<div class='info-card'><div class='info-card-label'>Flow Duration</div><div class='info-card-value'>{duration:,.0f} µs</div></div>", unsafe_allow_html=True)
        with f3:
            total_fwd_pkts = int(flow_feats.get("Total Fwd Packets", 0))
            st.markdown(f"<div class='info-card'><div class='info-card-label'>Fwd Packets</div><div class='info-card-value'>{total_fwd_pkts:,}</div></div>", unsafe_allow_html=True)
        with f4:
            fwd_len = float(flow_feats.get("Total Length of Fwd Packets", 0))
            st.markdown(f"<div class='info-card'><div class='info-card-label'>Fwd Payload</div><div class='info-card-value'>{fwd_len:,.0f} B</div></div>", unsafe_allow_html=True)
        with f5:
            flow_bps = float(flow_feats.get("Flow Bytes/s", 0))
            st.markdown(f"<div class='info-card'><div class='info-card-label'>Transfer Rate</div><div class='info-card-value'>{flow_bps:,.1f} B/s</div></div>", unsafe_allow_html=True)

        # Top 3 Predictions Display
        st.markdown("#### Top Predictions")
        sorted_probs = proba_df.iloc[0].sort_values(ascending=False)
        top3 = sorted_probs.head(3)
        
        t1, t2, t3 = st.columns(3)
        for idx, (cls_name, prob_val) in enumerate(top3.items()):
            col_target = [t1, t2, t3][idx]
            with col_target:
                status_color = "#16a34a" if cls_name.upper() == "BENIGN" else "#dc2626"
                col_target.markdown(
                    f"""
                    <div style='background:#f8fafc; border:1px solid #e2e8f0; border-left:4px solid {status_color}; padding:10px 14px; border-radius:6px;'>
                        <div style='font-size:0.8rem; color:#64748b;'>Rank #{idx+1}</div>
                        <div style='font-size:1.05rem; font-weight:700; color:#0f172a;'>{cls_name}</div>
                        <div style='font-size:0.95rem; font-weight:600; color:{status_color};'>{prob_val*100:.1f}%</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        st.markdown("<div style='margin-top: 12px;'></div>", unsafe_allow_html=True)

        # Detailed Probabilities Expander
        with st.expander("📊 Detailed Class Probabilities", expanded=False):
            c_chart, c_tbl = st.columns([3, 2])
            with c_chart:
                fig, ax = plt.subplots(figsize=(6, 3.8))
                top_classes = sorted_probs.head(8)
                colors = ["#16a34a" if c.upper() == "BENIGN" else "#dc2626" for c in top_classes.index]
                ax.barh(top_classes.index[::-1], top_classes.values[::-1] * 100, color=colors[::-1], edgecolor="none")
                ax.set_xlabel("Probability (%)", fontsize=9)
                ax.set_title("Top Predicted Classes", fontsize=10, fontweight="bold")
                ax.tick_params(labelsize=8)
                plt.tight_layout()
                st.pyplot(fig)
                plt.close()

            with c_tbl:
                prob_table = sorted_probs.reset_index()
                prob_table.columns = ["Class Name", "Probability"]
                prob_table["Confidence"] = (prob_table["Probability"] * 100).map("{:.2f}%".format)
                st.dataframe(prob_table[["Class Name", "Confidence"]], height=240, use_container_width=True)

    # Advanced 53-Feature Editor (Collapsed by default)
    with st.expander("⚙️ Advanced Feature Inspection (53 Features)", expanded=False):
        st.caption("Inspect or modify the 53 raw network flow features passed directly to the Extra Trees model pipeline.")
        for group_name, group_feats in FEATURE_GROUPS.items():
            st.markdown(f"**{group_name}**")
            cols = st.columns(3)
            for idx, feat in enumerate(group_feats):
                with cols[idx % 3]:
                    current_val = float(st.session_state.single_flow_data.get(feat, 0.0))
                    val = st.number_input(
                        feat,
                        value=current_val,
                        format="%.4f",
                        key=f"input_{feat}"
                    )
                    st.session_state.single_flow_data[feat] = val


def render_batch_csv_interface(model, scaler, encoder):
    """Render batch traffic analysis interface with filtering, summary, alerts, and export."""
    st.markdown("## Batch Traffic Analysis")
    st.markdown("Upload a network traffic CSV file containing flow records to classify bulk network traffic.")

    if "batch_df" not in st.session_state:
        st.session_state.batch_df = None
    if "batch_source" not in st.session_state:
        st.session_state.batch_source = None
    if "batch_results" not in st.session_state:
        st.session_state.batch_results = None
    if "detection_history" not in st.session_state:
        st.session_state.detection_history = []

    st.markdown("### Upload Network Traffic CSV")
    col_up, col_preset = st.columns([3, 1])
    with col_up:
        uploaded_file = st.file_uploader("Choose CSV File:", type=["csv"], key="batch_uploader", label_visibility="collapsed")
        if uploaded_file is not None:
            try:
                st.session_state.batch_df = pd.read_csv(uploaded_file)
                st.session_state.batch_source = uploaded_file.name
                st.session_state.batch_results = None
            except Exception as e:
                st.error(f"Unable to parse this CSV file: {str(e)}")
                st.session_state.batch_df = None

    with col_preset:
        if st.button("LOAD SAMPLE DATASET", use_container_width=True):
            if os.path.exists(SAMPLE_CSV):
                st.session_state.batch_df = pd.read_csv(SAMPLE_CSV)
                st.session_state.batch_source = "inference/sample_batch.csv"
                st.session_state.batch_results = None
                st.rerun()
            else:
                st.error(f"Sample dataset not found at: {SAMPLE_CSV}")

    df_batch = st.session_state.batch_df
    if df_batch is not None:
        st.info(f"Loaded: **{st.session_state.batch_source}** ({len(df_batch)} network flows)")
        
        # Collapsed raw data preview
        with st.expander("▼ View Input Data", expanded=False):
            st.dataframe(df_batch.head(10), use_container_width=True)

        col_btn, col_clr = st.columns([3, 1])
        with col_btn:
            run_batch = st.button("ANALYZE BATCH", type="primary", use_container_width=True)
        with col_clr:
            if st.button("Clear Batch", use_container_width=True):
                st.session_state.batch_df = None
                st.session_state.batch_source = None
                st.session_state.batch_results = None
                st.rerun()

        if run_batch:
            # Validate input features
            X_scaled, err = validate_and_preprocess_input(df_batch, scaler, allow_label=True)
            if err:
                st.error(f"Input validation failed: {err}")
                st.session_state.batch_results = None
                return

            with st.spinner("Processing batch..."):
                y_labels, confidences, proba_df = execute_nids_inference(X_scaled, model, encoder)

            clean_labels = [l.encode("ascii", errors="replace").decode("ascii") for l in y_labels]
            is_benign = [l.upper() == "BENIGN" for l in clean_labels]
            total_flows = len(clean_labels)
            benign_count = sum(is_benign)
            attack_count = total_flows - benign_count
            attack_rate = (attack_count / total_flows) * 100.0 if total_flows > 0 else 0.0

            results_table = pd.DataFrame({
                "Flow #": range(1, total_flows + 1),
                "Traffic Status": ["NORMAL" if b else "THREAT" for b in is_benign],
                "Risk Level": ["LOW" if b else "HIGH" for b in is_benign],
                "Predicted Classification": clean_labels,
                "Confidence": [f"{c * 100:.1f}%" for c in confidences],
            })

            # Preserve original useful identifying columns if present
            export_df = results_table.copy()
            for col in proba_df.columns:
                export_df[f"Prob_{col}"] = proba_df[col]

            st.session_state.batch_results = {
                "total_flows": total_flows,
                "benign_count": benign_count,
                "attack_count": attack_count,
                "attack_rate": attack_rate,
                "clean_labels": clean_labels,
                "results_table": results_table,
                "export_df": export_df
            }

            # Add to detection history
            st.session_state.detection_history.insert(0, {
                "Time": datetime.now().strftime("%H:%M:%S"),
                "Mode": "Batch",
                "Predicted Class": f"{attack_count} Threats / {total_flows} Flows",
                "Confidence": f"{attack_rate:.1f}% Threat Rate",
                "Risk": "HIGH" if attack_count > 0 else "LOW"
            })

    # Display results if available
    if st.session_state.batch_results is not None:
        res = st.session_state.batch_results
        st.markdown("---")
        st.markdown("### Batch Analysis Summary")

        b1, b2, b3, b4 = st.columns(4)
        with b1:
            st.metric("Total Flows", res["total_flows"])
        with b2:
            st.metric("Normal Traffic", res["benign_count"])
        with b3:
            st.metric("Threats Detected", res["attack_count"])
        with b4:
            st.metric("Attack Rate", f"{res['attack_rate']:.1f}%")

        # Threat Alert Breakdown Panel
        if res["attack_count"] > 0:
            attack_counts = pd.Series([l for l in res["clean_labels"] if l.upper() != "BENIGN"]).value_counts()
            threat_str = " &nbsp;|&nbsp; ".join([f"<strong>{k}:</strong> {v}" for k, v in attack_counts.items()])
            st.markdown(
                f"""
                <div class='threat-alert-box'>
                    <strong style='color:#be123c;'>THREAT ALERT:</strong> Identified {res['attack_count']} malicious network intrusion flow(s):<br>
                    <span style='color:#881337; font-size:0.95rem; margin-top:4px; display:inline-block;'>{threat_str}</span>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Visual Analytics
        st.markdown("### Visual Analytics")
        c_pie, c_bar = st.columns(2)

        with c_pie:
            fig_pie, ax_pie = plt.subplots(figsize=(4, 3.2))
            counts = [res["benign_count"], res["attack_count"]]
            lbls = ["Normal", "Threats"]
            colors = ["#16a34a", "#dc2626"]
            active_slices = [(c, l, col) for c, l, col in zip(counts, lbls, colors) if c > 0]
            if active_slices:
                c_, l_, col_ = zip(*active_slices)
                ax_pie.pie(c_, labels=l_, colors=col_, autopct="%1.1f%%", startangle=90)
            ax_pie.set_title("Traffic Distribution", fontsize=10, fontweight="bold")
            plt.tight_layout()
            st.pyplot(fig_pie)
            plt.close()

        with c_bar:
            fig_bar, ax_bar = plt.subplots(figsize=(5, 3.2))
            dist = pd.Series(res["clean_labels"]).value_counts()
            bar_cols = ["#16a34a" if c.upper() == "BENIGN" else "#dc2626" for c in dist.index]
            ax_bar.bar(dist.index, dist.values, color=bar_cols)
            ax_bar.set_title("Detected Class Breakdown", fontsize=10, fontweight="bold")
            ax_bar.set_ylabel("Count", fontsize=8)
            plt.xticks(rotation=35, ha="right", fontsize=8)
            plt.tight_layout()
            st.pyplot(fig_bar)
            plt.close()

        # Batch Results Table with Interactive Filtering
        st.markdown("### Prediction Results")
        
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            risk_filter = st.selectbox("Filter by Risk:", ["All", "LOW (Normal)", "HIGH (Threats)"])
        with col_f2:
            unique_classes = ["All"] + sorted(list(set(res["clean_labels"])))
            class_filter = st.selectbox("Filter by Class:", unique_classes)

        filtered_table = res["results_table"].copy()
        if risk_filter == "LOW (Normal)":
            filtered_table = filtered_table[filtered_table["Risk Level"] == "LOW"]
        elif risk_filter == "HIGH (Threats)":
            filtered_table = filtered_table[filtered_table["Risk Level"] == "HIGH"]

        if class_filter != "All":
            filtered_table = filtered_table[filtered_table["Predicted Classification"] == class_filter]

        st.dataframe(filtered_table, use_container_width=True)

        # Download button
        csv_data = res["export_df"].to_csv(index=False).encode("utf-8")
        st.download_button(
            label="DOWNLOAD PREDICTIONS CSV",
            data=csv_data,
            file_name="nids_batch_predictions.csv",
            mime="text/csv",
            type="primary",
            use_container_width=True
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
    "Infiltration": "CRITICAL",
    "Heartbleed": "CRITICAL",
}


def get_severity_for_class(class_name: str) -> str:
    """Returns the standardized severity level for an attack class."""
    return SEVERITY_MAPPING.get(class_name, "HIGH" if class_name.upper() != "BENIGN" else "LOW")


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


def get_attack_explanation(class_name: str) -> str:
    """Returns the plain-English explanation for an attack class, handling character encoding variations."""
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
    """Categorizes model prediction probability into interpretive levels (UI thresholds only)."""
    if conf_pct >= 80.0:
        return "HIGH"
    elif conf_pct >= 50.0:
        return "MEDIUM"
    else:
        return "LOW"


def get_operational_status(pred_class: str, conf_pct: float) -> str:
    """
    Computes operational status without altering model output:
    - BENIGN + High/Medium Conf -> NORMAL
    - BENIGN + Low Conf (<50%) -> UNCERTAIN
    - ATTACK + High Conf (>=80%) -> THREAT
    - ATTACK + Medium Conf (50%-79.99%) -> REVIEW
    - ATTACK + Low Conf (<50%) -> UNCERTAIN
    """
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


def generate_incident_report_text(inc: dict) -> str:
    """Generates a structured human-readable plain text / markdown incident report."""
    return f"""==================================================
NETSHIELD-NIDS SECURITY INCIDENT REPORT
==================================================
Incident ID:           {inc['Incident ID']}
Date / Time:           {inc['Timestamp']}
Investigation Status:  {inc['Status']}

--------------------------------------------------
1. DETECTION & CLASSIFICATION
--------------------------------------------------
Predicted Attack:      {inc['Attack']}
Model Confidence:      {inc['Confidence']} ({inc['Confidence Level']})
Severity Level:        {inc['Severity']}
Operational Status:    {inc['Operational Status']}

Context / Explanation:
{inc['Explanation']}

--------------------------------------------------
2. NETWORK ENDPOINTS
--------------------------------------------------
Source Host:           {inc['Source IP']}:{inc['Source Port']}
Destination Host:      {inc['Destination IP']}:{inc['Destination Port']}
Transport Protocol:    {inc['Protocol']}

--------------------------------------------------
3. TRAFFIC FLOW EVIDENCE
--------------------------------------------------
Flow Duration:         {inc['Flow Duration']} s
Total Packets:         {inc['Packets']} pkts
Total Bytes:           {inc['Bytes']} bytes

--------------------------------------------------
4. MODEL EVIDENCE (TOP 3 PREDICTIONS)
--------------------------------------------------
{inc.get('Top_3_Summary', 'Available in dashboard probability view')}

--------------------------------------------------
IMPORTANT DISCLAIMER:
This report represents a machine learning classification
and should not be interpreted as definitive proof of
malicious activity.
==================================================
"""


def render_live_traffic_interface(model, scaler, encoder):
    """Render live traffic capture, 53-feature extraction, Extra Trees ML classification, and threat investigation."""
    st.markdown("## Live Traffic Monitor & Incident Investigation")
    
    st.markdown(
        """
        <div class='prototype-banner'>
            <strong>LIVE NIDS PIPELINE:</strong> Live packet capture &rarr; 53-feature flow extraction &rarr; 
            StandardScaler &rarr; Extra Trees Classifier &rarr; 15-class intrusion verdict &rarr; Security Incident Reporting.
        </div>
        """,
        unsafe_allow_html=True
    )

    if "live_capture_data" not in st.session_state:
        st.session_state.live_capture_data = None
    if "live_capture_status" not in st.session_state:
        st.session_state.live_capture_status = "READY"
    if "live_error_msg" not in st.session_state:
        st.session_state.live_error_msg = None
    if "incidents_list" not in st.session_state:
        st.session_state.incidents_list = []
    if "incident_seq" not in st.session_state:
        st.session_state.incident_seq = 0

    # Guard: if the live module import failed, surface the real error
    if _LIVE_IMPORT_ERROR or RealtimeMonitorEngine is None:
        st.error("Live monitoring engine could not be loaded.")
        with st.expander("Technical Details", expanded=True):
            st.code(_LIVE_IMPORT_ERROR or "RealtimeMonitorEngine is None", language="text")
            st.info("Ensure the `live/` package is complete and all dependencies (Scapy, Npcap on Windows) are installed.")
        return

    if "monitor_engine" not in st.session_state or st.session_state.monitor_engine is None:
        st.session_state.monitor_engine = RealtimeMonitorEngine(model, scaler, encoder)

    engine: "RealtimeMonitorEngine" = st.session_state.monitor_engine

    # Detect Available Network Interfaces
    iface_dict = get_available_network_interfaces()
    
    if not iface_dict:
        st.error("Live packet capture could not be started.")
        with st.expander("Technical Details", expanded=False):
            st.write("No valid network adapters found.")
            st.info("On Windows, Scapy requires Npcap (https://npcap.com) with WinPcap compatibility enabled.")
        return

    # Interface and duration selection
    c_iface, c_dur, c_status = st.columns([3, 1, 1])
    with c_iface:
        selected_iface_label = st.selectbox(
            "Network Interface:",
            options=list(iface_dict.keys()),
            index=0
        )
        selected_iface_obj = iface_dict[selected_iface_label]

    with c_dur:
        duration_sec = st.number_input("Capture Duration (s):", min_value=1, max_value=60, value=5, step=1)

    with c_status:
        st.markdown("<div style='padding-top: 24px;'></div>", unsafe_allow_html=True)
        if engine.state == "RUNNING":
            st.success("● LIVE MONITORING ACTIVE")
        elif st.session_state.live_capture_status == "CAPTURING":
            st.warning("● CAPTURING")
        elif engine.state == "ERROR" or st.session_state.live_capture_status == "ERROR":
            st.error("● ERROR")
        else:
            st.info("● STOPPED (IDLE)")

    # Monitoring Control Buttons
    col_start, col_stop, col_reset = st.columns([2, 2, 1])
    with col_start:
        start_btn = st.button("START CONTINUOUS MONITORING", type="primary", use_container_width=True)
    with col_stop:
        stop_btn = st.button("STOP MONITORING", use_container_width=True)
    with col_reset:
        refresh_btn = st.button("REFRESH", use_container_width=True)

    if stop_btn:
        engine.stop_monitoring()
        st.session_state.live_capture_status = "STOPPED"
        st.success("Monitoring engine stopped cleanly.")
        st.rerun()

    if start_btn:
        ok = engine.start_monitoring(selected_iface_obj, selected_iface_label)
        if ok:
            st.session_state.live_capture_status = "CAPTURING"
            st.success(f"Continuous monitoring started on '{selected_iface_label}'.")
            st.rerun()
        else:
            st.error(f"Could not start monitoring: {engine.error_message}")

    # Fetch snapshot from RealtimeMonitorEngine
    snap = engine.get_snapshot()
    engine_classified = snap["recent_detections"]
    engine_incidents = snap["incidents_list"]

    # Display Live Monitoring Status and Real-Time Counters
    if snap["state"] == "RUNNING" or snap["classified_flows"] > 0 or snap["packets_captured"] > 0:
        st.markdown("---")
        st.markdown("### LIVE NIDS REAL-TIME STATUS")
        
        # Primary Traffic & Flow Metrics
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.metric("Packets Captured", f"{snap['packets_captured']:,}")
        with c2:
            st.metric("Active Flows", snap['active_flows'])
        with c3:
            st.metric("Completed Flows", snap['completed_flows'])
        with c4:
            st.metric("Classified Flows", snap['classified_flows'])
        with c5:
            st.metric("Skipped Flows", snap['skipped_flows'])

        # Security Verdict Metrics
        v1, v2, v3, v4, v5 = st.columns(5)
        with v1:
            st.metric("Normal Flows", snap['normal_count'])
        with v2:
            st.metric("Confirmed Threats", snap['threat_count'])
        with v3:
            st.metric("Under Review", snap['review_count'])
        with v4:
            st.metric("Uncertain", snap['uncertain_count'])
        with v5:
            st.metric("Attack Rate", f"{snap['attack_rate']:.1f}%")

        if snap["state"] == "RUNNING":
            st.info("● Engine is actively sniffing and analyzing incoming network flows in real-time.")

        # Real-time Attack Breakdown
        if snap["attack_breakdown"]:
            st.markdown("### Live Attack Breakdown")
            atk_rows = []
            for atk_name, atk_cnt in snap["attack_breakdown"].items():
                atk_rows.append({
                    "Attack Class": atk_name,
                    "Total Detections": atk_cnt,
                    "Severity": get_severity_for_class(atk_name),
                    "Explanation": get_attack_explanation(atk_name)
                })
            st.dataframe(pd.DataFrame(atk_rows), use_container_width=True)

    # Determine which detections and incidents to display (Engine snapshot preferred)
    classified = engine_classified if engine_classified else (
        st.session_state.live_capture_data.get("classified_flows", []) if st.session_state.live_capture_data else []
    )
    incidents = engine_incidents if engine_incidents else st.session_state.get("incidents_list", [])

    # Display Live Capture & Classification Results
    if classified:
        total_classified = len(classified)
        threat_count = sum(1 for c in classified if c.get("Operational Status") == "THREAT")
        review_count = sum(1 for c in classified if c.get("Operational Status") == "REVIEW")
        uncertain_count = sum(1 for c in classified if c.get("Operational Status") == "UNCERTAIN")
        normal_count = sum(1 for c in classified if c.get("Operational Status") == "NORMAL")
        attack_rate = ((threat_count + review_count) / total_classified * 100.0) if total_classified > 0 else 0.0

        # Threat Alert or Safe Banner
        if threat_count > 0:
            threat_details = []
            for c in classified:
                if c["Operational Status"] == "THREAT":
                    threat_details.append(f"🔴 <strong>{c['Prediction']}</strong> (Conf: {c['Confidence']} [{c['Confidence Level']}]) from {c['Source']}:{c['Source Port']} &rarr; {c['Destination']}:{c['Destination Port']} [{c['Protocol']}]")
            
            st.markdown(
                f"""
                <div class='threat-alert-box'>
                    <strong style='color:#b91c1c; font-size:1.1rem;'>🔴 HIGH-CONFIDENCE THREAT DETECTED:</strong> Identified {threat_count} confirmed intrusion flow(s):<br>
                    <div style='margin-top:6px; font-size:0.95rem;'>{"<br>".join(threat_details[:5])}</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        elif review_count > 0:
            st.markdown(
                f"""
                <div style='background:#fffbeb; border:1px solid #fde68a; border-left:6px solid #d97706; padding:16px 20px; border-radius:6px; margin:14px 0;'>
                    <strong style='color:#92400e; font-size:1.1rem;'>⚠️ SUSPICIOUS TRAFFIC (REVIEW REQUIRED)</strong><br>
                    <span style='color:#b45309;'>Identified {review_count} moderate-confidence flow(s) requiring operator inspection.</span>
                </div>
                """,
                unsafe_allow_html=True
            )
        elif total_classified > 0:
            st.markdown(
                f"""
                <div style='background:#ecfdf5; border:1.5px solid #a7f3d0; border-left:6px solid #059669; padding:16px 20px; border-radius:6px; margin:14px 0;'>
                    <strong style='color:#065f46; font-size:1.1rem;'>🟢 NORMAL TRAFFIC</strong><br>
                    <span style='color:#047857;'>All {total_classified} classified network flows were confirmed as BENIGN by Extra Trees model.</span>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Recent Detections Table & Filtering
        st.markdown("### Live Detections")
        
        col_fil1, col_fil2, col_fil3, col_fil4 = st.columns(4)
        with col_fil1:
            filt_status = st.selectbox("Operational Status:", ["All", "Normal", "Threat", "Review", "Uncertain"], key="live_filt_status")
        with col_fil2:
            filt_conf = st.selectbox("Confidence Level:", ["All", "HIGH", "MEDIUM", "LOW"], key="live_filt_conf")
        with col_fil3:
            filt_proto = st.selectbox("Protocol:", ["All", "TCP", "UDP", "ICMP", "Other"], key="live_filt_proto")
        with col_fil4:
            filt_ip = st.text_input("Filter IP:", placeholder="e.g. 192.168.1.1", key="live_filt_ip")

        if classified:
            det_rows = []
            for c in classified:
                src_ip = c.get("Source IP", c.get("Source", ""))
                dst_ip = c.get("Destination IP", c.get("Destination", ""))
                t_stamp = c.get("Timestamp", c.get("Time", ""))
                # Apply filters
                if filt_status != "All" and c["Operational Status"].upper() != filt_status.upper():
                    continue
                if filt_conf != "All" and c["Confidence Level"] != filt_conf:
                    continue
                if filt_proto != "All" and c["Protocol"] != filt_proto:
                    continue
                if filt_ip and (filt_ip not in src_ip and filt_ip not in dst_ip):
                    continue

                det_rows.append({
                    "Timestamp": t_stamp,
                    "Source": src_ip,
                    "Destination": dst_ip,
                    "Protocol": c["Protocol"],
                    "Source Port": c["Source Port"],
                    "Destination Port": c["Destination Port"],
                    "Prediction": c["Prediction"],
                    "Confidence": c["Confidence"],
                    "Confidence Level": c["Confidence Level"],
                    "Operational Status": c["Operational Status"]
                })

            if det_rows:
                st.dataframe(pd.DataFrame(det_rows), use_container_width=True, height=220)
            else:
                st.info("No detections match the selected filter criteria.")

            # CSV Export and Clear Session Controls
            col_exp, col_clr = st.columns([3, 1])
            with col_exp:
                csv_export_rows = []
                for c in classified:
                    csv_export_rows.append({
                        "Timestamp": c.get("Timestamp", c.get("Time", "")),
                        "Source IP": c.get("Source IP", c.get("Source", "")),
                        "Destination IP": c.get("Destination IP", c.get("Destination", "")),
                        "Protocol": c.get("Protocol", ""),
                        "Source Port": c.get("Source Port", 0),
                        "Destination Port": c.get("Destination Port", 0),
                        "Prediction": c.get("Prediction", ""),
                        "Confidence": c.get("Confidence", ""),
                        "Confidence Level": c.get("Confidence Level", ""),
                        "Operational Status": c.get("Operational Status", ""),
                        "Severity": c.get("Severity", "")
                    })
                csv_bytes = pd.DataFrame(csv_export_rows).to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="DOWNLOAD LIVE DETECTIONS CSV",
                    data=csv_bytes,
                    file_name="nids_live_detections.csv",
                    mime="text/csv",
                    type="primary",
                    use_container_width=True
                )
            with col_clr:
                if st.button("CLEAR LIVE SESSION", use_container_width=True):
                    engine.reset_session()
                    st.session_state.live_capture_data = None
                    st.session_state.live_capture_status = "READY"
                    st.rerun()
        else:
            st.info("No network flows were classified during this capture window.")

        # Attack Breakdown Summary (if threats present)
        threat_or_review = [c for c in classified if not c["Is_Benign"]]
        if threat_or_review:
            st.markdown("### Attack Breakdown & Confidence Distribution")
            threat_df = pd.DataFrame(threat_or_review)
            attack_summary_data = []
            for t_class, group in threat_df.groupby("Prediction"):
                attack_summary_data.append({
                    "Attack Class": t_class,
                    "Predictions": len(group),
                    "Avg Confidence": f"{group['Conf_Num'].mean():.1f}%",
                    "Min Confidence": f"{group['Conf_Num'].min():.1f}%",
                    "Max Confidence": f"{group['Conf_Num'].max():.1f}%",
                    "Severity": get_severity_for_class(t_class)
                })
            st.dataframe(pd.DataFrame(attack_summary_data), use_container_width=True)

        # Flow Investigation Section
        if classified:
            st.markdown("---")
            st.markdown("### Flow Investigation")
            
            selected_idx = st.selectbox(
                "Select Flow to Investigate:",
                options=range(1, len(classified) + 1),
                format_func=lambda i: f"Flow #{i}: {classified[i-1].get('Source IP', classified[i-1].get('Source', ''))}:{classified[i-1]['Source Port']} -> {classified[i-1].get('Destination IP', classified[i-1].get('Destination', ''))}:{classified[i-1]['Destination Port']} [{classified[i-1]['Prediction']} | Severity: {classified[i-1]['Severity']}]"
            )
            
            sel_flow = classified[selected_idx - 1]
            raw_f = sel_flow["Raw_Features"]
            scaled_f = sel_flow["Scaled_Features"]

            # Flow metadata and traffic stats
            if sel_flow["Operational Status"] == "UNCERTAIN":
                st.markdown(
                    f"""
                    <div style='background:#fffbeb; border:1px solid #fde68a; border-left:5px solid #d97706; padding:10px 14px; border-radius:6px; margin-bottom:12px;'>
                        <strong style='color:#92400e;'>⚠️ UNCERTAIN CLASSIFICATION</strong> &mdash; 
                        Prediction: <strong>{sel_flow['Prediction']}</strong> (Model Confidence: {sel_flow['Confidence']}).
                        <div style='font-size:0.85rem; color:#b45309; margin-top:2px;'>The model is not highly confident in this classification (&lt;50% probability).</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            c_info1, c_info2, c_info3, c_info4 = st.columns(4)
            with c_info1:
                st.markdown(f"<div class='info-card'><div class='info-card-label'>Endpoints</div><div class='info-card-value'>{sel_flow['Source']}:{sel_flow['Source Port']}<br>&rarr; {sel_flow['Destination']}:{sel_flow['Destination Port']}</div></div>", unsafe_allow_html=True)
            with c_info2:
                st.markdown(f"<div class='info-card'><div class='info-card-label'>Traffic Stats</div><div class='info-card-value'>{sel_flow['Packets']} pkts ({raw_f['Total Fwd Packets']:.0f} Fwd / {sel_flow['Packets'] - raw_f['Total Fwd Packets']:.0f} Bwd)<br>{sel_flow['Bytes']} bytes</div></div>", unsafe_allow_html=True)
            with c_info3:
                st.markdown(f"<div class='info-card'><div class='info-card-label'>Duration & Rate</div><div class='info-card-value'>{sel_flow['Duration (s)']} s ({raw_f['Flow Duration']:,.0f} µs)<br>{raw_f['Flow Bytes/s']:,.1f} B/s</div></div>", unsafe_allow_html=True)
            with c_info4:
                sev_color = "#16a34a" if sel_flow["Severity"] == "LOW" else ("#dc2626" if sel_flow["Severity"] in ["HIGH", "CRITICAL"] else "#ea580c")
                st.markdown(f"<div class='info-card'><div class='info-card-label'>Prediction & Status</div><div class='info-card-value' style='color:{sev_color};'>{sel_flow['Prediction']}<br><span style='font-size:0.85rem; color:#64748b;'>Status: {sel_flow['Operational Status']} ({sel_flow['Confidence']})</span></div></div>", unsafe_allow_html=True)

            # Top 3 Predictions Display
            st.markdown("#### Top 3 Model Predictions")
            p_df = sel_flow["Proba_DF"]
            sorted_p = p_df.iloc[0].sort_values(ascending=False)
            
            c1, c2, c3 = st.columns(3)
            for idx, (cls_name, prob_v) in enumerate(sorted_p.head(3).items()):
                with [c1, c2, c3][idx]:
                    col_clr = "#16a34a" if cls_name.upper() == "BENIGN" else "#dc2626"
                    st.markdown(
                        f"""
                        <div style='background:#f8fafc; border:1px solid #e2e8f0; border-left:4px solid {col_clr}; padding:10px 14px; border-radius:6px;'>
                            <div style='font-size:0.8rem; color:#64748b;'>Rank #{idx+1}</div>
                            <div style='font-size:1.05rem; font-weight:700; color:#0f172a;'>{cls_name}</div>
                            <div style='font-size:0.95rem; font-weight:600; color:{col_clr};'>{prob_v*100:.1f}%</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            # 53-Feature Transparency View ("Model Input")
            with st.expander("🔍 View Extracted Features (Model Input: 53 Features)", expanded=False):
                st.caption("Exact raw feature values calculated from live packets alongside standardized values provided directly to the Extra Trees classifier.")
                feature_table_data = []
                for idx, feat_name in enumerate(FEATURE_NAMES):
                    raw_val = raw_f[feat_name]
                    sc_val = scaled_f[idx]
                    feature_table_data.append({
                        "Index": idx,
                        "Feature Name": feat_name,
                        "Raw Value": round(raw_val, 4) if isinstance(raw_val, float) else raw_val,
                        "Scaled Value (StandardScaler)": round(float(sc_val), 4)
                    })
                st.dataframe(pd.DataFrame(feature_table_data), use_container_width=True, height=320)

            # Detailed 15-Class Probability Distribution
            with st.expander("📊 Complete 15-Class Probability Distribution", expanded=False):
                prob_table = sorted_p.reset_index()
                prob_table.columns = ["Class Name", "Probability"]
                prob_table["Confidence"] = (prob_table["Probability"] * 100).map("{:.2f}%".format)
                st.dataframe(prob_table[["Class Name", "Confidence"]], use_container_width=True, height=250)

        # Security Incidents & Reporting Section
        incidents = st.session_state.get("incidents_list", [])
        if incidents:
            st.markdown("---")
            st.markdown("### Security Incidents & Incident Reporting")
            
            # Incident Counters
            tot_inc = len(incidents)
            new_inc = sum(1 for i in incidents if i["Status"] == "New")
            inv_inc = sum(1 for i in incidents if i["Status"] == "Investigating")
            rev_inc = sum(1 for i in incidents if i["Status"] == "Reviewed")
            high_sev = sum(1 for i in incidents if i["Severity"] in ["HIGH", "CRITICAL"])
            med_sev = sum(1 for i in incidents if i["Severity"] == "MEDIUM")

            ic1, ic2, ic3, ic4, ic5 = st.columns(5)
            with ic1:
                st.metric("Total Incidents", tot_inc)
            with ic2:
                st.metric("New Incidents", new_inc)
            with ic3:
                st.metric("Under Investigation", inv_inc)
            with ic4:
                st.metric("Reviewed", rev_inc)
            with ic5:
                st.metric("High / Critical Severity", high_sev)

            # Filtering for Incidents
            if1, if2, if3 = st.columns(3)
            with if1:
                inc_status_filt = st.selectbox("Filter Status:", ["All Incidents", "Open Incidents", "Reviewed Incidents"], key="inc_filt_status")
            with if2:
                inc_attack_classes = ["All"] + sorted(list(set(i["Attack"] for i in incidents)))
                inc_class_filt = st.selectbox("Filter Attack Class:", inc_attack_classes, key="inc_filt_class")
            with if3:
                inc_sev_filt = st.selectbox("Filter Severity:", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="inc_filt_sev")

            filtered_incidents = []
            for inc in incidents:
                if inc_status_filt == "Open Incidents" and inc["Status"] == "Reviewed":
                    continue
                if inc_status_filt == "Reviewed Incidents" and inc["Status"] != "Reviewed":
                    continue
                if inc_class_filt != "All" and inc["Attack"] != inc_class_filt:
                    continue
                if inc_sev_filt != "All" and inc["Severity"] != inc_sev_filt:
                    continue
                filtered_incidents.append(inc)

            if filtered_incidents:
                selected_inc_idx = st.selectbox(
                    "Select Incident to Manage & Report:",
                    options=range(len(filtered_incidents)),
                    format_func=lambda idx: f"[{filtered_incidents[idx]['Incident ID']}] {filtered_incidents[idx]['Attack']} ({filtered_incidents[idx]['Severity']}) - Status: {filtered_incidents[idx]['Status']}"
                )
                
                sel_inc = filtered_incidents[selected_inc_idx]
                
                # Status Update Action
                c_stat_lbl, c_stat_sel = st.columns([2, 2])
                with c_stat_lbl:
                    st.markdown(f"**Current Status:** `{sel_inc['Status']}` &nbsp;|&nbsp; **Incident ID:** `{sel_inc['Incident ID']}`")
                with c_stat_sel:
                    new_status = st.selectbox(
                        "Update Investigation Status:",
                        options=["New", "Investigating", "Reviewed"],
                        index=["New", "Investigating", "Reviewed"].index(sel_inc["Status"]),
                        key=f"inc_stat_sel_{sel_inc['Incident ID']}"
                    )
                    if new_status != sel_inc["Status"]:
                        sel_inc["Status"] = new_status
                        st.rerun()

                # Compact Incident Details Card
                st.markdown(
                    f"""
                    <div style='background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:16px; margin:10px 0;'>
                        <div style='display:flex; justify-content:space-between; margin-bottom:8px;'>
                            <strong style='font-size:1.1rem; color:#0f172a;'>INCIDENT: {sel_inc['Incident ID']}</strong>
                            <span style='color:#64748b; font-size:0.9rem;'>{sel_inc['Timestamp']}</span>
                        </div>
                        <div style='margin-bottom:8px;'>
                            <strong>Attack:</strong> <span style='color:#b91c1c; font-weight:700;'>{sel_inc['Attack']}</span> &nbsp;|&nbsp; 
                            <strong>Severity:</strong> {sel_inc['Severity']} &nbsp;|&nbsp; 
                            <strong>Confidence:</strong> {sel_inc['Confidence']} ({sel_inc['Confidence Level']})
                        </div>
                        <div style='background:#fff; border:1px solid #e2e8f0; border-left:4px solid #3b82f6; padding:8px 12px; border-radius:4px; font-size:0.9rem; color:#334155; margin-bottom:10px;'>
                            <strong>Analysis Note:</strong> {sel_inc['Explanation']}
                        </div>
                        <div style='display:grid; grid-template-columns: 1fr 1fr 1fr; gap:10px; font-size:0.9rem;'>
                            <div><strong>Source:</strong> {sel_inc['Source IP']}:{sel_inc['Source Port']}</div>
                            <div><strong>Destination:</strong> {sel_inc['Destination IP']}:{sel_inc['Destination Port']}</div>
                            <div><strong>Traffic:</strong> {sel_inc['Protocol']} | {sel_inc['Packets']} pkts | {sel_inc['Bytes']} B ({sel_inc['Flow Duration']} s)</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                # Export buttons
                col_rep1, col_rep2 = st.columns(2)
                with col_rep1:
                    inc_csv_df = pd.DataFrame(incidents)[[
                        "Incident ID", "Timestamp", "Source IP", "Destination IP",
                        "Source Port", "Destination Port", "Protocol", "Attack",
                        "Confidence", "Confidence Level", "Severity", "Status"
                    ]]
                    st.download_button(
                        label="DOWNLOAD INCIDENTS CSV",
                        data=inc_csv_df.to_csv(index=False).encode("utf-8"),
                        file_name="nids_security_incidents.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                with col_rep2:
                    report_txt = generate_incident_report_text(sel_inc)
                    st.download_button(
                        label=f"DOWNLOAD REPORT ({sel_inc['Incident ID']})",
                        data=report_txt.encode("utf-8"),
                        file_name=f"{sel_inc['Incident ID']}_Report.txt",
                        mime="text/plain",
                        type="primary",
                        use_container_width=True
                    )
            else:
                st.info("No incidents match the active filter.")

    # Auto-refresh loop while live continuous monitoring is actively running
    if snap["state"] == "RUNNING":
        time.sleep(1.0)
        st.rerun()


def render_footer(encoder):
    """Render clean, collapsed model specifications and class reference section."""
    st.markdown("---")
    with st.expander("▼ Model Specifications & Supported Attack Classes", expanded=False):
        st.markdown(
            """
            - **Classification Model:** Extra Trees Classifier (*Extremely Randomized Trees*)
            - **Input Feature Vector:** 53 Network Flow Statistical Descriptors
            - **Target Classifications:** 15 Classes (14 Intrusion / Attack Types + Benign)
            - **Feature Standardization:** Pre-trained `StandardScaler`
            - **Validation Framework:** Verified End-to-End Inference Pipeline
            """
        )
        if encoder is not None:
            st.markdown("**Supported Class Labels:**")
            cols = st.columns(3)
            for idx, c in enumerate(encoder.classes_):
                safe_name = c.encode("ascii", errors="replace").decode("ascii")
                with cols[idx % 3]:
                    st.markdown(f"- `{safe_name}`")


# ─────────────────────────────────────────────────────────────
# MAIN APP ENTRY
# ─────────────────────────────────────────────────────────────
def main():
    render_header()
    mode = render_sidebar()

    model, scaler, encoder, load_errors = load_nids_components()

    if load_errors:
        st.error("### NIDS System Initialization Failed")
        for err in load_errors:
            st.error(err)
        st.warning("Please verify that `extra_trees_model.pkl`, `models/scaler.pkl`, and `models/label_encoder.pkl` exist.")
        return

    if mode == "Single Flow Analysis":
        render_single_flow_interface(model, scaler, encoder)
        render_detection_history()
    elif mode == "Batch Traffic Analysis":
        render_batch_csv_interface(model, scaler, encoder)
        render_detection_history()
    else:
        render_live_traffic_interface(model, scaler, encoder)

    render_footer(encoder)


if __name__ == "__main__":
    main()
