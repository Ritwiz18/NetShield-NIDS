# Network Intrusion Detection System Using Machine Learning

A production-grade, end-to-end Machine Learning based Network Intrusion Detection System (NIDS) designed to classify network traffic flows into benign activity and 14 distinct cyberattack categories with high precision and low latency.

---

## Quick Start

1. **Open Terminal / PowerShell**
2. **Navigate to the Project Directory:**
   ```bash
   cd /d "D:\7th sem project"
   ```
3. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **Launch the Web Interface:**
   ```bash
   streamlit run app/app.py
   ```
5. **Run CLI Inference:**
   ```bash
   python inference/nids_inference.py --mode demo
   python inference/nids_inference.py --mode batch --input inference/sample_batch.csv
   ```

---

## 1. Project Overview
Network Intrusion Detection Systems (NIDS) are critical perimeter defense mechanisms in modern cybersecurity infrastructure. This project provides an end-to-end machine learning pipeline that inspects aggregated TCP/IP network flow records and classifies traffic behavior into **BENIGN** or **14 specific attack vectors** (such as DDoS, PortScan, DoS variants, and Web Attacks) using an **Extra Trees Classifier**.

---

## 2. Objectives
- **Network Traffic Classification:** Multi-class classification of complex network statistical flow metrics.
- **High-Accuracy Intrusion Detection:** Achieve >99.8% detection accuracy with minimal false positive rates.
- **Robust Imbalance Handling:** Utilize controlled, training-only SMOTE oversampling for rare intrusion types without data leakage.
- **Real-Time & Batch Prediction:** Provide both a flexible CLI inference engine and an interactive Streamlit web dashboard.

---

## 3. Dataset
- **Total Flow Records:** 2,520,792
- **Total Feature Columns:** 53 numerical flow descriptors
- **Target Column:** `Label`
- **Total Classes:** 15 (1 Benign + 14 Malicious Attack Types)
- **Data Source:** Cleaned benchmark network flow dataset (`data/processed/cleaned_dataset.csv`)

---

## 4. Attack Classes
The target labels are mapped to 15 unique classes via `LabelEncoder`:
0. `BENIGN`
1. `Bot`
2. `DDoS`
3. `DoS GoldenEye`
4. `DoS Hulk`
5. `DoS Slowhttptest`
6. `DoS slowloris`
7. `FTP-Patator`
8. `Heartbleed`
9. `Infiltration`
10. `PortScan`
11. `SSH-Patator`
12. `Web Attack ? Brute Force`
13. `Web Attack ? Sql Injection`
14. `Web Attack ? XSS`

---

## 5. Machine Learning Pipeline Architecture
```
Cleaned Dataset (2,520,792 rows)
       ↓
Data Hygiene & Quality Checks (Missing: 0, Infinite: 0, Duplicates: 0)
       ↓
Feature / Target Separation (53 Features, 1 Target)
       ↓
Label Encoding (0 to 14)
       ↓
Stratified Train/Test Split (80% Train / 20% Test)
       ↓
Controlled SMOTE Oversampling (Applied ONLY to Training Data)
       ↓
Feature Scaling (StandardScaler fitted strictly on Training Data)
       ↓
Model Training & Comparison (Random Forest vs. Extra Trees)
       ↓
Final Model Selection (Extra Trees Classifier selected)
       ↓
Serialized Artifacts (`extra_trees_model.pkl`, `scaler.pkl`, `label_encoder.pkl`)
       ↓
Inference Engine (`inference/nids_inference.py`) & Web UI (`app/app.py`)
```

---

## 6. Data Validation
Before training and inference, dataset hygiene checks were verified:
- **Missing values:** 0
- **Infinite values:** 0
- **Duplicate rows:** 0
- **Constant features removed:** Zero-variance and redundant identifier columns eliminated.

---

## 7. Train / Test Split
- **Total Samples:** 2,520,792
- **Training Set (80%):** 2,016,633 samples (stratified by class)
- **Testing Set (20%):** 504,159 samples (held-out, completely untouched during SMOTE and scaling)
- **Random State:** 42

---

## 8. Controlled SMOTE
To prevent majority-class disruption while boosting representation for rare attacks:
- **Scope:** Applied **ONLY** to training data (`X_train`, `y_train`).
- **Pre-SMOTE Training Size:** 2,016,633 samples
- **Post-SMOTE Training Size:** 2,106,095 samples
- **Test Integrity:** Test partition (504,159 samples) remained completely unmodified to evaluate true real-world generalization.

---

## 9. Feature Scaling
- **Scaler:** `StandardScaler` ($Z$-score standardization: $\mu = 0, \sigma = 1$).
- **Fitting:** Fitted strictly on the training partition to prevent data leakage.
- **Transformation:** Applied to test sets and all runtime inference vectors.

---

## 10. Final Model Selection
- **Algorithm:** **Extra Trees Classifier** (*Extremely Randomized Trees*)
- **Parameters:** 100 estimators, Gini criterion, full feature randomization.
- **Selection Rationale:** Significantly outperformed baseline Random Forest on rare attack detection (Macro Recall 86.18% vs 70.49%; Macro F1 0.8766 vs 0.7579).

---

## 11. Model Evaluation & Performance
Evaluated on the held-out 504,159 test samples:

### Overall Metrics
| Metric | Score |
|---|---|
| **Accuracy** | **99.87%** (`0.998712`) |
| **Weighted Precision** | **99.88%** (`0.998773`) |
| **Weighted Recall** | **99.87%** (`0.998713`) |
| **Weighted F1-Score** | **99.87%** (`0.998729`) |
| **Macro Precision** | **93.66%** (`0.936636`) |
| **Macro Recall** | **86.18%** (`0.861804`) |
| **Macro F1-Score** | **87.66%** (`0.876623`) |

### Selected Attack Class Performance
- **BENIGN:** Precision = 99.96%, Recall = 99.92%, F1 = 99.94% (Support: 419,011)
- **DDoS:** Precision = 100.0%, Recall = 99.98%, F1 = 99.99% (Support: 25,603)
- **DoS Hulk:** Precision = 99.86%, Recall = 99.77%, F1 = 99.81% (Support: 34,569)
- **PortScan:** Precision = 98.97%, Recall = 99.94%, F1 = 99.46% (Support: 18,139)
- **FTP-Patator:** Precision = 100.0%, Recall = 99.92%, F1 = 99.96% (Support: 1,186)
- **SSH-Patator:** Precision = 100.0%, Recall = 100.0%, F1 = 100.0% (Support: 644)

---

## 12. Inference Pipeline
Implemented in `inference/nids_inference.py`:
- **Demo Mode:** Loads sample flow vectors, validates components, and outputs predictions.
- **Single Flow Mode:** Inspects a single 53-feature JSON or dictionary input.
- **Batch Mode:** Processes CSV files of arbitrary length, exporting predictions and class probabilities.

---

## 13. Web Application (Streamlit)
A modern, professional cybersecurity dashboard built with Streamlit (`app/app.py`):
- **Live Header & System Status Indicator**
- **Single Flow Analysis:** Grouped input form across 8 logical feature sections with BENIGN & DDoS quick presets.
- **Batch CSV Analysis:** Upload CSV, validate 53 columns, calculate summary metrics (Total, Benign, Attack %, Attack Rate), display distribution charts, and export `nids_predictions.csv`.
- **Expandable Information:** Complete model details and 15-class reference matrix.

```bash
streamlit run app/app.py
```

---

## 14. Input Feature Requirements
The model strictly expects **53 continuous/discrete numeric features** in exact dataset order:
1. `Destination Port`
2. `Flow Duration`
3. `Total Fwd Packets`
4. `Total Length of Fwd Packets`
5. `Fwd Packet Length Max`
6. `Fwd Packet Length Min`
7. `Fwd Packet Length Mean`
8. `Bwd Packet Length Max`
9. `Bwd Packet Length Min`
10. `Bwd Packet Length Mean`
11. `Bwd Packet Length Std`
12. `Flow Bytes/s`
13. `Flow Packets/s`
14. `Flow IAT Mean`
15. `Flow IAT Std`
16. `Flow IAT Max`
17. `Flow IAT Min`
18. `Fwd IAT Mean`
19. `Fwd IAT Std`
20. `Fwd IAT Min`
21. `Bwd IAT Total`
22. `Bwd IAT Mean`
23. `Bwd IAT Std`
24. `Bwd IAT Max`
25. `Bwd IAT Min`
26. `Fwd PSH Flags`
27. `Fwd URG Flags` *(Position 27 / index 26)*
28. `Fwd Header Length`
29. `Bwd Header Length`
30. `Bwd Packets/s`
31. `Min Packet Length`
32. `Max Packet Length`
33. `Packet Length Mean`
34. `Packet Length Variance`
35. `FIN Flag Count`
36. `SYN Flag Count`
37. `RST Flag Count`
38. `PSH Flag Count`
39. `ACK Flag Count`
40. `URG Flag Count`
41. `CWE Flag Count`
42. `ECE Flag Count`
43. `Down/Up Ratio`
44. `Average Packet Size`
45. `Init_Win_bytes_forward`
46. `Init_Win_bytes_backward`
47. `act_data_pkt_fwd`
48. `min_seg_size_forward`
49. `Active Mean`
50. `Active Std`
51. `Active Max`
52. `Active Min`
53. `Idle Std`

*All inputs must be non-empty, finite floating-point numbers without NaN or Inf values.*

---

## 15. Testing & Validation Suites
- **STEP 13 Test Suite:** Demo Mode, Batch Mode, Invalid Input Handling, Model Consistency, and Feature Order verification — **All Passed**.
- **STEP 15 Validation:** Complete end-to-end pipeline verification and artifact generation — **All Passed**.
- **STEP 16 Review:** Full system quality and security audit — **All Passed**.
- **STEP 17 UI Validation:** Single-flow, batch mode, and chart rendering tests — **All Passed**.

---

## 16. Project Directory Structure
```
D:\7th sem project\
├── app\
│   ├── app.py                          # Streamlit Web Application Dashboard
│   └── README.md                       # Application Usage Guide
├── data\
│   └── processed\
│       └── cleaned_dataset.csv         # 2.52M rows cleaned benchmark dataset
├── inference\
│   ├── nids_inference.py               # Core production inference engine
│   ├── sample_batch.csv                # 53-feature test batch CSV
│   ├── step13_inference_test.py        # STEP 13 validation suite
│   ├── step15_final_validation.py      # STEP 15 validation harness
│   ├── step16_project_review.py        # STEP 16 review script
│   └── README.md                       # Inference documentation
├── models\
│   ├── scaler.pkl                      # Fitted StandardScaler (53 features)
│   ├── label_encoder.pkl               # Fitted LabelEncoder (15 classes)
│   └── random_forest_model.pkl         # Baseline model comparison
├── results\
│   ├── NIDS_PROJECT_REPORT.md          # Comprehensive 19-section Project Report
│   ├── STEP_13_INFERENCE_TEST.txt      # STEP 13 test report
│   ├── STEP_15_FINAL_VALIDATION.txt    # STEP 15 validation status
│   ├── STEP_16_PROJECT_REVIEW.txt      # STEP 16 quality review report
│   ├── STEP_18_FINAL_PACKAGING.txt     # STEP 18 final packaging checklist
│   ├── classification_report.csv       # Test set classification metrics
│   ├── confusion_matrix.csv            # 15x15 test confusion matrix
│   ├── feature_importance.csv          # 53-feature importance rankings
│   ├── model_comparison.csv            # RF vs Extra Trees benchmark
│   └── final_end_to_end_test.csv       # End-to-end batch prediction results
├── src\
│   ├── ml\
│   │   ├── ml_pipeline.py              # Full ML training pipeline
│   │   ├── step9_feature_importance.py # Feature importance extraction
│   │   ├── step10_model_comparison.py  # Model comparison logic
│   │   └── step11_final_evaluation.py  # Final model evaluation
│   └── preprocessing\
│       └── analysis.py                 # Dataset EDA and cleaning
├── extra_trees_model.pkl               # Final production model (1.47 GB)
├── requirements.txt                    # Project Python dependencies
└── README.md                           # Master Project Documentation
```

## 15. FastAPI REST API Layer

NetShield-NIDS includes a production-ready FastAPI REST API backend (`backend/api.py`) that connects directly to the `RealtimeMonitorEngine`. This enables real-time metrics streaming, traffic time-series, threat analytics, incident alerts, and network adapter control for modern web dashboards (React, Vue, Next.js, Vite).

### System Architecture
```
Network Traffic
       ↓
Scapy Capture (live/capture.py)
       ↓
Flow Manager (live/flow_manager.py)
       ↓
53-Feature Extractor (live/feature_extractor.py)
       ↓
ML Extra Trees Detector (live/detector.py)
       ↓
Real-Time Engine (live/monitor.py)
       ↓
FastAPI REST API (backend/api.py)
  ├── Streamlit Web App (app/app.py)
  └── Future Web Dashboard (React/Next.js/Vite)
```

### Running the API
```bash
uvicorn backend.api:app --host 0.0.0.0 --port 8000
```
Documentation will be accessible at `http://localhost:8000/docs`.

### API Endpoint Summary
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | Engine running state, interface, uptime, and system metadata |
| `GET` | `/api/dashboard` | Unified snapshot of packets, active/completed flows, classifications, attack breakdown, protocol breakdown, and top source IPs |
| `GET` | `/api/traffic` | Lightweight time-series traffic stats (packets/sec, bytes/sec, flow counts) for frontend charts |
| `GET` | `/api/threats` | Detailed threat analytics, attack breakdown by type, and severity distribution |
| `GET` | `/api/alerts` | Security incident alerts formatted with 5-tuples, confidence, severity, and actionable explanations |
| `GET` | `/api/interfaces` | List of host network adapters with IP addresses and prioritization |
| `POST` | `/api/monitor/start` | Starts live Scapy packet capture and detection on target network adapter |
| `POST` | `/api/monitor/stop` | Safely stops capture worker and flushes active flows |
| `POST` | `/api/monitor/reset` | Resets session counters and detection history |

### Example API Response (`GET /api/dashboard`)
```json
{
  "status": "ok",
  "state": "RUNNING",
  "interface": "Wi-Fi (Intel(R) Wi-Fi 6 AX101) [192.168.1.8]",
  "packets_captured": 1245,
  "active_flows": 12,
  "completed_flows": 84,
  "classified_flows": 84,
  "normal_count": 81,
  "threat_count": 3,
  "review_count": 0,
  "uncertain_count": 0,
  "high_risk_threat_count": 2,
  "attack_rate": 3.57,
  "attack_breakdown": {
    "DDoS": 2,
    "PortScan": 1
  },
  "protocol_breakdown": {
    "TCP": 78,
    "UDP": 6,
    "ICMP": 0,
    "Other": 0
  },
  "recent_detections": [
    {
      "Timestamp": "19:40:12",
      "Source": "192.168.1.105",
      "Destination": "10.0.0.1",
      "Source Port": 54321,
      "Destination Port": 80,
      "Protocol": "TCP",
      "Prediction": "DDoS",
      "Confidence": "99.8%",
      "Confidence Level": "HIGH",
      "Operational Status": "THREAT",
      "Severity": "HIGH",
      "Is_Benign": false,
      "Explanation": "High volume or concentrated traffic patterns that may indicate a distributed denial-of-service attempt."
    }
  ]
}
```

---

### Running the React Web Dashboard
```bash
cd frontend
npm install
npm run dev
```
Accessible at `http://localhost:5173`.

### System Architecture
```
Network Traffic
       ↓
Scapy Capture (live/capture.py)
       ↓
Flow Manager (live/flow_manager.py)
       ↓
53-Feature Extractor (live/feature_extractor.py)
       ↓
ML Extra Trees Detector (live/detector.py)
       ↓
Real-Time Engine (live/monitor.py)
       ↓
FastAPI REST API (:8000) (backend/api.py)
  ├── Streamlit Web App (app/app.py)
  └── React SOC Web Dashboard (:5173) (frontend/)
```

---

## 16. Docker Container Deployment

NetShield-NIDS is fully containerized using Docker and Docker Compose for production deployment across Linux and Windows servers without manual environment configuration.

### Container Architecture
```
                     Browser (Host User)
                              │
                              ▼
                    ┌──────────────────┐
                    │ React Dashboard  │
                    │ Nginx Container  │
                    │      :5173       │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ FastAPI Backend  │
                    │ Python Container │
                    │      :8000       │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │ Net Shield NIDS  │
                    │ Monitor Engine   │
                    └────────┬─────────┘
                             │
                       ┌─────┴──────┐
                       ▼            ▼
                    Scapy          ML
                    Capture       Detector
                       │            │
                       └─────┬──────┘
                             ▼
                         Detection
                             │
                             ▼
                         Dashboard
```

### Docker Quickstart

```bash
# 1. Build and start all services in detached mode
docker compose up --build -d

# 2. View running container logs
docker compose logs -f

# 3. Stop services
docker compose down
```

### Container Endpoints
* **React SOC Web Dashboard:** `http://localhost:5173`
* **FastAPI REST API Service:** `http://localhost:8000`
* **Interactive OpenAPI Docs:** `http://localhost:8000/docs`

### Network Packet Capture Capabilities
* **Linux Hosts:** Scapy live packet capture requires binding to raw host network sockets. `docker-compose.yml` configures `NET_ADMIN` and `NET_RAW` Linux capabilities (`cap_add`). For physical adapter sniffing on Linux servers, set `network_mode: host`.
* **Windows Host Limitation:** On Windows Docker Desktop (WSL2), Docker containers run inside a hypervisor virtual machine. Live capture inside Windows containers sniffs the container virtual network. For native Windows physical Wi-Fi/Ethernet capture, use `run.bat` or native Python execution.

---

## 17. Usage Commands

### 1. Launch FastAPI REST API Server
```bash
uvicorn backend.api:app --host 0.0.0.0 --port 8000
```

### 2. Launch React SOC Web Dashboard
```bash
cd frontend
npm run dev
```

### 3. Run API Verification Test Suite
```bash
python tools/test_api.py
```

### 4. Launch Streamlit Web Application
```bash
streamlit run app/app.py
```

### 5. Run Single Demo Inference
```bash
python inference/nids_inference.py --mode demo
```

### 6. Run Batch CSV Inference
```bash
python inference/nids_inference.py --mode batch --input inference/sample_batch.csv --output results/batch_output.csv
```

### 7. Run Full Real-Time Pipeline Test
```bash
python tools/test_realtime_ml.py
```

---

## 17. Limitations
- **Statistical Flow Summaries:** Requires network traffic to be pre-aggregated into flow statistics (via tools such as CICFlowMeter or live `FlowManager`) rather than processing raw packet frames directly.
- **Ultra-Rare Classes:** Extremely scarce attacks in the original dataset (e.g., Heartbleed with 10 total instances) have wider confidence intervals than voluminous attacks like DDoS.
- **Offline Model:** Does not feature automated online reinforcement learning on live streaming interfaces.

---

## 18. Conclusion
The Network Intrusion Detection System represents a robust, highly optimized, and thoroughly tested machine learning solution for cyber threat identification. With a **99.87% accuracy rate**, leak-free preprocessing, standardized 53-feature architecture, resilient validation test suites, Streamlit dashboard, and a **FastAPI REST API layer**, the system provides an effective foundation for modern network security monitoring.
