# Network Intrusion Detection System

## 1. Project Overview
The Network Intrusion Detection System (NIDS) is designed to monitor, analyze, and classify network traffic flows to identify unauthorized intrusions, attacks, and anomalies. Using machine learning algorithms trained on high-dimensional statistical flow features, the system distinguishes benign network activity from 14 distinct categories of network attacks in real time and batch scenarios.

## 2. Dataset
The dataset utilized is the benchmark network traffic dataset containing 2,520,792 cleaned flow records with 54 total columns (53 features and 1 label).

- **Total Rows**: 2,520,792
- **Total Features**: 53 numeric flow features
- **Total Classes**: 15 (BENIGN + 14 Attack Classes)

### Class Distribution (Cleaned Dataset)
- **BENIGN**: ~2,095,057 flows (~83.1%)
- **DoS Hulk**: ~172,845 flows
- **PortScan**: ~90,695 flows
- **DDoS**: ~128,015 flows
- **DoS GoldenEye**: ~10,285 flows
- **FTP-Patator**: ~5,930 flows
- **DoS slowloris**: ~5,385 flows
- **DoS Slowhttptest**: ~5,230 flows
- **SSH-Patator**: ~3,220 flows
- **Bot**: ~1,950 flows
- **Web Attack - Brute Force**: ~1,470 flows
- **Web Attack - XSS**: ~650 flows
- **Infiltration**: ~35 flows
- **Web Attack - Sql Injection**: ~20 flows
- **Heartbleed**: ~10 flows

## 3. Data Preprocessing
Data hygiene and quality steps executed in the pipeline:
1. **Missing-Value Handling**: Checked for NaN and null values; imputed or filtered where appropriate.
2. **Infinite Value Cleaning**: Filtered out infinite rates (e.g. `Flow Bytes/s`, `Flow Packets/s`).
3. **Duplicate Removal**: Identified and dropped duplicate flow records to prevent synthetic over-representation.
4. **Constant & Quasi-Constant Feature Removal**: Dropped zero-variance columns (e.g., constant header lengths, single-valued flags).
5. **Correlation & Redundancy Analysis**: Removed highly collinear and redundant flow descriptors to reduce dimensionality from 78+ down to 53 critical features.
6. **Final Feature Count**: Exactly 53 continuous and discrete numerical features.

## 4. Feature Engineering / Selection
The final 53 network flow features maintained in strict pipeline order:
1. Destination Port
2. Flow Duration
3. Total Fwd Packets
4. Total Length of Fwd Packets
5. Fwd Packet Length Max
6. Fwd Packet Length Min
7. Fwd Packet Length Mean
8. Bwd Packet Length Max
9. Bwd Packet Length Min
10. Bwd Packet Length Mean
11. Bwd Packet Length Std
12. Flow Bytes/s
13. Flow Packets/s
14. Flow IAT Mean
15. Flow IAT Std
16. Flow IAT Max
17. Flow IAT Min
18. Fwd IAT Mean
19. Fwd IAT Std
20. Fwd IAT Min
21. Bwd IAT Total
22. Bwd IAT Mean
23. Bwd IAT Std
24. Bwd IAT Max
25. Bwd IAT Min
26. Fwd PSH Flags
27. Fwd URG Flags
28. Fwd Header Length
29. Bwd Header Length
30. Bwd Packets/s
31. Min Packet Length
32. Max Packet Length
33. Packet Length Mean
34. Packet Length Variance
35. FIN Flag Count
36. SYN Flag Count
37. RST Flag Count
38. PSH Flag Count
39. ACK Flag Count
40. URG Flag Count
41. CWE Flag Count
42. ECE Flag Count
43. Down/Up Ratio
44. Average Packet Size
45. Init_Win_bytes_forward
46. Init_Win_bytes_backward
47. act_data_pkt_fwd
48. min_seg_size_forward
49. Active Mean
50. Active Std
51. Active Max
52. Active Min
53. Idle Std

## 5. Label Encoding
The 15 target labels were mapped to integer indices (0 to 14) via `scikit-learn`'s `LabelEncoder` and persisted in `models/label_encoder.pkl`:
- **0**: BENIGN
- **1**: Bot
- **2**: DDoS
- **3**: DoS GoldenEye
- **4**: DoS Hulk
- **5**: DoS Slowhttptest
- **6**: DoS slowloris
- **7**: FTP-Patator
- **8**: Heartbleed
- **9**: Infiltration
- **10**: PortScan
- **11**: SSH-Patator
- **12**: Web Attack ? Brute Force
- **13**: Web Attack ? Sql Injection
- **14**: Web Attack ? XSS

## 6. Train/Test Split
A stratified random split was performed to preserve class ratios:
- **Training Samples (80%)**: 2,016,633
- **Testing Samples (20%)**: 504,159
- **Stratification**: Enabled (`stratify=y`)
- **Random State**: 42
- **Integrity**: The test partition was kept completely isolated and untouched during all oversampling and scaling operations.

## 7. Class Imbalance Handling
To balance rare attack types without distorting the majority distribution:
- **Controlled SMOTE**: Applied synthetic minority oversampling exclusively to minority classes with sample counts below defined thresholds.
- **Scope**: Applied **ONLY** to the training data partition (`X_train`, `y_train`).
- **Post-SMOTE Training Size**: 2,106,095 samples (increased from 2,016,633).
- **Test Integrity**: Test data (504,159 samples) remained completely un-oversampled to provide true real-world generalization metrics.

## 8. Feature Scaling
- **Scaler**: `StandardScaler` (Z-score normalization).
- **Fitting**: Fitted strictly on the training partition (`X_train_resampled`).
- **Transformation**: Scaler parameters ($\mu, \sigma$) applied to transform `X_test` and all subsequent real-time/batch inference inputs.
- **Data Leakage Prevention**: Zero statistics from the test set were exposed to the scaler.

## 9. Machine Learning Models
Two primary ensemble tree models were trained and benchmarked under identical splits:
1. **Random Forest Classifier**: Baseline ensemble estimator using bagging and random feature subsampling.
2. **Extra Trees Classifier** (*Extremely Randomized Trees*): Randomized cut-point decision tree ensemble yielding higher variance reduction and faster inference.

## 10. Model Evaluation
Evaluations conducted on the isolated 504,159 test samples yielded the following results:

### Overall Model Metrics (Extra Trees - Selected Model)
- **Accuracy**: 0.9987 (99.87%)
- **Weighted Precision**: 0.9988 (99.88%)
- **Weighted Recall**: 0.9987 (99.87%)
- **Weighted F1-Score**: 0.9987 (99.87%)
- **Macro Precision**: 0.9366 (93.66%)
- **Macro Recall**: 0.8618 (86.18%)
- **Macro F1-Score**: 0.8766 (87.66%)

### Per-Class Evaluation Summary
- **BENIGN**: Precision = 99.96%, Recall = 99.92%, F1 = 99.94% (Support: 419,011)
- **DDoS**: Precision = 99.99%, Recall = 99.98%, F1 = 99.99% (Support: 25,603)
- **DoS Hulk**: Precision = 99.86%, Recall = 99.77%, F1 = 99.81% (Support: 34,569)
- **PortScan**: Precision = 98.97%, Recall = 99.94%, F1 = 99.46% (Support: 18,139)
- **FTP-Patator**: Precision = 100.0%, Recall = 99.92%, F1 = 99.96% (Support: 1,186)
- **SSH-Patator**: Precision = 100.0%, Recall = 100.0%, F1 = 100.0% (Support: 644)
- **DoS GoldenEye**: Precision = 99.46%, Recall = 99.22%, F1 = 99.34% (Support: 2,057)
- **DoS Slowhttptest**: Precision = 99.24%, Recall = 99.62%, F1 = 99.43% (Support: 1,046)
- **DoS slowloris**: Precision = 99.63%, Recall = 98.98%, F1 = 99.30% (Support: 1,077)
- **Bot**: Precision = 79.38%, Recall = 85.90%, F1 = 82.51% (Support: 390)
- **Web Attack - Brute Force**: Precision = 81.86%, Recall = 65.99%, F1 = 73.07% (Support: 294)
- **Web Attack - XSS**: Precision = 46.60%, Recall = 68.46%, F1 = 55.45% (Support: 130)
- **Infiltration**: Precision = 100.0%, Recall = 100.0%, F1 = 100.0% (Support: 7)
- **Web Attack - Sql Injection**: Precision = 100.0%, Recall = 25.00%, F1 = 40.00% (Support: 4)
- **Heartbleed**: Precision = 100.0%, Recall = 50.00%, F1 = 66.67% (Support: 2)

## 11. Final Model Selection
**Extra Trees Classifier** was selected as the final production model based on empirical superiority across all key metrics:
- **Macro F1-Score**: Extra Trees (0.8766 / 0.8697) outperformed Random Forest (0.7579) significantly, particularly on rare attack classes.
- **Macro Recall**: Extra Trees (86.18%) exceeded Random Forest (70.49%), representing far fewer missed minority attack intrusions.
- **Overall Accuracy**: Extra Trees achieved 99.87% vs 96.24% for Random Forest.

## 12. Feature Importance
Based on Mean Decrease in Impurity (Gini importance) extracted from the Extra Trees model:
- **Top 5 Predictive Features**:
  1. `Bwd Packet Length Std` (0.0629)
  2. `Max Packet Length` (0.0624)
  3. `Packet Length Variance` (0.0587)
  4. `Bwd Packet Length Mean` (0.0582)
  5. `Packet Length Mean` (0.0553)
- **Key Insight**: Packet length variation, backward packet statistics, and average packet sizes constitute over 35% of total predictive power for attack identification.

## 13. Inference Pipeline
The inference architecture in `inference/nids_inference.py` ensures seamless deployment:
```
Input Vector / Batch CSV
        ↓
Feature Validation (exact 53 names, numeric check, NaN/Inf handling)
        ↓
Feature Ordering (aligned to training column order)
        ↓
StandardScaler Transform (`models/scaler.pkl`)
        ↓
Extra Trees Prediction (`extra_trees_model.pkl`)
        ↓
Label Decoding (`models/label_encoder.pkl`)
        ↓
Prediction Class & Confidence Computation
```

## 14. Web Interface
A dedicated web interface built with Streamlit (`app/app.py`):
- **Single-Flow Mode**: Grouped input UI across 10 semantic feature sets with quick presets (BENIGN, DDoS) and real-time prediction output.
- **Batch CSV Mode**: Uploads arbitrary traffic CSVs, validates columns, generates predictions, interactive distribution charts, and exports `nids_predictions.csv`.
- **Error Handling**: Gracefully rejects non-numeric entries, missing columns, or empty files without application crashes.

## 15. Testing

### STEP 13 Test Suite (All Passed)
1. **Demo Mode Test**: PASS
2. **Batch Mode Test**: PASS
3. **Invalid Input Handling Test**: PASS
4. **Model Consistency Test**: PASS
5. **Feature Order Verification Test**: PASS

### STEP 15 Final System Validation (All Passed)
1. **Model Loading & Verification**: PASS
2. **Scaler Loading & Features**: PASS
3. **Label Encoder & 15 Classes**: PASS
4. **Feature Order Alignment (53 features)**: PASS
5. **End-to-End Pipeline Inference**: PASS
6. **Web Application Syntax & Structure**: PASS

## 16. Project Architecture
```
Dataset (2.52M Rows)
        ↓
Data Preprocessing (Deduplication, Cleaning)
        ↓
Feature Selection (53 Selected Features)
        ↓
Label Encoding (15 Classes)
        ↓
Stratified Train/Test Split (80% / 20%)
        ↓
Controlled SMOTE (Training Data Only)
        ↓
StandardScaler (Fitted on Train Only)
        ↓
Model Training & Comparison (RF vs Extra Trees)
        ↓
Model Evaluation & Selection (Extra Trees Selected)
        ↓
Serialized Artifacts (`models/scaler.pkl`, `models/label_encoder.pkl`, `extra_trees_model.pkl`)
        ↓
Inference Engine (`inference/nids_inference.py`)
        ↓
Streamlit Web Interface (`app/app.py`)
```

## 17. Limitations
- **Extreme Class Imbalance**: Ultra-rare attacks (e.g. Heartbleed with 10 total samples, SQL Injection with 20) have wider confidence intervals.
- **Offline Batch Processing**: Input flows represent completed statistical summaries rather than raw live PCAP stream parsing.
- **Feature Computation Requirement**: Requires external flow generation tools (e.g. CICFlowMeter) to extract the 53 statistical features from packet streams.

## 18. Future Improvements
- **Live Packet Capture Integration**: Integration with `libpcap` / `scapy` and real-time flow exporters.
- **Deep Learning / Temporal Models**: Hybrid CNN-LSTM / Transformer architectures for sequential packet dynamics.
- **Active Alerting Engine**: Webhook / SIEM integrations (Splunk, Elastic) for automated alert dispatches.
- **Continuous Learning Loop**: Feedback-driven model retraining pipeline for emerging zero-day exploit variants.

## 19. Conclusion
The Network Intrusion Detection System project successfully delivers a production-grade, highly accurate (99.87% test accuracy, 0.8766 Macro F1) intrusion classification pipeline. By adhering to rigorous data science standards—including leak-free scaling, controlled training-only SMOTE, reproducible feature ordering, and extensive end-to-end validation—the system provides a reliable, explainable, and accessible interface for network traffic threat detection.
