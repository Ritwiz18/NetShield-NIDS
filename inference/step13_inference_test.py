"""
==================================================
STEP 13: END-TO-END NIDS INFERENCE TEST
==================================================
Runs all 5 validation tests against the STEP 12
inference pipeline and writes a full report to:
  D:\\7th sem project\\results\\STEP_13_INFERENCE_TEST.txt

No model training. No SMOTE. No preprocessing changes.
"""

import os
import sys
import subprocess
import tempfile
import csv
import io
import traceback
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import joblib

# ─────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────
PROJECT_ROOT    = r"D:\7th sem project"
RESULTS_DIR     = os.path.join(PROJECT_ROOT, "results")
INFERENCE_DIR   = os.path.join(PROJECT_ROOT, "inference")
MODELS_DIR      = os.path.join(PROJECT_ROOT, "models")

INFERENCE_SCRIPT   = os.path.join(INFERENCE_DIR, "nids_inference.py")
SAMPLE_BATCH       = os.path.join(INFERENCE_DIR, "sample_batch.csv")
FINAL_MODEL_TXT    = os.path.join(RESULTS_DIR,   "final_model.txt")
ET_MODEL_PATH      = os.path.join(PROJECT_ROOT,  "extra_trees_model.pkl")
RF_MODEL_PATH      = os.path.join(MODELS_DIR,    "random_forest_model.pkl")
SCALER_PATH        = os.path.join(MODELS_DIR,    "scaler.pkl")
ENCODER_PATH       = os.path.join(MODELS_DIR,    "label_encoder.pkl")
DATASET_PATH       = os.path.join(PROJECT_ROOT,  "data", "processed", "cleaned_dataset.csv")
BATCH_OUT_PATH     = os.path.join(RESULTS_DIR,   "inference_batch_results.csv")
REPORT_PATH        = os.path.join(RESULTS_DIR,   "STEP_13_INFERENCE_TEST.txt")

# ─────────────────────────────────────────────────────────────
# EXACT 53 FEATURES — must match cleaned_dataset.csv column order
# ─────────────────────────────────────────────────────────────
TRAINING_FEATURE_ORDER = [
    "Destination Port",            # 0
    "Flow Duration",               # 1
    "Total Fwd Packets",           # 2
    "Total Length of Fwd Packets", # 3
    "Fwd Packet Length Max",       # 4
    "Fwd Packet Length Min",       # 5
    "Fwd Packet Length Mean",      # 6
    "Bwd Packet Length Max",       # 7
    "Bwd Packet Length Min",       # 8
    "Bwd Packet Length Mean",      # 9
    "Bwd Packet Length Std",       # 10
    "Flow Bytes/s",                # 11
    "Flow Packets/s",              # 12
    "Flow IAT Mean",               # 13
    "Flow IAT Std",                # 14
    "Flow IAT Max",                # 15
    "Flow IAT Min",                # 16
    "Fwd IAT Mean",                # 17
    "Fwd IAT Std",                 # 18
    "Fwd IAT Min",                 # 19
    "Bwd IAT Total",               # 20
    "Bwd IAT Mean",                # 21
    "Bwd IAT Std",                 # 22
    "Bwd IAT Max",                 # 23
    "Bwd IAT Min",                 # 24
    "Fwd PSH Flags",               # 25
    "Fwd URG Flags",               # 26
    "Fwd Header Length",           # 27
    "Bwd Header Length",           # 28
    "Bwd Packets/s",               # 29
    "Min Packet Length",           # 30
    "Max Packet Length",           # 31
    "Packet Length Mean",          # 32
    "Packet Length Variance",      # 33
    "FIN Flag Count",              # 34
    "SYN Flag Count",              # 35
    "RST Flag Count",              # 36
    "PSH Flag Count",              # 37
    "ACK Flag Count",              # 38
    "URG Flag Count",              # 39
    "CWE Flag Count",              # 40
    "ECE Flag Count",              # 41
    "Down/Up Ratio",               # 42
    "Average Packet Size",         # 43
    "Init_Win_bytes_forward",      # 44
    "Init_Win_bytes_backward",     # 45
    "act_data_pkt_fwd",            # 46
    "min_seg_size_forward",        # 47
    "Active Mean",                 # 48
    "Active Std",                  # 49
    "Active Max",                  # 50
    "Active Min",                  # 51
    "Idle Std",                    # 52
]

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

class TestResult:
    def __init__(self, name):
        self.name    = name
        self.passed  = False
        self.details = []
        self.errors  = []

    def ok(self, msg):
        self.details.append(f"  [OK]   {msg}")

    def fail(self, msg):
        self.errors.append(f"  [FAIL] {msg}")

    def info(self, msg):
        self.details.append(f"         {msg}")

    def finalize(self):
        self.passed = len(self.errors) == 0
        return self.passed

    def status_str(self):
        return "PASS" if self.passed else "FAIL"

    def report_lines(self):
        lines = [f"\n{'='*60}", f"TEST: {self.name}", f"Result: {self.status_str()}", ""]
        lines += self.details
        if self.errors:
            lines += ["", "Errors:"]
            lines += self.errors
        return lines


def load_inference_feature_names():
    """Parse FEATURE_NAMES from nids_inference.py by importing it as a module."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("nids_inference", INFERENCE_SCRIPT)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.FEATURE_NAMES


# ─────────────────────────────────────────────────────────────
# TEST 1: DEMO MODE
# ─────────────────────────────────────────────────────────────

def test_demo_mode() -> TestResult:
    t = TestResult("TEST 1 — Demo Mode")
    print("\n" + "="*60)
    print("TEST 1: DEMO MODE")
    print("="*60)

    try:
        result = subprocess.run(
            [sys.executable, INFERENCE_SCRIPT, "--mode", "demo"],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout + result.stderr

        if result.returncode == 0:
            t.ok("Script exited with code 0 (success)")
        else:
            t.fail(f"Script exited with code {result.returncode}")
            t.errors.append(f"  stderr: {result.stderr[:500]}")

        checks = {
            "Model loads"          : "Loading model",
            "Scaler loads"         : "Loading scaler",
            "Encoder loads"        : "Loading encoder",
            "53 features expected" : "Features expected  : 53",
            "Predictions generated": "Predicted Label",
            "Confidence shown"     : "Confidence",
            "Labels displayed"     : "BENIGN",
        }
        for check, needle in checks.items():
            if needle in output:
                t.ok(check)
            else:
                t.fail(f"{check} — '{needle}' not found in output")

        # Print trimmed output
        print(output[:2000])

    except subprocess.TimeoutExpired:
        t.fail("Demo mode timed out after 120 seconds")
    except Exception as e:
        t.fail(f"Unexpected error: {e}")

    t.finalize()
    print(f"\n>> TEST 1 RESULT: {t.status_str()}")
    return t


# ─────────────────────────────────────────────────────────────
# TEST 2: BATCH MODE
# ─────────────────────────────────────────────────────────────

def test_batch_mode() -> TestResult:
    t = TestResult("TEST 2 — Batch Mode")
    print("\n" + "="*60)
    print("TEST 2: BATCH MODE")
    print("="*60)

    try:
        result = subprocess.run(
            [sys.executable, INFERENCE_SCRIPT, "--mode", "batch",
             "--input", SAMPLE_BATCH],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout + result.stderr

        if result.returncode == 0:
            t.ok("Script exited with code 0 (success)")
        else:
            t.fail(f"Script exited with code {result.returncode}")

        # Check output file
        batch_out = os.path.join(INFERENCE_DIR, "batch_predictions.csv")
        if os.path.exists(batch_out):
            t.ok(f"batch_predictions.csv created at: {batch_out}")

            # Read results
            df_res = pd.read_csv(batch_out)
            n_rows = len(df_res)
            t.ok(f"Rows predicted: {n_rows}")
            t.info(f"Columns: {list(df_res.columns)}")

            if "Predicted_Label" in df_res.columns:
                t.ok("Predicted_Label column present")
                for lbl in df_res["Predicted_Label"].tolist():
                    t.info(f"  -> {lbl}")
            else:
                t.fail("Predicted_Label column missing")

            if "Confidence" in df_res.columns:
                t.ok("Confidence column present")
                for conf in df_res["Confidence"].tolist():
                    t.info(f"  Confidence: {conf:.4f} ({conf*100:.2f}%)")
                nan_count = df_res["Confidence"].isna().sum()
                inf_count = np.isinf(df_res["Confidence"]).sum()
                if nan_count == 0 and inf_count == 0:
                    t.ok("No NaN or Inf in Confidence values")
                else:
                    t.fail(f"NaN={nan_count}, Inf={inf_count} in Confidence")
            else:
                t.fail("Confidence column missing")

            if "Match" in df_res.columns:
                acc = df_res["Match"].mean()
                t.info(f"Accuracy vs true labels: {acc:.4f} ({acc*100:.2f}%)")

            # Copy to results dir
            df_res.to_csv(BATCH_OUT_PATH, index=False)
            t.ok(f"Results also saved to: {BATCH_OUT_PATH}")

        else:
            t.fail(f"batch_predictions.csv not found at {batch_out}")

        print(output[:1500])

    except subprocess.TimeoutExpired:
        t.fail("Batch mode timed out after 300 seconds")
    except Exception as e:
        t.fail(f"Unexpected error: {e}")
        traceback.print_exc()

    t.finalize()
    print(f"\n>> TEST 2 RESULT: {t.status_str()}")
    return t


# ─────────────────────────────────────────────────────────────
# TEST 3: INVALID INPUT HANDLING
# ─────────────────────────────────────────────────────────────

def test_invalid_input() -> TestResult:
    t = TestResult("TEST 3 — Invalid Input Handling")
    print("\n" + "="*60)
    print("TEST 3: INVALID INPUT TEST")
    print("="*60)

    # Create a temp CSV with wrong number of features (only 10)
    tmp_path = os.path.join(INFERENCE_DIR, "_tmp_invalid_test.csv")
    wrong_cols = ["Feature_A", "Feature_B", "Feature_C",
                  "Feature_D", "Feature_E", "Feature_F",
                  "Feature_G", "Feature_H", "Feature_I", "Feature_J"]
    df_bad = pd.DataFrame([[0.0] * 10], columns=wrong_cols)
    df_bad.to_csv(tmp_path, index=False)
    t.info(f"Temporary invalid CSV created: {tmp_path} (10 columns, not 53)")

    try:
        result = subprocess.run(
            [sys.executable, INFERENCE_SCRIPT, "--mode", "batch",
             "--input", tmp_path],
            capture_output=True, text=True, timeout=60
        )
        stdout = result.stdout
        stderr = result.stderr
        combined = stdout + stderr

        # The inference script raises ValueError for missing features,
        # which exits with code 1 — that is correct controlled rejection.
        if result.returncode != 0:
            t.ok(f"Script correctly returned non-zero exit code ({result.returncode}) for invalid input")
        else:
            # Exit 0 is only acceptable if a clear warning was printed
            if any(kw in combined.lower() for kw in ["missing", "error", "feature", "required", "warning"]):
                t.ok("Script exited 0 but printed a clear error/warning message")
            else:
                t.fail("Script exited 0 with no error for invalid input (silent failure)")

        # Check that an informative message was produced in stdout or stderr
        if any(kw in combined.lower() for kw in ["missing", "required", "feature", "error", "not found", "valueerror"]):
            t.ok("Clear error message found in script output")
            # Show first 500 chars of stderr to confirm content
            excerpt = (stderr or stdout)[:500].strip()
            t.info(f"Error message (excerpt): {excerpt}")
        else:
            t.fail("No clear error message produced")

        # A controlled ValueError traceback in stderr is ACCEPTABLE (it means
        # the script detected the problem and raised an explicit error).
        # An UNACCEPTABLE crash would be AttributeError / IndexError / KeyError
        # that indicates a silent failure mode.
        uncontrolled_errors = ["AttributeError", "IndexError", "KeyError", "MemoryError"]
        has_uncontrolled = any(e in stderr for e in uncontrolled_errors)
        if has_uncontrolled:
            t.fail("Uncontrolled exception detected: " +
                   next(e for e in uncontrolled_errors if e in stderr))
        else:
            t.ok("No uncontrolled exception (AttributeError/IndexError/KeyError) detected")

    except subprocess.TimeoutExpired:
        t.fail("Invalid input test timed out")
    except Exception as e:
        t.fail(f"Unexpected error running invalid input test: {e}")
    finally:
        # Always remove the temporary file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
            t.ok(f"Temporary invalid CSV removed: {tmp_path}")

    t.finalize()
    print(f"\n>> TEST 3 RESULT: {t.status_str()}")
    return t


# ─────────────────────────────────────────────────────────────
# TEST 4: MODEL CONSISTENCY
# ─────────────────────────────────────────────────────────────

def test_model_consistency() -> TestResult:
    t = TestResult("TEST 4 — Model Consistency")
    print("\n" + "="*60)
    print("TEST 4: MODEL CONSISTENCY")
    print("="*60)

    try:
        # 4a. Read final_model.txt
        if not os.path.exists(FINAL_MODEL_TXT):
            t.fail(f"final_model.txt not found: {FINAL_MODEL_TXT}")
            t.finalize(); return t

        with open(FINAL_MODEL_TXT) as fh:
            selected = fh.read().strip()
        t.ok(f"final_model.txt reads: '{selected}'")

        if selected == "Extra Trees":
            t.ok("Selected model is 'Extra Trees' as expected")
            model_path = ET_MODEL_PATH
        elif selected == "Random Forest":
            t.ok("Selected model is 'Random Forest'")
            model_path = RF_MODEL_PATH
        else:
            t.fail(f"Unexpected model name: '{selected}'")
            t.finalize(); return t

        # 4b. Verify model file exists and loads
        if not os.path.exists(model_path):
            t.fail(f"Model file not found: {model_path}")
        else:
            t.ok(f"Model file exists: {model_path}")
            model = joblib.load(model_path)
            t.ok(f"Model loaded successfully: {type(model).__name__}")
            if hasattr(model, "n_features_in_"):
                t.ok(f"Model expects {model.n_features_in_} features")
                if model.n_features_in_ == 53:
                    t.ok("Feature count matches expected: 53")
                else:
                    t.fail(f"Feature count mismatch: model={model.n_features_in_}, expected=53")
            if hasattr(model, "predict_proba"):
                t.ok("Model supports predict_proba() (confidence scores available)")

        # 4c. Verify scaler
        if not os.path.exists(SCALER_PATH):
            t.fail(f"scaler.pkl not found: {SCALER_PATH}")
        else:
            t.ok(f"scaler.pkl exists: {SCALER_PATH}")
            scaler = joblib.load(SCALER_PATH)
            t.ok(f"Scaler loaded: {type(scaler).__name__}")
            if hasattr(scaler, "transform"):
                t.ok("Scaler has .transform() method")
            if hasattr(scaler, "mean_"):
                t.ok(f"Scaler fitted on {len(scaler.mean_)} features")

        # 4d. Verify label encoder
        if not os.path.exists(ENCODER_PATH):
            t.fail(f"label_encoder.pkl not found: {ENCODER_PATH}")
        else:
            t.ok(f"label_encoder.pkl exists: {ENCODER_PATH}")
            encoder = joblib.load(ENCODER_PATH)
            t.ok(f"Encoder loaded: {type(encoder).__name__}")
            if hasattr(encoder, "classes_"):
                safe_classes = [c.encode("ascii", errors="replace").decode("ascii")
                                for c in encoder.classes_]
                t.ok(f"Encoder classes ({len(encoder.classes_)}): {safe_classes}")
                if len(encoder.classes_) == 15:
                    t.ok("Encoder has 15 classes as expected")
                else:
                    t.fail(f"Encoder has {len(encoder.classes_)} classes, expected 15")
            if hasattr(encoder, "inverse_transform"):
                t.ok("Encoder has .inverse_transform() method")

        print("\n".join(t.details + t.errors))

    except Exception as e:
        t.fail(f"Unexpected error: {e}")
        traceback.print_exc()

    t.finalize()
    print(f"\n>> TEST 4 RESULT: {t.status_str()}")
    return t


# ─────────────────────────────────────────────────────────────
# TEST 5: FEATURE ORDER VERIFICATION
# ─────────────────────────────────────────────────────────────

def test_feature_order() -> TestResult:
    t = TestResult("TEST 5 — Feature Order Verification")
    print("\n" + "="*60)
    print("TEST 5: FEATURE ORDER")
    print("="*60)

    try:
        # 5a. Load feature order from inference script
        inference_features = load_inference_feature_names()
        t.ok(f"Loaded {len(inference_features)} features from nids_inference.py")

        # 5b. Load feature order from dataset header
        if not os.path.exists(DATASET_PATH):
            t.fail(f"Dataset not found: {DATASET_PATH}")
            t.finalize(); return t

        df_header = pd.read_csv(DATASET_PATH, nrows=0)
        dataset_features = [c for c in df_header.columns if c != "Label"]
        t.ok(f"Loaded {len(dataset_features)} features from cleaned_dataset.csv header")

        # 5c. Compare counts
        if len(inference_features) == len(dataset_features):
            t.ok(f"Feature count matches: {len(inference_features)}")
        else:
            t.fail(f"Count mismatch: inference={len(inference_features)}, dataset={len(dataset_features)}")

        # 5d. Compare order element by element
        mismatches = []
        for i, (inf_f, dat_f) in enumerate(zip(inference_features, dataset_features)):
            if inf_f != dat_f:
                mismatches.append((i, inf_f, dat_f))

        if not mismatches:
            t.ok("All 53 features match exactly in correct order")
        else:
            for pos, inf_f, dat_f in mismatches:
                t.fail(f"Position {pos}: inference='{inf_f}' | dataset='{dat_f}'")

        # 5e. Compare against TRAINING_FEATURE_ORDER constant in THIS script
        script_mismatches = []
        for i, (script_f, dat_f) in enumerate(zip(TRAINING_FEATURE_ORDER, dataset_features)):
            if script_f != dat_f:
                script_mismatches.append((i, script_f, dat_f))
        if not script_mismatches:
            t.ok("TRAINING_FEATURE_ORDER in test script also matches dataset")
        else:
            for pos, sf, df_ in script_mismatches:
                t.fail(f"Script constant pos {pos}: '{sf}' vs dataset '{df_}'")

        # 5f. Print full feature comparison table
        print(f"\n{'Pos':<5}{'Dataset Column':<40}{'Inference Script':<40}{'Match'}")
        print("-" * 90)
        max_len = max(len(inference_features), len(dataset_features))
        for i in range(max_len):
            d_f = dataset_features[i] if i < len(dataset_features) else "-- MISSING --"
            i_f = inference_features[i] if i < len(inference_features) else "-- MISSING --"
            match = "[OK]" if d_f == i_f else "[MISMATCH]"
            print(f"{i:<5}{d_f:<40}{i_f:<40}{match}")

    except Exception as e:
        t.fail(f"Unexpected error: {e}")
        traceback.print_exc()

    t.finalize()
    print(f"\n>> TEST 5 RESULT: {t.status_str()}")
    return t


# ─────────────────────────────────────────────────────────────
# WRITE REPORT
# ─────────────────────────────────────────────────────────────

def write_report(results: list, batch_df=None):
    lines = []
    lines.append("=" * 70)
    lines.append("NIDS INFERENCE SYSTEM — STEP 13 END-TO-END TEST REPORT")
    lines.append("=" * 70)
    lines.append(f"Project      : D:\\7th sem project")
    lines.append(f"Model        : Extra Trees")
    lines.append(f"Features     : 53")
    lines.append(f"Classes      : 15")
    lines.append("")
    lines.append("─" * 70)
    lines.append("SUMMARY")
    lines.append("─" * 70)

    all_pass = all(r.passed for r in results)
    for r in results:
        lines.append(f"  {r.name:<45} {r.status_str()}")

    lines.append("")
    lines.append(f"End-to-end result: {'PASS' if all_pass else 'FAIL'}")
    lines.append("")

    # Detailed results per test
    for r in results:
        lines += r.report_lines()

    # Batch prediction details
    if batch_df is not None:
        lines.append("\n" + "=" * 70)
        lines.append("BATCH PREDICTION DETAILS")
        lines.append("=" * 70)
        lines.append(f"Samples tested: {len(batch_df)}")
        lines.append(f"Predictions generated: {len(batch_df)}")
        lines.append("")
        if "True_Label" in batch_df.columns:
            lines.append(f"{'#':<5}{'True Label':<40}{'Predicted Label':<40}{'Confidence':<12}{'Match'}")
            lines.append("-" * 105)
            for i, row in batch_df.iterrows():
                conf_str = f"{row['Confidence']:.4f}" if "Confidence" in row else "N/A"
                match_str = "[OK]" if row.get("Match", False) else "[WRONG]"
                lines.append(f"{i+1:<5}{str(row.get('True_Label','?')):<40}"
                              f"{str(row['Predicted_Label']):<40}{conf_str:<12}{match_str}")
        else:
            lines.append(f"{'#':<5}{'Predicted Label':<40}{'Confidence'}")
            lines.append("-" * 65)
            for i, row in batch_df.iterrows():
                conf_str = f"{row['Confidence']:.4f}" if "Confidence" in row else "N/A"
                lines.append(f"{i+1:<5}{str(row['Predicted_Label']):<40}{conf_str}")

    lines.append("\n" + "=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"\n[Report saved] {REPORT_PATH}")
    return all_pass


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("STEP 13: END-TO-END NIDS INFERENCE TEST")
    print("=" * 60)

    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Run all 5 tests
    t1 = test_demo_mode()
    t2 = test_batch_mode()
    t3 = test_invalid_input()
    t4 = test_model_consistency()
    t5 = test_feature_order()

    results = [t1, t2, t3, t4, t5]

    # Try to load batch results for report
    batch_df = None
    if os.path.exists(BATCH_OUT_PATH):
        try:
            batch_df = pd.read_csv(BATCH_OUT_PATH)
        except Exception:
            pass

    all_pass = write_report(results, batch_df)

    # ─── FINAL PRINT ───────────────────────────────────────────
    print("\n")
    print("=" * 50)
    print("STEP 13 COMPLETED")
    print("=" * 50)
    print()
    print(f"End-to-end inference test:  {'PASS' if all_pass else 'FAIL'}")
    print()
    print(f"Demo test:                  {t1.status_str()}")
    print(f"Batch test:                 {t2.status_str()}")
    print(f"Invalid input test:         {t3.status_str()}")
    print(f"Feature order test:         {t5.status_str()}")
    print(f"Model consistency test:     {t4.status_str()}")
    print()
    print("Model:                      Extra Trees")
    print("Features:                   53")
    print()
    print(f"Results saved to:")
    print(f"  {REPORT_PATH}")
    print(f"  {BATCH_OUT_PATH}")
    print()
    print("Stopped. Awaiting STEP 14 instruction.")
    print("=" * 50)


if __name__ == "__main__":
    main()
