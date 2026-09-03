import os
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt

def main():
    print("==================================================")
    print("STEP 9: RANDOM FOREST FEATURE IMPORTANCE ANALYSIS")
    print("==================================================")

    # Paths (using the newly restructured directories)
    model_path = r"D:\7th sem project\models\random_forest_model.pkl"
    dataset_path = r"D:\7th sem project\data\processed\cleaned_dataset.csv"
    results_dir = r"D:\7th sem project\results"
    
    csv_out_path = os.path.join(results_dir, "feature_importance.csv")
    img_out_path = os.path.join(results_dir, "feature_importance_top20.png")

    # 1. Load model
    if not os.path.exists(model_path):
        print(f"ERROR: Model file not found at {model_path}")
        return

    print("Loading Random Forest model...")
    model = joblib.load(model_path)

    # 2. Extract feature importances
    if not hasattr(model, "feature_importances_"):
        print("ERROR: Loaded model does not contain 'feature_importances_'. Are you sure it's a Random Forest?")
        return
        
    importances = model.feature_importances_
    
    # 3. Load feature names
    print("Loading feature names from dataset...")
    if not os.path.exists(dataset_path):
        print(f"ERROR: Dataset not found at {dataset_path}")
        return
        
    # Read just the header to get feature names
    df_sample = pd.read_csv(dataset_path, nrows=0)
    
    if "Label" not in df_sample.columns:
        print("ERROR: 'Label' column not found in the dataset.")
        return
        
    feature_names = df_sample.drop(columns=["Label"]).columns.tolist()

    # Verify counts
    num_model_features = len(importances)
    num_dataset_features = len(feature_names)
    
    if num_model_features != 53 or num_dataset_features != 53:
        print("ERROR: Feature count mismatch!")
        print(f"Model expects {num_model_features} features.")
        print(f"Dataset contains {num_dataset_features} features.")
        print("Expected exactly 53 features. Stopping.")
        return

    # 4. Create DataFrame and sort
    fi_df = pd.DataFrame({
        "Feature": feature_names,
        "Importance": importances
    })
    fi_df = fi_df.sort_values(by="Importance", ascending=False).reset_index(drop=True)

    # 5. Print complete ranked table
    print("\n========================================")
    print("COMPLETE FEATURE IMPORTANCE RANKING")
    print("========================================")
    print(fi_df.to_string(index=True))

    # 6. Print TOP 20
    top_20 = fi_df.head(20)
    print("\n========================================")
    print("TOP 20 MOST IMPORTANT FEATURES")
    print("========================================")
    print(top_20.to_string(index=True))

    # 7. Save to CSV
    os.makedirs(results_dir, exist_ok=True)
    fi_df.to_csv(csv_out_path, index=False)
    
    # 8. Create Plot (matplotlib only)
    # We want highest importance at the top of the bar chart, so we need to reverse the order for plotting
    top_20_reversed = top_20.iloc[::-1]
    
    plt.figure(figsize=(10, 8))
    plt.barh(top_20_reversed["Feature"], top_20_reversed["Importance"], color="skyblue", edgecolor="black")
    plt.xlabel("Importance")
    plt.ylabel("Feature")
    plt.title("Random Forest - Top 20 Feature Importance")
    plt.tight_layout()
    plt.savefig(img_out_path, dpi=300)
    plt.close()

    # 9. Verification Summary
    print("\n========================================")
    print("STEP 9 COMPLETED")
    print("========================================")
    print(f"Total features: {num_model_features}")
    print(f"Feature importance calculated: YES")
    print(f"Feature importance CSV saved: YES")
    print(f"Top 20 feature chart saved: YES")
    print("\nCSV:")
    print(csv_out_path)
    print("\nChart:")
    print(img_out_path)

if __name__ == "__main__":
    main()
