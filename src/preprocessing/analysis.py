import pandas as pd
import numpy as np
import glob
import os


# =========================================================
# 1. FIND CSV FILES
# =========================================================

folder = r"D:\MachineLearningCVE"

files = glob.glob(os.path.join(folder, "*.csv"))

print("CSV files found:", len(files))

for file in files:
    print("-", os.path.basename(file))


# =========================================================
# 2. LOAD CSV FILES
# =========================================================

dataframes = []

for file in files:

    print("\nLoading:", os.path.basename(file))

    temp = pd.read_csv(file)

    # Clean column names
    temp.columns = temp.columns.str.strip()

    dataframes.append(temp)


# =========================================================
# 3. COMBINE DATASETS
# =========================================================

df = pd.concat(
    dataframes,
    ignore_index=True
)

print("\n========================================")
print("COMBINED DATASET")
print("========================================")

print("Rows:", df.shape[0])
print("Columns:", df.shape[1])


# =========================================================
# 4. DATA CLEANING
# =========================================================

print("\n========================================")
print("STARTING DATA CLEANING")
print("========================================")


# ---------------------------------------------------------
# Replace infinite values
# ---------------------------------------------------------

numeric_columns = df.select_dtypes(
    include=np.number
).columns

df[numeric_columns] = df[numeric_columns].replace(
    [np.inf, -np.inf],
    np.nan
)


# ---------------------------------------------------------
# Remove missing values
# ---------------------------------------------------------

print("\nMissing values:")

missing = df.isnull().sum()

print(
    missing[missing > 0]
)

before = len(df)

df = df.dropna()

print(
    "Rows removed because of missing values:",
    before - len(df)
)


# ---------------------------------------------------------
# Remove duplicates
# ---------------------------------------------------------

before = len(df)

df = df.drop_duplicates()

print(
    "Duplicate rows removed:",
    before - len(df)
)


# ---------------------------------------------------------
# Reset index
# ---------------------------------------------------------

df = df.reset_index(drop=True)


# =========================================================
# 5. REMOVE CONSTANT FEATURES
# =========================================================

print("\n========================================")
print("CONSTANT FEATURES")
print("========================================")


X = df.drop(columns=["Label"])

constant_features = X.columns[
    X.nunique() <= 1
]

print(
    "Constant features:",
    len(constant_features)
)

for feature in constant_features:
    print("-", feature)


# Remove them
df = df.drop(
    columns=list(constant_features)
)


# =========================================================
# 6. CHECK DATASET AFTER CONSTANT FEATURE REMOVAL
# =========================================================

print("\n========================================")
print("AFTER CONSTANT FEATURE REMOVAL")
print("========================================")

print("Rows:", df.shape[0])
print("Columns:", df.shape[1])
print("Features:", df.shape[1] - 1)


# =========================================================
# 7. CHECK NEGATIVE VALUES
# =========================================================

print("\n========================================")
print("NEGATIVE VALUES")
print("========================================")

X = df.drop(columns=["Label"])

negative_counts = (X < 0).sum()

negative_counts = negative_counts[
    negative_counts > 0
].sort_values(
    ascending=False
)

print(negative_counts)


# =========================================================
# 8. CORRELATION ANALYSIS
# =========================================================

print("\n========================================")
print("CORRELATION ANALYSIS")
print("========================================")

# Calculate absolute correlation
corr_matrix = X.corr().abs()


# Upper triangle only
upper_triangle = corr_matrix.where(
    np.triu(
        np.ones(corr_matrix.shape),
        k=1
    ).astype(bool)
)


# ---------------------------------------------------------
# Find correlations >= 0.95
# ---------------------------------------------------------

high_corr_pairs = []

for column in upper_triangle.columns:

    for row in upper_triangle.index:

        value = upper_triangle.loc[row, column]

        if pd.notna(value) and value >= 0.95:

            high_corr_pairs.append(
                (
                    row,
                    column,
                    value
                )
            )


# Convert to DataFrame
high_corr_df = pd.DataFrame(
    high_corr_pairs,
    columns=[
        "Feature 1",
        "Feature 2",
        "Correlation"
    ]
)


# Sort
if len(high_corr_df) > 0:

    high_corr_df = high_corr_df.sort_values(
        by="Correlation",
        ascending=False
    )


# =========================================================
# 9. DISPLAY RESULTS
# =========================================================

print("\n========================================")
print("HIGHLY CORRELATED FEATURES")
print("========================================")

print(
    "Number of highly correlated pairs:",
    len(high_corr_df)
)


if len(high_corr_df) > 0:

    print(
        high_corr_df.to_string(
            index=False
        )
    )

else:

    print(
        "No feature pairs with correlation >= 0.95"
    )


# =========================================================
# 10. FEATURES TO CONSIDER REMOVING
# =========================================================

features_to_remove = set()

for _, row in high_corr_df.iterrows():

    features_to_remove.add(
        row["Feature 2"]
    )


print("\n========================================")
print("FEATURES TO CONSIDER REMOVING")
print("========================================")

print(
    "Number:",
    len(features_to_remove)
)

for feature in sorted(features_to_remove):

    print(
        "-",
        feature
    )


# =========================================================
# 11. FINAL SUMMARY
# =========================================================

print("\n========================================")
print("FINAL SUMMARY")
print("========================================")

print("Rows:", df.shape[0])
print("Columns:", df.shape[1])
print("Features:", df.shape[1] - 1)

print(
    "Missing values:",
    df.isnull().sum().sum()
)

print(
    "Duplicate rows:",
    df.duplicated().sum()
)

print(
    "Constant features remaining:",
    len(
        df.drop(columns=["Label"]).columns[
            df.drop(columns=["Label"]).nunique() <= 1
        ]
    )
)

print("\nDone.")
# =========================================================
# STEP 14 - REMOVE REDUNDANT FEATURES
# =========================================================

features_to_remove = [
    "Avg Bwd Segment Size",
    "Avg Fwd Segment Size",
    "Fwd Header Length.1",
    "Fwd IAT Total",
    "Fwd IAT Max",
    "Fwd Packet Length Std",
    "Fwd Packets/s",
    "Idle Max",
    "Idle Mean",
    "Idle Min",
    "Packet Length Std",
    "Subflow Bwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Fwd Packets",
    "Total Backward Packets",
    "Total Length of Bwd Packets"
]

print("\n========================================")
print("REMOVING REDUNDANT FEATURES")
print("========================================")

print("Features before:", df.shape[1] - 1)

df = df.drop(
    columns=features_to_remove
)

print("Features removed:",
      len(features_to_remove))

print("Features after:",
      df.shape[1] - 1)


# =========================================================
# VERIFY
# =========================================================

print("\n========================================")
print("FEATURES REMAINING")
print("========================================")

X = df.drop(columns=["Label"])

print("Number of features:", X.shape[1])

print("\nFeature names:")

for i, feature in enumerate(X.columns, start=1):
    print(i, "-", feature)


# =========================================================
# FINAL CHECK
# =========================================================

print("\n========================================")
print("DATASET STATUS")
print("========================================")

print("Rows:", df.shape[0])
print("Columns:", df.shape[1])
print("Features:", df.shape[1] - 1)

print("Missing values:",
      df.isnull().sum().sum())

print("Duplicate rows:",
      df.duplicated().sum())
# =========================================================
# REMOVE DUPLICATES AGAIN AFTER FEATURE SELECTION
# =========================================================

print("\n========================================")
print("FINAL DUPLICATE REMOVAL")
print("========================================")

before = len(df)

df = df.drop_duplicates()

removed = before - len(df)

print("Duplicates removed:", removed)

df = df.reset_index(drop=True)

print("Rows after duplicate removal:", len(df))


# =========================================================
# FINAL DATASET CHECK
# =========================================================

print("\n========================================")
print("FINAL DATASET")
print("========================================")

print("Rows:", df.shape[0])
print("Columns:", df.shape[1])
print("Features:", df.shape[1] - 1)

print("Missing values:",
      df.isnull().sum().sum())

print("Infinite values:",
      np.isinf(
          df.select_dtypes(include=np.number)
      ).sum().sum())

print("Duplicate rows:",
      df.duplicated().sum())

print("\nLabel distribution:")

print("Label distribution printed safely to avoid encoding errors.")
try:
    print(df["Label"].value_counts())
except UnicodeEncodeError:
    # Print safe version if console encoding doesn't support the characters
    safe_series = df["Label"].value_counts()
    for idx, val in safe_series.items():
        print(f"{idx.encode('ascii', 'replace').decode('ascii')}: {val}")

# =========================================================
# SAVE CLEANED DATASET
# =========================================================

dataset_path = r"D:\7th sem project\data\processed\cleaned_dataset.csv"
df.to_csv(dataset_path, index=False)

print("\n========================================")
print("CLEANED DATASET SAVED")
print("========================================")
print("Path:", dataset_path)
print("Rows:", df.shape[0])
print("Columns:", df.shape[1])
print("========================================\n")
# =========================================================
# STEP 15 - KNOWN vs UNSEEN ATTACK SPLIT
# =========================================================

print("\n========================================")
print("KNOWN vs UNSEEN ATTACK EXPERIMENT")
print("========================================")


# ---------------------------------------------------------
# 1. Define known attack classes
# ---------------------------------------------------------

known_attacks = [
    "DoS Hulk",
    "DDoS",
    "PortScan",
    "DoS GoldenEye",
    "FTP-Patator",
    "SSH-Patator",
    "DoS slowloris",
    "DoS Slowhttptest"
]


# ---------------------------------------------------------
# 2. Define unseen attack classes
# ---------------------------------------------------------

unseen_attacks = [
    "Bot",
    "Web Attack � Brute Force",
    "Web Attack � XSS",
    "Web Attack � Sql Injection",
    "Infiltration",
    "Heartbleed"
]


# ---------------------------------------------------------
# 3. Check that all classes exist
# ---------------------------------------------------------

all_labels = set(df["Label"].unique())

print("\nKnown attacks:")
for attack in known_attacks:
    print("-", attack, "->", attack in all_labels)

print("\nUnseen attacks:")
for attack in unseen_attacks:
    print("-", attack, "->", attack in all_labels)


# ---------------------------------------------------------
# 4. Create known dataset
# ---------------------------------------------------------

known_labels = ["BENIGN"] + known_attacks

known_df = df[
    df["Label"].isin(known_labels)
].copy()


# ---------------------------------------------------------
# 5. Create unseen dataset
# ---------------------------------------------------------

unseen_df = df[
    df["Label"].isin(unseen_attacks)
].copy()


# =========================================================
# 6. DISPLAY DISTRIBUTION
# =========================================================

print("\n========================================")
print("KNOWN DATASET")
print("========================================")

print("Rows:", len(known_df))

print("\nLabel distribution:")
print("Label distribution printed safely to avoid encoding errors.")
try:
    print(known_df["Label"].value_counts())
except UnicodeEncodeError:
    safe_series = known_df["Label"].value_counts()
    for idx, val in safe_series.items():
        print(f"{idx.encode('ascii', 'replace').decode('ascii')}: {val}")


print("\n========================================")
print("UNSEEN DATASET")
print("========================================")

print("Rows:", len(unseen_df))

print("\nLabel distribution:")
print("Label distribution printed safely to avoid encoding errors.")
try:
    print(unseen_df["Label"].value_counts())
except UnicodeEncodeError:
    safe_series = unseen_df["Label"].value_counts()
    for idx, val in safe_series.items():
        print(f"{idx.encode('ascii', 'replace').decode('ascii')}: {val}")


# =========================================================
# 7. VERIFY NO UNSEEN ATTACK IS IN KNOWN DATA
# =========================================================

overlap = set(
    known_df["Label"].unique()
).intersection(
    set(unseen_df["Label"].unique())
)


print("\n========================================")
print("OVERLAP CHECK")
print("========================================")

print("Overlap between known and unseen:", overlap)


# =========================================================
# 8. VERIFY FINAL CLASSES
# =========================================================

print("\n========================================")
print("KNOWN CLASSES")
print("========================================")

print(
    sorted(
        known_df["Label"].unique()
    )
)


print("\n========================================")
print("UNSEEN CLASSES")
print("========================================")

print(
    sorted(
        unseen_df["Label"].unique()
    )
)


# =========================================================
# 9. SUMMARY
# =========================================================

print("\n========================================")
print("EXPERIMENT SUMMARY")
print("========================================")

print("Total dataset rows:", len(df))

print("Known dataset rows:", len(known_df))

print("Unseen dataset rows:", len(unseen_df))

print(
    "Known attack classes:",
    len(known_attacks)
)

print(
    "Unseen attack classes:",
    len(unseen_attacks)
)

print("\nKnown attacks:")
for attack in known_attacks:
    print("-", attack)

print("\nUnseen attacks:")
for attack in unseen_attacks:
    print("-", attack)

print("\nExperiment split completed.")
# ========================================
# SAVE FINAL CLEANED DATASET
# ========================================

output_file = r"D:\7th sem project\data\processed\cleaned_dataset.csv"

df.to_csv(output_file, index=False)

print("\n========================================")
print("DATASET SAVED SUCCESSFULLY")
print("========================================")
print("File:", output_file)
print("Rows:", df.shape[0])
print("Columns:", df.shape[1])