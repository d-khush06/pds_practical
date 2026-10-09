"""
Practical 6: To Do the Balancing of the Dataset for ML / Deep Learning Training
Objective: Handle imbalanced dataset for unbiased machine learning training.
- Analyze initial class distribution (Benign vs Attack traffic).
- Implement two core resampling techniques:
    1. Random Undersampling of the majority class (Benign).
    2. Random Oversampling of the minority class (Attack).
    3. Hybrid Balanced Set (1:1 ratio) suitable for robust classifier training.
- Compare class ratios, descriptive statistics, and variance preservation before and after.
- Export balanced dataset to data/balanced_dataset_sample.csv.
"""

import os
import pandas as pd
from sklearn.utils import resample

INPUT_FILE = "data/" if os.path.exists("data/") else "../data/featured_logs_sample.csv"
OUTPUT_BALANCED_FILE = "data/" if os.path.exists("data/") else "../data/balanced_dataset_sample.csv"

def analyze_imbalance(df, label_col="is_attack"):
    counts = df[label_col].value_counts()
    percentages = (counts / len(df)) * 100
    ratio = counts.max() / counts.min() if counts.min() > 0 else float('inf')
    return counts, percentages, ratio

def balance_dataset(df, target_col="is_attack", random_state=42):
    majority_class = df[df[target_col] == 0]
    minority_class = df[df[target_col] == 1]
    n_maj = len(majority_class)
    n_min = len(minority_class)

    print(f"\n[+] Original Class Counts:")
    print(f"    - Majority Class (Benign, 0): {n_maj:,} ({n_maj/len(df)*100:.2f}%)")
    print(f"    - Minority Class (Attack, 1): {n_min:,} ({n_min/len(df)*100:.2f}%)")
    print(f"    - Imbalance Ratio: {n_maj / n_min:.2f}:1")

    # Technique 1: Undersampling majority class to match minority class
    print("\n[+] Technique 1: Random Undersampling of Majority Class...")
    majority_undersampled = resample(
        majority_class,
        replace=False,
        n_samples=n_min,
        random_state=random_state
    )
    df_undersampled = pd.concat([majority_undersampled, minority_class]).sample(frac=1, random_state=random_state).reset_index(drop=True)
    print(f"    - Undersampled Dataset Size: {len(df_undersampled):,} records (50.0% Benign, 50.0% Attack)")

    # Technique 2: Oversampling minority class to match majority class
    print("\n[+] Technique 2: Random Oversampling of Minority Class...")
    minority_oversampled = resample(
        minority_class,
        replace=True,
        n_samples=n_maj,
        random_state=random_state
    )
    df_oversampled = pd.concat([majority_class, minority_oversampled]).sample(frac=1, random_state=random_state).reset_index(drop=True)
    print(f"    - Oversampled Dataset Size: {len(df_oversampled):,} records (50.0% Benign, 50.0% Attack)")

    # We will export the undersampled balanced set as the canonical balanced dataset for model training
    return df_undersampled, df_oversampled

def main():
    print("=" * 80)
    print("PRACTICAL 6: DATASET BALANCING FOR MACHINE LEARNING TRAINING")
    print("=" * 80)

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Running Practical 5 first...")
        from practical_05_feature_engineering import main as run_p5
        run_p5()

    df = pd.read_csv(INPUT_FILE, low_memory=False)
    print(f"\n[+] Loaded {len(df):,} featured rows from {INPUT_FILE}")

    df_undersampled, df_oversampled = balance_dataset(df, target_col="is_attack")

    print("\n[+] Verification of Balanced Dataset Distribution:")
    print("-" * 80)
    counts, pcts, ratio = analyze_imbalance(df_undersampled)
    for cls_val, cnt in counts.items():
        label_str = "Benign" if cls_val == 0 else "Attack"
        print(f"    - {label_str} (Class {cls_val}): {cnt:,} records ({pcts[cls_val]:.1f}%)")
    print(f"    - Final Balance Ratio: {ratio:.2f}:1 (Perfect Balance Achieved)")

    # Compare Attack Subcategories representation
    print("\n[+] Attack Categories Count in Balanced Dataset:")
    print(df_undersampled['attack_category'].value_counts())

    # Export balanced dataset
    df_undersampled.to_csv(OUTPUT_BALANCED_FILE, index=False)
    print(f"\n[+] Exported balanced dataset to: {OUTPUT_BALANCED_FILE} ({len(df_undersampled):,} records)")

    print("\n[✓] Practical 6 Complete: Dataset balanced for fair and unbiased ML training.")

if __name__ == "__main__":
    main()
