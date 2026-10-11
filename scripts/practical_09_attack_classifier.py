"""
Practical 9: To Build a Simple Classifier to Detect Attacks
Objective: Train machine learning models to classify web access log requests as Benign or Malicious Attack.
- Feature Selection: Use behavioral, structural, and syntactic features engineered in Practical 5.
- Dataset Partitioning: Stratified 80/20 Train-Test split.
- Model Training:
    1. Logistic Regression (Linear baseline model with standard scaling)
    2. Random Forest Classifier (Ensemble decision trees with feature importance)
- Evaluation Metrics:
    * Accuracy, Precision, Recall, F1-Score
    * Confusion Matrix (True Positives, False Positives, False Negatives, True Negatives)
    * Classification Report
    * Feature Importance Ranking
- Visualizations:
    * Confusion Matrix Heatmap (figures/p09_confusion_matrix.png)
    * ROC Curve (figures/p09_roc_curve.png)
"""

import os
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report, roc_curve, auc

INPUT_FILE = "data/balanced_dataset_sample.csv" if os.path.exists("data") else "../data/balanced_dataset_sample.csv"
FIGURES_DIR = "figures" if os.path.exists("figures") else "../figures"
OUTPUTS_DIR = "outputs" if os.path.exists("outputs") else "../outputs"

FEATURE_COLUMNS = [
    'requests_per_ip',
    'time_diff_sec',
    'payload_length',
    'key_length',
    'payload_entropy',
    'special_char_count',
    'special_char_ratio',
    'has_digits',
    'is_scanner_ua',
    'is_headless_tool',
    'is_missing_ua',
    'has_accept_lang'
]

def main():
    print("=" * 80)
    print("PRACTICAL 9: BUILD A MACHINE LEARNING CLASSIFIER TO DETECT ATTACKS")
    print("=" * 80)

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Running Practical 6 first...")
        from practical_06_dataset_balancing import main as run_p6
        run_p6()

    df = pd.read_csv(INPUT_FILE, low_memory=False)
    print(f"\n[+] Loaded {len(df):,} balanced rows from {INPUT_FILE}")

    X = df[FEATURE_COLUMNS].fillna(0)
    y = df['is_attack']

    print(f"\n[+] Features Selected ({len(FEATURE_COLUMNS)} variables):")
    for f in FEATURE_COLUMNS:
        print(f"    - {f}")

    # 1. Stratified Train-Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"\n[+] Train-Test Split Completed:")
    print(f"    - Training Set: {len(X_train):,} samples (50% benign, 50% attack)")
    print(f"    - Testing Set : {len(X_test):,} samples (50% benign, 50% attack)")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 2. Model 1: Logistic Regression
    print("\n[+] Training Model 1: Logistic Regression...")
    lr_model = LogisticRegression(max_iter=1000, random_state=42)
    lr_model.fit(X_train_scaled, y_train)
    y_pred_lr = lr_model.predict(X_test_scaled)
    y_prob_lr = lr_model.predict_proba(X_test_scaled)[:, 1]

    lr_acc = accuracy_score(y_test, y_pred_lr)
    lr_prec = precision_score(y_test, y_pred_lr)
    lr_rec = recall_score(y_test, y_pred_lr)
    lr_f1 = f1_score(y_test, y_pred_lr)

    print(f"    - Logistic Regression Accuracy : {lr_acc*100:.2f}%")
    print(f"    - Logistic Regression Precision: {lr_prec*100:.2f}%")
    print(f"    - Logistic Regression Recall   : {lr_rec*100:.2f}%")
    print(f"    - Logistic Regression F1-Score : {lr_f1*100:.2f}%")

    # 3. Model 2: Random Forest Classifier
    print("\n[+] Training Model 2: Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf_model.fit(X_train, y_train)
    y_pred_rf = rf_model.predict(X_test)
    y_prob_rf = rf_model.predict_proba(X_test)[:, 1]

    rf_acc = accuracy_score(y_test, y_pred_rf)
    rf_prec = precision_score(y_test, y_pred_rf)
    rf_rec = recall_score(y_test, y_pred_rf)
    rf_f1 = f1_score(y_test, y_pred_rf)

    print(f"    - Random Forest Accuracy : {rf_acc*100:.2f}%")
    print(f"    - Random Forest Precision: {rf_prec*100:.2f}%")
    print(f"    - Random Forest Recall   : {rf_rec*100:.2f}%")
    print(f"    - Random Forest F1-Score : {rf_f1*100:.2f}%")

    print("\n[+] Detailed Classification Report (Random Forest):")
    print("-" * 80)
    print(classification_report(y_test, y_pred_rf, target_names=["Benign (0)", "Attack (1)"]))

    # 4. Feature Importance
    importances = rf_model.feature_importances_
    feat_imp = pd.Series(importances, index=FEATURE_COLUMNS).sort_values(ascending=False)
    print("\n[+] Random Forest Feature Importance Ranking:")
    print("-" * 80)
    for feat, imp in feat_imp.items():
        print(f"    - {feat:<22}: {imp*100:.2f}%")

    # 5. Visualizations
    os.makedirs(FIGURES_DIR, exist_ok=True)
    os.makedirs(OUTPUTS_DIR, exist_ok=True)

    # Plot Confusion Matrix
    cm = confusion_matrix(y_test, y_pred_rf)
    fig, ax = plt.subplots(figsize=(6, 5), dpi=150)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False, ax=ax,
                xticklabels=['Pred: Benign', 'Pred: Attack'],
                yticklabels=['Actual: Benign', 'Actual: Attack'])
    ax.set_title('Random Forest - Confusion Matrix', fontweight='bold', pad=15)
    plt.tight_layout()
    cm_path = os.path.join(FIGURES_DIR, "p09_confusion_matrix.png")
    plt.savefig(cm_path)
    plt.close()

    # Plot ROC Curve Comparison
    fpr_lr, tpr_lr, _ = roc_curve(y_test, y_prob_lr)
    fpr_rf, tpr_rf, _ = roc_curve(y_test, y_prob_rf)
    auc_lr = auc(fpr_lr, tpr_lr)
    auc_rf = auc(fpr_rf, tpr_rf)

    fig, ax = plt.subplots(figsize=(7, 5), dpi=150)
    ax.plot(fpr_lr, tpr_lr, color='#f59e0b', lw=2, label=f'Logistic Regression (AUC = {auc_lr:.4f})')
    ax.plot(fpr_rf, tpr_rf, color='#10b981', lw=2, label=f'Random Forest (AUC = {auc_rf:.4f})')
    ax.plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--')
    ax.set_title('ROC Curves - Attack Detection Models', fontweight='bold', pad=15)
    ax.set_xlabel('False Positive Rate (1 - Specificity)')
    ax.set_ylabel('True Positive Rate (Recall / Sensitivity)')
    ax.legend(loc='lower right', frameon=True)
    plt.tight_layout()
    roc_path = os.path.join(FIGURES_DIR, "p09_roc_curve.png")
    plt.savefig(roc_path)
    plt.close()

    # Save metrics JSON
    metrics = {
        "models": {
            "logistic_regression": {
                "accuracy": round(lr_acc, 4),
                "precision": round(lr_prec, 4),
                "recall": round(lr_rec, 4),
                "f1_score": round(lr_f1, 4),
                "roc_auc": round(auc_lr, 4)
            },
            "random_forest": {
                "accuracy": round(rf_acc, 4),
                "precision": round(rf_prec, 4),
                "recall": round(rf_rec, 4),
                "f1_score": round(rf_f1, 4),
                "roc_auc": round(auc_rf, 4)
            }
        },
        "top_features": feat_imp.to_dict()
    }
    with open(os.path.join(OUTPUTS_DIR, "p09_model_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n[+] Saved Confusion Matrix to: {cm_path}")
    print(f"[+] Saved ROC Curve to: {roc_path}")
    print(f"[+] Saved Model Metrics JSON to: {os.path.join(OUTPUTS_DIR, 'p09_model_metrics.json')}")

    print("\n[✓] Practical 9 Complete: Classifier trained, evaluated, and performance verified.")

if __name__ == "__main__":
    main()
