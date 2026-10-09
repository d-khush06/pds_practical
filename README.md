# Python for Data Science (PDS) — Honeypot Log Analysis & ML Pipeline

A comprehensive data science workflow and interactive dashboard analyzing raw honeypot access logs (`cj.log`). This repository covers 10 sequential practicals moving from raw log ingestion to feature engineering, threat classification, and an end-to-end reusable pipeline.

---

## 📌 Practicals Overview

| Practical | Title | Description |
|---|---|---|
| **P01** | Load & Explore Log Data | Read raw unstructured JSON-formatted log streams and inspect field structures. |
| **P02** | Structured Dataset Creation | Transform raw arrays into structured tabular Pandas DataFrames. |
| **P03** | Data Cleaning & Preprocessing | URL decode payloads, clean User-Agents, handle missing values, and cast types. |
| **P04** | Attack Labeling & Categorization | Signature-based labeling for SQLi, XSS, Path Traversal, Command Injection, and Scanners. |
| **P05** | Feature Engineering | Extract Shannon entropy, request velocity, payload lengths, and scanner flags. |
| **P06** | Dataset Balancing | Handle class imbalance using stratified sampling and undersampling benign records. |
| **P07** | Data Wrangling & Aggregation | Group by IP and hourly windows to aggregate request counts and threat density. |
| **P08** | Exploratory Data Analysis & Visualization | Correlation heatmaps, attack frequency distributions, and hourly trends. |
| **P09** | Machine Learning Attack Classifier | Train and evaluate Random Forest models with confusion matrix and ROC curves. |
| **P10** | Reusable Data Pipeline | Production-grade `LogSecurityPipeline` class supporting real-time stream threat inference. |

---

## 📂 Repository Structure

```
├── Practical List for the Python for Data Science.pdf  # Lab syllabus & requirements
├── data/                                              # Processed sample datasets (CSV)
├── figures/                                           # Generated charts & analytical plots
├── notebooks/                                         # Jupyter Notebooks for each practical
├── scripts/                                           # Standalone runnable Python scripts (P01-P10)
├── outputs/                                           # Model metrics, aggregations, and pipeline outputs
├── dashboard-react/                                   # Interactive React + Vite security dashboard
├── app.js / index.html / styles.css                   # Standalone web viewer
└── web_data.json                                      # Unified practical metadata & outputs
```

---

## 🚀 Getting Started

### 1. Python Environment Setup
```bash
# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install required dependencies
pip install pandas numpy scikit-learn matplotlib seaborn jupyter
```

### 2. Running Individual Practicals
```bash
python scripts/practical_01_load_explore.py
python scripts/practical_09_attack_classifier.py
python scripts/practical_10_reusable_pipeline.py
```

### 3. Launching the Interactive React Dashboard
```bash
cd dashboard-react
npm install
npm run dev
```

---

## 📄 Note on Raw Logs
The raw honeypot file `cj.log` (>200 MB) is excluded via `.gitignore` to comply with GitHub file size restrictions. Structured sample extracts and pipeline test inputs are included under [`data/`](file:///home/khush/Downloads/PDS_Practicals/data) and [`outputs/`](file:///home/khush/Downloads/PDS_Practicals/outputs).
