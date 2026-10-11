"""
Practical 3: To Clean the Data and Preprocessing for Further Process of Dataset
Objective: Clean structured data for analysis.
- Convert timestamp to datetime format.
- Handle missing values and inconsistent entries (fill NaNs with meaningful defaults).
- Normalize URL paths/payloads (URL decode, strip extraneous whitespace).
- Lowercase strings and standardize formatting.
- Cast client_port to numeric, dropping corrupted/invalid rows if any.
- Extract temporal features: hour, day of week, date.
- Save cleaned dataset to data/cleaned_logs_sample.csv.
"""

import os
import urllib.parse
import pandas as pd

INPUT_FILE = "data/structured_logs_sample.csv" if os.path.exists("data") else "../data/structured_logs_sample.csv"
OUTPUT_FILE = "data/cleaned_logs_sample.csv" if os.path.exists("data") else "../data/cleaned_logs_sample.csv"

def clean_and_preprocess(df):
    initial_rows = len(df)
    print(f"\n[+] Starting data cleaning on {initial_rows:,} records...")

    # 1. Convert timestamp to datetime
    print("    - Converting 'timestamp' to datetime...")
    df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
    invalid_dates = df['datetime'].isnull().sum()
    if invalid_dates > 0:
        df = df.dropna(subset=['datetime'])
        print(f"      [!] Dropped {invalid_dates} rows with invalid datetime.")

    # Extract temporal components
    df['date'] = df['datetime'].dt.date
    df['hour'] = df['datetime'].dt.hour
    df['day_name'] = df['datetime'].dt.day_name()
    df['is_weekend'] = df['datetime'].dt.dayofweek >= 5

    # 2. Clean client_port: convert to integer
    print("    - Cleaning 'client_port'...")
    df['client_port'] = pd.to_numeric(df['client_port'], errors='coerce').fillna(0).astype(int)

    # 3. Handle missing values for string columns
    print("    - Imputing missing values for text fields...")
    df['param_key'] = df['param_key'].fillna('none').astype(str).str.strip().str.lower()
    
    # URL decode and clean param_value
    def normalize_payload(val):
        if pd.isna(val) or val is None or str(val).lower() == 'none' or str(val).lower() == 'nan':
            return 'none'
        val_str = str(val).strip()
        try:
            val_str = urllib.parse.unquote(val_str)
        except Exception:
            pass
        return val_str.strip().lower()

    print("    - Normalizing and URL-decoding 'param_value'...")
    df['param_value_clean'] = df['param_value'].apply(normalize_payload)

    # Clean user_agent
    print("    - Standardizing 'user_agent'...")
    df['user_agent_clean'] = df['user_agent'].fillna('unknown').astype(str).str.strip()
    
    # Clean accept_language & target_ip
    df['accept_language'] = df['accept_language'].fillna('missing').astype(str).str.strip()
    df['target_ip'] = df['target_ip'].fillna('unknown').astype(str).str.strip()
    df['client_ip'] = df['client_ip'].astype(str).str.strip()

    print(f"    - Cleaning complete. Final records: {len(df):,} (Retained: {(len(df)/initial_rows)*100:.2f}%)")
    return df

def main():
    print("=" * 80)
    print("PRACTICAL 3: DATA CLEANING AND PREPROCESSING")
    print("=" * 80)

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Running Practical 2 first is recommended.")
        from practical_02_structured_dataset import main as run_p2
        run_p2()

    df = pd.read_csv(INPUT_FILE, low_memory=False)
    print(f"\n[+] Loaded {len(df):,} rows from {INPUT_FILE}")

    cleaned_df = clean_and_preprocess(df)

    print("\n[+] Cleaned Dataset Summary & Schema:")
    print("-" * 80)
    print(cleaned_df.info())

    print("\n[+] Verification of Missing Values after Imputation:")
    print(cleaned_df.isnull().sum())

    print("\n[+] Temporal Distribution (Requests by Hour):")
    print(cleaned_df['hour'].value_counts().sort_index().head(10))

    # Save cleaned dataset
    cleaned_df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[+] Exported cleaned dataset to: {OUTPUT_FILE} ({len(cleaned_df):,} records)")

    print("\n[✓] Practical 3 Complete: Structured log data cleaned, normalized, and preprocessed.")

if __name__ == "__main__":
    main()
