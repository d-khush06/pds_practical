"""
Practical 2: To Convert the Unstructured Log Data into a Structured Dataset
Objective: Parse raw log data into structured tabular form.
- Parse JSON/regex records into defined schema fields:
    * IP address (client_ip)
    * Date/time (timestamp)
    * Request/Param key (param_key)
    * Payload/Resource requested (param_value)
    * Client port (client_port)
    * User-agent (user_agent)
    * Accept-Language header (accept_language)
    * Target server IP (target_ip)
- Store data in a Pandas DataFrame.
- Display summary statistics, column data types, missing value percentages, and preview rows.
- Save structured sample dataset into data/structured_logs_sample.csv.
"""

import os
import json
import pandas as pd

LOG_FILE = "cj.log" if os.path.exists("cj.log") else "../cj.log"
OUTPUT_SAMPLE = "data/structured_logs_sample.csv" if os.path.exists("data") else "../data/structured_logs_sample.csv"
SAMPLE_SIZE = 50000

def parse_logs_to_dataframe(filepath, limit=50000):
    records = []
    skipped_count = 0
    
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            line_str = line.strip()
            if not line_str:
                continue
            try:
                item = json.loads(line_str)
                if isinstance(item, list) and len(item) == 8:
                    records.append({
                        "param_key": item[0],
                        "param_value": item[1],
                        "timestamp": item[2],
                        "client_ip": item[3],
                        "client_port": item[4],
                        "user_agent": item[5],
                        "accept_language": item[6],
                        "target_ip": item[7]
                    })
                else:
                    skipped_count += 1
            except Exception:
                skipped_count += 1
                
    df = pd.DataFrame(records)
    return df, skipped_count

def main():
    print("=" * 80)
    print("PRACTICAL 2: CONVERT UNSTRUCTURED LOG DATA INTO STRUCTURED DATASET")
    print("=" * 80)

    if not os.path.exists(LOG_FILE):
        print(f"Error: {LOG_FILE} not found.")
        return

    print(f"\n[+] Parsing first {SAMPLE_SIZE:,} lines from {LOG_FILE} into Pandas DataFrame...")
    df, skipped = parse_logs_to_dataframe(LOG_FILE, limit=SAMPLE_SIZE)
    print(f"    - Successfully parsed {len(df):,} structured records.")
    print(f"    - Skipped/Corrupt lines: {skipped}")

    print("\n[+] Structured DataFrame Schema & Dimensions:")
    print(f"    - Shape: {df.shape[0]:,} rows x {df.shape[1]} columns")
    print(f"    - Memory Usage: {df.memory_usage(deep=True).sum() / (1024 * 1024):.2f} MB")

    print("\n[+] Column Info & Data Types:")
    print(df.dtypes)

    print("\n[+] Missing Values Breakdown:")
    missing = df.isnull().sum()
    missing_pct = (missing / len(df)) * 100
    missing_df = pd.DataFrame({"Missing Count": missing, "Percentage (%)": missing_pct.round(2)})
    print(missing_df)

    print("\n[+] Sample First 5 Structured Records:")
    print("-" * 80)
    print(df.head(5).to_string(index=True))

    # Save structured sample to data/
    os.makedirs("data", exist_ok=True)
    df.to_csv(OUTPUT_SAMPLE, index=False)
    print(f"\n[+] Exported structured dataset to: {OUTPUT_SAMPLE} ({len(df):,} records)")

    print("\n[✓] Practical 2 Complete: Log data converted into structured tabular dataset.")

if __name__ == "__main__":
    main()
