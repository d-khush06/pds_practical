"""
Practical 10: To Create a Reusable Data Pipeline for the Log File
Objective: Wrap the entire log processing and inference workflow into a modular, production-ready pipeline.
- Class: `LogSecurityPipeline`
    * Step 1: `load_raw_logs(filepath, max_lines)` - Ingests raw JSON/unstructured log stream.
    * Step 2: `parse_and_structure()` - Transforms raw arrays into structured tabular format.
    * Step 3: `clean_and_preprocess()` - Handles missing values, URL decoding, and type casting.
    * Step 4: `engineer_features()` - Computes entropy, request velocity, UA fingerprints.
    * Step 5: `label_data()` - Applies signature-based attack taxonomy.
    * Step 6: `fit_classifier()` - Fits Random Forest ML classifier for automated detection.
    * Step 7: `predict_stream(raw_log_lines)` - Real-time zero-day/anomaly inference on new incoming logs.
- Export pipeline processed outputs as CSV and Parquet files.
"""

import os
import re
import json
import math
import urllib.parse
import pandas as pd
import numpy as np
from collections import Counter
from sklearn.ensemble import RandomForestClassifier

SQLI_PATTERN = re.compile(r"('|--|union\s+select|select\s+.*from|sleep\(|benchmark\(|order\s+by|\b1=1\b|or\s+true)", re.IGNORECASE)
PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini|windows/system32|boot\.ini)", re.IGNORECASE)
CMD_INJECTION_PATTERN = re.compile(r"(;|\&\&|\|)\s*(cat\s+|ls|ps|wget\s+|curl\s+|rm\s+-rf|id\b|whoami|chmod|chown)|passthru\(|system\(|shell_exec\(", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script|alert\(|javascript:|onerror=|onload=|<img\s+src=)", re.IGNORECASE)
RFI_PATTERN = re.compile(r"(https?://|ftp://|rfiinc\.txt)", re.IGNORECASE)
SCANNER_UA_PATTERN = re.compile(r"(nikto|dirbuster|gobuster|sqlmap|nmap|zgrab|masscan|wpscan|python-requests|go-http-client|curl/|censys)", re.IGNORECASE)

class LogSecurityPipeline:
    def __init__(self):
        self.feature_columns = [
            'requests_per_ip', 'time_diff_sec', 'payload_length', 'key_length',
            'payload_entropy', 'special_char_count', 'special_char_ratio',
            'has_digits', 'is_scanner_ua', 'is_headless_tool', 'is_missing_ua', 'has_accept_lang'
        ]
        self.classifier = None
        self.known_ip_counts = {}

    @staticmethod
    def _entropy(text):
        if not text or text in ['none', 'nan']:
            return 0.0
        n = len(text)
        if n <= 1:
            return 0.0
        counts = Counter(text)
        return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 4)

    @staticmethod
    def _count_special(text):
        if not text or text == 'none':
            return 0
        return len(re.findall(r"['\";<>\(\)\{\}\[\]/\\%\$\*\+\-\=\&\|]", text))

    def parse_raw_records(self, raw_lines):
        records = []
        for line in raw_lines:
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
            except Exception:
                continue
        return pd.DataFrame(records)

    def clean_records(self, df):
        df = df.copy()
        df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df['hour'] = df['datetime'].dt.hour.fillna(0).astype(int)
        df['client_port'] = pd.to_numeric(df['client_port'], errors='coerce').fillna(0).astype(int)
        df['param_key'] = df['param_key'].fillna('none').astype(str).str.strip().str.lower()

        def clean_val(v):
            if v is None:
                return 'none'
            if isinstance(v, (list, tuple, dict)):
                return str(v).strip().lower()
            try:
                if pd.isna(v):
                    return 'none'
            except (ValueError, TypeError):
                pass
            s = str(v).strip()
            if s.lower() in ['none', 'nan', '']:
                return 'none'
            try:
                return urllib.parse.unquote(s).strip().lower()
            except Exception:
                return s.strip().lower()

        df['param_value_clean'] = df['param_value'].apply(clean_val)
        df['user_agent_clean'] = df['user_agent'].fillna('unknown').astype(str).str.strip()
        df['accept_language'] = df['accept_language'].fillna('missing').astype(str).str.strip()
        df['client_ip'] = df['client_ip'].astype(str).str.strip()
        return df

    def label_records(self, df):
        df = df.copy()
        def classify(row):
            k = str(row['param_key']).lower()
            v = str(row['param_value_clean']).lower()
            ua = str(row['user_agent_clean']).lower()

            if k in ['ls', 'ps', 'cat', 'id', 'whoami'] or CMD_INJECTION_PATTERN.search(v) or CMD_INJECTION_PATTERN.search(k):
                return 'cmd_injection'
            if PATH_TRAVERSAL_PATTERN.search(v) or PATH_TRAVERSAL_PATTERN.search(k):
                return 'path_traversal'
            if SQLI_PATTERN.search(v) or SQLI_PATTERN.search(k):
                return 'sqli'
            if XSS_PATTERN.search(v):
                return 'xss'
            if RFI_PATTERN.search(v):
                return 'rfi'
            if SCANNER_UA_PATTERN.search(ua):
                return 'scanner_recon'
            return 'benign'

        df['attack_category'] = df.apply(classify, axis=1)
        df['is_attack'] = (df['attack_category'] != 'benign').astype(int)
        return df

    def extract_features(self, df):
        df = df.copy()
        # IP counts
        current_ip_counts = df['client_ip'].value_counts().to_dict()
        df['requests_per_ip'] = df['client_ip'].map(lambda ip: self.known_ip_counts.get(ip, 0) + current_ip_counts.get(ip, 1))

        # Time diff
        df['prev_time'] = df.groupby('client_ip')['datetime'].shift(1)
        df['time_diff_sec'] = (df['datetime'] - df['prev_time']).dt.total_seconds().fillna(60.0).clip(0.0, 3600.0)
        df.drop(columns=['prev_time'], inplace=True)

        payloads = df['param_value_clean'].astype(str)
        keys = df['param_key'].astype(str)

        df['payload_length'] = payloads.apply(lambda s: 0 if s in ['none', 'nan'] else len(s))
        df['key_length'] = keys.apply(lambda s: 0 if s in ['none', 'nan'] else len(s))
        df['payload_entropy'] = payloads.apply(self._entropy)
        df['special_char_count'] = payloads.apply(self._count_special)
        df['special_char_ratio'] = np.where(df['payload_length'] > 0, 
                                            (df['special_char_count'] / df['payload_length']).round(4), 
                                            0.0)
        df['has_digits'] = payloads.apply(lambda s: 1 if re.search(r'\d', s) else 0)

        ua_lower = df['user_agent_clean'].astype(str).str.lower()
        df['is_scanner_ua'] = ua_lower.str.contains(r'nikto|dirbuster|gobuster|sqlmap|nmap|zgrab|masscan', regex=True).astype(int)
        df['is_headless_tool'] = ua_lower.str.contains(r'python-requests|go-http-client|curl|wget', regex=True).astype(int)
        df['is_missing_ua'] = (df['user_agent_clean'] == 'unknown').astype(int)
        df['has_accept_lang'] = (df['accept_language'] != 'missing').astype(int)
        return df

    def fit(self, raw_lines):
        print("[Pipeline] Ingesting and training on baseline batch...")
        df_raw = self.parse_raw_records(raw_lines)
        df_clean = self.clean_records(df_raw)
        df_labeled = self.label_records(df_clean)
        df_feat = self.extract_features(df_labeled)

        # Update known IP counts
        for ip, cnt in df_feat['client_ip'].value_counts().items():
            self.known_ip_counts[ip] = self.known_ip_counts.get(ip, 0) + cnt

        X = df_feat[self.feature_columns].fillna(0)
        y = df_feat['is_attack']

        self.classifier = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        self.classifier.fit(X, y)
        print(f"[Pipeline] Classifier successfully trained on {len(X):,} events.")
        return df_feat

    def predict_stream(self, raw_stream_lines):
        """Simulates real-time stream ingestion and threat inference."""
        if self.classifier is None:
            raise ValueError("Pipeline model is not fitted yet.")

        df_raw = self.parse_raw_records(raw_stream_lines)
        df_clean = self.clean_records(df_raw)
        df_feat = self.extract_features(df_clean)

        X = df_feat[self.feature_columns].fillna(0)
        preds = self.classifier.predict(X)
        probs = self.classifier.predict_proba(X)[:, 1]

        df_feat['predicted_label'] = np.where(preds == 1, 'MALICIOUS_ATTACK', 'BENIGN')
        df_feat['attack_probability'] = probs.round(4)
        return df_feat[['client_ip', 'param_key', 'param_value_clean', 'user_agent_clean', 'predicted_label', 'attack_probability']]

def main():
    print("=" * 80)
    print("PRACTICAL 10: END-TO-END REUSABLE LOG PROCESSING & THREAT DETECTION PIPELINE")
    print("=" * 80)

    pipeline = LogSecurityPipeline()

    # Ingest training batch (first 30,000 lines)
    print("\n[+] Step 1: Loading raw training logs from cj.log...")
    train_lines = []
    with open("cj.log", "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= 30000:
                break
            train_lines.append(line)

    print(f"    - Read {len(train_lines):,} raw lines.")
    processed_df = pipeline.fit(train_lines)

    # Export structured output as CSV & Parquet
    os.makedirs("outputs", exist_ok=True)
    csv_path = "outputs/pipeline_processed_dataset.csv"
    parquet_path = "outputs/pipeline_processed_dataset.parquet"
    
    # Save a clean subset
    export_cols = ['datetime', 'client_ip', 'param_key', 'param_value_clean', 'user_agent_clean', 'attack_category', 'is_attack'] + pipeline.feature_columns
    processed_df[export_cols].to_csv(csv_path, index=False)
    try:
        processed_df[export_cols].to_parquet(parquet_path, index=False)
        print(f"[+] Exported pipeline data to Parquet: {parquet_path}")
    except Exception as e:
        print(f"[!] Parquet export note: {e}")

    print(f"[+] Exported pipeline data to CSV: {csv_path} ({len(processed_df):,} rows)")

    # Simulate real-time streaming inference
    print("\n[+] Step 2: Testing Real-Time Streaming Inference on New Incoming Logs...")
    test_stream = [
        # Benign browser request
        json.dumps([None, None, "2023-01-15 10:00:00", "192.168.1.50", "51234", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/110.0", "en-US", "10.0.0.1"]),
        # SQL Injection attempt
        json.dumps(["id", "1' OR '1'='1", "2023-01-15 10:00:01", "45.33.32.156", "44122", "sqlmap/1.6.12#stable", None, "10.0.0.1"]),
        # Directory Buster scanner
        json.dumps([None, None, "2023-01-15 10:00:02", "198.51.100.22", "38910", "DirBuster-1.0-RC1", None, "10.0.0.1"]),
        # Command Injection
        json.dumps(["cmd", ";cat /etc/passwd", "2023-01-15 10:00:03", "185.220.101.5", "59801", "curl/7.68.0", None, "10.0.0.1"]),
        # XSS Payload
        json.dumps(["search", "<script>alert('pwned')</script>", "2023-01-15 10:00:04", "203.0.113.88", "61022", "Mozilla/5.0 Firefox/110.0", "en", "10.0.0.1"])
    ]

    results = pipeline.predict_stream(test_stream)
    print("\n[+] Real-Time Streaming Detection Results:")
    print("-" * 80)
    for idx, row in results.iterrows():
        status_color = "[ALERT!]" if row['predicted_label'] == 'MALICIOUS_ATTACK' else "[OK]"
        print(f"{status_color} IP: {row['client_ip']:<15} | Param: {row['param_key']:<7} | Val: {row['param_value_clean'][:25]:<25} | Pred: {row['predicted_label']:<16} | Conf: {row['attack_probability']*100:.1f}%")

    print("\n[✓] Practical 10 Complete: End-to-end reusable pipeline operational.")

if __name__ == "__main__":
    main()
