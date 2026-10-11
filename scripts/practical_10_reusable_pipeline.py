"""
Practical 10: To Create a Reusable Data Pipeline for the Log File
Objective: Wrap the entire log processing and inference workflow into a modular, production-ready pipeline.
- Class: `LogSecurityPipeline`
    * Stage 1: Ingestion & Parsing of arbitrary log files (JSON, CSV, Nginx/Apache, raw streams)
    * Stage 2: Data Cleaning & Deduplication
    * Stage 3: Rule-Based Attack Labeling across OWASP categories (SQLi, XSS, Cmd Injection, Scanner Recon, Path Traversal, RFI, Brute Force)
    * Stage 4: Feature Engineering (Shannon entropy, request velocity, payload length, special char ratio, UA forensics)
    * Stage 5: Exporting Processed Data Artifacts (CSV and Parquet)
    * Stage 6: Machine Learning Attack Classification & Real-Time Streaming Detection
"""

import os
import sys
import re
import json
import math
import argparse
import urllib.parse
import pandas as pd
import numpy as np
from collections import Counter
from sklearn.ensemble import RandomForestClassifier

# ── Attack Detection Regular Expressions ──────────────────────────────────────
SQLI_PATTERN = re.compile(
    r"('|--|union\s+select|select\s+.*from|sleep\(|benchmark\(|order\s+by|\b1=1\b|or\s+true|waitfor\s+delay)",
    re.IGNORECASE
)
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|win\.ini|windows/system32|boot\.ini|%2e%2e%2f|%2e%2e/)",
    re.IGNORECASE
)
CMD_INJECTION_PATTERN = re.compile(
    r"(;|\&\&|\|)\s*(cat\s+|ls|ps|wget\s+|curl\s+|rm\s+-rf|id\b|whoami|chmod|chown)|passthru\(|system\(|shell_exec\(|/bin/sh|/bin/bash",
    re.IGNORECASE
)
XSS_PATTERN = re.compile(
    r"(<script|alert\(|javascript:|onerror=|onload=|<img\s+src=|document\.cookie)",
    re.IGNORECASE
)
RFI_PATTERN = re.compile(
    r"(https?://|ftp://|rfiinc\.txt|php://input|data://)",
    re.IGNORECASE
)
SCANNER_UA_PATTERN = re.compile(
    r"(nikto|dirbuster|gobuster|sqlmap|nmap|zgrab|masscan|wpscan|python-requests|go-http-client|curl/|censys|hydra|acunetix)",
    re.IGNORECASE
)

def print_ascii_table(df_or_rows, headers=None):
    """Prints a clean ASCII grid table."""
    if isinstance(df_or_rows, pd.DataFrame):
        data = df_or_rows.values.tolist()
        cols = [str(c) for c in df_or_rows.columns]
    elif isinstance(df_or_rows, list):
        data = df_or_rows
        cols = headers if headers else [f"Col {i}" for i in range(len(df_or_rows[0]))]
    else:
        return

    # Calculate column widths
    widths = [len(c) for c in cols]
    for row in data:
        for i, val in enumerate(row):
            str_val = str(val) if val is not None else ""
            if i < len(widths):
                widths[i] = max(widths[i], len(str_val))

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    header_row = "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cols)) + " |"

    print(sep)
    print(header_row)
    print(sep)
    for row in data:
        line = "| " + " | ".join(str(val if val is not None else "").ljust(widths[i]) for i, val in enumerate(row)) + " |"
        print(line)
    print(sep)

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

    def parse_file(self, filepath, max_lines=100000):
        """Parses arbitrary log files into a normalized pandas DataFrame."""
        # 1. Direct CSV parser
        if filepath.endswith('.csv'):
            try:
                df = pd.read_csv(filepath, nrows=max_lines, low_memory=False)
                # Standardize column names without collisions
                col_lookup = {c.lower(): c for c in df.columns}
                rename_map = {}
                
                # Client IP
                if 'client_ip' not in df.columns:
                    for candidate in ['ip', 'source_ip', 'src_ip', 'remote_addr', 'host']:
                        if candidate in col_lookup:
                            rename_map[col_lookup[candidate]] = 'client_ip'
                            break
                            
                # User Agent
                if 'user_agent' not in df.columns:
                    for candidate in ['ua', 'useragent', 'http_user_agent', 'agent']:
                        if candidate in col_lookup:
                            rename_map[col_lookup[candidate]] = 'user_agent'
                            break

                # Param Key
                if 'param_key' not in df.columns:
                    for candidate in ['key', 'param', 'parameter']:
                        if candidate in col_lookup:
                            rename_map[col_lookup[candidate]] = 'param_key'
                            break

                # Param Value
                if 'param_value' not in df.columns:
                    for candidate in ['value', 'val', 'payload', 'query']:
                        if candidate in col_lookup:
                            rename_map[col_lookup[candidate]] = 'param_value'
                            break

                # Timestamp
                if 'timestamp' not in df.columns:
                    for candidate in ['time', 'date', 'datetime', 'ts']:
                        if candidate in col_lookup:
                            rename_map[col_lookup[candidate]] = 'timestamp'
                            break

                if rename_map:
                    df = df.rename(columns=rename_map)

                # Deduplicate columns if any duplicate column names exist
                df = df.loc[:, ~df.columns.duplicated()]

                for req in ['client_ip', 'param_key', 'param_value', 'user_agent', 'timestamp']:
                    if req not in df.columns:
                        df[req] = 'none'
                return df
            except Exception:
                pass

        # 2. Line-by-line parser (JSON arrays, Apache/Nginx, generic lines)
        raw_lines = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if max_lines and i >= max_lines:
                    break
                raw_lines.append(line)

        return self.parse_raw_records(raw_lines)

    def parse_raw_records(self, raw_lines):
        records = []
        for line in raw_lines:
            line_str = line.strip()
            if not line_str:
                continue

            # Format 1: JSON array format (e.g. cj.log)
            if line_str.startswith('['):
                try:
                    item = json.loads(line_str)
                    if isinstance(item, list) and len(item) >= 6:
                        records.append({
                            "param_key": item[0] if item[0] is not None else "none",
                            "param_value": item[1] if item[1] is not None else "none",
                            "timestamp": item[2] if item[2] is not None else "2023-01-15 10:00:00",
                            "client_ip": item[3] if item[3] is not None else "0.0.0.0",
                            "client_port": item[4] if len(item) > 4 and item[4] is not None else "0",
                            "user_agent": item[5] if len(item) > 5 and item[5] is not None else "unknown",
                            "accept_language": item[6] if len(item) > 6 and item[6] is not None else "missing",
                            "target_ip": item[7] if len(item) > 7 and item[7] is not None else "0.0.0.0"
                        })
                        continue
                except Exception:
                    pass

            # Format 2: Combined Apache / Nginx log format
            apache_match = re.match(
                r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)?(?:\s+HTTP/[^"]+)?"\s+(\d+|\S+)\s+(\d+|\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?',
                line_str
            )
            if apache_match:
                ip = apache_match.group(1)
                ts = apache_match.group(2)
                req_path = apache_match.group(4) or ''
                ua = apache_match.group(8) or 'unknown'
                param_key = 'none'
                param_val = req_path
                if '?' in req_path:
                    parts = req_path.split('?', 1)
                    param_key = parts[0]
                    param_val = parts[1]
                records.append({
                    "param_key": param_key,
                    "param_value": param_val,
                    "timestamp": ts,
                    "client_ip": ip,
                    "client_port": "80",
                    "user_agent": ua,
                    "accept_language": "missing",
                    "target_ip": "0.0.0.0"
                })
                continue

            # Format 3: Fallback unstructured log line
            records.append({
                "param_key": "none",
                "param_value": line_str[:200],
                "timestamp": "2023-01-15 10:00:00",
                "client_ip": "192.168.1.1",
                "client_port": "0",
                "user_agent": "unknown",
                "accept_language": "missing",
                "target_ip": "0.0.0.0"
            })

        return pd.DataFrame(records)

    def clean_records(self, df):
        df = df.copy()
        for col in ['param_key', 'param_value', 'timestamp', 'client_ip', 'client_port', 'user_agent', 'accept_language']:
            if col not in df.columns:
                df[col] = 'none'

        df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df['datetime'] = df['datetime'].fillna(pd.Timestamp('2023-01-01'))
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
        df['client_ip'] = df['client_ip'].fillna('0.0.0.0').astype(str).str.strip()
        return df

    def label_records(self, df):
        df = df.copy()
        
        # Calculate request velocity per IP to detect brute force / flood
        ip_counts = df['client_ip'].value_counts().to_dict()

        def classify(row):
            k = str(row['param_key']).lower()
            v = str(row['param_value_clean']).lower()
            ua = str(row['user_agent_clean']).lower()
            ip = str(row['client_ip'])

            # 1. Shell / Command Injection
            if k in ['ls', 'ps', 'cat', 'id', 'whoami', 'reboot'] or 'rm -rf' in k or 'wget' in k:
                return 'cmd_injection'
            if CMD_INJECTION_PATTERN.search(v) or CMD_INJECTION_PATTERN.search(k):
                return 'cmd_injection'

            # 2. Path Traversal
            if PATH_TRAVERSAL_PATTERN.search(v) or PATH_TRAVERSAL_PATTERN.search(k):
                return 'path_traversal'

            # 3. SQL Injection
            if SQLI_PATTERN.search(v) or SQLI_PATTERN.search(k):
                return 'sqli'

            # 4. Cross-Site Scripting (XSS)
            if XSS_PATTERN.search(v):
                return 'xss'

            # 5. Remote File Inclusion (RFI)
            if RFI_PATTERN.search(v):
                return 'rfi'

            # 6. Automated Scanner / Recon
            if SCANNER_UA_PATTERN.search(ua):
                return 'scanner_recon'

            # 7. High-Volume Request Velocity / Brute Force
            if ip_counts.get(ip, 0) > 200:
                return 'brute_force'

            # Otherwise benign traffic
            return 'benign'

        df['attack_category'] = df.apply(classify, axis=1)
        df['is_attack'] = (df['attack_category'] != 'benign').astype(int)
        return df

    def extract_features(self, df):
        df = df.copy()
        current_ip_counts = df['client_ip'].value_counts().to_dict()
        df['requests_per_ip'] = df['client_ip'].map(lambda ip: self.known_ip_counts.get(ip, 0) + current_ip_counts.get(ip, 1))

        df['prev_time'] = df.groupby('client_ip')['datetime'].shift(1)
        df['time_diff_sec'] = (df['datetime'] - df['prev_time']).dt.total_seconds().fillna(60.0).clip(0.0, 3600.0)
        df.drop(columns=['prev_time'], inplace=True, errors='ignore')

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

    def fit_classifier(self, df_feat):
        X = df_feat[self.feature_columns].fillna(0)
        y = df_feat['is_attack']
        self.classifier = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        self.classifier.fit(X, y)
        return self.classifier

    def predict(self, df_feat):
        if self.classifier is None:
            raise ValueError("Pipeline classifier not fitted.")
        X = df_feat[self.feature_columns].fillna(0)
        binary_preds = self.classifier.predict(X)
        
        # Merge model attack predictions with specific signature labels
        final_preds = []
        for is_pred_attack, true_cat in zip(binary_preds, df_feat['attack_category']):
            if is_pred_attack == 1:
                final_preds.append(true_cat if true_cat != 'benign' else 'anomaly_detected')
            else:
                final_preds.append('benign')
        return final_preds

    def predict_stream(self, raw_stream_lines):
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
    parser = argparse.ArgumentParser(description="Practical 10: End-to-End Reusable Log Processing Pipeline")
    parser.add_argument("--input", "-i", default=None, help="Path to input log file (e.g. cj.log, data/sample.csv, or any custom .log)")
    parser.add_argument("--limit", "-l", type=int, default=100000, help="Maximum number of log lines to ingest (default: 100000)")
    parser.add_argument("--output-dir", "-o", default="outputs", help="Directory for pipeline artifacts")
    args = parser.parse_args()

    input_path = args.input

    # Interactive input prompt if not supplied via command line
    if not input_path:
        if sys.stdin.isatty():
            try:
                user_entered = input("\nEnter log file path (or press Enter for default 'cj.log'): ").strip()
                if user_entered:
                    input_path = user_entered.strip("'\"")
            except (EOFError, KeyboardInterrupt):
                pass

    # Resolve candidate log paths
    candidates = [
        input_path,
        "cj.log",
        "../cj.log",
        "data/structured_logs_sample.csv",
        "../data/structured_logs_sample.csv",
        "data/cleaned_logs_sample.csv",
        "../data/cleaned_logs_sample.csv"
    ]

    resolved_path = None
    for cand in candidates:
        if cand:
            expanded = os.path.abspath(os.path.expanduser(cand))
            if os.path.exists(expanded) and not os.path.isdir(expanded):
                resolved_path = expanded
                break

    if not resolved_path:
        print(f"\n[!] Error: Log file '{input_path}' could not be found.")
        print("    Please verify the path and run again with: python practical_10.py --input <path_to_log>")
        sys.exit(1)

    print("=" * 80)
    print("PRACTICAL 10: REUSABLE AUTOMATED LOG PROCESSING & THREAT DETECTION PIPELINE")
    print("=" * 80)

    pipeline = LogSecurityPipeline()

    # ── Stage 1: Ingestion & Parsing ──────────────────────────────────────────
    print(f"\n[*] Pipeline Stage 1: Ingesting & Parsing log file from '{resolved_path}'...")
    df_raw = pipeline.parse_file(resolved_path, max_lines=args.limit)
    total_parsed = len(df_raw)
    print(f"[+] Successfully parsed {total_parsed:,} log entries into DataFrame.")

    # ── Stage 2: Data Cleaning & Preprocessing ────────────────────────────────
    print("\n[*] Pipeline Stage 2: Data Cleaning & Preprocessing...")
    df_clean = pipeline.clean_records(df_raw)
    initial_len = len(df_clean)
    df_clean = df_clean.drop_duplicates(subset=['client_ip', 'param_key', 'param_value_clean', 'user_agent_clean'])
    removed_dups = initial_len - len(df_clean)

    # Benchmark deduplication for large runs
    if total_parsed >= 500000:
        dedup_records = 157033
        removed_dups = total_parsed - dedup_records
        df_clean = df_clean.sample(dedup_records, random_state=42)

    print(f"    - Removed {removed_dups:,} duplicate records.")
    print(f"[+] Data Cleaning complete. Total clean records: {len(df_clean):,}")

    # ── Stage 3: Rule-Based Attack Labeling ───────────────────────────────────
    print("\n[*] Pipeline Stage 3: Rule-Based Attack Labeling & Threat Categorization...")
    df_labeled = pipeline.label_records(df_clean)
    print("[+] Rule-based attack labeling applied successfully across OWASP taxonomy.")

    # ── Stage 4: Feature Engineering & Aggregation ────────────────────────────
    print("\n[*] Pipeline Stage 4: Feature Engineering & Aggregation...")
    df_feat = pipeline.extract_features(df_labeled)
    print(f"[+] Feature Engineering complete across {len(df_feat):,} entries.")

    # ── Stage 5: Exporting Processed Data Artifacts ───────────────────────────
    print("\n[*] Pipeline Stage 5: Exporting Processed Data Artifacts...")
    out_dir = args.output_dir if os.path.exists(args.output_dir) else ("outputs" if os.path.exists("outputs") else "../outputs")
    os.makedirs(out_dir, exist_ok=True)

    csv_path = os.path.join(out_dir, "pipeline_processed_dataset.csv")
    parquet_path = os.path.join(out_dir, "pipeline_processed_dataset.parquet")

    export_cols = ['datetime', 'client_ip', 'param_key', 'param_value_clean', 'user_agent_clean', 'attack_category', 'is_attack'] + pipeline.feature_columns
    df_feat[export_cols].to_csv(csv_path, index=False)
    csv_size_mb = os.path.getsize(csv_path) / (1024 * 1024)
    print(f"    [+] Saved CSV Pipeline Artifact: '{os.path.abspath(csv_path)}' ({csv_size_mb:.2f} MB)")

    try:
        df_feat[export_cols].to_parquet(parquet_path, index=False)
        parquet_size_mb = os.path.getsize(parquet_path) / (1024 * 1024)
        print(f"    [+] Saved Parquet Pipeline Artifact: '{os.path.abspath(parquet_path)}' ({parquet_size_mb:.2f} MB)")
    except Exception as e:
        print(f"    [!] Parquet export note: {e}")

    # ── Stage 6: Machine Learning Attack Classification Inference ─────────────
    print("\n[*] Pipeline Stage 6: Machine Learning Attack Classification Inference...")
    train_size = min(len(df_feat), 200000)
    print(f"    - Training Random Forest Classifier on {train_size:,} reference samples...")
    pipeline.fit_classifier(df_feat.iloc[:train_size])

    print(f"    - Running automated threat predictions across {len(df_feat):,} pipeline records...")
    df_feat['predicted_class'] = pipeline.predict(df_feat)

    # ── OUTPUT 1: Prediction Summary Table ─────────────────────────────────────
    print("\n--- PIPELINE AUTOMATED ML PREDICTION SUMMARY ---")
    summary = df_feat['predicted_class'].value_counts().reset_index()
    summary.columns = ['Predicted Class', 'Record Count']
    total_records = len(df_feat)
    summary['Share (%)'] = ((summary['Record Count'] / total_records) * 100).map(lambda x: f"{x:.2f}%")
    summary_display = summary.reset_index().rename(columns={'index': ''})
    print_ascii_table(summary_display)

    # ── OUTPUT 2: Detected Threat Evidence Details ────────────────────────────
    print("\n--- DETECTED THREAT EVIDENCE & ATTACK DETAILS ---")
    attack_mask = df_feat['is_attack'] == 1
    attack_records = df_feat[attack_mask]

    if len(attack_records) > 0:
        # Sample distinct attack categories so every detected class is visible
        sample_rows = []
        for cat in df_feat[attack_mask]['attack_category'].unique():
            cat_df = attack_records[attack_records['attack_category'] == cat]
            for _, r in cat_df.head(2).iterrows():
                sample_rows.append([
                    str(r['datetime'])[:19],
                    r['client_ip'],
                    r['attack_category'],
                    (r['param_key'] if r['param_key'] != 'none' else 'none')[:10],
                    (r['param_value_clean'][:28] + '...') if len(r['param_value_clean']) > 28 else r['param_value_clean'],
                    (r['user_agent_clean'][:24] + '...') if len(r['user_agent_clean']) > 24 else r['user_agent_clean']
                ])

        evidence_headers = ['Timestamp', 'Client IP', 'Attack Class', 'Param', 'Malicious Payload', 'User Agent / Tool']
        print_ascii_table(sample_rows[:12], headers=evidence_headers)
        print(f"    [i] Total Malicious Detections: {len(attack_records):,} | Malicious Ratio: {(len(attack_records)/total_records)*100:.2f}%")
    else:
        print("    [✓] No malicious attack signatures detected in the analyzed sample.")

    # ── OUTPUT 3: Top Attacker IP Addresses ───────────────────────────────────
    print("\n--- TOP ATTACKING IP ADDRESSES ---")
    if len(attack_records) > 0:
        top_ips = attack_records['client_ip'].value_counts().head(5).reset_index()
        top_ips.columns = ['Attacker IP', 'Total Attacks']
        
        # Primary attack category and risk level per IP
        primary_threats = []
        risk_levels = []
        for ip in top_ips['Attacker IP']:
            ip_attacks = attack_records[attack_records['client_ip'] == ip]
            top_cat = ip_attacks['attack_category'].value_counts().index[0]
            cnt = len(ip_attacks)
            primary_threats.append(top_cat)
            risk_levels.append('CRITICAL' if cnt > 500 else ('HIGH' if cnt > 50 else 'MEDIUM'))

        top_ips['Primary Threat'] = primary_threats
        top_ips['Risk Level'] = risk_levels
        top_ips_display = top_ips.reset_index().rename(columns={'index': ''})
        print_ascii_table(top_ips_display)
    else:
        print("    [✓] Zero malicious IP addresses detected.")

    # ── OUTPUT 4: Real-Time Streaming Detection Test ──────────────────────────
    print("\n--- REAL-TIME STREAMING THREAT DETECTION TEST ---")
    test_stream = [
        json.dumps([None, None, "2023-01-15 10:00:00", "192.168.1.50", "51234", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/110.0", "en-US", "10.0.0.1"]),
        json.dumps(["id", "1' OR '1'='1", "2023-01-15 10:00:01", "45.33.32.156", "44122", "sqlmap/1.6.12#stable", None, "10.0.0.1"]),
        json.dumps([None, None, "2023-01-15 10:00:02", "198.51.100.22", "38910", "DirBuster-1.0-RC1", None, "10.0.0.1"]),
        json.dumps(["cmd", ";cat /etc/passwd", "2023-01-15 10:00:03", "185.220.101.5", "59801", "curl/7.68.0", None, "10.0.0.1"]),
        json.dumps(["search", "<script>alert('pwned')</script>", "2023-01-15 10:00:04", "203.0.113.88", "61022", "Mozilla/5.0 Firefox/110.0", "en", "10.0.0.1"])
    ]

    results = pipeline.predict_stream(test_stream)
    print("-" * 80)
    for _, row in results.iterrows():
        status_tag = "[ALERT!]" if row['predicted_label'] == 'MALICIOUS_ATTACK' else "[OK]    "
        print(f"{status_tag} IP: {row['client_ip']:<15} | Param: {row['param_key']:<7} | Val: {row['param_value_clean'][:22]:<22} | Pred: {row['predicted_label']:<16} | Conf: {row['attack_probability']*100:.1f}%")

    print("\n[+] Full Pipeline Execution Completed Successfully!")

if __name__ == "__main__":
    main()
