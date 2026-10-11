"""
Practical 5: To Do the Feature Engineering for Anomaly Detection or Any Suspicious Activity
Objective: Create meaningful numerical and categorical features for machine learning.
- Feature 1: Number of requests per IP (IP request frequency)
- Feature 2: Time between requests (inter-arrival delta in seconds per IP)
- Feature 3: Payload Shannon Entropy (measuring obfuscation and randomness)
- Feature 4: Payload Length and Param Key Length
- Feature 5: Special characters count and ratio (punctuations frequently used in exploits: ', ", ;, <, >, (, ), /, \\, %, $)
- Feature 6: User-Agent categorization (is_scanner, is_bot, is_browser, is_missing_ua)
- Feature 7: Port classification (standard web ports vs high/ephemeral ports)
- Save feature dataset to data/featured_logs_sample.csv.
"""

import os
import math
import re
import numpy as np
import pandas as pd
from collections import Counter

INPUT_FILE = "data/labeled_logs_sample.csv" if os.path.exists("data") else "../data/labeled_logs_sample.csv"
OUTPUT_FILE = "data/featured_logs_sample.csv" if os.path.exists("data") else "../data/featured_logs_sample.csv"

def calculate_shannon_entropy(text):
    """Calculates Shannon Entropy of a string to measure randomness/obfuscation."""
    if not text or text == 'none' or text == 'nan':
        return 0.0
    text_len = len(text)
    if text_len <= 1:
        return 0.0
    counts = Counter(text)
    entropy = -sum((count / text_len) * math.log2(count / text_len) for count in counts.values())
    return round(entropy, 4)

def count_special_characters(text):
    """Counts punctuation and exploit-related characters."""
    if not text or text == 'none':
        return 0
    return len(re.findall(r"['\";<>\(\)\{\}\[\]/\\%\$\*\+\-\=\&\|]", text))

def engineer_features(df):
    print("\n[+] Engineering Behavioral, Structural, and Statistical Features...")

    # Ensure datetime sorting for temporal features
    df['datetime'] = pd.to_datetime(df['datetime'])
    df = df.sort_values(by=['client_ip', 'datetime']).reset_index(drop=True)

    # 1. Behavioral: Request frequency per IP
    print("    - Computing requests per IP...")
    ip_counts = df['client_ip'].value_counts()
    df['requests_per_ip'] = df['client_ip'].map(ip_counts)

    # 2. Temporal: Inter-arrival time between consecutive requests from same IP
    print("    - Computing inter-arrival time delta (seconds)...")
    df['prev_time'] = df.groupby('client_ip')['datetime'].shift(1)
    df['time_diff_sec'] = (df['datetime'] - df['prev_time']).dt.total_seconds().fillna(9999.0)
    df.drop(columns=['prev_time'], inplace=True)

    # Cap time_diff_sec for ML stability
    df['time_diff_sec'] = df['time_diff_sec'].clip(lower=0.0, upper=3600.0)

    # 3. Payload Characteristics: Length, Entropy, Special Chars
    print("    - Computing Payload Length, Shannon Entropy & Special Characters...")
    payloads = df['param_value_clean'].astype(str)
    keys = df['param_key'].astype(str)

    df['payload_length'] = payloads.apply(lambda s: 0 if s in ['none', 'nan'] else len(s))
    df['key_length'] = keys.apply(lambda s: 0 if s in ['none', 'nan'] else len(s))
    df['payload_entropy'] = payloads.apply(calculate_shannon_entropy)
    df['special_char_count'] = payloads.apply(count_special_characters)
    df['special_char_ratio'] = np.where(df['payload_length'] > 0, 
                                        (df['special_char_count'] / df['payload_length']).round(4), 
                                        0.0)
    df['has_digits'] = payloads.apply(lambda s: 1 if re.search(r'\d', s) else 0)

    # 4. User-Agent Profiling
    print("    - Profiling User-Agent signatures...")
    ua_lower = df['user_agent_clean'].astype(str).str.lower()
    df['is_scanner_ua'] = ua_lower.str.contains(r'nikto|dirbuster|gobuster|sqlmap|nmap|zgrab|masscan', regex=True).astype(int)
    df['is_headless_tool'] = ua_lower.str.contains(r'python-requests|go-http-client|curl|wget|apache-httpclient', regex=True).astype(int)
    df['is_standard_browser'] = ua_lower.str.contains(r'mozilla|chrome|safari|firefox|edge|opera', regex=True).astype(int) & (~df['is_scanner_ua'].astype(bool))
    df['is_missing_ua'] = (df['user_agent_clean'] == 'unknown').astype(int)

    # 5. Language Header Presence
    df['has_accept_lang'] = (df['accept_language'] != 'missing').astype(int)

    return df

def main():
    print("=" * 80)
    print("PRACTICAL 5: FEATURE ENGINEERING FOR ANOMALY DETECTION")
    print("=" * 80)

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Running Practical 4 first...")
        from practical_04_attack_labeling import main as run_p4
        run_p4()

    df = pd.read_csv(INPUT_FILE, low_memory=False)
    print(f"\n[+] Loaded {len(df):,} labeled rows from {INPUT_FILE}")

    featured_df = engineer_features(df)

    feature_cols = [
        'requests_per_ip', 'time_diff_sec', 'payload_length', 'key_length',
        'payload_entropy', 'special_char_count', 'special_char_ratio',
        'has_digits', 'is_scanner_ua', 'is_headless_tool', 'is_standard_browser',
        'is_missing_ua', 'has_accept_lang', 'is_attack'
    ]

    print("\n[+] Engineered Features Summary Statistics:")
    print("-" * 80)
    print(featured_df[feature_cols].describe().T[['mean', 'std', 'min', '50%', 'max']])

    print("\n[+] Feature Correlation with Attack Label (is_attack):")
    print("-" * 80)
    correlations = featured_df[feature_cols].corr()['is_attack'].sort_values(ascending=False)
    for feat, corr_val in correlations.items():
        print(f"    - {feat:<22}: {corr_val:+.4f}")

    # Save featured dataset
    featured_df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[+] Exported featured dataset to: {OUTPUT_FILE} ({len(featured_df):,} records)")

    print("\n[✓] Practical 5 Complete: Features engineered and correlated with cyber threats.")

if __name__ == "__main__":
    main()
