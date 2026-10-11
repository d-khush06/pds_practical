"""
Practical 4: To Label the Requests as Benign or Attack (Basic Classification)
Objective: Create labeled categories for cybersecurity analysis.
- Implement rule-based detection for known attack patterns:
    * SQL Injection (SQLi): `' OR 1=1`, `union select`, `sleep(`, `benchmark(`, etc.
    * Path Traversal / LFI: `../`, `..\\`, `/etc/passwd`, `win.ini`
    * Command Injection / RCE: `ls`, `ps`, `;cat `, `rm -rf`, `wget `, `curl `, `passthru`, `system(`
    * Automated Reconnaissance / Scanner: Nikto, DirBuster, gobuster, sqlmap, nmap, zgrab, masscan
    * Cross-Site Scripting (XSS): `<script>`, `alert(`, `javascript:`, `onerror=`
    * Remote File Inclusion (RFI): `http://`, `https://`, `rfiinc.txt` in params
- Create categorical column `attack_category` and binary column `is_attack` (0 = Benign, 1 = Attack).
- Analyze class distribution and export labeled data to data/labeled_logs_sample.csv.
"""

import os
import re
import pandas as pd

INPUT_FILE = "data/cleaned_logs_sample.csv" if os.path.exists("data") else "../data/cleaned_logs_sample.csv"
OUTPUT_FILE = "data/labeled_logs_sample.csv" if os.path.exists("data") else "../data/labeled_logs_sample.csv"

# Pre-compiled regex patterns for attack classification
SQLI_PATTERN = re.compile(r"('|--|union\s+select|select\s+.*from|sleep\(|benchmark\(|order\s+by|\b1=1\b|or\s+true)", re.IGNORECASE)
PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini|windows/system32|boot\.ini)", re.IGNORECASE)
CMD_INJECTION_PATTERN = re.compile(r"(;|\&\&|\|)\s*(cat\s+|ls|ps|wget\s+|curl\s+|rm\s+-rf|id\b|whoami|chmod|chown)|passthru\(|system\(|shell_exec\(", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script|alert\(|javascript:|onerror=|onload=|<img\s+src=)", re.IGNORECASE)
RFI_PATTERN = re.compile(r"(https?://|ftp://|rfiinc\.txt)", re.IGNORECASE)
SCANNER_UA_PATTERN = re.compile(r"(nikto|dirbuster|gobuster|sqlmap|nmap|zgrab|masscan|wpscan|python-requests|go-http-client|curl/|censys)", re.IGNORECASE)

def classify_request(row):
    key = str(row['param_key']).lower()
    val = str(row['param_value_clean']).lower()
    ua = str(row['user_agent_clean']).lower()
    
    # 1. Shell commands directly in key or val
    if key in ['ls', 'ps', 'cat', 'id', 'whoami', 'reboot'] or 'rm -rf' in key or 'wget' in key:
        return 'cmd_injection'
    if CMD_INJECTION_PATTERN.search(val) or CMD_INJECTION_PATTERN.search(key):
        return 'cmd_injection'
        
    # 2. Path Traversal
    if PATH_TRAVERSAL_PATTERN.search(val) or PATH_TRAVERSAL_PATTERN.search(key):
        return 'path_traversal'

    # 3. SQL Injection
    if SQLI_PATTERN.search(val) or SQLI_PATTERN.search(key):
        return 'sqli'

    # 4. Cross-Site Scripting (XSS)
    if XSS_PATTERN.search(val):
        return 'xss'

    # 5. Remote File Inclusion (RFI)
    if RFI_PATTERN.search(val):
        return 'rfi'

    # 6. Automated Scanner / Recon
    if SCANNER_UA_PATTERN.search(ua):
        return 'scanner_recon'

    # Otherwise benign traffic
    return 'benign'

def main():
    print("=" * 80)
    print("PRACTICAL 4: LABEL REQUESTS AS BENIGN OR ATTACK")
    print("=" * 80)

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Running Practical 3 first...")
        from practical_03_data_cleaning import main as run_p3
        run_p3()

    df = pd.read_csv(INPUT_FILE, low_memory=False)
    print(f"\n[+] Loaded {len(df):,} cleaned records from {INPUT_FILE}")

    print("\n[+] Applying attack signature matching rules across dataset...")
    df['attack_category'] = df.apply(classify_request, axis=1)
    df['is_attack'] = (df['attack_category'] != 'benign').astype(int)

    print("\n[+] Categorical Attack Breakdown:")
    category_counts = df['attack_category'].value_counts()
    category_pct = (category_counts / len(df)) * 100
    cat_summary = pd.DataFrame({"Count": category_counts, "Percentage (%)": category_pct.round(2)})
    print(cat_summary)

    print("\n[+] Binary Classification Breakdown (Benign vs Attack):")
    binary_counts = df['is_attack'].value_counts()
    binary_labels = {0: "Benign (0)", 1: "Attack (1)"}
    for val, count in binary_counts.items():
        print(f"    - {binary_labels[val]}: {count:,} ({count / len(df) * 100:.2f}%)")

    print("\n[+] Sample Attack Detections:")
    print("-" * 80)
    attack_samples = df[df['is_attack'] == 1][['client_ip', 'attack_category', 'param_key', 'param_value_clean', 'user_agent_clean']].head(10)
    print(attack_samples.to_string(index=False))

    # Save labeled dataset
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[+] Exported labeled dataset to: {OUTPUT_FILE} ({len(df):,} records)")

    print("\n[✓] Practical 4 Complete: Log requests labeled with attack signatures and binary classes.")

if __name__ == "__main__":
    main()
