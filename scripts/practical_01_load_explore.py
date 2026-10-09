"""
Practical 1: To Load and Explore the Unstructured Access Log Data
Objective: Learn how to import and explore raw server access logs.
- Load sample access.log / cj.log file using Python with open() and json inspection.
- Understand the typical log structure (IP, timestamp, request, status/port, size, user-agent, etc.).
- Extract 5-10 random lines to manually inspect the pattern.
- Identify useful fields for analysis.
"""

import os
import json
import random
from collections import Counter

LOG_FILE = "cj.log" if os.path.exists("cj.log") else "../cj.log"

def main():
    print("=" * 80)
    print("PRACTICAL 1: LOAD AND EXPLORE UNSTRUCTURED ACCESS LOG DATA")
    print("=" * 80)

    if not os.path.exists(LOG_FILE):
        print(f"Error: {LOG_FILE} not found in current directory.")
        return

    file_size_bytes = os.path.getsize(LOG_FILE)
    file_size_mb = file_size_bytes / (1024 * 1024)
    print(f"\n[+] Log File Information:")
    print(f"    - File Name: {LOG_FILE}")
    print(f"    - File Size: {file_size_bytes:,} bytes ({file_size_mb:.2f} MB)")

    # 1. Load lines and inspect total count & format
    print("\n[+] Reading raw log lines...")
    sample_lines = []
    total_lines = 0
    valid_json_count = 0
    schema_lengths = Counter()

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            total_lines += 1
            line_str = line.strip()
            if not line_str:
                continue

            # Store first 10 lines for immediate inspection
            if len(sample_lines) < 10:
                sample_lines.append(line_str)

            # Check JSON structure
            try:
                parsed = json.loads(line_str)
                valid_json_count += 1
                if isinstance(parsed, list):
                    schema_lengths[len(parsed)] += 1
            except json.JSONDecodeError:
                pass

            # For fast exploration, we scan up to 100,000 lines for the statistical overview
            if total_lines >= 100000:
                break

    print(f"    - Inspected {total_lines:,} lines from {LOG_FILE}")
    print(f"    - Valid JSON Arrays: {valid_json_count:,} ({(valid_json_count/total_lines)*100:.2f}%)")
    print(f"    - Array Length Distribution: {dict(schema_lengths)}")

    # 2. Extract 5-10 random lines for manual inspection
    print("\n[+] Extracting 5 Random Lines for Manual Pattern Inspection:")
    print("-" * 80)
    # Collect random lines from a reservoir
    random_samples = []
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= 10000:
                break
            line_str = line.strip()
            if line_str:
                random_samples.append(line_str)

    selected_lines = random.sample(random_samples, min(5, len(random_samples)))
    for idx, raw_line in enumerate(selected_lines, 1):
        print(f"\n[Random Sample #{idx}]:")
        print(f"  Raw: {raw_line[:120]}..." if len(raw_line) > 120 else f"  Raw: {raw_line}")
        try:
            parsed = json.loads(raw_line)
            print(f"  Parsed Fields ({len(parsed)} elements):")
            for elem_idx, val in enumerate(parsed):
                print(f"    Index {elem_idx}: {repr(val)}")
        except Exception as e:
            print(f"  Parse Error: {e}")

    # 3. Identify Useful Fields for Analysis
    print("\n" + "=" * 80)
    print("[+] Structural Mapping & Useful Fields Identification:")
    print("=" * 80)
    field_mapping = [
        ("Index 0", "param_key / command", "Extracted parameter name, HTTP command or shell command (e.g. ls, ps, auto, id)"),
        ("Index 1", "param_value / payload", "Payload or resource requested (e.g. /etc/passwd, SQLi strings, URLs, script tags)"),
        ("Index 2", "timestamp", "Event date and time (format: YYYY-MM-DD HH:MM:SS) for temporal & rate analysis"),
        ("Index 3", "client_ip", "Source IP address of requesting host for geolocation and IP frequency profiling"),
        ("Index 4", "client_port", "Source port number / connection port used by the client"),
        ("Index 5", "user_agent", "User-Agent string identifying browser, bot, or attack scanner tool (Nikto, DirBuster, gobuster)"),
        ("Index 6", "accept_language", "Client language preference header (en, de, etc.) or None for headless scripts"),
        ("Index 7", "target_ip", "Destination or honeypot server IP address receiving the request")
    ]

    print(f"{'Position':<10} | {'Field Name':<22} | {'Description & Analytical Value':<50}")
    print("-" * 88)
    for pos, name, desc in field_mapping:
        print(f"{pos:<10} | {name:<22} | {desc:<50}")

    print("\n[✓] Practical 1 Complete: Raw access log successfully loaded, explored, and structured fields identified.")

if __name__ == "__main__":
    main()
