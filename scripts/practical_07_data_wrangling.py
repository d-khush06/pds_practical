"""
Practical 7: To Do the Data Wrangling for Aggregated Analysis on the Balanced Dataset
Objective: Aggregate, group, and reshape data for cyber threat intelligence insights.
- Group by client IP: Calculate total requests, total attacks, attack percentage, unique user agents.
- Time-series Resampling: Resample log volume by hourly intervals to track attack surges vs benign activity.
- Pivot Tables: Reshape data to cross-tabulate attack categories across hours of the day and top offending IPs.
- Filtering: Separate high-volume malicious scanners and identify persistent threat actors.
- Export aggregated summaries to outputs/p07_ip_aggregation.csv and outputs/p07_hourly_summary.csv.
"""

import os
import pandas as pd

INPUT_FILE = "data/balanced_dataset_sample.csv" if os.path.exists("data") else "../data/balanced_dataset_sample.csv"
OUTPUT_DIR = "outputs" if os.path.exists("outputs") else "../outputs"

def wrangle_and_aggregate(df):
    print("\n[+] 1. Grouping by Client IP for Host Profiling...")
    # IP aggregated metrics
    ip_summary = df.groupby('client_ip').agg(
        total_requests=('is_attack', 'count'),
        attack_count=('is_attack', 'sum'),
        benign_count=('is_attack', lambda x: (x == 0).sum()),
        attack_ratio=('is_attack', 'mean'),
        unique_user_agents=('user_agent_clean', 'nunique'),
        avg_entropy=('payload_entropy', 'mean'),
        max_payload_len=('payload_length', 'max')
    ).reset_index()

    ip_summary['attack_ratio_pct'] = (ip_summary['attack_ratio'] * 100).round(2)
    ip_summary = ip_summary.sort_values(by='attack_count', ascending=False).reset_index(drop=True)

    print("\n[+] Top 10 Most Aggressive Attacking IPs:")
    print("-" * 80)
    top_10_ips = ip_summary.head(10)[['client_ip', 'total_requests', 'attack_count', 'attack_ratio_pct', 'unique_user_agents']]
    print(top_10_ips.to_string(index=False))

    # 2. Time-series Resampling (Hourly traffic)
    print("\n[+] 2. Time-Series Resampling by Hour...")
    df['datetime'] = pd.to_datetime(df['datetime'])
    df_time = df.set_index('datetime').sort_index()

    hourly_ts = df_time.resample('1h').agg(
        total_requests=('is_attack', 'count'),
        attack_volume=('is_attack', 'sum'),
        benign_volume=('is_attack', lambda x: (x == 0).sum())
    ).fillna(0)

    print("\n[+] Sample Hourly Traffic Aggregation (First 8 active hours):")
    print(hourly_ts[hourly_ts['total_requests'] > 0].head(8))

    # 3. Pivot Tables: Attack Category by Hour of Day
    print("\n[+] 3. Pivot Table: Attack Categories vs Hour of Day:")
    print("-" * 80)
    pivot_hour_cat = pd.pivot_table(
        df,
        values='client_ip',
        index='hour',
        columns='attack_category',
        aggfunc='count',
        fill_value=0
    )
    print(pivot_hour_cat.head(10))

    # 4. Pivot Table: Top 5 IPs vs Attack Types
    top_ips_list = ip_summary.head(5)['client_ip'].tolist()
    pivot_top_ips = pd.pivot_table(
        df[df['client_ip'].isin(top_ips_list)],
        values='hour',
        index='client_ip',
        columns='attack_category',
        aggfunc='count',
        fill_value=0
    )
    print("\n[+] 4. Pivot Table: Top 5 Attacker IPs by Specific Attack Category:")
    print("-" * 80)
    print(pivot_top_ips)

    return ip_summary, hourly_ts, pivot_hour_cat

def main():
    print("=" * 80)
    print("PRACTICAL 7: DATA WRANGLING FOR AGGREGATED ANALYSIS")
    print("=" * 80)

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Running Practical 6 first...")
        from practical_06_dataset_balancing import main as run_p6
        run_p6()

    df = pd.read_csv(INPUT_FILE, low_memory=False)
    print(f"\n[+] Loaded {len(df):,} balanced rows from {INPUT_FILE}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ip_summary, hourly_ts, pivot_hour_cat = wrangle_and_aggregate(df)

    ip_out = os.path.join(OUTPUT_DIR, "p07_ip_aggregation.csv")
    hourly_out = os.path.join(OUTPUT_DIR, "p07_hourly_summary.csv")
    ip_summary.to_csv(ip_out, index=False)
    hourly_ts.to_csv(hourly_out)

    print(f"\n[+] Saved IP aggregation summary to: {ip_out}")
    print(f"[+] Saved Hourly time-series summary to: {hourly_out}")

    print("\n[✓] Practical 7 Complete: Data wrangling, aggregation, and pivot analysis finished.")

if __name__ == "__main__":
    main()
