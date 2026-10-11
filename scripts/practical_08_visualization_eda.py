"""
Practical 8: To Use Visual Tools or by Using Python for Data Visualization and EDA
Objective: Visual analysis and exploratory data analysis of cybersecurity log records.
- Visualization 1: Requests per Hour (Total Traffic vs Attack Volume)
- Visualization 2: Top 10 Attacking IPs (Horizontal Bar Chart)
- Visualization 3: Attack Categories Distribution (Pie & Donut Chart)
- Visualization 4: Payload Shannon Entropy Distribution (Benign vs Attack KDE/Violin)
- Visualization 5: Correlation Heatmap of Engineered Features
- Visualization 6: Hour of Day vs Attack Type Activity Heatmap
- Save all generated plots as high-resolution images in figures/ directory.
"""

import os
import matplotlib
matplotlib.use('Agg') # Headless rendering for terminal and backend execution
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

INPUT_FILE = "data/balanced_dataset_sample.csv" if os.path.exists("data") else "../data/balanced_dataset_sample.csv"
FIGURES_DIR = "figures" if os.path.exists("figures") else "../figures"

# Professional styling
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 10
plt.rcParams['axes.titlesize'] = 13
plt.rcParams['axes.labelsize'] = 11

def generate_visualizations(df):
    os.makedirs(FIGURES_DIR, exist_ok=True)
    generated_files = []

    # -------------------------------------------------------------
    # 1. Hourly Traffic Trend (Total vs Attack)
    # -------------------------------------------------------------
    print("\n[+] Generating Plot 1: Requests per Hour (Benign vs Attack)...")
    hourly_traffic = df.groupby(['hour', 'is_attack']).size().unstack(fill_value=0)
    
    fig, ax = plt.subplots(figsize=(10, 5), dpi=150)
    hourly_traffic[0].plot(kind='bar', color='#3b82f6', alpha=0.85, label='Benign Traffic', ax=ax, position=1, width=0.4)
    if 1 in hourly_traffic.columns:
        hourly_traffic[1].plot(kind='bar', color='#ef4444', alpha=0.85, label='Attack Traffic', ax=ax, position=0, width=0.4)
    ax.set_title('Hourly Request Distribution (Benign vs Attack)', fontweight='bold', pad=15)
    ax.set_xlabel('Hour of Day (0 - 23)')
    ax.set_ylabel('Number of Requests')
    ax.set_xlim(-0.5, 23.5)
    ax.legend(frameon=True, facecolor='white', framealpha=0.9)
    plt.tight_layout()
    f1 = os.path.join(FIGURES_DIR, "p08_hourly_traffic.png")
    plt.savefig(f1)
    plt.close()
    generated_files.append(f1)

    # -------------------------------------------------------------
    # 2. Top 10 Attacking IPs
    # -------------------------------------------------------------
    print("[+] Generating Plot 2: Top 10 Offending IPs...")
    attack_ips = df[df['is_attack'] == 1]['client_ip'].value_counts().head(10)
    
    fig, ax = plt.subplots(figsize=(9, 5), dpi=150)
    colors = sns.color_palette("Reds_r", n_colors=len(attack_ips))
    sns.barplot(x=attack_ips.values, y=attack_ips.index, palette=colors, ax=ax, hue=attack_ips.index, legend=False)
    ax.set_title('Top 10 Most Aggressive Attacking IPs', fontweight='bold', pad=15)
    ax.set_xlabel('Total Attack Requests')
    ax.set_ylabel('Client IP Address')
    for i, v in enumerate(attack_ips.values):
        ax.text(v + (max(attack_ips.values)*0.01), i, f"{v:,}", va='center', fontweight='bold', fontsize=9)
    plt.tight_layout()
    f2 = os.path.join(FIGURES_DIR, "p08_top_ips.png")
    plt.savefig(f2)
    plt.close()
    generated_files.append(f2)

    # -------------------------------------------------------------
    # 3. Attack Categories Distribution (Pie & Donut)
    # -------------------------------------------------------------
    print("[+] Generating Plot 3: Attack Category Breakdown...")
    attacks_only = df[df['attack_category'] != 'benign']['attack_category'].value_counts()
    
    fig, ax = plt.subplots(figsize=(8, 6), dpi=150)
    palette = sns.color_palette("rocket", n_colors=len(attacks_only))
    wedges, texts, autotexts = ax.pie(
        attacks_only,
        labels=attacks_only.index,
        autopct='%1.1f%%',
        startangle=140,
        colors=palette,
        pctdistance=0.75,
        textprops=dict(color="black", fontweight="medium")
    )
    # Donut center circle
    centre_circle = plt.Circle((0,0), 0.55, fc='white')
    fig.gca().add_artist(centre_circle)
    ax.set_title('Proportional Distribution of Attack Categories', fontweight='bold', pad=15)
    plt.tight_layout()
    f3 = os.path.join(FIGURES_DIR, "p08_attack_distribution.png")
    plt.savefig(f3)
    plt.close()
    generated_files.append(f3)

    # -------------------------------------------------------------
    # 4. Payload Shannon Entropy Distribution
    # -------------------------------------------------------------
    print("[+] Generating Plot 4: Payload Shannon Entropy Distribution...")
    fig, ax = plt.subplots(figsize=(9, 5), dpi=150)
    sns.kdeplot(data=df[df['is_attack'] == 0]['payload_entropy'], fill=True, color='#2563eb', label='Benign (0)', common_norm=False, ax=ax, alpha=0.3)
    sns.kdeplot(data=df[df['is_attack'] == 1]['payload_entropy'], fill=True, color='#dc2626', label='Attack (1)', common_norm=False, ax=ax, alpha=0.3)
    ax.set_title('KDE: Payload Shannon Entropy (Benign vs Attack)', fontweight='bold', pad=15)
    ax.set_xlabel('Shannon Entropy (Bits per Symbol)')
    ax.set_ylabel('Density')
    ax.legend(frameon=True, facecolor='white')
    plt.tight_layout()
    f4 = os.path.join(FIGURES_DIR, "p08_entropy_distribution.png")
    plt.savefig(f4)
    plt.close()
    generated_files.append(f4)

    # -------------------------------------------------------------
    # 5. Correlation Heatmap of Engineered Features
    # -------------------------------------------------------------
    print("[+] Generating Plot 5: Feature Correlation Heatmap...")
    feature_cols = [
        'is_attack', 'is_scanner_ua', 'special_char_ratio', 'special_char_count',
        'payload_entropy', 'payload_length', 'is_headless_tool', 'has_digits',
        'requests_per_ip', 'time_diff_sec', 'has_accept_lang'
    ]
    corr_matrix = df[feature_cols].corr()
    
    fig, ax = plt.subplots(figsize=(10, 8), dpi=150)
    mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
    sns.heatmap(corr_matrix, mask=mask, cmap='coolwarm', vmin=-1, vmax=1, annot=True, fmt='.2f', 
                square=True, linewidths=.5, cbar_kws={"shrink": .8}, ax=ax)
    ax.set_title('Feature Correlation Heatmap with Target (is_attack)', fontweight='bold', pad=15)
    plt.tight_layout()
    f5 = os.path.join(FIGURES_DIR, "p08_correlation_heatmap.png")
    plt.savefig(f5)
    plt.close()
    generated_files.append(f5)

    # -------------------------------------------------------------
    # 6. Hour of Day vs Attack Type Activity Heatmap
    # -------------------------------------------------------------
    print("[+] Generating Plot 6: Hour of Day vs Attack Type Heatmap...")
    pivot_heat = pd.pivot_table(
        df[df['attack_category'] != 'benign'],
        index='attack_category',
        columns='hour',
        values='client_ip',
        aggfunc='count',
        fill_value=0
    )
    
    fig, ax = plt.subplots(figsize=(11, 5), dpi=150)
    sns.heatmap(pivot_heat, cmap='YlOrRd', annot=True, fmt='d', linewidths=.5, ax=ax, cbar=True)
    ax.set_title('Hourly Frequency Heatmap of Attack Categories', fontweight='bold', pad=15)
    ax.set_xlabel('Hour of Day')
    ax.set_ylabel('Attack Category')
    plt.tight_layout()
    f6 = os.path.join(FIGURES_DIR, "p08_attack_heatmap.png")
    plt.savefig(f6)
    plt.close()
    generated_files.append(f6)

    return generated_files

def main():
    print("=" * 80)
    print("PRACTICAL 8: DATA VISUALIZATION AND EXPLORATORY DATA ANALYSIS (EDA)")
    print("=" * 80)

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found. Running Practical 6 first...")
        from practical_06_dataset_balancing import main as run_p6
        run_p6()

    df = pd.read_csv(INPUT_FILE, low_memory=False)
    print(f"\n[+] Loaded {len(df):,} balanced rows from {INPUT_FILE}")

    figures = generate_visualizations(df)

    print("\n[+] Successfully Generated High-Resolution Visualizations:")
    print("-" * 80)
    for fig_path in figures:
        print(f"    - [✓] Saved: {fig_path} ({os.path.getsize(fig_path):,} bytes)")

    print("\n[✓] Practical 8 Complete: Visualizations and exploratory data analysis generated.")

if __name__ == "__main__":
    main()
