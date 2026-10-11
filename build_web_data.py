"""
Builds comprehensive educational web data for all 10 Data Science Practicals.
Includes Plain-English Real-World Analogies, Mathematical Foundations,
Step-by-Step Logic, and Matplotlib Visual Chart mappings.
Zero emojis - Pure professional vector icons.
"""

import json
import os

PRACTICALS = [
    {
        "id": 1,
        "title": "Practical 1: Load and Explore Unstructured Access Log Data",
        "short_title": "Load & Explore Raw Logs",
        "icon": "file-search",
        "category": "Data Exploration",
        "tags": ["Raw Telemetry", "JSON Ingestion", "Stream I/O", "Schema Discovery"],
        "py_file": "scripts/practical_01_load_explore.py",
        "ipynb_file": "notebooks/practical_01_load_explore.ipynb",
        "chart_path": "figures/p01_schema_distribution.png",
        "chart_title": "Practical 1: Unstructured Log Field Completeness (100,000 Records)",
        "chart_desc": "Evaluates the density of all 8 fields across 100,000 raw log records from cj.log. Highlights high completeness in client IP, timestamp, and client port, contrasted with sparse optional parameter keys.",
        "key_metrics": [
            {"label": "Total Lines Scanned", "value": "100,000"},
            {"label": "JSON Array Integrity", "value": "99.99%"},
            {"label": "Extracted Schema", "value": "8 Attributes"},
            {"label": "Log File Volume", "value": "215.4 MB"}
        ],
        "learning": {
            "analogy_title": "The Airplane Black-Box Flight Recorder",
            "analogy_desc": "Imagine finding a flight data recorder from an aircraft. It doesn't contain a neat Microsoft Excel sheet; it stores continuous raw binary pulses of altitude, speed, temperature, and pilot inputs. Before you can analyze why turbulence occurred, you must first open the raw stream, verify whether the sensor readings are intact, decode the delimiters, and map which position records which measurement. Practical 1 does exactly this for server security logs.",
            "concept_summary": "Access logs record every request made to a web server or honeypot. In production, logs arrive in high-velocity, semi-structured JSON streams. Practical 1 demonstrates how to safely ingest massive multi-megabyte log files using memory-efficient line iterators, inspect structural patterns, sample live lines, and discover the 8-column schema.",
            "theoretical_foundations": [
                "**Memory-Efficient Stream Iterators:** Reading a 215 MB file with `f.read()` loads all 2 million strings into heap memory, causing latency spikes. Iterating line-by-line (`for line in f:`) maintains a tiny constant O(1) memory footprint.",
                "**Positional Array Semantics:** The honeypot outputs records as fixed-order JSON arrays: `[param_key, param_value, timestamp, client_ip, port, user_agent, lang, target_ip]`. Positional decoding requires bounds validation before field extraction.",
                "**Character Encoding & Malformed Bytes:** Attackers frequently transmit non-UTF-8 binary shellcodes. Using `errors='ignore'` prevents runtime decode crashes."
            ],
            "methodology_steps": [
                "Inspect file physical metadata (`os.path.getsize`) to determine file size (215.40 MB).",
                "Execute reservoir stream sampling across the first 100,000 lines to assess JSON structural validity.",
                "Extract 5 uniformly sampled records to inspect real payload variations (Nikto scans, shell commands, clean browser sessions).",
                "Construct the canonical 8-field schema mapping table defining the analytical value of each attribute."
            ]
        }
    },
    {
        "id": 2,
        "title": "Practical 2: Convert Unstructured Log Data into a Structured Dataset",
        "short_title": "Structured Dataset Conversion",
        "icon": "database",
        "category": "Data Engineering",
        "tags": ["Tabular Schema", "Pandas DataFrame", "Type Casting", "CSV Export"],
        "py_file": "scripts/practical_02_structured_dataset.py",
        "ipynb_file": "notebooks/practical_02_structured_dataset.ipynb",
        "chart_path": "figures/p02_missing_values.png",
        "chart_title": "Practical 2: Tabular Schema Null-Value Profiling (49,994 Rows)",
        "chart_desc": "Bar chart quantifying missing value percentages across parsed columns in the 49,994 record structured dataset. Illustrates that core forensic anchors (IP, port, timestamp) have 0% missing values.",
        "key_metrics": [
            {"label": "Structured Rows", "value": "49,994"},
            {"label": "Column Dimensions", "value": "8 Columns"},
            {"label": "Memory Footprint", "value": "21.83 MB"},
            {"label": "Exported Artifact", "value": "CSV Format"}
        ],
        "learning": {
            "analogy_title": "Converting a Shoebox of Receipts into an Organized Ledger",
            "analogy_desc": "Imagine running a business where receipts are tossed randomly into a shoebox. To do tax accounting or discover spending patterns, an accountant must pull out each receipt, create neat columns (Date, Vendor, Amount, Category), handle blank entries, and produce a balanced spreadsheet. Practical 2 converts the chaotic shoebox of raw JSON log strings into a structured, typed Pandas DataFrame.",
            "concept_summary": "Data science and machine learning algorithms cannot ingest arbitrary raw text strings. Practical 2 parses unstructured JSON arrays into an 8-column structured tabular DataFrame, profiles data types, audits missing values, and saves a standardized CSV artifact.",
            "theoretical_foundations": [
                "**Vectorized DataFrame Construction:** Appending rows iteratively to a DataFrame causes continuous memory re-allocation (O(N^2) complexity). Accumulating dictionaries in a native Python list and creating the DataFrame once operates in optimal O(N) linear time.",
                "**Missing Data Categorization:** Missing values in logs are Missing Not at Random (MNAR). Normal browser visits to the root page (`/`) have no parameter keys or values, which represents benign intent rather than data loss.",
                "**Schema Enforcing:** Assigning explicit column names (`client_ip`, `timestamp`, `param_key`, etc.) establishes a reliable data contract for downstream cleaning and feature extraction."
            ],
            "methodology_steps": [
                "Implement `parse_logs_to_dataframe()` using list-accumulation buffer pattern for 50,000 lines.",
                "Assign standardized column identities: `client_ip`, `timestamp`, `param_key`, `param_value`, `client_port`, `user_agent`, `accept_language`, `target_ip`.",
                "Compute non-null counts, null percentages, data type signatures, and deep memory usage.",
                "Persist structured tabular dataset to `data/structured_logs_sample.csv`."
            ]
        }
    },
    {
        "id": 3,
        "title": "Practical 3: Data Cleaning and Preprocessing",
        "short_title": "Data Cleaning & Preprocessing",
        "icon": "sparkles",
        "category": "Preprocessing",
        "tags": ["URL Decoding", "Datetime Casting", "Null Imputation", "Feature Extraction"],
        "py_file": "scripts/practical_03_data_cleaning.py",
        "ipynb_file": "notebooks/practical_03_data_cleaning.ipynb",
        "chart_path": "figures/p03_cleaning_impact.png",
        "chart_title": "Practical 3: Cleaned Temporal Request Velocity (24-Hour Timeline)",
        "chart_desc": "Continuous hourly traffic curve following timestamp normalization and ISO 8601 parsing. Highlights a dramatic surge at 07:00 UTC (6,939 requests) representing coordinated automated reconnaissance.",
        "key_metrics": [
            {"label": "Retention Rate", "value": "100.00%"},
            {"label": "Datetime Format", "value": "ISO 8601"},
            {"label": "Sanitized Fields", "value": "URL Decoded"},
            {"label": "Temporal Features", "value": "Hour, Day, Weekend"}
        ],
        "learning": {
            "analogy_title": "Translating Coded Wiretaps and Fixing Corrupted Timestamps",
            "analogy_desc": "Imagine FBI investigators listening to wiretapped audio where criminals speak in slang and encoded acronyms, with audio timestamps recorded in inconsistent time zones. Before the evidence can be presented in court, translators must decode percent-encoded terms (`%27` -> `'`), normalize timestamps to standard 24-hour clocks, and fill missing caller IDs with 'Unknown'. That is what data cleaning accomplishes for cyber telemetry.",
            "concept_summary": "Raw web logs contain percent-encoded URLs, irregular string casings, missing values, and unparsed timestamp strings. Practical 3 standardizes the data: converting timestamps to standard datetime objects, unquoting hexadecimal URL payloads, stripping whitespace, and imputing missing text values.",
            "theoretical_foundations": [
                "**Percent-Encoding De-obfuscation (RFC 3986):** Attackers obfuscate payloads using hex escapes (e.g. `%27` for `'`, `%2e%2e%2f` for `../`). URL unquoting exposes canonical attack signatures prior to pattern matching.",
                "**Temporal Feature Decomposition:** Converting timestamp strings into discrete temporal components (hour of day, day of week, weekend indicator) enables temporal anomaly detection and diurnal traffic profiling.",
                "**Safe Missing Value Imputation:** Imputing missing parameter values with `'none'` and missing User-Agents with `'unknown'` preserves complete row counts without dropping data."
            ],
            "methodology_steps": [
                "Convert timestamp strings into Pandas datetime format (`pd.to_datetime`).",
                "Extract derived temporal features: `hour`, `date`, `day_name`, and `is_weekend`.",
                "Sanitize `client_port` by coercing non-numeric entries to zero and casting to 64-bit integer.",
                "Apply `urllib.parse.unquote()` to normalize payloads and lowercase all parameter keys.",
                "Impute text nulls: replace NaN with `'none'` for parameters, `'unknown'` for user-agent, and `'missing'` for accept-language."
            ]
        }
    },
    {
        "id": 4,
        "title": "Practical 4: Label Requests as Benign or Attack",
        "short_title": "Cyber Threat Labeling",
        "icon": "shield-alert",
        "category": "Cybersecurity",
        "tags": ["Threat Taxonomy", "SQL Injection", "Path Traversal", "Signature Rules"],
        "py_file": "scripts/practical_04_attack_labeling.py",
        "ipynb_file": "notebooks/practical_04_attack_labeling.ipynb",
        "chart_path": "figures/p04_attack_breakdown.png",
        "chart_title": "Practical 4: Ground-Truth Threat Taxonomy Distribution",
        "chart_desc": "Dual visualization displaying binary classification (68.2% Benign vs 31.8% Attack) alongside a horizontal bar breakdown of attack subcategories dominated by automated scanners (12,621 events).",
        "key_metrics": [
            {"label": "Benign Requests", "value": "34,098 (68.2%)"},
            {"label": "Malicious Attacks", "value": "15,896 (31.8%)"},
            {"label": "Scanner Scans", "value": "12,621 Events"},
            {"label": "Exploit Payloads", "value": "3,275 Events"}
        ],
        "learning": {
            "analogy_title": "Airport Security Metal Detectors & Biometric Scanners",
            "analogy_desc": "When passengers walk through an airport terminal, metal detectors search for weapons (guns, knives) and passport scanners cross-reference international watchlists. Normal passengers are tagged 'Clear/Benign', while prohibited items are flagged with specific violation categories (Weapons, Contraband). Practical 4 acts as the security scanner for web requests, tagging normal traffic as 'Benign' and identifying specific attack types.",
            "concept_summary": "Supervised machine learning requires accurate ground-truth labels. Practical 4 develops a signature-based threat labeling engine utilizing regular expressions to detect OWASP Top 10 vulnerabilities: SQL Injection, Path Traversal, Command Injection, Vulnerability Scanners, XSS, and Remote File Inclusion.",
            "theoretical_foundations": [
                "**OWASP Top 10 Attack Signatures:**",
                "  - **SQL Injection (SQLi):** Matches `' OR 1=1`, `UNION SELECT`, `SLEEP()`, `benchmark()` targeting database engines.",
                "  - **Path Traversal / LFI:** Matches `../`, `..\\`, `/etc/passwd`, `win.ini` attempting directory escaping.",
                "  - **Command Injection (RCE):** Matches shell separators `;cat /etc/passwd`, `wget`, `curl`, `rm -rf`, `whoami`.",
                "  - **Cross-Site Scripting (XSS):** Detects script injection tags `<script>`, `alert()`, `javascript:`.",
                "  - **Automated Recon Scanners:** Detects user-agent headers from Nikto, DirBuster, gobuster, sqlmap, and masscan.",
                "**Binary vs Multi-Class Target Engineering:** Produces both a binary classification column (`is_attack`: 0 vs 1) and a multi-class categorization (`attack_category`)."
            ],
            "methodology_steps": [
                "Compile regular expression patterns for SQLi, Path Traversal, RCE, XSS, RFI, and Scanner user-agents.",
                "Implement `classify_request()` assigning hierarchical labels based on threat severity.",
                "Generate granular categorical label column: `attack_category`.",
                "Generate binary machine learning target column: `is_attack` (0 = Benign, 1 = Malicious).",
                "Audit frequency distributions and verify ground-truth integrity on sample payloads."
            ]
        }
    },
    {
        "id": 5,
        "title": "Practical 5: Feature Engineering for Anomaly Detection",
        "short_title": "Security Feature Engineering",
        "icon": "cpu",
        "category": "Feature Engineering",
        "tags": ["Shannon Entropy", "Inter-Arrival Time", "Velocity", "Correlation"],
        "py_file": "scripts/practical_05_feature_engineering.py",
        "ipynb_file": "notebooks/practical_05_feature_engineering.ipynb",
        "chart_path": "figures/p05_feature_correlations.png",
        "chart_title": "Practical 5: Pearson Correlation of Engineered Features with Attack Label (r)",
        "chart_desc": "Correlation ranking illustrating the highest predictive factors for attack detection: is_scanner_ua (+0.88), special_char_ratio (+0.28), and payload_entropy (+0.25).",
        "key_metrics": [
            {"label": "Engineered Features", "value": "12 Variables"},
            {"label": "Top Correlation", "value": "+0.8788 (Scanner)"},
            {"label": "Entropy Correlation", "value": "+0.2480 (Shannon)"},
            {"label": "Velocity Profiling", "value": "Time Deltas"}
        ],
        "learning": {
            "analogy_title": "The Lie Detector (Polygraph) for Computer Networks",
            "analogy_desc": "A polygraph machine doesn't read a person's thoughts directly; it measures physical indicators—heart rate, respiration speed, perspiration, and voice modulation. In cybersecurity, we cannot ask a network packet if it is malicious. Instead, we engineer statistical indicators: how fast are requests arriving (heart rate)? How random is the text string (sweat level)? How many weird punctuation marks are inside (voice pitch)?",
            "concept_summary": "Machine learning algorithms require numeric feature vectors. Practical 5 engineers 12 statistical, behavioral, structural, and linguistic features: Shannon Information Entropy (randomness), inter-arrival time deltas (velocity), special character ratios, and scanner tool indicators.",
            "theoretical_foundations": [
                "**Shannon Information Entropy Formula:**",
                "  $$H(X) = -\\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)$$",
                "  Normal human queries display low entropy (1.0 - 2.5 bits/char). Obfuscated shellcodes, base64 payloads, and random parameter fuzzing exhibit high entropy (3.5 - 5.5 bits/char).",
                "**Behavioral Velocity & Inter-Arrival Time:** Attack tools issue automated requests in rapid bursts (<0.05 seconds), whereas human browsing exhibits Poisson-distributed pauses (seconds to minutes).",
                "**Syntactic Exploit Characters:** Exploits rely heavily on syntax-breaking characters (', ;, <, >, /, $). The special character ratio normalizes this punctuation count against total payload length."
            ],
            "methodology_steps": [
                "Sort log entries by `client_ip` and `datetime` to construct temporal event timelines.",
                "Calculate `requests_per_ip` (request density) and `time_diff_sec` (inter-arrival delta).",
                "Implement `calculate_shannon_entropy()` using character frequency distribution vectors.",
                "Compute structural properties: `payload_length`, `key_length`, and `special_char_ratio`.",
                "Fingerprint client software: `is_scanner_ua`, `is_headless_tool`, and `has_accept_lang`.",
                "Calculate Pearson correlation coefficients against `is_attack`."
            ]
        }
    },
    {
        "id": 6,
        "title": "Practical 6: Dataset Balancing for ML/DL Training",
        "short_title": "Dataset Balancing",
        "icon": "scale",
        "category": "Data Balancing",
        "tags": ["Class Imbalance", "Undersampling", "Oversampling", "Fair Training"],
        "py_file": "scripts/practical_06_dataset_balancing.py",
        "ipynb_file": "notebooks/practical_06_dataset_balancing.ipynb",
        "chart_path": "figures/p06_class_balancing.png",
        "chart_title": "Practical 6: Class Balancing Resampling Strategies (Preserving 1:1 Parity)",
        "chart_desc": "Side-by-side grouped bar chart comparing class distributions across Original (2.15:1 ratio), Random Undersampling (1:1 ratio, 31,792 rows), and Random Oversampling (1:1 ratio, 68,196 rows).",
        "key_metrics": [
            {"label": "Original Ratio", "value": "2.15 : 1"},
            {"label": "Balanced Samples", "value": "31,792 Rows"},
            {"label": "Final Balance", "value": "50.0% / 50.0%"},
            {"label": "Attack Diversity", "value": "Preserved"}
        ],
        "learning": {
            "analogy_title": "A Fair Jury Trial with Equal Representation",
            "analogy_desc": "Imagine a courtroom trial where 95 jurors support the prosecution and only 5 represent the defense. The jury will almost certainly return a guilty verdict regardless of evidence, simply due to overwhelming majority bias. To achieve a fair verdict, we must balance the jury with an equal number of jurors for both sides (50/50). Practical 6 balances the dataset so our machine learning model does not favor the majority class.",
            "concept_summary": "Cybersecurity datasets suffer from class imbalance: benign traffic often outnumbers attacks. Models trained on imbalanced data achieve misleadingly high accuracy by simply guessing the majority class. Practical 6 applies Random Undersampling and Random Oversampling to construct a balanced training dataset with an exact 1:1 class ratio.",
            "theoretical_foundations": [
                "**The Accuracy Paradox:** In a dataset with 99% benign traffic, a trivial model predicting 'Benign' every time achieves 99% accuracy while failing completely at attack detection (0% recall).",
                "**Random Undersampling:** Subsamples the majority class without replacement to match the minority count. Avoids synthetic noise and dramatically speeds up training, though it discards some majority data.",
                "**Random Oversampling / SMOTE:** Duplicates minority instances or synthesizes convex combinations of k-nearest neighbors in feature space. Retains all original records but can increase overfitting risk if unregularized.",
                "**Strategic Selection:** For high-volume log data (>50,000 samples), Random Undersampling provides sufficient representation for both classes while eliminating training bottlenecks."
            ],
            "methodology_steps": [
                "Calculate initial class counts: 34,098 Benign vs 15,896 Attacks (2.15:1 imbalance ratio).",
                "Apply `sklearn.utils.resample` to perform Random Undersampling of majority class.",
                "Apply Random Oversampling of the minority class for benchmarking.",
                "Verify stratified balance: exactly 15,896 Benign and 15,896 Attack records (1:1 ratio).",
                "Persist balanced dataset to `data/balanced_dataset_sample.csv`."
            ]
        }
    },
    {
        "id": 7,
        "title": "Practical 7: Data Wrangling for Aggregated Analysis",
        "short_title": "Aggregated Threat Wrangling",
        "icon": "network",
        "category": "Analytics",
        "tags": ["Threat Profiling", "Time-Series", "Pivot Tables", "Host Forensics"],
        "py_file": "scripts/practical_07_data_wrangling.py",
        "ipynb_file": "notebooks/practical_07_data_wrangling.ipynb",
        "chart_path": "figures/p07_aggregated_matrix.png",
        "chart_title": "Practical 7: Top Attacking Threat Actor IPs vs Exploit Vectors Cross-Tabulation",
        "chart_desc": "Two-dimensional heatmap cross-tabulating the top 5 threat actor IP addresses against specific attack categories, exposing dedicated scanner campaigns from IPs 42.105.165.217 and 157.32.110.9.",
        "key_metrics": [
            {"label": "Top Offender", "value": "5,218 Attacks (IP 42.105)"},
            {"label": "Resampling Frequency", "value": "1-Hour Windows"},
            {"label": "Pivot Dimensions", "value": "Hour x Category"},
            {"label": "Threat Actors", "value": "Persistent Hosts"}
        ],
        "learning": {
            "analogy_title": "The Detective's Crime Map Pinboard",
            "analogy_desc": "If police officers only look at individual 911 calls, each event seems like an isolated incident. But when a chief detective pins all crimes onto a city map and groups them by suspect and time of night, criminal syndicates emerge: Suspect A always strikes at 3:00 AM using crowbars, while Suspect B robs stores at noon. Practical 7 aggregates logs by IP and hour to expose coordinated cyber attack campaigns.",
            "concept_summary": "Individual log events show what happened at a single moment; aggregated data wrangling reveals multi-stage attack campaigns. Practical 7 groups by client IP to profile persistent threat actors, resamples time-series into 1-hour intervals, and creates multi-dimensional pivot tables.",
            "theoretical_foundations": [
                "**Split-Apply-Combine Paradigm:** Grouping log events by `client_ip` computes non-trivial aggregated statistics: attack ratio, user-agent diversity, average entropy, and maximum payload length.",
                "**Time-Series Resampling (Hourly Intervals):** Transforming non-uniform event streams into fixed-interval time buckets exposes bursty attacks and diurnal cycles.",
                "**Multi-Dimensional Pivot Tables:** Cross-tabulating two categorical dimensions (e.g. Hour of Day vs Attack Type) reveals synchronized attacks across different vectors."
            ],
            "methodology_steps": [
                "Group by `client_ip` to compute host behavioral profiles: request count, attack count, attack ratio percentage, and user agent diversity.",
                "Identify top 10 most aggressive attacking IP addresses (e.g., `42.105.165.217` generated 5,218 attacks).",
                "Set `datetime` as index and execute `df.resample('1h')` to track hourly assault waves.",
                "Construct pivot tables cross-tabulating attack categories across hours and top threat hosts.",
                "Export aggregated summaries to `outputs/p07_ip_aggregation.csv` and `outputs/p07_hourly_summary.csv`."
            ]
        }
    },
    {
        "id": 8,
        "title": "Practical 8: Data Visualization and Exploratory Data Analysis (EDA)",
        "short_title": "Visual EDA & Threat Analytics",
        "icon": "bar-chart-2",
        "category": "Visualization",
        "tags": ["Matplotlib", "Seaborn", "Multi-Panel Dashboard", "KDE Density"],
        "py_file": "scripts/practical_08_visualization_eda.py",
        "ipynb_file": "notebooks/practical_08_visualization_eda.ipynb",
        "chart_path": "figures/p08_eda_dashboard.png",
        "chart_title": "Practical 8: Comprehensive Cyber Telemetry Exploratory Data Analysis (EDA)",
        "chart_desc": "Multi-panel analytical dashboard combining Hourly Request Trends, Top 5 Threat Actors Bar Chart, Attack Vector Taxonomy Donut, and Shannon Entropy KDE Density curves.",
        "key_metrics": [
            {"label": "Dashboard Plots", "value": "4 Synchronized Views"},
            {"label": "Plotting Engines", "value": "Matplotlib & Seaborn"},
            {"label": "Entropy Analysis", "value": "KDE Density Curves"},
            {"label": "Threat Taxonomy", "value": "Donut Distribution"}
        ],
        "learning": {
            "analogy_title": "The Doppler Weather Radar for Cyber Hurricanes",
            "analogy_desc": "Meteorologists don't just read wind speed spreadsheets—they look at color-coded Doppler radar maps showing hurricane eye walls, storm intensity, and landfall predictions. Visual graphs translate raw numbers into intuitive spatial understanding. Practical 8 builds a 4-panel visual dashboard to identify cyber attack storms and traffic surges.",
            "concept_summary": "Exploratory Data Analysis (EDA) leverages graphical representations to uncover hidden patterns, detect anomalies, test hypotheses, and validate data distributions. Practical 8 produces publication-grade cybersecurity visualizations utilizing Matplotlib and Seaborn, communicating analytical insights into traffic surges, attacker distributions, and feature separations.",
            "theoretical_foundations": [
                "**Cognitive Visual Encodings:** Bar charts encode discrete quantities via length; line charts convey continuous temporal trends; heatmaps map scalar frequencies to perceptual color gradients.",
                "**Kernel Density Estimation (KDE):** Approximates the continuous Probability Density Function (PDF) of a random variable using Gaussian kernels, highlighting clear separation in payload Shannon entropy between benign and malicious traffic.",
                "**Headless Visual Generation:** Server and terminal environments lack X11 displays. Configuring `matplotlib.use('Agg')` ensures thread-safe, headless rasterization to PNG files."
            ],
            "methodology_steps": [
                "Configure publication style: dark background styling, tailored color palettes, and high resolution (150 DPI).",
                "Construct Subplot A: Hourly request timeline contrasting benign versus attack volumes.",
                "Construct Subplot B: Horizontal bar chart ranking top offending IP addresses with exact event annotations.",
                "Construct Subplot C: Proportional attack category distribution donut chart.",
                "Construct Subplot D: Kernel Density Estimate (KDE) demonstrating Shannon entropy separation.",
                "Export complete multi-panel dashboard to `figures/p08_eda_dashboard.png`."
            ]
        }
    },
    {
        "id": 9,
        "title": "Practical 9: Build a Classifier to Detect Attacks",
        "short_title": "Machine Learning Attack Classifier",
        "icon": "crosshair",
        "category": "Machine Learning",
        "tags": ["Random Forest", "Logistic Regression", "Confusion Matrix", "ROC-AUC"],
        "py_file": "scripts/practical_09_attack_classifier.py",
        "ipynb_file": "notebooks/practical_09_attack_classifier.ipynb",
        "chart_path": "figures/p09_model_evaluation.png",
        "chart_title": "Practical 9: Supervised Machine Learning Classifier Evaluation Suite",
        "chart_desc": "Three-part model evaluation: Random Forest Confusion Matrix (3,148 True Positives), ROC Curves (Random Forest AUC = 0.9994 vs Logistic Regression AUC = 0.9934), and Gini Feature Importance Ranking.",
        "key_metrics": [
            {"label": "Random Forest Accuracy", "value": "99.21%"},
            {"label": "Precision / Recall", "value": "99.40% / 99.02%"},
            {"label": "F1-Score", "value": "99.21%"},
            {"label": "ROC-AUC Score", "value": "0.9994"}
        ],
        "learning": {
            "analogy_title": "The Veteran Cyber Security Guard",
            "analogy_desc": "Imagine a bank security guard who has inspected thousands of visitors over 20 years. Instead of relying on a rigid rulebook, the guard observes behavioral cues: nervous glances, hidden pockets, mismatched badges. A rookie guard (Logistic Regression) makes linear assumptions; a veteran team of 100 guards conferring together (Random Forest) achieves near-perfect accuracy (99.21%) in catching intruders while letting customers pass.",
            "concept_summary": "Supervised machine learning allows automated, real-time threat detection without manual rule maintenance. Practical 9 trains and rigorously evaluates two classification paradigms: a linear Logistic Regression baseline and a non-linear ensemble Random Forest Classifier across 12 engineered features, achieving 99.21% test accuracy.",
            "theoretical_foundations": [
                "**Logistic Regression (Linear Hypothesis):**",
                "  $$P(y=1|X) = \\frac{1}{1 + e^{-(\\beta_0 + \\sum \\beta_i X_i)}}$$",
                "  Interpretable baseline that requires feature standardization (Z-score scaling) to converge properly.",
                "**Random Forest (Bagged Ensembles):** Combines 100 decorrelated Decision Trees with bootstrap aggregating and random feature subsampling. Resistant to overfitting and captures non-linear feature interactions.",
                "**Evaluation Metrics Beyond Accuracy:**",
                "  - **Precision:** $\\frac{TP}{TP + FP}$ — Measures false alarm resistance.",
                "  - **Recall:** $\\frac{TP}{TP + FN}$ — Measures threat capture rate.",
                "  - **F1-Score:** Harmonic mean balancing precision and recall.",
                "  - **ROC-AUC:** Area Under the Receiver Operating Characteristic curve measuring class discriminability across all thresholds."
            ],
            "methodology_steps": [
                "Partition balanced dataset into 80% Training (25,433 rows) and 20% Testing (6,359 rows) using stratified sampling.",
                "Apply `StandardScaler` to normalize feature distributions for Logistic Regression.",
                "Train Logistic Regression baseline (Accuracy = 98.24%, F1 = 98.22%).",
                "Train Random Forest Classifier with 100 estimators (Accuracy = 99.21%, F1 = 99.21%).",
                "Compute Confusion Matrix, ROC curves, and Gini feature importances (`is_scanner_ua` accounts for 43.78% of decision weight).",
                "Export evaluation triad visualization to `figures/p09_model_evaluation.png`."
            ]
        }
    },
    {
        "id": 10,
        "title": "Practical 10: Reusable Data Pipeline for Log Processing",
        "short_title": "Production Data Pipeline",
        "icon": "workflow",
        "category": "MLOps Pipeline",
        "tags": ["OOP Architecture", "Streaming Inference", "ETL Workflow", "Throughput"],
        "py_file": "scripts/practical_10_reusable_pipeline.py",
        "ipynb_file": "notebooks/practical_10_reusable_pipeline.ipynb",
        "chart_path": "figures/p10_pipeline_throughput.png",
        "chart_title": "Practical 10: Production Pipeline Stage Latency Benchmarks (~7,400 req/sec)",
        "chart_desc": "Horizontal breakdown of processing latency across each pipeline stage from Ingestion (0.12 ms) to ML Inference (0.18 ms), demonstrating an overall throughput of ~7,400 requests per second.",
        "key_metrics": [
            {"label": "Pipeline Class", "value": "LogSecurityPipeline"},
            {"label": "Training Batch", "value": "30,000 Records"},
            {"label": "End-to-End Latency", "value": "1.35 ms / record"},
            {"label": "Throughput", "value": "~7,400 req/sec"}
        ],
        "learning": {
            "analogy_title": "The Fully Automated Car Assembly Line",
            "analogy_desc": "Imagine building a car by hand in a garage vs inside an automated Tesla Gigafactory. In the Gigafactory, a raw steel chassis enters a conveyor belt: robotic arm 1 welds parts, arm 2 cleans surfaces, arm 3 installs electronics, arm 4 paints, and arm 5 performs diagnostic tests before it drives off the line. Practical 10 builds this automated conveyor belt (ETL pipeline) for cybersecurity data, processing thousands of requests per second.",
            "concept_summary": "In enterprise cybersecurity operations (SOC / SIEM), models cannot remain isolated in experimental scripts. Practical 10 encapsulates the entire data lifecycle into a production-grade, object-oriented class: LogSecurityPipeline. It automates log ingestion, schema parsing, cleaning, feature extraction, labeling, model fitting, and real-time streaming threat inference.",
            "theoretical_foundations": [
                "**Encapsulation & State Management:** A production pipeline maintains internal state—including known IP frequency counters and fitted model weights—preventing training-serving skew.",
                "**Batch vs Stream Processing Paradigm:** Batch pipelines process bounded historical logs for model fitting (`fit()`); streaming pipelines ingest unbounded real-time events (`predict_stream()`) with sub-millisecond latencies.",
                "**End-to-End Data Lineage & Serialization:** Traceability from raw JSON array to feature vector, prediction class, and confidence score ensures compliance and auditability in automated threat prevention systems."
            ],
            "methodology_steps": [
                "Architect `LogSecurityPipeline` class encapsulating 7 modular processing stages.",
                "Ingest 30,000 baseline log lines and execute end-to-end batch fitting.",
                "Export structured output dataset to `outputs/pipeline_processed_dataset.csv`.",
                "Simulate real-time streaming inference with diverse synthetic events (SQLi, DirBuster, RCE, XSS, Benign).",
                "Measure per-stage latency and benchmark throughput (~7,400 events/second).",
                "Export pipeline benchmarks chart to `figures/p10_pipeline_throughput.png`."
            ]
        }
    }
]

def main():
    print("Re-compiling web_data.json with rich analogies, plain-English explanations, and chart mappings...")
    for item in PRACTICALS:
        if os.path.exists(item['py_file']):
            with open(item['py_file'], 'r', encoding='utf-8') as f:
                item['py_code'] = f.read()
        else:
            item['py_code'] = "# Code not found"

        if os.path.exists(item['ipynb_file']):
            with open(item['ipynb_file'], 'r', encoding='utf-8') as f:
                nb_obj = json.load(f)
                stdout_text = ""
                for cell in nb_obj.get('cells', []):
                    if cell.get('cell_type') == 'code':
                        for out in cell.get('outputs', []):
                            if out.get('output_type') == 'stream' and 'text' in out:
                                if isinstance(out['text'], list):
                                    stdout_text += "".join(out['text'])
                                else:
                                    stdout_text += out['text']
                item['terminal_output'] = stdout_text.strip()
        else:
            item['terminal_output'] = "No terminal output recorded."

    with open("web_data.json", "w", encoding="utf-8") as f:
        json.dump(PRACTICALS, f, indent=2)

    print(f"Successfully re-compiled web_data.json ({len(PRACTICALS)} modules updated).")

if __name__ == "__main__":
    main()
