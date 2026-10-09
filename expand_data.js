const fs = require('fs');

const dataPaths = [
  '/home/khush/Downloads/PDS_Practicals/web_data.json',
  '/home/khush/Downloads/PDS_Practicals/dashboard-react/public/web_data.json'
];

let data = JSON.parse(fs.readFileSync(dataPaths[0], 'utf8'));

const detailedLearning = {
  1: {
    analogy_desc: "Imagine you are a detective entering a crime scene for the first time. Before dusting for fingerprints or collecting DNA, you must first survey the entire room, map out all the exits, note the positions of furniture, and catalog exactly what items are present or missing. Data Exploration is this initial 'scene survey' for data scientists.",
    concept_summary: "Data Exploration (EDA) is the foundational phase of the data science lifecycle where raw data is critically evaluated for structure, anomalies, and underlying patterns before any formal modeling occurs. In cybersecurity, this involves parsing unstructured log files to identify key dimensions—such as timestamps, IP addresses, HTTP request methods, and user-agent strings—that can reveal the attack surface. This practical emphasizes programmatic log parsing, schema inference, and the identification of missing data mechanisms (like Missing Not at Random, MNAR), which are critical for distinguishing automated bot traffic from legitimate user interactions.",
    theoretical_foundations: [
      "**Unstructured Data Parsing:** Regular expressions (regex) are employed to extract structured fields from raw textual logs. The time complexity of regex evaluation is a critical consideration when processing millions of log entries.",
      "**Data Types & Schema Inference:** Determining whether a field is nominal (e.g., HTTP methods), ordinal (e.g., severity levels), or continuous (e.g., payload size) dictates the choice of subsequent statistical analysis techniques.",
      "**Missing Data Mechanisms:** Understanding why data is missing is crucial. MNAR (Missing Not at Random) occurs when the probability of missingness depends on the unobserved value itself. For example, malicious scripts often deliberately omit the `User-Agent` header to evade detection, making the *absence* of the header a strong predictive feature."
    ],
    methodology_steps: [
      "**Step 1: Ingestion.** Read the raw `cj.log` file line by line using memory-efficient generators to prevent out-of-memory errors on large datasets.",
      "**Step 2: Parsing.** Apply a compiled regular expression to extract key components like IP, timestamp, request URL, status code, and user agent.",
      "**Step 3: Profiling.** Calculate summary statistics for each extracted field, including total count, unique values, and missing value percentages.",
      "**Step 4: Anomaly Detection.** Identify initial structural anomalies, such as malformed URLs or unexpected characters in standard headers, documenting them for the preprocessing phase."
    ],
    viva_questions: [
      { q: "Why is the generator pattern preferred over loading the entire log file into memory?", a: "Generators yield one item at a time, keeping the memory footprint constant (O(1) space complexity) regardless of the file size, which is essential for processing massive log files that exceed available RAM." },
      { q: "Explain the concept of 'Missing Not at Random' (MNAR) in the context of web logs.", a: "MNAR means the missingness is related to the data itself. In web logs, an automated attack script might deliberately not send a 'User-Agent' or 'Accept-Language' header. Thus, the missing value is not a random error but a direct indicator of malicious behavior." },
      { q: "How do regular expressions impact the time complexity of log parsing?", a: "Poorly constructed regular expressions can lead to catastrophic backtracking, resulting in exponential time complexity O(2^n). Using optimized, pre-compiled regex with atomic groups ensures linear O(n) parsing time per line." }
    ]
  },
  2: {
    analogy_desc: "Think of a factory assembly line. Raw materials (like iron ore and rubber) arrive in chaotic heaps. Data Engineering is the complex machinery that smelts the iron, shapes the rubber, and systematically assembles them into a perfectly structured car chassis, ready for the engine (machine learning) to be installed.",
    concept_summary: "Data Engineering is the discipline of designing and building pipelines that transform unstructured or semi-structured raw data into highly structured, usable formats. In this practical, we convert raw Apache/Nginx-style logs into a tabular Pandas DataFrame. This involves robust data typing, timezone-aware datetime conversion, and the extraction of granular features (like HTTP query parameters) from complex strings. Effective data engineering ensures that downstream algorithms receive clean, consistent, and semantically meaningful inputs, significantly reducing the 'garbage in, garbage out' risk.",
    theoretical_foundations: [
      "**Tabular Data Structures:** Utilizing columnar data formats (like DataFrames or Parquet) provides O(1) column access and enables vectorized operations, drastically improving computational efficiency compared to row-based processing.",
      "**Type Casting & Memory Optimization:** Downcasting 64-bit integers to 32-bit or converting low-cardinality string columns to categorical types can reduce memory footprint by 50-80%, enabling larger datasets to fit into RAM.",
      "**Idempotency in Data Pipelines:** A core principle of data engineering is ensuring that transformations are idempotent—running the same pipeline multiple times on the same raw data must always yield the exact same structured output without unintended side effects."
    ],
    methodology_steps: [
      "**Step 1: DataFrame Initialization.** Construct a Pandas DataFrame from the parsed log dictionaries.",
      "**Step 2: Type Enforcement.** Convert the 'timestamp' column to proper datetime objects with explicit timezone handling (UTC).",
      "**Step 3: URL Decomposition.** Parse the request URL to separate the base path from query parameters, creating new columns for 'param_key' and 'param_value'.",
      "**Step 4: Memory Optimization.** Convert nominal categorical variables like HTTP methods to Pandas `category` types to minimize memory usage.",
      "**Step 5: Serialization.** Export the structured DataFrame to a CSV or Parquet file for efficient downstream consumption."
    ],
    viva_questions: [
      { q: "What is the advantage of vectorization in Pandas over iterative loops?", a: "Vectorization delegates operations to highly optimized, pre-compiled C code under the hood, allowing operations to be performed on entire arrays simultaneously rather than iterating element-by-element in slow Python loops." },
      { q: "Why is handling timezones explicitly crucial in security data engineering?", a: "Cyber attacks are global. If logs from servers in different regions aren't normalized to a single timezone (like UTC), correlating events temporally to track the lateral movement of an attacker becomes impossible." },
      { q: "How does converting strings to 'category' types save memory?", a: "Instead of storing the full string (e.g., 'GET' or 'POST') for every single row, categorical types store a dictionary mapping integers to strings (e.g., 0='GET', 1='POST') and use a small integer array for the data, massively reducing storage for low-cardinality columns." }
    ]
  },
  3: {
    analogy_desc: "Imagine buying an old, abandoned house. Before you can paint the walls or move in furniture, you must first exterminate the pests, fix the broken plumbing, and sand down the rough floors. Data Cleaning is this essential renovation process that makes the data habitable for analysis.",
    concept_summary: "Data Preprocessing and Cleaning involves identifying and rectifying errors, inconsistencies, and artifacts in the dataset. In web security logs, this specifically entails decoding obfuscated URLs (e.g., converting `%27` to `'`), handling null values intelligently based on their mechanism (imputation vs. indicator variables), and normalizing continuous features. This stage is critical because malicious actors frequently use encoding techniques to hide exploits from basic signature-based detection systems. Proper cleaning unmasks the true nature of the payload.",
    theoretical_foundations: [
      "**URL Encoding (Percent-encoding):** A mechanism for encoding information in a Uniform Resource Identifier (URI). Attackers exploit this to obfuscate payloads. Preprocessing must recursively decode these strings to reveal SQL injection or XSS payloads.",
      "**Imputation Strategies:** Handling missing values can involve mean/median imputation, forward-filling, or treating the missingness as a distinct category (e.g., replacing null User-Agents with 'UNKNOWN_AGENT').",
      "**Feature Normalization:** Techniques like Min-Max scaling or Z-score normalization (Standardization) adjust the scale of numerical features so that distance-based ML algorithms (like KNN or SVM) are not biased by features with larger magnitudes."
    ],
    methodology_steps: [
      "**Step 1: URL Decoding.** Apply `urllib.parse.unquote` iteratively to decode all percent-encoded characters in the 'param_value' column.",
      "**Step 2: Null Handling.** Impute missing values in structural columns (like target_ip) with a designated placeholder ('0.0.0.0').",
      "**Step 3: Deduplication.** Identify and remove exact duplicate rows that may have resulted from logging errors or retries, ensuring they don't skew event frequencies.",
      "**Step 4: Case Normalization.** Convert all text fields (like URLs and User-Agents) to lowercase to ensure consistency during string matching and feature extraction."
    ],
    viva_questions: [
      { q: "Why might an attacker use double URL encoding, and how does your cleaning process address it?", a: "Attackers use double encoding (e.g., encoding '%' as '%25') to bypass rudimentary security filters that only decode once. A robust cleaning process uses recursive decoding until the string no longer changes." },
      { q: "In what scenario is replacing missing values with the mean inappropriate?", a: "Mean imputation is inappropriate for categorical data, heavily skewed numerical distributions (where median is better), or when the data is Missing Not at Random (MNAR), where the absence itself is a signal that would be destroyed by imputation." },
      { q: "What is the difference between Min-Max scaling and Z-score standardization?", a: "Min-Max scaling binds values between a specific range (usually 0 and 1), which is useful for neural networks. Z-score standardization centers data around a mean of 0 with a standard deviation of 1, which is better for algorithms that assume normally distributed data and handles outliers more gracefully." }
    ]
  },
  4: {
    analogy_desc: "Think of an airport security screener analyzing X-ray images of luggage. Without labels indicating what a 'gun' or a 'bomb' looks like, the screener is just guessing. Threat labeling provides the exact ground-truth definitions (the labels) so the system can learn to distinguish normal clothes from dangerous weapons.",
    concept_summary: "Cyber Threat Labeling is the process of assigning categorical ground-truth labels (e.g., 'Benign', 'SQLi', 'XSS', 'Path Traversal') to historical log data based on known attack signatures and behavioral heuristics. This transforms an unsupervised dataset into a supervised dataset, enabling the training of predictive machine learning models. This practical involves building a rules engine that utilizes advanced regular expressions and threat intelligence patterns to accurately classify each request, effectively mapping the dataset to the OWASP Top 10 vulnerability categories.",
    theoretical_foundations: [
      "**Supervised Learning Paradigm:** Supervised ML algorithms require a target variable (y) to map input features (X) to outputs. The quality, accuracy, and granularity of these labels directly determine the model's upper bound of performance.",
      "**Signature-Based Detection:** Utilizing precise byte sequences or regular expressions (signatures) known to be associated with specific exploits. While rigid, signatures provide high-fidelity labels for known attacks.",
      "**The OWASP Top 10 Taxonomy:** A standardized awareness document that represents a broad consensus on the most critical security risks to web applications. Mapping labels to OWASP (e.g., A03:2021-Injection) standardizes the threat intelligence."
    ],
    methodology_steps: [
      "**Step 1: Signature Definition.** Define a dictionary of compiled regular expressions representing known attack vectors (e.g., `(?i)(UNION.*SELECT)` for SQLi).",
      "**Step 2: Heuristic Rule Application.** Iterate through the decoded payloads and User-Agents, applying the regex signatures to categorize each row.",
      "**Step 3: Multi-class to Binary Mapping.** Create a high-level binary target variable (`is_attack`: 1 or 0) from the specific granular threat categories.",
      "**Step 4: Validation.** Sample the labeled data and manually verify a subset to calculate the labeling error rate and refine the regex rules."
    ],
    viva_questions: [
      { q: "What is the primary limitation of signature-based labeling?", a: "Signature-based detection cannot identify zero-day attacks or highly obfuscated variants of known attacks that alter their syntax just enough to bypass the specific regex rule." },
      { q: "Why do we create both granular categories (e.g., 'SQLi', 'XSS') and a binary label ('is_attack')?", a: "The binary label simplifies the problem for basic binary classification models (Attack vs. Benign). Granular labels allow for more advanced multi-class classification and detailed threat intelligence reporting on *what kind* of attacks are prevalent." },
      { q: "How would you handle a log entry that matches both an SQLi signature and an XSS signature?", a: "You must establish a precedence hierarchy based on severity (e.g., RCE > SQLi > XSS), assign a multi-label format, or categorize it as a 'Compound Attack' depending on the specific ML architecture being utilized." }
    ]
  },
  5: {
    analogy_desc: "Imagine tasting a complex soup. You don't just perceive 'soup'; your brain extracts specific features: the saltiness, the temperature, the texture of the vegetables, and the spice level. Feature engineering is teaching the computer to 'taste' the raw log data by extracting these specific, quantifiable metrics.",
    concept_summary: "Security Feature Engineering is the creative and analytical process of deriving new, highly predictive variables from raw data columns to improve machine learning model performance. In cybersecurity, attackers often try to blend in, so raw fields (like the payload string) are insufficient. We must engineer behavioral and structural features—such as payload Shannon Entropy, special character density, time elapsed since the last request, and user-agent legitimacy. These engineered features expose the underlying mathematical differences between human-driven browsers and automated malicious bots.",
    theoretical_foundations: [
      "**Information Theory (Shannon Entropy):** A mathematical measure of unpredictability or randomness in a string of characters. Obfuscated payloads or encrypted shellcode naturally exhibit much higher entropy than standard English words or typical URLs.",
      "**Temporal Dynamics & Velocity:** Automated scripts execute tasks at machine speed. Calculating the time difference ($\Delta t$) between consecutive requests from the same IP address provides a powerful signal of automation.",
      "**Dimensionality Reduction:** Feature engineering often involves summarizing complex, high-dimensional data (like a 500-character payload) into a single, highly informative float value (like 'special_char_ratio'), reducing the curse of dimensionality."
    ],
    methodology_steps: [
      "**Step 1: Structural Features.** Calculate the lengths of the URI and payload, and compute the ratio of special characters to alphanumeric characters.",
      "**Step 2: Information Theoretic Features.** Implement a function to calculate the Shannon Entropy of the decoded payload string.",
      "**Step 3: Temporal Features.** Sort the dataset by IP and Timestamp, then use `shift()` operations to calculate the exact time difference (in milliseconds) between consecutive requests per IP.",
      "**Step 4: Behavioral Features.** Flag known headless automated tools (e.g., `curl`, `python-requests`) based on User-Agent string analysis."
    ],
    viva_questions: [
      { q: "What is Shannon Entropy and why is it a good feature for detecting attacks?", a: "Shannon Entropy measures the randomness of data. Attackers often use Base64 encoding, encryption, or heavy obfuscation to hide payloads, which results in a high entropy value compared to the predictable, low-entropy structure of normal English words or URLs." },
      { q: "How do you calculate the velocity of requests for a specific IP address?", a: "By grouping the data by IP address, sorting chronologically by timestamp, and calculating the time delta between the current row and the previous row (`df.groupby('ip')['timestamp'].diff()`). A consistently near-zero delta strongly indicates a bot." },
      { q: "What is the 'curse of dimensionality' and how does feature engineering help?", a: "The curse refers to the fact that as the number of features increases, the data space becomes exponentially sparse, requiring exponentially more data to train models effectively. Feature engineering condenses complex text into a few highly informative numerical features, reducing dimensionality while maximizing predictive power." }
    ]
  },
  6: {
    analogy_desc: "Imagine a teacher giving a test where 99 questions are 'True' and only 1 is 'False'. A student who blindly guesses 'True' every time scores 99%—but they haven't learned anything. Dataset balancing ensures the teacher asks an equal number of True and False questions, forcing the student (the ML model) to actually learn the subject.",
    concept_summary: "Dataset Balancing addresses the fundamental issue of class imbalance, a pervasive problem in cybersecurity where benign traffic vastly outnumbers malicious traffic (e.g., 99:1). If a model is trained on this skewed data, it suffers from the 'Accuracy Paradox'—it achieves high accuracy by simply predicting the majority class while completely failing to detect the minority class (attacks). This practical explores techniques like Random Undersampling, Oversampling, and Synthetic Minority Over-sampling Technique (SMOTE) to equalize class distribution, ensuring the model optimizes for Recall and Precision rather than deceptive overall Accuracy.",
    theoretical_foundations: [
      "**The Accuracy Paradox:** In highly imbalanced datasets, accuracy is a misleading metric. A model predicting 'Benign' 100% of the time on a dataset with 1% attacks is 99% accurate but entirely useless for intrusion detection.",
      "**Undersampling vs. Oversampling:** Undersampling discards majority class data to match the minority class, risking the loss of valuable information. Oversampling duplicates minority data, which preserves information but increases the risk of overfitting.",
      "**SMOTE (Synthetic Minority Over-sampling Technique):** Instead of duplicating exact rows, SMOTE creates synthetic minority examples by interpolating new points along the line segments connecting nearest neighbors of the minority class in the feature space."
    ],
    methodology_steps: [
      "**Step 1: Distribution Analysis.** Calculate the exact ratio of benign to attack classes to quantify the imbalance severity.",
      "**Step 2: Undersampling.** Utilize `imblearn` or Pandas sampling methods to randomly select a subset of the benign traffic equal in size to the attack traffic.",
      "**Step 3: Verification.** Verify that the resulting dataset has a perfect 1:1 distribution ratio.",
      "**Step 4: Metric Realignment.** Shift the evaluation strategy away from Accuracy toward F1-Score, Precision-Recall AUC, and the Confusion Matrix."
    ],
    viva_questions: [
      { q: "Why is accuracy a terrible metric for a real-world Intrusion Detection System?", a: "Because real-world traffic is heavily skewed (e.g., 99.9% benign). A broken system that always says 'benign' will be 99.9% accurate while allowing 100% of attacks to succeed. This is the accuracy paradox." },
      { q: "What is the primary risk of using Random Oversampling to balance a dataset?", a: "Random oversampling simply duplicates existing minority class rows. This can lead to severe overfitting, where the model memorizes those specific duplicated examples rather than learning generalizable patterns, failing when exposed to novel attack variants." },
      { q: "Explain briefly how SMOTE generates synthetic data.", a: "SMOTE selects a minority class instance, finds its k-nearest minority class neighbors, and then creates synthetic data points randomly along the geometric line segments connecting the instance to its neighbors in the feature space." }
    ]
  },
  7: {
    analogy_desc: "Think of a police detective looking at a board covered in pushpins and string. A single reported theft (a single log entry) might not mean much. But when the detective groups incidents by neighborhood and maps them over time (aggregation), they suddenly reveal the coordinated pattern of an organized crime syndicate.",
    concept_summary: "Aggregated Threat Wrangling shifts the focus from individual log events to the behavioral profiles of entities (specifically, IP addresses). An attacker might send 100 malicious requests amidst 1,000 seemingly benign requests. By aggregating data using GroupBy operations and Pivot Tables, we create comprehensive 'Threat Actor Profiles'. We calculate metrics like the ratio of attacks to total requests, the number of distinct user-agents utilized (indicating evasion tactics), and temporal spread. This macro-level analytics is essential for identifying persistent advanced threats and generating actionable firewall blocklists.",
    theoretical_foundations: [
      "**Entity Profiling:** Moving from event-based analysis (each row is a request) to entity-based analysis (each row is an IP address or User ID) allows for the detection of distributed or 'low-and-slow' campaigns.",
      "**Cross-Tabulation (Pivot Tables):** Mathematical summarization techniques that transpose rows and columns to summarize relationships between categorical variables (e.g., mapping IP addresses against the specific types of attacks they deploy).",
      "**Evasion Detection through Variance:** An IP address cycling through dozens of different 'User-Agent' strings in a short timeframe is exhibiting high variance in a nominally static field, strongly indicating automated evasion attempts."
    ],
    methodology_steps: [
      "**Step 1: IP Grouping.** Group the balanced dataset by 'client_ip' using Pandas `.groupby()`.",
      "**Step 2: Metric Aggregation.** Calculate total requests, total confirmed attacks, and the unique count of user-agents (`nunique`) for each IP.",
      "**Step 3: Ratio Calculation.** Compute the 'Malicious Ratio' (attacks / total requests) to determine the persistence and intent of the actor.",
      "**Step 4: Pivot Cross-Tabulation.** Create a pivot table showing the frequency of each specific attack category (SQLi, XSS, etc.) deployed by the top 10 most aggressive IPs."
    ],
    viva_questions: [
      { q: "What is the difference between a groupby operation and a pivot table?", a: "A groupby operation groups data by one or more keys and applies an aggregation function, returning a one-dimensional grouped index. A pivot table reshapes the data, placing one categorical variable on the rows and another on the columns, creating a two-dimensional matrix of aggregated values." },
      { q: "Why is tracking the number of unique User-Agents for a single IP address useful?", a: "Normal users typically browse with a single browser, meaning their IP will show 1 or 2 distinct User-Agents. If a single IP exhibits 50 different User-Agents in an hour, it definitively indicates an automated script rotating agents to evade fingerprinting." },
      { q: "How can entity aggregation detect a 'low-and-slow' attack?", a: "A low-and-slow attack sends malicious requests very infrequently to avoid triggering rate limits. While individual requests look benign, aggregating data over a week for that IP might reveal a pattern of probing specific vulnerable endpoints that becomes statistically significant at the macro level." }
    ]
  },
  8: {
    analogy_desc: "Imagine staring at a spreadsheet with a million numbers. Your brain struggles to comprehend it. Visual EDA is like putting on infrared goggles; suddenly, the invisible patterns, heat signatures, and outliers jump out at you immediately. It translates cold mathematics into human intuition.",
    concept_summary: "Visual Exploratory Data Analysis (EDA) is the art and science of utilizing graphical representations to uncover underlying structures, trends, and anomalies within the engineered dataset. While statistical metrics provide numbers, visualization reveals the shape of the data. In this practical, we leverage Matplotlib and Seaborn to generate publication-quality figures: time-series distributions of attack surges, density plots (KDE) demonstrating feature separation (like Shannon Entropy), and correlation heatmaps to prevent multicollinearity in our downstream ML models.",
    theoretical_foundations: [
      "**Anscombe's Quartet:** A classic statistical phenomenon demonstrating that four datasets can have nearly identical summary statistics (mean, variance, correlation) yet appear completely different when graphed. This proves visualization is not optional, but strictly mandatory.",
      "**Kernel Density Estimation (KDE):** A non-parametric way to estimate the probability density function of a continuous random variable. It smooths out histograms, providing a clearer view of the bimodal separation between benign and malicious feature distributions.",
      "**Multicollinearity and Heatmaps:** If two independent features are highly correlated with each other (multicollinearity), they provide redundant information and can destabilize certain ML models. Correlation heatmaps visualize this matrix to aid in feature selection."
    ],
    methodology_steps: [
      "**Step 1: Temporal Visualization.** Plot a line chart or grouped bar chart showing the volume of benign vs. malicious traffic mapped against the hour of the day.",
      "**Step 2: Distribution Analysis.** Use Seaborn's KDE plot to visualize the distribution of Shannon Entropy, clearly illustrating the bimodal separation of classes.",
      "**Step 3: Correlation Matrix.** Compute the Pearson correlation coefficient matrix for all numerical features and render it as an annotated Seaborn heatmap.",
      "**Step 4: Threat Taxonomy.** Generate a doughnut chart visualizing the proportional breakdown of specific attack categories."
    ],
    viva_questions: [
      { q: "What is the purpose of a Kernel Density Estimation (KDE) plot compared to a standard histogram?", a: "A histogram bins continuous data into discrete intervals, making the shape heavily dependent on the chosen bin width. A KDE plot uses a smoothing kernel to create a continuous curve representing the true underlying probability density, offering a clearer, bin-independent view of the distribution." },
      { q: "Why is it important to check for highly correlated features using a heatmap before training a model?", a: "Highly correlated features (multicollinearity) offer redundant information, unnecessarily increasing the dimensionality of the model. Furthermore, in models like Linear or Logistic Regression, multicollinearity can cause unstable coefficient estimates, making it impossible to interpret feature importance." },
      { q: "How does visualizing temporal data (time-series) help in cybersecurity?", a: "Cyber attacks are rarely uniform. Visualizing traffic over time reveals critical patterns like automated surges at 3:00 AM, the duration of DDoS campaigns, or the synchronization of botnets, which static aggregate statistics completely hide." }
    ]
  },
  9: {
    analogy_desc: "Think of an expert art appraiser. Through years of training, they have learned to instinctively recognize the subtle brushstrokes of a forgery versus a masterpiece. An ML Classifier is an artificial appraiser trained on thousands of examples, learning the complex mathematical 'brushstrokes' that differentiate a benign user from a hacker.",
    concept_summary: "The Machine Learning Attack Classifier is the culmination of the data science pipeline. We transition from analyzing historical data to predicting future threats. We train a Random Forest ensemble classifier—a robust, non-linear model highly resistant to overfitting—on our balanced, engineered feature set. The model learns complex decision boundaries based on entropy, velocity, and signatures. Crucially, we evaluate the model not just on Accuracy, but on Precision (minimizing false positives/alert fatigue) and Recall (minimizing false negatives/missed breaches), utilizing the ROC curve to assess discriminatory power.",
    theoretical_foundations: [
      "**Ensemble Learning (Random Forest):** Instead of training a single decision tree (which is prone to overfitting and high variance), a Random Forest trains hundreds of trees on bootstrapped subsets of the data and random subsets of features, aggregating their predictions via majority voting. This dramatically increases generalization and robustness.",
      "**The Confusion Matrix:** A fundamental 2x2 matrix categorizing predictions into True Positives (caught attack), True Negatives (allowed benign), False Positives (false alarm), and False Negatives (missed attack).",
      "**Precision-Recall Tradeoff:** In cybersecurity, there is a constant tension between Precision (if the model flags an attack, how likely is it real?) and Recall (out of all real attacks, what percentage did the model catch?). Tuning the classification threshold dictates this tradeoff."
    ],
    methodology_steps: [
      "**Step 1: Train/Test Split.** Partition the balanced dataset into an 80% training set and a 20% holdout testing set to evaluate generalization on unseen data.",
      "**Step 2: Model Instantiation.** Initialize a Random Forest Classifier and a baseline Logistic Regression model for comparative analysis.",
      "**Step 3: Training & Prediction.** Fit the models to the training data (X_train, y_train) and generate probability predictions on the test set (X_test).",
      "**Step 4: Metric Evaluation.** Calculate Accuracy, Precision, Recall, F1-Score, and the ROC-AUC score.",
      "**Step 5: Feature Importance.** Extract Gini importance from the Random Forest to rank which engineered features contributed most to the model's decisions."
    ],
    viva_questions: [
      { q: "Why is a Random Forest generally preferred over a single Decision Tree for security classification?", a: "A single Decision Tree is highly prone to overfitting; it memorizes the training data perfectly but fails on new, unseen attack variants. Random Forest, by averaging the predictions of many decorrelated trees, drastically reduces this variance, leading to much better generalization." },
      { q: "In the context of a Security Operations Center (SOC), would you prioritize Precision or Recall?", a: "It depends on the SOC's resources, but usually, a balance leaning towards Precision is required. If a model has high Recall but terrible Precision, it will generate thousands of False Positives. This causes 'alert fatigue', where security analysts become overwhelmed and begin ignoring alerts, eventually missing real attacks." },
      { q: "What does the Area Under the Receiver Operating Characteristic Curve (ROC-AUC) measure?", a: "ROC-AUC measures the model's ability to discriminate between the two classes across all possible classification thresholds. An AUC of 0.5 indicates random guessing, while 1.0 indicates perfect separation. It is an excellent metric for evaluating model robustness on imbalanced data." }
    ]
  },
  10: {
    analogy_desc: "Imagine a master chef who has perfected a recipe in a quiet test kitchen. MLOps is the process of taking that recipe and building an automated, industrial kitchen capable of serving a thousand meals a minute, perfectly and safely, without the chef needing to be there.",
    concept_summary: "The Production Data Pipeline (MLOps) transitions the machine learning model from a static Jupyter Notebook experiment into a dynamic, real-time software engineering system. This practical focuses on model serialization, constructing a streaming pipeline capable of ingesting micro-batches of data, engineering features on the fly, and returning predictions with sub-second latency. We emphasize system architecture, throughput optimization, and performance benchmarking, simulating how this classifier would operate as a live Intrusion Detection System (IDS) sitting behind a web server.",
    theoretical_foundations: [
      "**Model Serialization (Pickle/Joblib):** The process of translating the in-memory state of a trained ML model into a byte stream that can be saved to disk and instantly reloaded into a different Python process in production without retraining.",
      "**Streaming vs. Batch Processing:** Unlike historical batch processing, production security requires analyzing unbounded streams of data in near real-time. This necessitates highly optimized feature engineering code that avoids expensive global operations (like sorting large dataframes).",
      "**Throughput & Latency Benchmarking:** System performance is measured by throughput (requests processed per second) and latency (time taken to process a single request). A production IDS must maintain microsecond latency to avoid bottlenecking network traffic."
    ],
    methodology_steps: [
      "**Step 1: Serialization.** Use `joblib` to save the trained Random Forest model and any necessary scalers or encoders to disk.",
      "**Step 2: Pipeline Encapsulation.** Write a Python class (`LiveThreatDetector`) that encapsulates the loading of the model, real-time feature extraction, and prediction logic.",
      "**Step 3: Micro-batch Ingestion.** Simulate a real-time data stream by feeding the pipeline chunks (e.g., 1000 rows at a time) from the raw log file.",
      "**Step 4: Benchmarking.** Instrument the pipeline with `time.time()` to measure exact latency per micro-batch and calculate overall throughput (records/second).",
      "**Step 5: Alert Generation.** Write logic that triggers a high-severity alert whenever the model's prediction probability exceeds a defined threshold (e.g., 0.85)."
    ],
    viva_questions: [
      { q: "What is the danger of using 'Pickle' to load models in a production environment?", a: "Pickle files can execute arbitrary code during the unpickling process. If a malicious actor can replace the model.pkl file on the server, loading it will result in Remote Code Execution (RCE). Models should be verified via cryptographic hashes or stored in safer formats like ONNX." },
      { q: "How does feature engineering differ in a real-time streaming pipeline compared to a batch Jupyter Notebook?", a: "In a notebook, you have the entire dataset and can do global operations like standardizing a column by dividing by the dataset's global maximum. In a real-time stream, you only see one request at a time. You must use pre-computed scaling factors (saved during training) to scale new data points." },
      { q: "If your real-time pipeline is processing 1,000 records per second, what is the average latency per record?", a: "If 1,000 records are processed in 1 second (1000 milliseconds), the average latency per record is 1 millisecond." }
    ]
  }
};

for (const p of data) {
  if (detailedLearning[p.id]) {
    p.learning = detailedLearning[p.id];
  }
}

const prettyData = JSON.stringify(data, null, 2);

fs.writeFileSync(dataPaths[0], prettyData);
if (fs.existsSync(dataPaths[1])) {
  fs.writeFileSync(dataPaths[1], prettyData);
}

console.log("Successfully expanded learning content for all 10 practicals!");
