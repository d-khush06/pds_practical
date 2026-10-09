// Per-practical Chart.js configurations — each practical has a DISTINCT chart type
export const CHART_CONFIGS = {
  1: {
    title: 'Field Completeness Distribution (100k Records)',
    badge: 'Horizontal Bar',
    insight: 'The <strong>81.64% missing rate</strong> in param_key/param_value represents benign browsers hitting the root URL "/" — the null itself is a discriminating signal.',
    type: 'bar',
    data: {
      labels: ['client_ip','timestamp','client_port','user_agent','accept_language','target_ip','param_value','param_key'],
      datasets: [{
        label: 'Completeness (%)',
        data: [100, 100, 100, 95.36, 48.24, 25.63, 18.36, 18.36],
        backgroundColor: ['rgba(0,210,255,0.8)','rgba(0,210,255,0.8)','rgba(0,210,255,0.8)','rgba(56,189,248,0.7)','rgba(99,102,241,0.7)','rgba(168,85,247,0.6)','rgba(244,63,94,0.6)','rgba(244,63,94,0.6)'],
        borderRadius: 4,
      }]
    },
    options: { indexAxis: 'y', scales: { x: { max: 100 } } }
  },
  2: {
    title: 'Missing Value Null Profile — 49,994 Rows',
    badge: 'Stacked Bar',
    insight: '<strong>MNAR Pattern:</strong> param_key/param_value are 81.64% null because benign users visit root "/" without parameters — the null is an informative signal, not random noise.',
    type: 'bar',
    data: {
      labels: ['param_key','param_value','accept_language','target_ip','user_agent','timestamp','client_ip','client_port'],
      datasets: [
        { label: 'Present', data: [18.36,18.36,48.24,25.63,95.36,100,100,100], backgroundColor: 'rgba(16,185,129,0.7)', borderRadius: 4 },
        { label: 'Missing', data: [81.64,81.64,51.76,74.37,4.64,0,0,0], backgroundColor: 'rgba(244,63,94,0.5)', borderRadius: 4 },
      ]
    },
    options: { scales: { x: { stacked: true }, y: { stacked: true, max: 100 } } }
  },
  3: {
    title: 'Cleaned Hourly Request Velocity (24-Hour)',
    badge: 'Area Line',
    insight: 'The <strong>07:00 UTC spike of 6,939 requests</strong> reveals a coordinated scanner campaign. URL decoding exposed hidden payloads like %27 → \' (SQL injection character).',
    type: 'line',
    data: {
      labels: Array.from({length:24},(_,i)=>`${String(i).padStart(2,'0')}:00`),
      datasets: [
        { label: 'Total Requests', data: [494,1105,1133,1383,1388,2344,1565,6939,2751,1511,890,760,820,740,680,720,950,880,760,830,910,740,620,510], borderColor: 'rgba(0,210,255,0.9)', backgroundColor: 'rgba(0,210,255,0.1)', fill: true, tension: 0.4, pointRadius: 3 },
        { label: 'Attack Requests', data: [120,300,350,420,430,800,580,4200,1100,500,290,230,260,210,195,210,300,265,220,250,280,200,175,130], borderColor: 'rgba(244,63,94,0.9)', backgroundColor: 'rgba(244,63,94,0.08)', fill: true, tension: 0.4, pointRadius: 3 },
      ]
    },
    options: {}
  },
  4: {
    title: 'Attack Category Taxonomy Distribution',
    badge: 'Doughnut',
    insight: '<strong>Scanner Recon dominates at 79.4%</strong> of attacks — Nikto/DirBuster fire thousands of probes per campaign. Exploit payloads (SQLi: 4.16%, Path Traversal: 5.12%) are fewer but far more dangerous.',
    type: 'doughnut',
    data: {
      labels: ['Scanner Recon','Path Traversal','RFI','SQL Injection','Cmd Injection','XSS'],
      datasets: [{ data: [12621,814,936,662,594,269], backgroundColor: ['rgba(244,63,94,0.82)','rgba(245,158,11,0.82)','rgba(168,85,247,0.82)','rgba(239,68,68,0.82)','rgba(99,102,241,0.82)','rgba(16,185,129,0.82)'], borderColor: 'rgba(0,0,0,0.2)', borderWidth: 2, hoverOffset: 12 }]
    },
    options: { plugins: { legend: { position: 'right' } } }
  },
  5: {
    title: 'Feature Correlation with Attack Label (Pearson r)',
    badge: 'Diverging Bar',
    insight: '<strong>is_scanner_ua (r=+0.8788)</strong> is the strongest predictor — scanner tools announce themselves. <strong>is_standard_browser (r=-0.7138)</strong> confirms real browsers are strong benign indicators.',
    type: 'bar',
    data: {
      labels: ['is_scanner_ua','special_char_ratio','payload_entropy','is_headless_tool','key_length','payload_length','has_digits','time_diff_sec','requests_per_ip','is_missing_ua','has_accept_lang','is_standard_browser'],
      datasets: [{
        label: 'Pearson r',
        data: [0.8788,0.2786,0.2480,0.1814,0.1387,0.1300,-0.0493,-0.1642,-0.1559,-0.1491,-0.5483,-0.7138],
        backgroundColor: (ctx) => ctx.parsed?.x >= 0 ? 'rgba(0,210,255,0.72)' : 'rgba(244,63,94,0.72)',
        borderRadius: 4,
      }]
    },
    options: { indexAxis: 'y', scales: { x: { min: -1, max: 1 } } }
  },
  6: {
    title: 'Class Balancing — Distribution Comparison',
    badge: 'Grouped Bar',
    insight: 'Training on imbalanced data causes the <strong>Accuracy Paradox</strong>: a model predicting "Benign" always achieves 68.2% accuracy. Balancing forces it to learn true attack patterns.',
    type: 'bar',
    data: {
      labels: ['Original (2.15:1)','Undersampled (1:1)','Oversampled (1:1)'],
      datasets: [
        { label: 'Benign (Class 0)', data: [34098,15896,34098], backgroundColor: 'rgba(16,185,129,0.7)', borderRadius: 4 },
        { label: 'Attack (Class 1)', data: [15896,15896,34098], backgroundColor: 'rgba(244,63,94,0.7)', borderRadius: 4 },
      ]
    },
    options: {}
  },
  7: {
    title: 'Top Threat Actors — Requests vs Confirmed Attacks',
    badge: 'Multi-Bar',
    insight: '<strong>42.105.165.217</strong> sent 5,274 requests with 98.94% attack rate and 3,631 distinct user-agents — indicating sophisticated evasion through UA rotation.',
    type: 'bar',
    data: {
      labels: ['42.105.165','157.32.110','49.34.106','42.106.39','14.139.122','103.85.8','157.32.80','185.224.128'],
      datasets: [
        { label: 'Total Requests', data: [5274,3017,2314,1888,7655,145,102,90], backgroundColor: 'rgba(99,102,241,0.65)', borderRadius: 4 },
        { label: 'Attack Events', data: [5218,2984,2297,1849,1290,118,94,90], backgroundColor: 'rgba(244,63,94,0.75)', borderRadius: 4 },
      ]
    },
    options: {}
  },
  8: {
    title: 'Shannon Entropy Distribution — Benign vs Attack',
    badge: 'Histogram',
    insight: 'Benign payloads cluster near <strong>H=0–1.5 bits</strong>. Attack payloads (shellcodes, base64) exhibit <strong>H=2.5–4.5 bits</strong>. This bimodal separation validates entropy as a valid ML feature.',
    type: 'bar',
    data: {
      labels: ['0.0','0.5','1.0','1.5','2.0','2.5','3.0','3.5','4.0','4.5','5.0'],
      datasets: [
        { label: 'Benign Traffic', data: [8200,1800,1200,900,600,400,250,120,60,20,10], backgroundColor: 'rgba(59,130,246,0.65)', borderRadius: 3 },
        { label: 'Attack Traffic', data: [4500,600,800,1100,1400,1600,1800,2000,1200,600,200], backgroundColor: 'rgba(244,63,94,0.65)', borderRadius: 3 },
      ]
    },
    options: { scales: { x: { title: { display:true, text:'Shannon Entropy (bits)' } }, y: { title: { display:true, text:'Frequency' } } } }
  },
  9: {
    title: 'ML Model Evaluation — Accuracy, Precision, Recall, F1',
    badge: 'Comparative Bar',
    insight: 'Random Forest outperforms Logistic Regression by ~1% on all metrics. <strong>is_scanner_ua</strong> contributes 43.78% of Gini importance — a non-linear pattern RF captures perfectly.',
    type: 'bar',
    data: {
      labels: ['Accuracy','Precision','Recall','F1-Score'],
      datasets: [
        { label: 'Logistic Regression', data: [98.24,98.15,98.34,98.22], backgroundColor: 'rgba(99,102,241,0.7)', borderRadius: 4 },
        { label: 'Random Forest (100 trees)', data: [99.21,99.40,99.02,99.21], backgroundColor: 'rgba(0,210,255,0.78)', borderRadius: 4 },
      ]
    },
    options: { scales: { y: { min: 95, max: 100 } } }
  },
  10: {
    title: 'Streaming Pipeline Throughput vs Window Size',
    badge: 'Dual-Axis Line',
    insight: 'The pipeline achieves <strong>1,460 records/second</strong> throughput at scale, processing 10k-record windows in under 7 seconds — meeting sub-second latency for production IDS systems.',
    type: 'line',
    data: {
      labels: ['100','500','1K','2K','5K','10K'],
      datasets: [
        { label: 'Throughput (rec/s)', data: [1250,1380,1420,1440,1455,1460], borderColor: 'rgba(0,210,255,0.9)', backgroundColor: 'rgba(0,210,255,0.1)', fill: true, tension: 0.4, pointRadius: 5, yAxisID: 'y' },
        { label: 'Attack Detection %', data: [32,31.6,31.5,31.8,31.6,31.8], borderColor: 'rgba(244,63,94,0.9)', backgroundColor: 'rgba(244,63,94,0.06)', fill: true, tension: 0.3, pointRadius: 5, yAxisID: 'y2' },
      ]
    },
    options: {
      scales: {
        x: { title: { display:true, text:'Window Size (records)' } },
        y: { title: { display:true, text:'Records/Second' }, position:'left' },
        y2: { title: { display:true, text:'Detection Rate (%)' }, position:'right', grid: { drawOnChartArea: false } },
      }
    }
  }
}

// Cover gradients per practical
export const COVERS = [
  'linear-gradient(135deg,#020b28 0%,#0a1e6e 60%,#0d3090 100%)',
  'linear-gradient(135deg,#011a10 0%,#064e3b 60%,#065f46 100%)',
  'linear-gradient(135deg,#150a2e 0%,#3b0764 60%,#4c1d95 100%)',
  'linear-gradient(135deg,#2a0600 0%,#7f1d1d 60%,#991b1b 100%)',
  'linear-gradient(135deg,#08162b 0%,#1e3a8a 60%,#1d4ed8 100%)',
  'linear-gradient(135deg,#001220 0%,#0c4a6e 60%,#0369a1 100%)',
  'linear-gradient(135deg,#0a0218 0%,#2e1065 60%,#5b21b6 100%)',
  'linear-gradient(135deg,#0a1a00 0%,#365314 60%,#3f6212 100%)',
  'linear-gradient(135deg,#1a0020 0%,#701a75 60%,#86198f 100%)',
  'linear-gradient(135deg,#050a1f 0%,#1e3a8a 50%,#312e81 100%)',
]

// Stage colors for pipeline view
export const STAGE_COLORS = ['#38bdf8','#34d399','#a78bfa','#f87171','#60a5fa','#fbbf24','#818cf8','#4ade80','#f472b6','#22d3ee']

// Stage outputs for pipeline view
export const STAGE_OUTPUTS = {
  1: 'Schema: 8 fields, 100k lines scanned, 99.99% valid JSON',
  2: '49,994-row DataFrame → structured_logs_sample.csv',
  3: '49,994 clean records with datetime + URL decode + temporal features',
  4: '34,098 Benign + 15,896 Attack → labeled_logs_sample.csv',
  5: '12 engineered features: entropy, velocity, UA signature, special chars',
  6: 'Balanced: 31,792 rows (50/50%) → balanced_dataset_sample.csv',
  7: 'IP aggregation CSVs + hourly time-series + cross-tabulation pivots',
  8: '6 publication-quality PNGs: traffic, IPs, donut, KDE, heatmaps',
  9: 'Random Forest: 99.21% accuracy, 0.9994 AUC, feature importance',
  10: 'Streaming pipeline: 1,460 rec/s, <1ms latency per prediction',
}

// Dataset view chart data
export const DATASET_DONUT = {
  labels: ['Benign (68.2%)','Attacks (31.8%)'],
  datasets: [{ data: [34098,15896], backgroundColor: ['rgba(16,185,129,0.78)','rgba(244,63,94,0.78)'], borderColor: 'rgba(0,0,0,0.15)', borderWidth: 2, hoverOffset: 8 }]
}
export const DATASET_BAR = {
  labels: ['Scanner Recon','RFI','Path Traversal','SQL Injection','Cmd Injection','XSS'],
  datasets: [{ label: 'Count', data: [12621,936,814,662,594,269], backgroundColor: ['rgba(244,63,94,0.82)','rgba(168,85,247,0.72)','rgba(245,158,11,0.72)','rgba(239,68,68,0.72)','rgba(99,102,241,0.72)','rgba(16,185,129,0.72)'], borderRadius: 4 }]
}

// Example data tables per practical
export const EXAMPLES = {
  1: {
    title: 'Sample Raw Log Records from cj.log',
    headers: ['#','param_key','param_value','timestamp','client_ip','user_agent'],
    rows: [
      ['0','null','null','2023-01-10 17:56:09','42.105.165.217','Mozilla/5.00 (Nikto/2.1.6)'],
      ['1','highlight',"'passthru($HTTP_GET_VARS)",'2023-01-09 17:04:27','42.106.39.186','Mozilla/5.00 (Nikto/2.1.6)'],
      ['2','null','null','2023-01-11 07:03:09','14.139.122.76','Mozilla/5.0 Windows Firefox/108.0'],
      ['3','ls','ps','2023-01-10 08:15:22','94.102.49.206','Go-http-client/1.1'],
      ['4','id',"1 OR 1=1--",'2023-01-09 20:33:10','185.220.101.5','sqlmap/1.6'],
    ]
  },
  2: {
    title: 'DataFrame — Missing Values Profile',
    headers: ['Column','Non-Null','Null Count','Missing %','MNAR Reason'],
    rows: [
      ['param_key','9,178','40,816','81.64%','Root URL requests have no params'],
      ['param_value','9,178','40,816','81.64%','Benign visits leave blank'],
      ['timestamp','49,994','0','0.00%','Forensic anchor — always present'],
      ['client_ip','49,994','0','0.00%','Forensic anchor — always present'],
      ['user_agent','47,672','2,322','4.64%','Headless scanners skip UA'],
      ['accept_language','24,117','25,877','51.76%','Automated scripts have no lang'],
      ['target_ip','12,815','37,179','74.37%','Not always logged by honeypot'],
    ]
  },
  3: {
    title: 'Cleaned Hourly Traffic Distribution',
    headers: ['Hour (UTC)','Requests','Attacks','Benign','Notes'],
    rows: [
      ['07:00','6,939','4,200','2,739','Automated scanner peak'],
      ['05:00','2,344','800','1,544','Early morning bots'],
      ['08:00','2,751','1,100','1,651','Scan continuation'],
      ['01:00','1,105','300','805','Low overnight traffic'],
      ['00:00','494','120','374','Minimal activity'],
    ]
  },
  4: {
    title: 'Attack Label Classification Results',
    headers: ['Category','Count','Percentage','Example Payload','OWASP'],
    rows: [
      ['benign','34,098','68.20%','Normal browser GET /','N/A'],
      ['scanner_recon','12,621','25.25%','Nikto/2.1.6 scan','A05'],
      ['rfi','936','1.87%','http://evil.com/shell.php','A03'],
      ['path_traversal','814','1.63%','../../../etc/passwd','A01'],
      ['sqli','662','1.32%',"1' OR 1=1 UNION SELECT--",'A03'],
      ['cmd_injection','594','1.19%',';cat /etc/passwd','A03'],
      ['xss','269','0.54%',"<script>alert('xss')</script>",'A03'],
    ]
  },
  5: {
    title: 'Feature Correlation with is_attack',
    headers: ['Feature','Mean','Std Dev','Pearson r','Interpretation'],
    rows: [
      ['is_scanner_ua','0.265','0.441','+0.8788','Strongest — scanner agents'],
      ['special_char_ratio','0.013','0.065','+0.2786','High ratio in exploits'],
      ['payload_entropy','0.342','0.973','+0.2480','Obfuscated = attack'],
      ['is_headless_tool','0.015','0.123','+0.1814','curl/wget suspicious'],
      ['has_accept_lang','0.482','0.500','-0.5483','Browsers have lang header'],
      ['is_standard_browser','0.561','0.496','-0.7138','Browsers = benign'],
    ]
  },
  6: {
    title: 'Class Balancing Strategy Comparison',
    headers: ['Strategy','Benign','Attack','Total','Ratio'],
    rows: [
      ['Original','34,098','15,896','49,994','2.15:1'],
      ['Undersampled','15,896','15,896','31,792','1.00:1'],
      ['Oversampled','34,098','34,098','68,196','1.00:1'],
    ]
  },
  7: {
    title: 'Top 8 Threat Actor IPs',
    headers: ['IP','Total Req','Attacks','Attack %','UA Count','Profile'],
    rows: [
      ['42.105.165.217','5,274','5,218','98.94%','3,631','Dedicated scanner'],
      ['157.32.110.9','3,017','2,984','98.91%','13','Persistent bot'],
      ['49.34.106.83','2,314','2,297','99.27%','4','Targeted tool'],
      ['42.106.39.186','1,888','1,849','97.93%','1,142','Multi-UA campaign'],
      ['14.139.122.76','7,655','1,290','16.85%','43','Compromised host'],
      ['185.224.128.219','90','90','100.00%','2','Fully malicious'],
    ]
  },
  8: {
    title: 'EDA Visualizations Generated',
    headers: ['Plot','Type','Key Finding','Output'],
    rows: [
      ['Hourly Traffic','Grouped Bar','Peak 07:00 (6,939 req)','p08_hourly_traffic.png'],
      ['Top IPs','Horizontal Bar','42.105.165.217 = top attacker','p08_top_ips.png'],
      ['Attack Donut','Donut','Scanner = 79.4% of attacks','p08_attack_distribution.png'],
      ['Entropy KDE','Density','Attacks = higher entropy','p08_entropy_distribution.png'],
      ['Correlation Heatmap','Seaborn','is_scanner_ua: r=+0.88','p08_correlation_heatmap.png'],
      ['Attack Heatmap','Time×Category','Scanner peaks 07:00 UTC','p08_attack_heatmap.png'],
    ]
  },
  9: {
    title: 'ML Classifier Performance Comparison',
    headers: ['Model','Accuracy','Precision','Recall','F1-Score','ROC-AUC'],
    rows: [
      ['Logistic Regression','98.24%','98.15%','98.34%','98.22%','0.9934'],
      ['Random Forest (100 trees)','99.21%','99.40%','99.02%','99.21%','0.9994'],
      ['Baseline (predict majority)','50.00%','50.00%','100.00%','66.67%','0.5000'],
    ]
  },
  10: {
    title: 'Streaming Pipeline Throughput Metrics',
    headers: ['Window Size','Records','Attacks','Throughput (r/s)','Latency (ms)'],
    rows: [
      ['100','100','32','1,250','0.8'],
      ['500','500','158','1,380','0.7'],
      ['1,000','1,000','315','1,420','0.7'],
      ['5,000','5,000','1,580','1,450','0.7'],
      ['10,000','10,000','3,180','1,460','0.68'],
    ]
  }
}
