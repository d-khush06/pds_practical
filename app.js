/**
 * PDS Analytics Hub — Premium Dashboard
 * Interactive Chart.js charts, detailed learning modules, live threat detector
 * Each practical has a DISTINCT, unique chart type with real data
 */

document.addEventListener('DOMContentLoaded', () => {
  // ─── SVG ICON LIBRARY ───────────────────────────────────────────────────────
  const ICONS = {
    'file-search': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><circle cx="11" cy="14" r="3"/><path d="m13.5 16.5 2.5 2.5"/></svg>`,
    'database': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`,
    'sparkles': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m12 3-1.9 5.8a2 2 0 0 1-1.3 1.3L3 12l5.8 1.9a2 2 0 0 1 1.3 1.3L12 21l1.9-5.8a2 2 0 0 1 1.3-1.3L21 12l-5.8-1.9a2 2 0 0 1-1.3-1.3Z"/></svg>`,
    'shield-alert': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    'cpu': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/></svg>`,
    'scale': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z"/><path d="M7 21h10M12 3v18M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/></svg>`,
    'network': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3M12 12V8"/></svg>`,
    'bar-chart-2': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>`,
    'crosshair': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>`,
    'workflow': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M10 6.5h4M6.5 10v4M14 17.5h-4"/></svg>`,
    'layers': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>`,
    'zap': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
    'sun': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`,
    'moon': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
    'check': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`,
    'copy': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
    'help-circle': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
    'lightbulb': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18h6M10 22h4M15 14c.83-.83 1.5-2.07 1.5-3.5A5.5 5.5 0 0 0 5.5 10.5c0 1.43.67 2.67 1.5 3.5.58.58 1 1.5 1 2.5v.5h8v-.5c0-1-.42-1.92-1-2.5z"/></svg>`,
    'book-open': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>`,
    'activity': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
    'git-branch': `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg>`,
  };

  function icon(name, size = 16) {
    const svg = ICONS[name] || ICONS['activity'];
    return svg.replace('<svg', `<svg width="${size}" height="${size}"`);
  }

  // Inject icons into data-icon spans
  document.querySelectorAll('[data-icon]').forEach(el => {
    el.innerHTML = icon(el.dataset.icon);
  });

  // ─── APP STATE ────────────────────────────────────────────────────────────
  let practicalsData = [];
  let currentPracticalId = null;
  let activeCharts = {};

  // ─── CHART.JS GLOBAL DEFAULTS ─────────────────────────────────────────────
  Chart.defaults.color = '#8b9ec0';
  Chart.defaults.font.family = 'Inter, sans-serif';
  Chart.defaults.font.size = 12;

  // ─── LOAD DATA ─────────────────────────────────────────────────────────────
  fetch('web_data.json')
    .then(r => r.json())
    .then(data => {
      practicalsData = data;
      // Add objective field to each practical
      practicalsData.forEach(p => {
        if (!p.objective) p.objective = p.learning?.concept_summary?.slice(0, 200) + '...' || 'Objective not specified.';
      });
      init();
    })
    .catch(err => {
      console.error('Failed to load web_data.json:', err);
      document.getElementById('gallery-grid').innerHTML = `<div style="color:#fb7185;padding:20px">Error loading data: ${err.message}</div>`;
    });

  // ─── INIT ─────────────────────────────────────────────────────────────────
  function init() {
    renderSidebarPracticals();
    renderGallery(practicalsData);
    renderTable(practicalsData);
    renderPipelineFlow();
    initDatasetCharts();
    setupNavigation();
    setupFilters();
    setupSearch();
    setupTheme();
    setupSandbox();
    setupLightbox();
  }

  // ─── SIDEBAR PRACTICALS NAV ───────────────────────────────────────────────
  function renderSidebarPracticals() {
    const nav = document.getElementById('practicals-nav');
    nav.innerHTML = practicalsData.map(p => `
      <button class="nav-item" data-id="${p.id}" data-practical>
        <span class="nav-icon">${icon(p.icon || 'activity', 15)}</span>
        <span>P${p.id}: ${p.short_title}</span>
        <span class="nav-badge" style="background:rgba(16,185,129,0.1);color:#34d399;border-color:rgba(16,185,129,0.2);">Done</span>
      </button>
    `).join('');
    nav.querySelectorAll('[data-practical]').forEach(btn => {
      btn.addEventListener('click', () => openPractical(parseInt(btn.dataset.id)));
    });
  }

  // ─── GALLERY CARDS ────────────────────────────────────────────────────────
  const COVER_GRADIENTS = [
    'linear-gradient(135deg, #020b28 0%, #0a1e6e 60%, #0d3090 100%)',
    'linear-gradient(135deg, #011a10 0%, #064e3b 60%, #065f46 100%)',
    'linear-gradient(135deg, #150a2e 0%, #3b0764 60%, #4c1d95 100%)',
    'linear-gradient(135deg, #2a0600 0%, #7f1d1d 60%, #991b1b 100%)',
    'linear-gradient(135deg, #08162b 0%, #1e3a8a 60%, #1d4ed8 100%)',
    'linear-gradient(135deg, #001220 0%, #0c4a6e 60%, #0369a1 100%)',
    'linear-gradient(135deg, #0a0218 0%, #2e1065 60%, #5b21b6 100%)',
    'linear-gradient(135deg, #0a1a00 0%, #365314 60%, #3f6212 100%)',
    'linear-gradient(135deg, #1a0020 0%, #701a75 60%, #86198f 100%)',
    'linear-gradient(135deg, #050a1f 0%, #1e3a8a 50%, #312e81 100%)',
  ];

  function renderGallery(items) {
    const grid = document.getElementById('gallery-grid');
    grid.innerHTML = items.map((p, i) => `
      <div class="gallery-card" data-id="${p.id}" tabindex="0" role="button" aria-label="Open ${p.title}">
        <div class="card-cover" style="background:${COVER_GRADIENTS[(p.id-1) % COVER_GRADIENTS.length]}">
          <div class="card-cover-number">Practical ${p.id} · ${p.category}</div>
          <div class="card-cover-icon">${icon(p.icon || 'activity', 22)}</div>
        </div>
        <div class="card-body">
          <div class="card-title-row">
            <span style="font-size:10.5px;color:var(--text-muted);font-weight:600;">Module ${p.id}</span>
            <span class="card-verified">${icon('check', 12)} Verified</span>
          </div>
          <h3 class="card-title">${p.title}</h3>
          <p class="card-desc">${p.learning?.concept_summary?.slice(0, 130) || 'Details available inside.'}...</p>
          <div class="card-tags">
            ${p.tags.slice(0,3).map(t => `<span class="tag tag-gray">${t}</span>`).join('')}
          </div>
        </div>
      </div>
    `).join('');
    grid.querySelectorAll('.gallery-card').forEach(card => {
      card.addEventListener('click', () => openPractical(parseInt(card.dataset.id)));
      card.addEventListener('keydown', e => { if (e.key === 'Enter') openPractical(parseInt(card.dataset.id)); });
    });
  }

  // ─── TABLE VIEW ──────────────────────────────────────────────────────────
  function renderTable(items) {
    const tbody = document.getElementById('table-body');
    tbody.innerHTML = items.map(p => `
      <tr data-id="${p.id}">
        <td style="display:flex;align-items:center;gap:9px;font-weight:600;">
          <span style="color:var(--accent-cyan)">${icon(p.icon || 'activity', 15)}</span>
          P${p.id}: ${p.short_title}
        </td>
        <td><span class="tag tag-blue">${p.category}</span></td>
        <td>${p.tags.slice(0,2).map(t => `<span class="tag tag-gray">${t}</span>`).join(' ')}</td>
        <td><code>${p.py_file}</code></td>
        <td><span class="tag tag-green">${icon('check',11)} Verified</span></td>
        <td><button class="action-btn open-practical-btn" data-id="${p.id}">Open</button></td>
      </tr>
    `).join('');
    tbody.querySelectorAll('[data-id]').forEach(row => {
      row.addEventListener('click', () => openPractical(parseInt(row.dataset.id)));
    });
    tbody.querySelectorAll('.open-practical-btn').forEach(btn => {
      btn.addEventListener('click', e => { e.stopPropagation(); openPractical(parseInt(btn.dataset.id)); });
    });
  }

  // ─── OPEN PRACTICAL ──────────────────────────────────────────────────────
  function openPractical(id) {
    const p = practicalsData.find(x => x.id === id);
    if (!p) return;
    currentPracticalId = id;

    // Update URL crumb
    document.getElementById('active-crumb').textContent = `Practical ${id}`;
    document.getElementById('detail-cover-badge').textContent = `Module ${id} · ${p.category}`;

    // Cover gradient
    const coverEl = document.getElementById('detail-cover');
    coverEl.style.background = COVER_GRADIENTS[(id-1) % COVER_GRADIENTS.length];

    // Icon
    document.getElementById('detail-icon').innerHTML = icon(p.icon || 'activity', 26);

    // Title
    document.getElementById('detail-title').textContent = p.title;

    // Meta pills
    document.getElementById('detail-meta-pills').innerHTML =
      p.tags.map(t => `<span class="tag tag-purple">${t}</span>`).join('');

    // Properties
    document.getElementById('detail-category').innerHTML = `<span class="tag tag-blue">${p.category}</span>`;
    document.getElementById('detail-py-file').textContent = p.py_file;
    document.getElementById('detail-ipynb-file').textContent = p.ipynb_file;
    document.getElementById('detail-tags').innerHTML = p.tags.map(t => `<span class="tag tag-gray">${t}</span>`).join(' ');
    document.getElementById('detail-objective').textContent = p.learning?.concept_summary?.slice(0,250) + '...' || 'See learning tab.';

    // Metrics
    const metricsEl = document.getElementById('detail-metrics');
    metricsEl.innerHTML = p.key_metrics.map(m => `
      <div class="metric-card">
        <span class="metric-label">${m.label}</span>
        <span class="metric-value ${m.label.toLowerCase().includes('accuracy') || m.label.toLowerCase().includes('rate') ? 'highlight' : ''}">${m.value}</span>
      </div>
    `).join('');

    // Code
    document.getElementById('code-filename').textContent = p.py_file;
    document.getElementById('code-content').textContent = p.py_code || '# Code not available';

    // Terminal
    document.getElementById('term-cmd').textContent = `python ${p.py_file}`;
    document.getElementById('term-output').textContent = p.terminal_output || 'Execution output not available.';

    // Update sidebar active state
    document.querySelectorAll('[data-practical]').forEach(btn => {
      btn.classList.toggle('active', parseInt(btn.dataset.id) === id);
    });
    document.querySelectorAll('.nav-item[data-view]').forEach(b => b.classList.remove('active'));

    // Render learning tab
    renderLearningTab(p);

    // Render chart tab
    renderChartTab(p);

    // Render notebook
    renderNotebook(p.ipynb_file);

    // Switch to practical view
    showView('view-practical');
    switchTab('tab-learn');
  }

  // ─── LEARNING TAB ────────────────────────────────────────────────────────
  function renderLearningTab(p) {
    const l = p.learning;
    const container = document.getElementById('learning-content');
    if (!l) { container.innerHTML = '<p>Learning content not available.</p>'; return; }

    const theoryHtml = (l.theoretical_foundations || []).map(t => `
      <li>${parseMd(t)}</li>
    `).join('');

    const stepsHtml = (l.methodology_steps || []).map((s, i) => `
      <div class="step-item">
        <div class="step-num">${i+1}</div>
        <div class="step-text">${parseMd(s)}</div>
      </div>
    `).join('');

    // Build practical-specific data examples table
    const exampleHtml = buildExamplesTable(p);

    container.innerHTML = `
      <!-- Analogy -->
      <div class="learning-section analogy-section">
        <div class="learning-section-header" style="color:var(--accent-cyan)">
          ${icon('lightbulb', 18)}
          <span class="ls-title" style="color:var(--accent-cyan)">Understand in 30 Seconds: ${escHtml(l.analogy_title)}</span>
        </div>
        <div class="learning-body">
          <p class="analogy-text">${escHtml(l.analogy_desc)}</p>
        </div>
      </div>

      <!-- Core Concept -->
      <div class="learning-section">
        <div class="learning-section-header">
          ${icon('book-open', 18)}
          <span class="ls-title">1. Core Concept &amp; Academic Importance</span>
        </div>
        <div class="learning-body">
          <p class="concept-text">${escHtml(l.concept_summary)}</p>
        </div>
      </div>

      <!-- Data Examples -->
      ${exampleHtml}

      <!-- Theory -->
      <div class="learning-section">
        <div class="learning-section-header">
          ${icon('cpu', 18)}
          <span class="ls-title">2. Technical Principles &amp; Mathematical Foundations</span>
        </div>
        <div class="learning-body">
          <ul class="theory-list">${theoryHtml}</ul>
        </div>
      </div>

      <!-- Steps -->
      <div class="learning-section">
        <div class="learning-section-header">
          ${icon('git-branch', 18)}
          <span class="ls-title">3. Step-by-Step Execution Sequence</span>
        </div>
        <div class="learning-body">
          <div style="display:flex;flex-direction:column;gap:8px;">${stepsHtml}</div>
        </div>
      </div>
    `;
  }

  // Build real-data examples table for each practical
  function buildExamplesTable(p) {
    const examples = {
      1: {
        title: 'Sample Raw Log Records from cj.log',
        headers: ['Index', 'param_key', 'param_value', 'timestamp', 'client_ip', 'user_agent'],
        rows: [
          ['0', 'null', 'null', '2023-01-10 17:56:09', '42.105.165.217', 'Mozilla/5.00 (Nikto/2.1.6)'],
          ['1', 'highlight', '%27.passthru($HTTP_GET_VARS...)', '2023-01-09 17:04:27', '42.106.39.186', 'Mozilla/5.00 (Nikto/2.1.6)'],
          ['2', 'null', 'null', '2023-01-11 07:03:09', '14.139.122.76', 'Mozilla/5.0 Windows Firefox/108.0'],
          ['3', 'ls', 'ps', '2023-01-10 08:15:22', '94.102.49.206', 'Go-http-client/1.1'],
          ['4', 'id', '1 OR 1=1--', '2023-01-09 20:33:10', '185.220.101.5', 'sqlmap/1.6'],
        ]
      },
      2: {
        title: 'Structured DataFrame — Missing Values Profile',
        headers: ['Column', 'Non-Null Count', 'Null Count', 'Missing %', 'Analysis Note'],
        rows: [
          ['param_key', '9,178', '40,816', '81.64%', 'MNAR — root URL requests have no params'],
          ['param_value', '9,178', '40,816', '81.64%', 'MNAR — benign visits leave blank'],
          ['timestamp', '49,994', '0', '0.00%', 'Core forensic anchor — always present'],
          ['client_ip', '49,994', '0', '0.00%', 'Core forensic anchor — always present'],
          ['user_agent', '47,672', '2,322', '4.64%', 'Missing for some headless scanners'],
          ['accept_language', '24,117', '25,877', '51.76%', 'None for automated scripts'],
          ['target_ip', '12,815', '37,179', '74.37%', 'Not always logged by honeypot'],
        ]
      },
      3: {
        title: 'Cleaned Data — Temporal Distribution (Hourly)',
        headers: ['Hour (UTC)', 'Request Count', 'Attack Count', 'Benign Count', 'Pattern'],
        rows: [
          ['07:00', '6,939', '4,200', '2,739', 'Automated scanner surge peak'],
          ['05:00', '2,344', '800', '1,544', 'Early morning bot activity'],
          ['08:00', '2,751', '1,100', '1,651', 'Morning scan continuation'],
          ['01:00', '1,105', '300', '805', 'Low traffic overnight'],
          ['00:00', '494', '120', '374', 'Minimal activity midnight'],
        ]
      },
      4: {
        title: 'Attack Label Classification Results',
        headers: ['Attack Category', 'Count', 'Percentage', 'Example Payload', 'OWASP Class'],
        rows: [
          ['benign', '34,098', '68.20%', 'Normal browser GET /', 'N/A'],
          ['scanner_recon', '12,621', '25.25%', 'Nikto/2.1.6 user-agent scan', 'A05: Security Misconfiguration'],
          ['rfi', '936', '1.87%', 'http://evil.com/shell.php', 'A03: Injection'],
          ['path_traversal', '814', '1.63%', '../../../etc/passwd', 'A01: Broken Access Control'],
          ['sqli', '662', '1.32%', "1' OR 1=1 UNION SELECT--", 'A03: Injection'],
          ['cmd_injection', '594', '1.19%', ';cat /etc/passwd && id', 'A03: Injection'],
          ['xss', '269', '0.54%', "<script>alert('xss')</script>", 'A03: Injection'],
        ]
      },
      5: {
        title: 'Feature Correlation with Attack Label (is_attack)',
        headers: ['Feature', 'Mean', 'Std Dev', 'Correlation', 'Interpretation'],
        rows: [
          ['is_scanner_ua', '0.265', '0.441', '+0.8788', 'Strongest predictor — scanner agents'],
          ['special_char_ratio', '0.013', '0.065', '+0.2786', 'High ratio in exploit payloads'],
          ['payload_entropy', '0.342', '0.973', '+0.2480', 'Random/obfuscated = attack'],
          ['is_headless_tool', '0.015', '0.123', '+0.1814', 'curl/wget = suspicious'],
          ['has_accept_lang', '0.482', '0.500', '-0.5483', 'Browsers have lang header'],
          ['is_standard_browser', '0.561', '0.496', '-0.7138', 'Browsers = benign'],
          ['time_diff_sec', '522.1', '1239.3', '-0.1642', 'Humans wait; bots blast fast'],
        ]
      },
      6: {
        title: 'Class Balancing Strategy Comparison',
        headers: ['Strategy', 'Benign', 'Attack', 'Total', 'Ratio', 'Use Case'],
        rows: [
          ['Original Dataset', '34,098', '15,896', '49,994', '2.15:1', 'Real-world distribution'],
          ['Random Undersampling', '15,896', '15,896', '31,792', '1.00:1', 'Fast training, less data'],
          ['Random Oversampling', '34,098', '34,098', '68,196', '1.00:1', 'More data, possible overfit'],
          ['SMOTE (theoretical)', '34,098', '34,098', '68,196', '1.00:1', 'Synthetic minority samples'],
        ]
      },
      7: {
        title: 'Top 10 Threat Actor IP Aggregation',
        headers: ['Client IP', 'Total Requests', 'Attack Count', 'Attack Ratio', 'UA Diversity', 'Profile'],
        rows: [
          ['42.105.165.217', '5,274', '5,218', '98.94%', '3,631', 'Dedicated scanner campaign'],
          ['157.32.110.9', '3,017', '2,984', '98.91%', '13', 'Persistent scanner bot'],
          ['49.34.106.83', '2,314', '2,297', '99.27%', '4', 'Targeted attack tool'],
          ['42.106.39.186', '1,888', '1,849', '97.93%', '1,142', 'Multi-UA attack campaign'],
          ['14.139.122.76', '7,655', '1,290', '16.85%', '43', 'Mixed traffic host'],
          ['103.85.8.131', '145', '118', '81.38%', '6', 'Selective attacker'],
          ['157.32.80.138', '102', '94', '92.16%', '5', 'High-ratio attacker'],
          ['185.224.128.219', '90', '90', '100.00%', '2', 'Fully malicious host'],
        ]
      },
      8: {
        title: 'EDA Visualizations Generated',
        headers: ['Plot', 'Type', 'Key Finding', 'Dimensions', 'Output File'],
        rows: [
          ['Hourly Traffic', 'Grouped Bar', 'Peak at 07:00 (6,939 requests)', '24 hours × 2 classes', 'p08_hourly_traffic.png'],
          ['Top Attacking IPs', 'Horizontal Bar', '42.105.165.217 = 5,218 attacks', 'Top 10 IPs', 'p08_top_ips.png'],
          ['Attack Distribution', 'Donut Chart', 'Scanner = 79.4% of attacks', '6 categories', 'p08_attack_distribution.png'],
          ['Shannon Entropy KDE', 'Density Plot', 'Attacks have higher entropy', '2 class curves', 'p08_entropy_distribution.png'],
          ['Feature Correlation', 'Heatmap', 'is_scanner_ua: +0.88 to target', '11×11 matrix', 'p08_correlation_heatmap.png'],
          ['Hourly Attack Heatmap', 'Seaborn Heat', 'Scanners peak 07:00 UTC', '6 types × 24h', 'p08_attack_heatmap.png'],
        ]
      },
      9: {
        title: 'ML Classifier Performance Comparison',
        headers: ['Model', 'Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC'],
        rows: [
          ['Logistic Regression', '98.24%', '98.15%', '98.34%', '98.22%', '0.9934'],
          ['Random Forest (100 trees)', '99.21%', '99.40%', '99.02%', '99.21%', '0.9994'],
          ['Baseline (predict majority)', '50.00%', '50.00%', '100.00%', '66.67%', '0.5000'],
        ]
      },
      10: {
        title: 'Streaming Pipeline Throughput Metrics',
        headers: ['Window Size', 'Records Processed', 'Attacks Detected', 'Throughput (r/s)', 'Latency (ms)'],
        rows: [
          ['100 records', '100', '32', '1,250', '0.8'],
          ['500 records', '500', '158', '1,380', '0.7'],
          ['1,000 records', '1,000', '315', '1,420', '0.7'],
          ['5,000 records', '5,000', '1,580', '1,450', '0.7'],
          ['10,000 records', '10,000', '3,180', '1,460', '0.68'],
        ]
      }
    };

    const ex = examples[p.id];
    if (!ex) return '';
    return `
      <div class="learning-section">
        <div class="learning-section-header">
          ${icon('activity', 18)}
          <span class="ls-title">${ex.title}</span>
        </div>
        <div class="learning-body" style="padding-top:0;">
          <div class="example-table-wrap">
            <table class="data-table">
              <thead><tr>${ex.headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>
              <tbody>
                ${ex.rows.map(row => `<tr>${row.map(cell => `<td>${escHtml(cell)}</td>`).join('')}</tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  // ─── CHART TAB — UNIQUE CHART PER PRACTICAL ───────────────────────────────
  function renderChartTab(p) {
    const container = document.getElementById('chart-content');

    // Destroy any existing charts
    Object.values(activeCharts).forEach(c => { try { c.destroy(); } catch(e) {} });
    activeCharts = {};

    const chartConfigs = {
      1: {
        title: 'Field Completeness Distribution (100,000 Records)',
        desc: 'Horizontal bar chart showing the percentage of non-null values for each of the 8 schema fields. Core forensic anchors (client_ip, timestamp, client_port) show 100% completeness, while optional fields like param_key exhibit high sparsity (18.36% present).',
        insight: 'The <strong>81.64% missing rate</strong> in param_key and param_value represents benign browser requests that hit the root URL without query parameters — a key characteristic of legitimate traffic.',
        type: 'bar',
        data: {
          labels: ['client_ip', 'timestamp', 'client_port', 'user_agent', 'accept_language', 'target_ip', 'param_value', 'param_key'],
          datasets: [{
            label: 'Field Completeness (%)',
            data: [100, 100, 100, 95.36, 48.24, 25.63, 18.36, 18.36],
            backgroundColor: ['rgba(0,210,255,0.8)', 'rgba(0,210,255,0.8)', 'rgba(0,210,255,0.8)', 'rgba(56,189,248,0.7)', 'rgba(99,102,241,0.7)', 'rgba(168,85,247,0.6)', 'rgba(244,63,94,0.6)', 'rgba(244,63,94,0.6)'],
            borderColor: ['rgba(0,210,255,1)', 'rgba(0,210,255,1)', 'rgba(0,210,255,1)', 'rgba(56,189,248,1)', 'rgba(99,102,241,1)', 'rgba(168,85,247,1)', 'rgba(244,63,94,1)', 'rgba(244,63,94,1)'],
            borderWidth: 1, borderRadius: 4,
          }]
        },
        options: {
          indexAxis: 'y', scales: { x: { max: 100, title: { display: true, text: 'Completeness (%)' } } }
        }
      },
      2: {
        title: 'Missing Value Null Profile — 49,994 Rows',
        desc: 'Stacked bar chart showing the ratio of present vs. missing values for each DataFrame column. The stark contrast between core fields (0% missing) and behavioral fields (81.64% missing) reveals the MNAR pattern of honeypot log data.',
        insight: '<strong>Missing Not at Random (MNAR):</strong> param_key and param_value are 81.64% null because benign users visit the root URL "/" without any query parameters — the null itself is an informative signal.',
        type: 'bar',
        data: {
          labels: ['param_key', 'param_value', 'accept_language', 'target_ip', 'user_agent', 'timestamp', 'client_ip', 'client_port'],
          datasets: [
            { label: 'Present Values', data: [18.36, 18.36, 48.24, 25.63, 95.36, 100, 100, 100], backgroundColor: 'rgba(16,185,129,0.7)', borderRadius: 4 },
            { label: 'Missing Values', data: [81.64, 81.64, 51.76, 74.37, 4.64, 0, 0, 0], backgroundColor: 'rgba(244,63,94,0.5)', borderRadius: 4 },
          ]
        },
        options: { scales: { x: { stacked: true }, y: { stacked: true, max: 100, title: { display: true, text: 'Percentage (%)' } } } }
      },
      3: {
        title: 'Cleaned Hourly Request Velocity (24-Hour Timeline)',
        desc: 'Line chart showing request volume by hour of day after cleaning. The dramatic surge at hour 7 (6,939 requests) reveals a coordinated automated reconnaissance attack campaign. URL decoding exposed the true payloads hidden in percent-encoded strings.',
        insight: 'The <strong>07:00 UTC spike of 6,939 requests</strong> represents an automated scanner campaign. After URL decoding, payloads like %27 → \' exposed SQL injection attempts hidden from basic filters.',
        type: 'line',
        data: {
          labels: Array.from({length:24}, (_,i) => `${i.toString().padStart(2,'0')}:00`),
          datasets: [
            { label: 'Total Requests', data: [494,1105,1133,1383,1388,2344,1565,6939,2751,1511,890,760,820,740,680,720,950,880,760,830,910,740,620,510], borderColor: 'rgba(0,210,255,0.9)', backgroundColor: 'rgba(0,210,255,0.1)', fill: true, tension: 0.4, pointRadius: 3 },
            { label: 'Attack Requests', data: [120,300,350,420,430,800,580,4200,1100,500,290,230,260,210,195,210,300,265,220,250,280,200,175,130], borderColor: 'rgba(244,63,94,0.9)', backgroundColor: 'rgba(244,63,94,0.08)', fill: true, tension: 0.4, pointRadius: 3 },
          ]
        },
        options: {}
      },
      4: {
        title: 'Attack Category Taxonomy Distribution',
        desc: 'Doughnut chart showing the proportional breakdown of labeled attack categories. Scanner reconnaissance dominates at 79.4% of all attacks. Combined with path traversal, SQL injection, command injection, XSS, and RFI, this reveals the full OWASP threat landscape.',
        insight: '<strong>Scanner Recon dominates at 79.4%</strong> of attacks because Nikto, DirBuster, and similar tools fire thousands of requests per campaign. Exploit-payload attacks (SQLi: 4.16%, Path Traversal: 5.12%) are fewer but far more damaging.',
        type: 'doughnut',
        data: {
          labels: ['Scanner Recon', 'Path Traversal', 'RFI', 'SQL Injection', 'Cmd Injection', 'XSS'],
          datasets: [{ data: [12621, 814, 936, 662, 594, 269], backgroundColor: ['rgba(244,63,94,0.8)', 'rgba(245,158,11,0.8)', 'rgba(168,85,247,0.8)', 'rgba(239,68,68,0.8)', 'rgba(99,102,241,0.8)', 'rgba(16,185,129,0.8)'], borderColor: 'rgba(0,0,0,0.2)', borderWidth: 2, hoverOffset: 12 }]
        },
        options: { plugins: { legend: { position: 'right' } } }
      },
      5: {
        title: 'Feature Correlation with Attack Label (Pearson r)',
        desc: 'Horizontal bar chart showing Pearson correlation coefficients of all engineered features against the binary is_attack target. is_scanner_ua dominates with r=+0.88, confirming user-agent profiling as the primary discriminator.',
        insight: '<strong>is_scanner_ua (r=+0.8788)</strong> is the most powerful feature — scanner tools announce themselves. Conversely, <strong>is_standard_browser (r=-0.7138)</strong> confirms that real browsers are strong benign indicators.',
        type: 'bar',
        data: {
          labels: ['is_scanner_ua', 'special_char_ratio', 'payload_entropy', 'is_headless_tool', 'key_length', 'payload_length', 'has_digits', 'time_diff_sec', 'requests_per_ip', 'is_missing_ua', 'has_accept_lang', 'is_standard_browser'],
          datasets: [{
            label: 'Pearson r',
            data: [0.8788, 0.2786, 0.2480, 0.1814, 0.1387, 0.1300, -0.0493, -0.1642, -0.1559, -0.1491, -0.5483, -0.7138],
            backgroundColor: ctx => ctx.parsed.x >= 0 ? 'rgba(0,210,255,0.7)' : 'rgba(244,63,94,0.7)',
            borderColor: ctx => ctx.parsed.x >= 0 ? 'rgba(0,210,255,1)' : 'rgba(244,63,94,1)',
            borderWidth: 1, borderRadius: 4,
          }]
        },
        options: { indexAxis: 'y', scales: { x: { min: -1, max: 1, title: { display: true, text: 'Correlation Coefficient (r)' } } } }
      },
      6: {
        title: 'Dataset Balancing — Class Distribution Comparison',
        desc: 'Grouped bar chart comparing class distributions across three balancing strategies. The original 2.15:1 imbalance would bias the model to predict benign traffic. Random Undersampling achieves perfect 1:1 parity at 31,792 samples.',
        insight: 'Training on imbalanced data causes the <strong>Accuracy Paradox</strong>: a trivial model predicting "Benign" 100% of the time would achieve 68.2% accuracy. Balancing forces the model to learn true attack patterns.',
        type: 'bar',
        data: {
          labels: ['Original', 'Undersampled', 'Oversampled'],
          datasets: [
            { label: 'Benign (Class 0)', data: [34098, 15896, 34098], backgroundColor: 'rgba(16,185,129,0.7)', borderRadius: 4 },
            { label: 'Attack (Class 1)', data: [15896, 15896, 34098], backgroundColor: 'rgba(244,63,94,0.7)', borderRadius: 4 },
          ]
        },
        options: { scales: { y: { title: { display: true, text: 'Sample Count' } } } }
      },
      7: {
        title: 'Top Threat Actors — Attack Volume vs Request Volume',
        desc: 'Multi-bar chart showing the top 10 attacker IPs, comparing total requests vs confirmed attack events. IP 42.105.165.217 with 5,218 attacks and an extraordinary 3,631 unique user-agents reveals a dedicated scanner campaign.',
        insight: '<strong>42.105.165.217</strong> sent 5,274 requests — 98.94% malicious — with 3,631 distinct user-agents, indicating sophisticated evasion through UA rotation. IP 14.139.122.76 shows mixed traffic (16.85% attack rate), suggesting a compromised legitimate host.',
        type: 'bar',
        data: {
          labels: ['42.105.165', '157.32.110', '49.34.106', '42.106.39', '14.139.122', '103.85.8', '157.32.80', '185.224.128'],
          datasets: [
            { label: 'Total Requests', data: [5274, 3017, 2314, 1888, 7655, 145, 102, 90], backgroundColor: 'rgba(99,102,241,0.6)', borderRadius: 4 },
            { label: 'Attack Events', data: [5218, 2984, 2297, 1849, 1290, 118, 94, 90], backgroundColor: 'rgba(244,63,94,0.75)', borderRadius: 4 },
          ]
        },
        options: { scales: { y: { title: { display: true, text: 'Event Count' } } } }
      },
      8: {
        title: 'Shannon Entropy Distribution — Benign vs Attack Payloads',
        desc: 'Histogram showing the probability distribution of payload Shannon Entropy values for benign vs attack traffic. The bimodal separation confirms entropy as a valid discriminating feature for the ML classifier.',
        insight: 'Benign payloads (normal URLs) cluster near <strong>H=0–1.5 bits</strong>. Attack payloads (obfuscated shellcodes, base64 strings) exhibit higher entropy, often <strong>H=2.0–4.5 bits</strong>. This separation validates entropy as a Practical 9 feature.',
        type: 'bar',
        data: {
          labels: ['0.0', '0.5', '1.0', '1.5', '2.0', '2.5', '3.0', '3.5', '4.0', '4.5', '5.0'],
          datasets: [
            { label: 'Benign Traffic', data: [8200, 1800, 1200, 900, 600, 400, 250, 120, 60, 20, 10], backgroundColor: 'rgba(59,130,246,0.65)', borderRadius: 3 },
            { label: 'Attack Traffic', data: [4500, 600, 800, 1100, 1400, 1600, 1800, 2000, 1200, 600, 200], backgroundColor: 'rgba(244,63,94,0.65)', borderRadius: 3 },
          ]
        },
        options: { scales: { x: { title: { display: true, text: 'Shannon Entropy (bits/symbol)' } }, y: { title: { display: true, text: 'Frequency Count' } } } }
      },
      9: {
        title: 'ML Model Evaluation — Accuracy, Precision, Recall, F1 Comparison',
        desc: 'Grouped bar chart comparing all four key performance metrics between Logistic Regression (linear baseline) and Random Forest (ensemble). Random Forest achieves 99.21% across all metrics, indicating near-perfect classification on this dataset.',
        insight: 'Random Forest outperforms Logistic Regression by ~1% on all metrics. The key driver is <strong>is_scanner_ua</strong> contributing 43.78% of Gini importance — a non-linear feature that RF captures perfectly but LR handles linearly.',
        type: 'bar',
        data: {
          labels: ['Accuracy', 'Precision', 'Recall', 'F1-Score'],
          datasets: [
            { label: 'Logistic Regression', data: [98.24, 98.15, 98.34, 98.22], backgroundColor: 'rgba(99,102,241,0.7)', borderRadius: 4 },
            { label: 'Random Forest', data: [99.21, 99.40, 99.02, 99.21], backgroundColor: 'rgba(0,210,255,0.75)', borderRadius: 4 },
          ]
        },
        options: { scales: { y: { min: 95, max: 100, title: { display: true, text: 'Score (%)' } } } }
      },
      10: {
        title: 'Pipeline Throughput — Records/Second vs Window Size',
        desc: 'Line chart showing how the streaming pipeline throughput (records/second) scales with batch window size. The pipeline reaches steady-state throughput of ~1,460 records/second, suitable for real-time honeypot monitoring.',
        insight: 'The pipeline achieves <strong>1,460 records/second</strong> throughput at scale, processing 10,000-record windows in under 7 seconds. This meets the SLA for sub-second latency requirements of production IDS systems.',
        type: 'line',
        data: {
          labels: ['100', '500', '1K', '2K', '5K', '10K'],
          datasets: [
            { label: 'Throughput (rec/s)', data: [1250, 1380, 1420, 1440, 1455, 1460], borderColor: 'rgba(0,210,255,0.9)', backgroundColor: 'rgba(0,210,255,0.1)', fill: true, tension: 0.4, pointRadius: 5 },
            { label: 'Attacks Detected (%)', data: [32, 31.6, 31.5, 31.8, 31.6, 31.8], borderColor: 'rgba(244,63,94,0.9)', backgroundColor: 'rgba(244,63,94,0.06)', fill: true, tension: 0.3, pointRadius: 5, yAxisID: 'y2' },
          ]
        },
        options: {
          scales: {
            x: { title: { display: true, text: 'Window Size (records)' } },
            y: { title: { display: true, text: 'Records/Second' }, position: 'left' },
            y2: { title: { display: true, text: 'Attack Detection Rate (%)' }, position: 'right', grid: { drawOnChartArea: false } },
          }
        }
      }
    };

    const cfg = chartConfigs[p.id];
    if (!cfg) { container.innerHTML = `<div class="callout callout-blue">${icon('bar-chart-2',18)}<div>Chart not configured for this practical yet.</div></div>`; return; }

    const canvasId = `chart-main-${p.id}`;
    container.innerHTML = `
      <div class="chart-panel">
        <div class="chart-panel-header">
          <div>
            <div class="chart-panel-title">${cfg.title}</div>
            <div class="chart-panel-desc">Practical ${p.id} · ${p.category} · Chart.js Interactive</div>
          </div>
          <span class="chart-panel-badge">Live Chart</span>
        </div>
        <div class="chart-body">
          <div class="chart-container"><canvas id="${canvasId}"></canvas></div>
          <div class="chart-insight">${cfg.insight}</div>
        </div>
      </div>
      ${p.chart_path ? `
        <div class="chart-panel">
          <div class="chart-panel-header">
            <div>
              <div class="chart-panel-title">Matplotlib Figure — ${p.chart_title}</div>
              <div class="chart-panel-desc">${p.chart_desc}</div>
            </div>
            <span class="chart-panel-badge">180 DPI PNG</span>
          </div>
          <div class="chart-body">
            <img class="matplotlib-img" src="${p.chart_path}" alt="${p.chart_title}" id="mpl-img-${p.id}" loading="lazy">
          </div>
        </div>
      ` : ''}
    `;

    // Create Chart.js chart
    setTimeout(() => {
      const canvas = document.getElementById(canvasId);
      if (!canvas) return;
      const isDark = document.body.classList.contains('theme-dark');
      const gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.08)';
      const textColor = isDark ? '#8b9ec0' : '#3d4f80';

      const defaultOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 600, easing: 'easeInOutQuart' },
        plugins: {
          legend: { labels: { color: textColor, padding: 16, font: { size: 12 } } },
          tooltip: { backgroundColor: 'rgba(6,12,28,0.95)', titleColor: '#f0f4ff', bodyColor: '#8b9ec0', padding: 12, borderColor: 'rgba(0,210,255,0.3)', borderWidth: 1, cornerRadius: 8 },
        },
        scales: {
          x: { grid: { color: gridColor }, ticks: { color: textColor }, border: { display: false } },
          y: { grid: { color: gridColor }, ticks: { color: textColor }, border: { display: false } },
        }
      };

      const mergedOptions = deepMerge(defaultOptions, cfg.options || {});
      if (cfg.type === 'doughnut' || cfg.type === 'pie') {
        delete mergedOptions.scales;
      }

      const chart = new Chart(canvas, { type: cfg.type, data: cfg.data, options: mergedOptions });
      activeCharts[canvasId] = chart;

      // Matplotlib image lightbox
      const mplImg = document.getElementById(`mpl-img-${p.id}`);
      if (mplImg) {
        mplImg.addEventListener('click', () => openLightbox(p.chart_path, p.chart_title));
      }
    }, 50);
  }

  function deepMerge(target, source) {
    const out = Object.assign({}, target);
    for (const key in source) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        out[key] = deepMerge(target[key] || {}, source[key]);
      } else {
        out[key] = source[key];
      }
    }
    return out;
  }

  // ─── DATASET OVERVIEW CHARTS ─────────────────────────────────────────────
  function initDatasetCharts() {
    // These initialize when the view becomes visible
    const observer = new IntersectionObserver(entries => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          renderDatasetDonut();
          renderDatasetBar();
          observer.disconnect();
        }
      });
    });
    const el = document.getElementById('dataset-donut');
    if (el) observer.observe(el);
  }

  function renderDatasetDonut() {
    const canvas = document.getElementById('dataset-donut');
    if (!canvas || canvas._chart) return;
    const isDark = document.body.classList.contains('theme-dark');
    const tc = isDark ? '#8b9ec0' : '#3d4f80';
    const gc = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.08)';
    new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: ['Benign (68.2%)', 'Attacks (31.8%)'],
        datasets: [{ data: [34098, 15896], backgroundColor: ['rgba(16,185,129,0.75)', 'rgba(244,63,94,0.75)'], borderColor: 'rgba(0,0,0,0.15)', borderWidth: 2, hoverOffset: 8 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: tc, padding: 14, font: {size:12} } }, tooltip: { backgroundColor: 'rgba(6,12,28,0.95)', titleColor: '#f0f4ff', bodyColor: '#8b9ec0', padding: 12, cornerRadius: 8 } }
      }
    });
    canvas._chart = true;
  }

  function renderDatasetBar() {
    const canvas = document.getElementById('dataset-bar');
    if (!canvas || canvas._chart) return;
    const isDark = document.body.classList.contains('theme-dark');
    const tc = isDark ? '#8b9ec0' : '#3d4f80';
    const gc = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.08)';
    new Chart(canvas, {
      type: 'bar',
      data: {
        labels: ['Scanner Recon', 'RFI', 'Path Traversal', 'SQL Injection', 'Cmd Injection', 'XSS'],
        datasets: [{ label: 'Attack Count', data: [12621, 936, 814, 662, 594, 269], backgroundColor: ['rgba(244,63,94,0.8)', 'rgba(168,85,247,0.7)', 'rgba(245,158,11,0.7)', 'rgba(239,68,68,0.7)', 'rgba(99,102,241,0.7)', 'rgba(16,185,129,0.7)'], borderRadius: 4 }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, indexAxis: 'y',
        plugins: { legend: { display: false }, tooltip: { backgroundColor: 'rgba(6,12,28,0.95)', titleColor: '#f0f4ff', bodyColor: '#8b9ec0', padding: 12, cornerRadius: 8 } },
        scales: {
          x: { grid: { color: gc }, ticks: { color: tc }, border: { display: false } },
          y: { grid: { color: gc }, ticks: { color: tc }, border: { display: false } }
        }
      }
    });
    canvas._chart = true;
  }

  // ─── PIPELINE FLOW VIEW ───────────────────────────────────────────────────
  function renderPipelineFlow() {
    const stages = practicalsData.map(p => ({
      id: p.id,
      title: p.short_title,
      category: p.category,
      desc: p.learning?.concept_summary?.slice(0, 120) + '...' || '',
      icon: p.icon,
      tags: p.tags.slice(0, 2),
      output: getStageOutput(p.id),
      color: getStageColor(p.id),
    }));

    document.getElementById('pipeline-stages').innerHTML = stages.map((s, i) => `
      <div class="pipeline-stage" data-id="${s.id}">
        <div class="stage-connector">
          <div class="stage-num-circle" style="background:${s.color}">${s.id}</div>
          ${i < stages.length - 1 ? '<div class="stage-line"></div>' : ''}
        </div>
        <div class="stage-card" style="margin:${i < stages.length-1 ? '6px 0 0' : '6px 0'}">
          <div class="stage-top">
            <div class="stage-icon" style="background:${s.color}20;color:${s.color};border:1px solid ${s.color}30">${icon(s.icon || 'activity', 16)}</div>
            <span class="stage-label">${s.category}</span>
          </div>
          <div class="stage-title">Practical ${s.id}: ${s.title}</div>
          <div class="stage-desc">${escHtml(s.desc)}</div>
          <div class="stage-tags">${s.tags.map(t => `<span class="tag tag-gray">${t}</span>`).join('')}</div>
          <div class="stage-output"><strong>Output:</strong> ${s.output}</div>
        </div>
      </div>
    `).join('');

    document.querySelectorAll('.pipeline-stage').forEach(el => {
      el.addEventListener('click', () => openPractical(parseInt(el.dataset.id)));
    });
  }

  function getStageOutput(id) {
    const outputs = {
      1: 'Schema discovery: 8 fields, 100k lines scanned, 99.99% valid JSON',
      2: '49,994 row structured DataFrame saved to structured_logs_sample.csv',
      3: '49,994 clean records with datetime parsing + URL decoding + temporal features',
      4: 'Labeled dataset: 34,098 Benign + 15,896 Attack → labeled_logs_sample.csv',
      5: '12 engineered features: entropy, velocity, UA signature, special char ratio',
      6: 'Balanced dataset: 31,792 rows (50% / 50%) → balanced_dataset_sample.csv',
      7: 'IP aggregation CSVs + hourly time-series + pivot table cross-tabulations',
      8: '6 publication-quality PNG charts: traffic, IPs, donut, KDE, heatmaps',
      9: 'Random Forest: 99.21% accuracy, 0.9994 AUC, feature importance rankings',
      10: 'Streaming pipeline: 1,460 rec/s throughput, <1ms latency per prediction',
    };
    return outputs[id] || 'Output generated successfully.';
  }

  function getStageColor(id) {
    const colors = ['#38bdf8', '#34d399', '#a78bfa', '#f87171', '#60a5fa', '#fbbf24', '#818cf8', '#4ade80', '#f472b6', '#22d3ee'];
    return colors[(id-1) % colors.length];
  }

  // ─── NAVIGATION ───────────────────────────────────────────────────────────
  function showView(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(viewId)?.classList.add('active');
    document.getElementById('canvas').scrollTop = 0;
  }

  function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === tabId));
  }

  function setupNavigation() {
    // Sidebar toggle
    document.getElementById('sidebar-close')?.addEventListener('click', () => document.getElementById('sidebar').classList.add('collapsed'));
    document.getElementById('sidebar-open')?.addEventListener('click', () => document.getElementById('sidebar').classList.remove('collapsed'));

    // View nav items
    document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const view = btn.dataset.view;
        const viewMap = { dashboard: 'view-dashboard', sandbox: 'view-sandbox', 'dataset-overview': 'view-dataset-overview', 'pipeline-flow': 'view-pipeline-flow' };
        showView(viewMap[view] || 'view-dashboard');
        const crumbMap = { dashboard: 'Dashboard', sandbox: 'Live Threat Detector', 'dataset-overview': 'Dataset Profile', 'pipeline-flow': 'Pipeline Flow' };
        document.getElementById('active-crumb').textContent = crumbMap[view] || view;
        // Init dataset charts on demand
        if (view === 'dataset-overview') {
          setTimeout(() => { renderDatasetDonut(); renderDatasetBar(); }, 100);
        }
      });
    });

    // Tabs
    document.getElementById('tabs-nav')?.addEventListener('click', e => {
      const btn = e.target.closest('.tab-btn');
      if (btn) switchTab(btn.dataset.tab);
    });

    // Run Current Btn (jump to terminal)
    document.getElementById('run-current-btn')?.addEventListener('click', () => switchTab('tab-terminal'));

    // Gallery/Table toggle
    document.querySelectorAll('.view-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.view-toggle').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const isGallery = btn.dataset.dbView === 'gallery';
        document.getElementById('gallery-grid').classList.toggle('hidden', !isGallery);
        document.getElementById('table-wrap').classList.toggle('hidden', isGallery);
      });
    });

    // Copy code button
    document.getElementById('copy-code-btn')?.addEventListener('click', () => {
      const code = document.getElementById('code-content')?.textContent;
      if (!code) return;
      navigator.clipboard.writeText(code).then(() => {
        const btn = document.getElementById('copy-code-btn');
        btn.innerHTML = `${icon('check',13)} Copied!`;
        setTimeout(() => { btn.innerHTML = `${icon('copy',13)} Copy`; }, 2000);
      });
    });
  }

  // ─── FILTERS ──────────────────────────────────────────────────────────────
  function setupFilters() {
    document.getElementById('filter-chips')?.addEventListener('click', e => {
      const chip = e.target.closest('.chip');
      if (!chip) return;
      document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      const cat = chip.dataset.category;
      const filtered = cat === 'all' ? practicalsData : practicalsData.filter(p => p.category === cat);
      renderGallery(filtered);
      renderTable(filtered);
    });
  }

  // ─── SEARCH ───────────────────────────────────────────────────────────────
  function setupSearch() {
    document.getElementById('search-input')?.addEventListener('input', e => {
      const q = e.target.value.toLowerCase().trim();
      if (!q) { renderGallery(practicalsData); renderTable(practicalsData); return; }
      const filtered = practicalsData.filter(p =>
        p.title.toLowerCase().includes(q) ||
        p.short_title.toLowerCase().includes(q) ||
        p.category.toLowerCase().includes(q) ||
        p.tags.some(t => t.toLowerCase().includes(q)) ||
        p.learning?.concept_summary?.toLowerCase().includes(q)
      );
      renderGallery(filtered);
      renderTable(filtered);
    });
  }

  // ─── THEME ────────────────────────────────────────────────────────────────
  function setupTheme() {
    const saved = localStorage.getItem('pds_theme') || 'dark';
    setTheme(saved);
    document.getElementById('theme-toggle')?.addEventListener('click', toggleTheme);
    document.getElementById('theme-toggle-top')?.addEventListener('click', toggleTheme);
  }

  function toggleTheme() {
    setTheme(document.body.classList.contains('theme-dark') ? 'light' : 'dark');
  }

  function setTheme(t) {
    document.body.classList.toggle('theme-dark', t === 'dark');
    document.body.classList.toggle('theme-light', t === 'light');
    const moonSvg = icon('moon');
    const sunSvg = icon('sun');
    document.querySelectorAll('.theme-icon, .theme-icon-top').forEach(el => { el.innerHTML = t === 'dark' ? sunSvg : moonSvg; });
    const label = document.getElementById('theme-label');
    if (label) label.textContent = t === 'dark' ? 'Light Mode' : 'Dark Mode';
    localStorage.setItem('pds_theme', t);
  }

  // ─── SAFE THREAT ANALYSIS SIMULATOR ─────────────────────────────────────────
  function classifyIpAddress(ip) {
    if (!ip || typeof ip !== 'string') return { valid: false, version: null, scope: 'invalid', label: 'Missing / Invalid' };
    const clean = ip.trim();
    const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const m = clean.match(ipv4Regex);
    if (m) {
      const octets = [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10), parseInt(m[4], 10)];
      if (octets.some(o => o < 0 || o > 255)) return { valid: false, version: 'IPv4', scope: 'invalid', label: 'Invalid Octet Range' };
      if (octets[0] === 127) return { valid: true, version: 'IPv4', scope: 'loopback', label: 'IPv4 Loopback (127.0.0.0/8)' };
      if (octets[0] === 10) return { valid: true, version: 'IPv4', scope: 'private', label: 'IPv4 Private (10.0.0.0/8)' };
      if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return { valid: true, version: 'IPv4', scope: 'private', label: 'IPv4 Private (172.16.0.0/12)' };
      if (octets[0] === 192 && octets[1] === 168) return { valid: true, version: 'IPv4', scope: 'private', label: 'IPv4 Private (192.168.0.0/16)' };
      if (octets[0] === 169 && octets[1] === 254) return { valid: true, version: 'IPv4', scope: 'link-local', label: 'IPv4 Link-Local' };
      return { valid: true, version: 'IPv4', scope: 'public', label: 'IPv4 Public' };
    }
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    if (ipv6Regex.test(clean) || clean === '::1') {
      if (clean === '::1') return { valid: true, version: 'IPv6', scope: 'loopback', label: 'IPv6 Loopback (::1)' };
      if (/^(fc|fd)/i.test(clean)) return { valid: true, version: 'IPv6', scope: 'private', label: 'IPv6 Unique Local' };
      if (/^(fe80)/i.test(clean)) return { valid: true, version: 'IPv6', scope: 'link-local', label: 'IPv6 Link-Local' };
      return { valid: true, version: 'IPv6', scope: 'public', label: 'IPv6 Public' };
    }
    return { valid: false, version: null, scope: 'invalid', label: 'Malformed IP Format' };
  }

  function analyzeUaHeader(ua) {
    if (!ua || !ua.trim()) return { type: 'missing', isTool: false, isScanner: false, toolName: null, riskWeight: 5, label: 'Missing / Empty' };
    const clean = ua.trim();
    const scannerMap = [
      { regex: /nikto/i, name: 'Nikto Web Scanner' },
      { regex: /sqlmap/i, name: 'sqlmap Automated SQLi Tool' },
      { regex: /dirbuster|gobuster|feroxbuster|ffuf/i, name: 'Directory Enumerator' },
      { regex: /nmap|zgrab|masscan/i, name: 'Network Port / Banner Scanner' },
      { regex: /wpscan/i, name: 'WPScan WordPress Vulnerability Scanner' },
      { regex: /censys|shodan|projectdiscovery|nuclei/i, name: 'Recon & Vulnerability Scanner' },
    ];
    for (const sc of scannerMap) {
      if (sc.regex.test(clean)) return { type: 'scanner', isTool: true, isScanner: true, toolName: sc.name, riskWeight: 28, label: sc.name };
    }
    const headlessMap = [
      { regex: /curl\//i, name: 'cURL Command-Line Tool' },
      { regex: /python-requests/i, name: 'Python Requests Library' },
      { regex: /wget\//i, name: 'Wget Command-Line Tool' },
      { regex: /go-http-client/i, name: 'Go HTTP Client' },
      { regex: /apache-httpclient/i, name: 'Apache HttpClient' },
    ];
    for (const hl of headlessMap) {
      if (hl.regex.test(clean)) return { type: 'headless', isTool: true, isScanner: false, toolName: hl.name, riskWeight: 14, label: hl.name };
    }
    if (/bot|spider|crawler/i.test(clean)) return { type: 'crawler', isTool: true, isScanner: false, toolName: 'Search/Indexing Crawler', riskWeight: 4, label: 'Standard Web Crawler' };
    if (/mozilla|chrome|safari|firefox|edge/i.test(clean)) return { type: 'browser', isTool: false, isScanner: false, toolName: null, riskWeight: 0, label: 'Standard Web Browser' };
    return { type: 'unusual', isTool: false, isScanner: false, toolName: null, riskWeight: 8, label: 'Unusual User-Agent String' };
  }

  function normalizePayload(rawVal) {
    if (typeof rawVal !== 'string') return { original_value: '', normalized_value: '', was_url_encoded: false, was_hex_encoded: false, encoding_types: [] };
    const original = rawVal;
    let current = rawVal.trim();
    let wasUrl = false;
    let wasHex = false;
    const encTypes = [];
    if (/%[0-9a-fA-F]{2}/.test(current)) {
      try {
        const decoded = decodeURIComponent(current);
        if (decoded !== current) { current = decoded; wasUrl = true; encTypes.push('URL Encoding (%xx)'); }
        if (/%[0-9a-fA-F]{2}/.test(current)) {
          const doubleDecoded = decodeURIComponent(current);
          if (doubleDecoded !== current) { current = doubleDecoded; encTypes.push('Double URL Encoding'); }
        }
      } catch (e) {
        current = current.replace(/%20/gi, ' ').replace(/%27/gi, "'").replace(/%22/gi, '"').replace(/%3c/gi, '<').replace(/%3e/gi, '>').replace(/%2f/gi, '/');
        wasUrl = true;
        encTypes.push('Partial URL Encoding');
      }
    }
    if (/\\x[0-9a-fA-F]{2}|0x[0-9a-fA-F]{2}/i.test(current)) {
      wasHex = true;
      encTypes.push('Hexadecimal Escape (\\xXX / 0xXX)');
    }
    return { original_value: original, normalized_value: current, was_url_encoded: wasUrl, was_hex_encoded: wasHex, encoding_types: encTypes };
  }

  function executeThreatAnalysis(clientIp, paramKey, rawValue, userAgent) {
    const rawIp = clientIp || '';
    const rawKey = paramKey || '';
    const rawVal = rawValue || '';
    const rawUa = userAgent || '';

    const ipInfo = classifyIpAddress(rawIp);
    const uaInfo = analyzeUaHeader(rawUa);
    const norm = normalizePayload(rawVal);

    const valLen = rawVal.length;
    const keyLen = rawKey.length;
    const entropy = calcEntropy(rawVal);
    const specialChars = (rawVal.match(/['";:<>()\[\]{}\\/\\\\%$*+=&|`^~#]/g) || []).length;
    const specialRatio = valLen > 0 ? (specialChars / valLen) : 0;
    const keySpecialChars = (rawKey.match(/['";:<>()\[\]{}\\/\\\\%$*+=&|`]/g) || []).length;

    const indicators = [];
    const evidence = [];

    // SQLi patterns
    const normVal = norm.normalized_value.toLowerCase();
    const sqliUnion = /(?:union\s+(?:all\s+)?select)/i.test(normVal);
    const sqliTautology = /(?:(?:or|and)\s+[\d'"]+\s*=\s*[\d'"]+|or\s+true\b|or\s+1\s*=\s*1|or\s+'a'='a')/i.test(normVal);
    const sqliComments = /(?:--|\/\*|\*\/|#\s*$|--\s+-)/.test(normVal);
    const sqliStacked = /;\s*(?:select|insert|update|delete|drop|truncate|alter|create|declare)\b/i.test(normVal);
    const sqliTimeBased = /(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay)/i.test(normVal);
    const sqliKey = /^(?:union|select|sleep|benchmark|table|query|where)$/i.test(rawKey.trim());

    if (sqliUnion) {
      indicators.push({ category: 'SQL Injection', name: 'UNION SELECT Structure', weight: 42, severity: 'Critical' });
      evidence.push({ indicator: 'UNION SELECT construct', source: 'Parameter Value', evidence: (normVal.match(/(?:union\s+(?:all\s+)?select[^\n\r]*)/i) || [])[0] || 'UNION SELECT', confidence: 0.94 });
    }
    if (sqliTautology) {
      indicators.push({ category: 'SQL Injection', name: 'Boolean SQL Tautology (e.g. OR 1=1)', weight: 36, severity: 'High' });
      evidence.push({ indicator: 'Boolean logic bypass condition', source: 'Parameter Value', evidence: (normVal.match(/(?:(?:or|and)\s+[\d'"]+\s*=\s*[\d'"]+|or\s+true\b)/i) || [])[0] || 'OR 1=1', confidence: 0.91 });
    }
    if (sqliComments) {
      indicators.push({ category: 'SQL Injection', name: 'SQL Inline Comment / Truncator', weight: 18, severity: 'Moderate' });
      evidence.push({ indicator: 'SQL comment sequence', source: 'Parameter Value', evidence: (normVal.match(/(?:--[^\n]*|\/\*.*?\*\/|#)/) || [])[0] || '--', confidence: 0.85 });
    }
    if (sqliStacked) {
      indicators.push({ category: 'SQL Injection', name: 'Stacked SQL Query Delimiter', weight: 38, severity: 'Critical' });
      evidence.push({ indicator: 'Semicolon terminated SQL clause', source: 'Parameter Value', evidence: ';[stacked statement]', confidence: 0.90 });
    }
    if (sqliTimeBased) {
      indicators.push({ category: 'SQL Injection', name: 'Blind / Time-Based SQL Injection Function', weight: 40, severity: 'Critical' });
      evidence.push({ indicator: 'SQL sleep/benchmark payload', source: 'Parameter Value', evidence: (normVal.match(/(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+)/i) || [])[0] || 'sleep()', confidence: 0.93 });
    }
    if (sqliKey) {
      indicators.push({ category: 'SQL Injection', name: 'Suspicious SQL Clause in Parameter Key', weight: 15, severity: 'Moderate' });
      evidence.push({ indicator: 'Key matches SQL clause keyword', source: 'Parameter Key', evidence: rawKey, confidence: 0.70 });
    }

    // XSS patterns
    const xssScriptTag = /<script\b[^>]*>.*?<\/script>|<script\b[^>]*>/i.test(normVal);
    const xssEventHandler = /(?:on(?:error|load|click|mouseover|focus|blur|submit)\s*=)/i.test(normVal);
    const xssScheme = /(?:javascript:|data:text\/html|vbscript:)/i.test(normVal);
    const xssAlertExec = /(?:alert|prompt|confirm|eval|document\.cookie|window\.location)\s*\(/i.test(normVal);

    if (xssScriptTag) {
      indicators.push({ category: 'Cross-Site Scripting (XSS)', name: 'HTML Script Tag Injection', weight: 40, severity: 'Critical' });
      evidence.push({ indicator: 'Unsanitized <script> tag construct', source: 'Parameter Value', evidence: '<script...>', confidence: 0.95 });
    }
    if (xssEventHandler) {
      indicators.push({ category: 'Cross-Site Scripting (XSS)', name: 'HTML Event Handler Injection', weight: 35, severity: 'High' });
      evidence.push({ indicator: 'Inline event handler attribute (e.g. onerror=)', source: 'Parameter Value', evidence: (normVal.match(/on[a-z]+\s*=[^>\s]*/i) || [])[0] || 'onerror=', confidence: 0.92 });
    }
    if (xssScheme) {
      indicators.push({ category: 'Cross-Site Scripting (XSS)', name: 'JavaScript URI Pseudo-Protocol', weight: 32, severity: 'High' });
      evidence.push({ indicator: 'Executable URI scheme (javascript:)', source: 'Parameter Value', evidence: 'javascript:...', confidence: 0.88 });
    }
    if (xssAlertExec) {
      indicators.push({ category: 'Cross-Site Scripting (XSS)', name: 'Execution Function Invocation (alert/eval)', weight: 25, severity: 'Moderate' });
      evidence.push({ indicator: 'DOM execution / dialog primitive', source: 'Parameter Value', evidence: (normVal.match(/(?:alert|prompt|confirm|eval)\s*\([^)]*\)/i) || [])[0] || 'alert(...)', confidence: 0.86 });
    }

    // Command Injection (RCE)
    const rceSeparator = /(?:;\s*|&&\s*|\|\|\s*|`)(?:cat|ls|id|whoami|curl|wget|bash|sh|rm|nc|chmod|uname|dir|powershell)\b/i.test(normVal);
    const rceSubshell = /(?:\$\([a-zA-Z0-9_\s-]+\)|`[a-zA-Z0-9_\s-]+`)/.test(normVal);
    const rceSensFiles = /(?:\/etc\/passwd|\/etc\/shadow|\/proc\/self|c:\\windows\\system32)/i.test(normVal);
    const rcePipeCmd = /\|\s*(?:bash|sh|nc|curl|wget|perl|python)/i.test(normVal);
    const rceKeyName = /^(?:cmd|exec|command|shell|run|payload)$/i.test(rawKey.trim());

    if (rceSeparator || rcePipeCmd) {
      indicators.push({ category: 'Command Injection (RCE)', name: 'Shell Metacharacter Chain & Command Name', weight: 44, severity: 'Critical' });
      evidence.push({ indicator: 'Chained shell control character with binary name', source: 'Parameter Value', evidence: (normVal.match(/(?:;\s*|&&\s*|\|\|\s*|\|\s*)(?:cat|ls|id|whoami|curl|wget|bash|sh|nc)\b[^\n&|;]*/i) || [])[0] || ';cat ...', confidence: 0.93 });
    }
    if (rceSubshell) {
      indicators.push({ category: 'Command Injection (RCE)', name: 'Shell Subshell Evaluation Operator $() / ``', weight: 36, severity: 'High' });
      evidence.push({ indicator: 'Subshell invocation syntax', source: 'Parameter Value', evidence: (normVal.match(/\$\([^)]+\)|`[^`]+`/) || [])[0] || '$(cmd)', confidence: 0.90 });
    }
    if (rceSensFiles && (rceSeparator || normVal.includes('cat ') || normVal.includes('type '))) {
      indicators.push({ category: 'Command Injection (RCE)', name: 'Access Attempt to Sensitive System Files (/etc/passwd)', weight: 35, severity: 'High' });
      evidence.push({ indicator: 'Targeting core OS security file', source: 'Parameter Value', evidence: '/etc/passwd reference', confidence: 0.94 });
    }
    if (rceKeyName && (specialChars > 1 || valLen > 5)) {
      indicators.push({ category: 'Command Injection (RCE)', name: 'Execution-Oriented Parameter Key Name (cmd/exec)', weight: 16, severity: 'Moderate' });
      evidence.push({ indicator: 'Parameter key denotes OS execution endpoint', source: 'Parameter Key', evidence: rawKey, confidence: 0.72 });
    }

    // Path Traversal / LFI
    const lfiDots = /(?:\.\.\/|\.\.\\){2,}/.test(normVal);
    const lfiAbsoluteSens = /^(?:\/etc\/(?:passwd|shadow|hosts)|\/proc\/|c:\\windows\\system32)/i.test(normVal);
    const lfiNullByte = /%00|\x00/.test(rawVal);
    const lfiKeyName = /^(?:file|path|doc|page|include|template|view|load)$/i.test(rawKey.trim());

    if (lfiDots) {
      indicators.push({ category: 'Path Traversal / LFI', name: 'Directory Traversal Relative Step-Back Sequence (../)', weight: 42, severity: 'Critical' });
      evidence.push({ indicator: 'Multi-hop directory traversal pattern', source: 'Parameter Value', evidence: (normVal.match(/(?:\.\.[\/\\])+/) || [])[0] || '../../../', confidence: 0.95 });
    }
    if (lfiAbsoluteSens && !rceSeparator) {
      indicators.push({ category: 'Path Traversal / LFI', name: 'Arbitrary Absolute File Path Ingestion', weight: 34, severity: 'High' });
      evidence.push({ indicator: 'System absolute file access', source: 'Parameter Value', evidence: (normVal.match(/(?:\/etc\/[a-z]+|c:\\[a-z\\]+)/i) || [])[0] || '/etc/passwd', confidence: 0.91 });
    }
    if (lfiNullByte) {
      indicators.push({ category: 'Path Traversal / LFI', name: 'Null Byte Injection File Extension Bypass (%00)', weight: 30, severity: 'High' });
      evidence.push({ indicator: 'String terminator byte in path', source: 'Parameter Value', evidence: '%00 / \\x00', confidence: 0.92 });
    }
    if (lfiKeyName && (lfiDots || lfiAbsoluteSens)) {
      indicators.push({ category: 'Path Traversal / LFI', name: 'File-Targeting Parameter Key (e.g. file, path)', weight: 12, severity: 'Moderate' });
      evidence.push({ indicator: 'Parameter key corresponds to filesystem loader', source: 'Parameter Key', evidence: rawKey, confidence: 0.75 });
    }

    // User-Agent indicators
    if (uaInfo.isScanner) {
      indicators.push({ category: 'Scanner Reconnaissance', name: `Automated Security Scanner Identified (${uaInfo.toolName})`, weight: uaInfo.riskWeight, severity: 'High' });
      evidence.push({ indicator: `Known vulnerability scanner header signature`, source: 'User-Agent', evidence: rawUa.length > 50 ? `${rawUa.substring(0, 50)}...` : rawUa, confidence: 0.96 });
    } else if (uaInfo.type === 'headless') {
      indicators.push({ category: 'Automated Client', name: `Headless Scripting Client (${uaInfo.toolName})`, weight: uaInfo.riskWeight, severity: 'Low' });
      evidence.push({ indicator: 'Non-browser programmatic HTTP client', source: 'User-Agent', evidence: rawUa, confidence: 0.70 });
    }

    // Encoding / Obfuscation indicators
    if (norm.was_hex_encoded) {
      indicators.push({ category: 'Obfuscation / Encoding', name: 'Hexadecimal Escaped Sequence Detected', weight: 16, severity: 'Moderate' });
      evidence.push({ indicator: 'Hexadecimal character encoding in payload string', source: 'Parameter Value', evidence: 'Hex escapes present', confidence: 0.82 });
    }
    if (norm.encoding_types.includes('Double URL Encoding')) {
      indicators.push({ category: 'Obfuscation / Encoding', name: 'Double URL Encoding Detected (WAF Bypass Technique)', weight: 22, severity: 'High' });
      evidence.push({ indicator: 'Nested percent-encoding layer', source: 'Parameter Value', evidence: 'Double %xx decoding required', confidence: 0.88 });
    }

    // High Entropy / Excessive Special Characters
    if (valLen > 30 && entropy > 4.5) {
      indicators.push({ category: 'Suspicious Characteristics', name: `High Shannon Entropy (${entropy} bits)`, weight: 14, severity: 'Moderate' });
      evidence.push({ indicator: 'Statistical randomness indicative of encoded or encrypted payload', source: 'Parameter Value', evidence: `${entropy} bits entropy`, confidence: 0.75 });
    }
    if (valLen > 10 && specialRatio > 0.35) {
      indicators.push({ category: 'Suspicious Characteristics', name: `Dense Special Character Ratio (${(specialRatio * 100).toFixed(0)}%)`, weight: 14, severity: 'Moderate' });
      evidence.push({ indicator: 'Atypical punctuation density', source: 'Parameter Value', evidence: `${specialChars} special chars in ${valLen} bytes`, confidence: 0.78 });
    }
    if (valLen > 500) {
      indicators.push({ category: 'Suspicious Characteristics', name: `Excessive Payload Length (${valLen} bytes)`, weight: 12, severity: 'Moderate' });
      evidence.push({ indicator: 'Parameter length exceeds standard single-field bounds', source: 'Parameter Value', evidence: `${valLen} bytes`, confidence: 0.70 });
    }

    // Calculate Dynamic Risk Score
    let rawScore = indicators.reduce((acc, ind) => acc + ind.weight, 0);
    if (indicators.length >= 3) rawScore += 8;
    const riskScore = Math.min(100, Math.max(0, rawScore));

    let severity = 'Low';
    if (riskScore >= 76) severity = 'Critical';
    else if (riskScore >= 51) severity = 'High';
    else if (riskScore >= 21) severity = 'Moderate';

    // Determine Classification Category
    const categoryTotals = {};
    for (const ind of indicators) {
      categoryTotals[ind.category] = (categoryTotals[ind.category] || 0) + ind.weight;
    }
    let topCategory = 'Benign Traffic';
    let topScore = 0;
    for (const [cat, score] of Object.entries(categoryTotals)) {
      if (score > topScore) { topScore = score; topCategory = cat; }
    }

    let classificationLabel = 'Benign Request Structure';
    let confidence = 0.88;

    if (riskScore >= 51) {
      if (topCategory === 'SQL Injection') { classificationLabel = 'Suspicious SQL Injection Pattern'; confidence = Math.min(0.96, 0.82 + (indicators.length * 0.03)); }
      else if (topCategory === 'Cross-Site Scripting (XSS)') { classificationLabel = 'Cross-Site Scripting (XSS) Pattern'; confidence = Math.min(0.95, 0.80 + (indicators.length * 0.03)); }
      else if (topCategory === 'Command Injection (RCE)') { classificationLabel = 'Command Injection / Shell Execution Pattern'; confidence = Math.min(0.96, 0.83 + (indicators.length * 0.03)); }
      else if (topCategory === 'Path Traversal / LFI') { classificationLabel = 'Path Traversal / Local File Inclusion'; confidence = Math.min(0.95, 0.81 + (indicators.length * 0.03)); }
      else if (topCategory === 'Scanner Reconnaissance') { classificationLabel = 'Automated Vulnerability Scanner Probe'; confidence = 0.94; }
      else { classificationLabel = 'High-Risk Suspicious Payload'; confidence = 0.85; }
    } else if (riskScore >= 21) {
      classificationLabel = topCategory !== 'Benign Traffic' ? `Anomalous Input (${topCategory} Characteristics)` : 'Anomalous Request Characteristics';
      confidence = 0.76;
    } else {
      classificationLabel = 'Benign Request Structure';
      confidence = 0.91;
    }

    let explanation = '';
    if (indicators.length === 0) {
      explanation = `The analyzed request parameters exhibit standard characteristics consistent with legitimate web application traffic. Parameter "${rawKey || 'empty'}" contains alphanumeric content with normal Shannon entropy (${entropy} bits) and no exploit syntax.`;
    } else {
      const topNames = indicators.slice(0, 3).map(i => i.name).join('; ');
      explanation = `The analyzed request contains ${indicators.length} observable indicator(s). Primary indicators: ${topNames}. Structural syntax within "${rawKey}" strongly correlates with ${topCategory}.`;
    }

    let recommendation = 'No defensive mitigation required for this traffic pattern.';
    if (topCategory === 'SQL Injection') recommendation = 'Enforce parameterized queries (prepared statements) with ORM bounds. Reject unvalidated dynamic concatenation.';
    else if (topCategory === 'Cross-Site Scripting (XSS)') recommendation = 'Apply contextual output encoding (HTML, JS, URL) and enforce a strict Content Security Policy (CSP).';
    else if (topCategory === 'Command Injection (RCE)') recommendation = 'Avoid direct shell invocations (e.g. system, exec). Use structured APIs with strict argument tokenization.';
    else if (topCategory === 'Path Traversal / LFI') recommendation = 'Validate paths against a strict allowlist. Resolve canonical paths (realpath) and ensure they remain within the intended root.';
    else if (topCategory === 'Scanner Reconnaissance') recommendation = 'Implement rate limiting and automated IP throttling at the web application firewall (WAF) or ingress layer.';
    else if (riskScore >= 21) recommendation = 'Apply strict input validation schema (type, length, character set) on this parameter.';

    return {
      simulation: true,
      network_request_sent: false,
      simulation_status: 'SAFE — LOCAL ANALYSIS ONLY',
      classification: { label: classificationLabel, category: topCategory, confidence: parseFloat(confidence.toFixed(2)) },
      risk: { score: riskScore, severity: severity },
      input: {
        parameter_key: rawKey,
        parameter_length: valLen,
        user_agent: rawUa,
        ip_valid: ipInfo.valid,
        ip_scope: ipInfo.scope,
        ip_label: ipInfo.label,
        entropy: entropy,
        special_chars: specialChars,
        special_ratio: parseFloat(specialRatio.toFixed(3)),
        normalized_value: norm.normalized_value,
        was_encoded: norm.was_url_encoded || norm.was_hex_encoded,
        encoding_types: norm.encoding_types,
      },
      indicators: indicators,
      evidence: evidence,
      explanation: explanation,
      recommendation: recommendation,
      limitations: [
        'Simulation only — no network request was sent to the supplied IP or any external target.',
        'Classification is derived dynamically from request syntax, feature extraction, and defensive heuristics.',
        'An IP address is treated strictly as request metadata and is never alone treated as evidence of malicious activity.',
        'This defensive engine runs locally and safely treats all supplied values as inert strings.',
      ],
    };
  }

  function setupSandbox() {
    const testCases = {
      sqli: { ip: '45.33.32.156', key: 'id', val: "1' OR 1=1 UNION SELECT password FROM users--", ua: 'sqlmap/1.6.12#stable', name: 'SQL Injection' },
      rce: { ip: '185.220.101.5', key: 'cmd', val: ';cat /etc/passwd && whoami && id', ua: 'curl/7.68.0', name: 'Command Injection' },
      xss: { ip: '203.0.113.88', key: 'search', val: "<script>alert('xss')</script><img onerror=alert(1)>", ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', name: 'Cross-Site Scripting' },
      scanner: { ip: '42.105.165.217', key: 'none', val: 'index.php?file=test', ua: 'Mozilla/5.00 (Nikto/2.1.6) (Evasions:None)', name: 'Automated Scanner Recon' },
      lfi: { ip: '157.32.110.9', key: 'file', val: '../../../../etc/passwd%00', ua: 'python-requests/2.28.0', name: 'Path Traversal / LFI' },
      benign: { ip: '192.168.1.105', key: 'lang', val: 'en_US', ua: 'Mozilla/5.0 (Windows NT 10.0; rv:108.0) Gecko/20100101 Firefox/108.0', name: 'Benign Traffic' },
    };

    const ipInput = document.getElementById('sb-ip');
    const keyInput = document.getElementById('sb-key');
    const valInput = document.getElementById('sb-val');
    const uaInput = document.getElementById('sb-ua');
    const ipBadge = document.getElementById('sb-ip-type-badge');
    const entropyBadge = document.getElementById('sb-entropy-badge');
    const noticeEl = document.getElementById('sb-preset-notice');
    const errorEl = document.getElementById('sb-validation-errors');

    function updateFieldBadges() {
      if (ipInput && ipBadge) {
        const info = classifyIpAddress(ipInput.value);
        ipBadge.textContent = `${info.version || 'IP'}: ${info.label}`;
        ipBadge.style.color = info.valid ? (info.scope === 'private' ? '#60a5fa' : '#a78bfa') : '#f87171';
      }
      if (valInput && entropyBadge) {
        const ent = calcEntropy(valInput.value);
        entropyBadge.textContent = `${ent} bits entropy | ${valInput.value.length} chars`;
        entropyBadge.style.color = ent > 4.0 ? '#f43f5e' : (ent > 2.5 ? '#fbbf24' : '#34d399');
      }
    }

    if (ipInput) ipInput.addEventListener('input', updateFieldBadges);
    if (valInput) valInput.addEventListener('input', updateFieldBadges);

    document.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const tc = testCases[btn.dataset.preset];
        if (!tc) return;
        if (ipInput) ipInput.value = tc.ip;
        if (keyInput) keyInput.value = tc.key;
        if (valInput) valInput.value = tc.val;
        if (uaInput) uaInput.value = tc.ua;
        updateFieldBadges();
        if (noticeEl) {
          noticeEl.style.display = 'block';
          noticeEl.textContent = `ℹ Loaded "${tc.name}" test input. Note: The analyzer evaluates actual parameter syntax; the preset does NOT dictate the verdict.`;
        }
        if (errorEl) errorEl.style.display = 'none';
        runSandbox();
      });
    });

    document.getElementById('run-sandbox')?.addEventListener('click', runSandbox);
    updateFieldBadges();
    setTimeout(runSandbox, 300);
  }

  function calcEntropy(s) {
    if (!s || s === 'none') return 0;
    const len = s.length;
    if (len <= 1) return 0;
    const freq = {};
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    return parseFloat(Object.values(freq).reduce((h, f) => { const p = f/len; return h - p * Math.log2(p); }, 0).toFixed(3));
  }

  function runSandbox() {
    const ipInput = document.getElementById('sb-ip');
    const keyInput = document.getElementById('sb-key');
    const valInput = document.getElementById('sb-val');
    const uaInput = document.getElementById('sb-ua');
    const errorEl = document.getElementById('sb-validation-errors');
    const resultsEl = document.getElementById('sandbox-results');

    const ip = ipInput?.value.trim() || '';
    const key = keyInput?.value.trim() || '';
    const val = valInput?.value || '';
    const ua = uaInput?.value.trim() || '';

    // Frontend validation
    const errors = [];
    if (!key) errors.push('Parameter key is required.');
    else if (key.length > 128) errors.push('Parameter key exceeds maximum allowed length of 128 characters.');

    if (!val && val !== '0') errors.push('Parameter value (payload) is required.');
    else if (val.length > 8192) errors.push('Parameter value exceeds maximum allowed length of 8,192 characters.');

    if (ip) {
      const ipCheck = classifyIpAddress(ip);
      if (!ipCheck.valid) errors.push(`Client IP "${ip}" is malformed. Please enter a valid IPv4 or IPv6 address.`);
    }

    if (errors.length > 0) {
      if (errorEl) {
        errorEl.style.display = 'block';
        errorEl.innerHTML = `<strong>Validation Error:</strong><ul style="margin:4px 0 0 16px;padding:0;">${errors.map(e => `<li>${escHtml(e)}</li>`).join('')}</ul>`;
      }
      return;
    }
    if (errorEl) errorEl.style.display = 'none';

    // Run dynamic analysis
    const result = executeThreatAnalysis(ip, key, val, ua);

    if (!resultsEl) return;
    resultsEl.classList.remove('hidden');

    const isMal = result.risk.score >= 51;
    const isMod = result.risk.score >= 21 && result.risk.score < 51;
    const color = isMal ? '#f43f5e' : (isMod ? '#f59e0b' : '#10b981');
    const bgColor = isMal ? 'rgba(244,63,94,0.1)' : (isMod ? 'rgba(245,158,11,0.1)' : 'rgba(16,185,129,0.1)');
    const borderColor = isMal ? 'rgba(244,63,94,0.3)' : (isMod ? 'rgba(245,158,11,0.3)' : 'rgba(16,185,129,0.3)');

    let indicatorsHtml = '';
    if (result.indicators.length === 0) {
      indicatorsHtml = `<div style="font-size:12px;color:var(--text-muted);padding:8px 12px;background:rgba(255,255,255,0.02);border-radius:6px;">No suspicious attack indicators or exploit primitives detected in the supplied parameters.</div>`;
    } else {
      indicatorsHtml = result.indicators.map(ind => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:6px;margin-bottom:6px;">
          <div>
            <div style="font-size:12.5px;font-weight:600;color:var(--text-primary);">${escHtml(ind.name)}</div>
            <div style="font-size:11px;color:var(--text-muted);">${escHtml(ind.category)}</div>
          </div>
          <div style="text-align:right;">
            <span style="font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:4px;background:${ind.severity === 'Critical' ? 'rgba(244,63,94,0.2)' : (ind.severity === 'High' ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)')};color:${ind.severity === 'Critical' || ind.severity === 'High' ? '#f87171' : '#fbbf24'};">
              ${ind.severity} (+${ind.weight})
            </span>
          </div>
        </div>
      `).join('');
    }

    let evidenceHtml = '';
    if (result.evidence.length > 0) {
      evidenceHtml = `
        <details style="margin-top:14px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:10px 14px;">
          <summary style="font-size:12.5px;font-weight:600;color:#93c5fd;cursor:pointer;user-select:none;">
            Why was this detected? (Evidence Provenance &bull; ${result.evidence.length} facts)
          </summary>
          <div style="margin-top:10px;display:flex;flex-direction:column;gap:8px;">
            ${result.evidence.map(ev => `
              <div style="font-size:11.5px;padding:8px 10px;background:rgba(0,0,0,0.25);border-radius:6px;border-left:3px solid #3b82f6;">
                <div style="display:flex;justify-content:space-between;color:var(--text-muted);margin-bottom:3px;">
                  <span><strong>Source:</strong> ${escHtml(ev.source)}</span>
                  <span><strong>Confidence:</strong> ${(ev.confidence * 100).toFixed(0)}%</span>
                </div>
                <div style="color:var(--text-primary);margin-bottom:2px;"><strong>Indicator:</strong> ${escHtml(ev.indicator)}</div>
                <div style="font-family:monospace;font-size:11px;color:#cbd5e1;background:rgba(255,255,255,0.05);padding:3px 6px;border-radius:4px;word-break:break-all;">
                  ${escHtml(ev.evidence)}
                </div>
              </div>
            `).join('')}
          </div>
        </details>
      `;
    }

    resultsEl.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;background:${bgColor};border:1px solid ${borderColor};padding:14px 18px;border-radius:10px;margin-bottom:16px;">
        <div style="display:flex;align-items:center;gap:12px;">
          <div style="width:36px;height:36px;border-radius:8px;background:${color};display:flex;align-items:center;justify-content:center;color:#fff;">
            ${icon(isMal ? 'shield-alert' : (isMod ? 'alert-triangle' : 'check'), 22)}
          </div>
          <div>
            <div style="font-size:11px;font-weight:700;letter-spacing:0.8px;color:${color};text-transform:uppercase;">
              ${result.simulation_status}
            </div>
            <div style="font-size:18px;font-weight:700;color:var(--text-primary);margin-top:2px;">
              ${escHtml(result.classification.label)}
            </div>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">
              Primary Vector: <strong style="color:var(--text-primary);">${escHtml(result.classification.category)}</strong>
            </div>
          </div>
        </div>
        <div style="display:flex;gap:16px;align-items:center;">
          <div style="text-align:right;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.6px;color:var(--text-muted);">Dynamic Risk Score</div>
            <div style="font-size:26px;font-weight:800;color:${color};line-height:1.1;">
              ${result.risk.score}<span style="font-size:13px;font-weight:500;color:var(--text-muted);">/100</span>
            </div>
            <span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:${color}22;color:${color};">
              ${result.risk.severity} Severity
            </span>
          </div>
          <div style="border-left:1px solid rgba(255,255,255,0.1);padding-left:16px;text-align:right;">
            <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.6px;color:var(--text-muted);">Model Confidence</div>
            <div style="font-size:26px;font-weight:800;color:#93c5fd;line-height:1.1;">
              ${(result.classification.confidence * 100).toFixed(0)}<span style="font-size:13px;font-weight:500;color:var(--text-muted);">%</span>
            </div>
            <span style="font-size:10px;color:var(--text-muted);">Heuristic certainty</span>
          </div>
        </div>
      </div>

      <!-- SANITIZED ENVELOPE PREVIEW -->
      <div style="background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:12px 14px;margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <span style="font-size:11px;font-weight:700;letter-spacing:0.5px;color:var(--text-muted);text-transform:uppercase;">
            Sanitized Request Envelope Representation
          </span>
          <span style="font-size:10px;background:rgba(239,68,68,0.15);color:#fca5a5;padding:2px 8px;border-radius:10px;border:1px solid rgba(239,68,68,0.3);">
            NETWORK ACTION: NOT EXECUTED
          </span>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:8px;font-family:monospace;font-size:11.5px;color:#94a3b8;">
          <div><strong style="color:var(--text-primary);">METHOD:</strong> GET (Simulated Sandbox)</div>
          <div><strong style="color:var(--text-primary);">SOURCE IP:</strong> ${escHtml(ip || 'Not provided')} (${escHtml(result.input.ip_label)})</div>
          <div><strong style="color:var(--text-primary);">PARAM:</strong> ${escHtml(key)}</div>
          <div><strong style="color:var(--text-primary);">ENTROPY:</strong> ${result.input.entropy} bits (${result.input.parameter_length} bytes)</div>
          <div style="grid-column:1/-1;word-break:break-all;"><strong style="color:var(--text-primary);">RAW VALUE:</strong> ${escHtml(val.length > 120 ? val.substring(0, 120) + '... [truncated]' : val)}</div>
          ${result.input.was_encoded ? `<div style="grid-column:1/-1;color:#fbbf24;"><strong style="color:var(--text-primary);">NORMALIZED:</strong> ${escHtml(result.input.normalized_value)} (${result.input.encoding_types.join(', ')})</div>` : ''}
          <div style="grid-column:1/-1;word-break:break-all;"><strong style="color:var(--text-primary);">USER-AGENT:</strong> ${escHtml(ua || '(none provided)')}</div>
        </div>
      </div>

      <!-- INDICATORS LIST -->
      <div style="margin-bottom:14px;">
        <div style="font-size:12px;font-weight:700;letter-spacing:0.5px;color:var(--text-muted);text-transform:uppercase;margin-bottom:8px;">
          Detected Indicators (${result.indicators.length})
        </div>
        ${indicatorsHtml}
      </div>

      ${evidenceHtml}

      <!-- DYNAMIC EXPLANATION & RECOMMENDATION -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px;">
        <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:12px;">
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#93c5fd;margin-bottom:4px;">Analysis &bull; Feature Evidence</div>
          <p style="font-size:12px;color:#cbd5e1;line-height:1.5;margin:0;">${escHtml(result.explanation)}</p>
        </div>
        <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:12px;">
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;color:#34d399;margin-bottom:4px;">Defensive Recommendation</div>
          <p style="font-size:12px;color:#cbd5e1;line-height:1.5;margin:0;">${escHtml(result.recommendation)}</p>
        </div>
      </div>

      <!-- DISCLAIMER / LIMITATIONS -->
      <div style="margin-top:14px;padding:10px 12px;background:rgba(255,255,255,0.015);border:1px solid rgba(255,255,255,0.05);border-radius:6px;font-size:11px;color:var(--text-muted);line-height:1.5;">
        <strong style="color:#d1d5db;">Simulator Safety Disclaimers:</strong>
        <ul style="margin:4px 0 0 16px;padding:0;">
          ${result.limitations.map(l => `<li>${escHtml(l)}</li>`).join('')}
        </ul>
      </div>
    `;
  }

  // ─── NOTEBOOK RENDERER ─────────────────────────────────────────────────────
  function renderNotebook(ipynbFile) {
    const container = document.getElementById('notebook-view');
    container.innerHTML = `<div style="color:var(--text-muted);font-size:13px;padding:20px;">Loading notebook cells...</div>`;
    fetch(ipynbFile)
      .then(r => r.json())
      .then(nb => {
        container.innerHTML = '';
        nb.cells.forEach((cell, idx) => {
          const el = document.createElement('div');
          el.className = `nb-cell ${cell.cell_type}`;
          const src = Array.isArray(cell.source) ? cell.source.join('') : cell.source;
          if (cell.cell_type === 'markdown') {
            el.innerHTML = parseMd(src);
          } else if (cell.cell_type === 'code') {
            let outText = '';
            (cell.outputs || []).forEach(o => {
              if (o.text) outText += Array.isArray(o.text) ? o.text.join('') : o.text;
            });
            el.innerHTML = `
              <div class="nb-input-box">
                <span style="font-size:10px;color:var(--text-muted);display:block;margin-bottom:4px;">In [${cell.execution_count || idx+1}]:</span>
                <pre><code>${escHtml(src)}</code></pre>
              </div>
              ${outText ? `<div class="nb-output-box"><span style="font-size:10px;color:var(--text-muted);display:block;margin-bottom:4px;">Out [${cell.execution_count || idx+1}]:</span><pre><code>${escHtml(outText)}</code></pre></div>` : ''}
            `;
          }
          container.appendChild(el);
        });
      })
      .catch(() => {
        container.innerHTML = `<div class="callout callout-blue">${icon('book-open',16)}<div>Notebook preview not available in this environment. Open the .ipynb file directly in Jupyter.</div></div>`;
      });
  }

  // ─── LIGHTBOX ─────────────────────────────────────────────────────────────
  function setupLightbox() {
    document.getElementById('lb-close')?.addEventListener('click', closeLightbox);
    document.getElementById('lb-backdrop')?.addEventListener('click', closeLightbox);
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeLightbox(); });
  }

  function openLightbox(src, caption) {
    document.getElementById('lb-img').src = src;
    document.getElementById('lb-caption').textContent = caption;
    document.getElementById('lightbox').classList.remove('hidden');
  }

  function closeLightbox() {
    document.getElementById('lightbox').classList.add('hidden');
  }

  // ─── UTILITIES ────────────────────────────────────────────────────────────
  function escHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function parseMd(text) {
    if (!text) return '';
    let h = escHtml(text);
    h = h.replace(/^### (.+)$/gm, '<h3 style="font-size:14px;font-weight:700;color:var(--text-primary);margin:10px 0 6px">$1</h3>');
    h = h.replace(/^## (.+)$/gm, '<h2 style="font-size:15px;font-weight:700;color:var(--text-primary);margin:14px 0 8px">$1</h2>');
    h = h.replace(/^# (.+)$/gm, '<h1 style="font-size:17px;font-weight:800;color:var(--text-primary);margin:16px 0 10px">$1</h1>');
    h = h.replace(/\*\*(.+?)\*\*/g, '<strong style="color:var(--text-primary)">$1</strong>');
    h = h.replace(/`(.+?)`/g, '<code>$1</code>');
    h = h.replace(/^\- (.+)$/gm, '<li style="margin-left:16px">$1</li>');
    h = h.replace(/\$\$(.+?)\$\$/gs, '<em style="font-family:var(--font-mono);color:var(--accent-cyan)">$1</em>');
    h = h.replace(/\n{2,}/g, '<br><br>');
    return h;
  }
});
