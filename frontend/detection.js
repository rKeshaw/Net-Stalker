/* ============================================================
   PHISH-NET — Detection Module
   ============================================================ */

let currentQRFile = null;
let lastResult = null;
let currentTaskId = null; 

// ── URL Analysis ─────────────────────────────────────────────

async function analyzeURL() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) { showError('Please enter a URL to analyze.'); return; }

  const useBrowser = document.getElementById('urlUseBrowser').checked;
  const useHoneypot = document.getElementById('urlUseHoneypot').checked;
  const useDeepScan = document.getElementById('urlUseDeepScan').checked;

  resetUI();
  setButtonLoading('analyzeUrlBtn', true, 'SCAN');
  showProgressModal('Scanning URL...');
  updateProgress(5, 'Resolving target...');

  try {
    const data = await apiPost('/analyze/url', {
      url,
      use_external_apis: useHoneypot,
      async_mode: true,
      enable_behavioral: useBrowser || useDeepScan,
      enable_live_capture: useBrowser
    });

    if (data.task_id) {
      currentTaskId = data.task_id;
      updateProgress(15, 'Task queued, monitoring progress...');
      await new Promise((resolve, reject) => {
        streamTaskProgress(data.task_id,
          (pct, msg) => updateProgress(15 + pct * 0.8, msg),
          result => { displayAllResults(result, 'url'); resolve(); },
          err => reject(new Error(err))
        );
      });
    } else {
      updateProgress(100, 'Analysis complete.');
      displayAllResults(data, 'url');
    }
  } catch (err) {
    showError('URL analysis failed: ' + err.message);
  } finally {
    setButtonLoading('analyzeUrlBtn', false, 'SCAN');
    hideProgressModal();
  }
}

// ── Email Analysis ───────────────────────────────────────────

async function analyzeEmail() {
  const from = document.getElementById('emailFrom').value.trim();
  const subject = document.getElementById('emailSubject').value.trim();
  const body = document.getElementById('emailBody').value.trim();

  if (!body && !from) { showError('Please enter at least a sender address or email body.'); return; }

  resetUI();
  setButtonLoading('analyzeEmailBtn', true, 'ANALYZE EMAIL');
  showProgressModal('Analyzing email...');
  updateProgress(5, 'Parsing email headers...');

  try {
    const emlContent = [
      `From: ${from || 'unknown@unknown.local'}`,
      'To: victim@example.com',
      `Subject: ${subject || '(No Subject)'}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=UTF-8',
      '',
      body || subject || from,
    ].join('\r\n');

    const formData = new FormData();
    formData.append('file', new Blob([emlContent], { type: 'message/rfc822' }), 'frontend-input.eml');

    const data = await apiPost('/analyze/email', formData, true);

    if (data.task_id) {
      currentTaskId = data.task_id;
      updateProgress(15, 'Processing...');
      await new Promise((resolve, reject) => {
        streamTaskProgress(data.task_id,
          (pct, msg) => updateProgress(15 + pct * 0.8, msg),
          result => { displayAllResults(result, 'email'); resolve(); },
          err => reject(new Error(err))
        );
      });
    } else {
      updateProgress(100, 'Done.');
      displayAllResults(data, 'email');
    }
  } catch (err) {
    showError('Email analysis failed: ' + err.message);
  } finally {
    setButtonLoading('analyzeEmailBtn', false, 'ANALYZE EMAIL');
    hideProgressModal();
  }
}

function clearEmailForm() {
  ['emailFrom','emailSubject','emailBody'].forEach(id => { document.getElementById(id).value = ''; });
  resetUI();
}

// ── Text Analysis ────────────────────────────────────────────

async function analyzeText() {
  const text = document.getElementById('textInput').value.trim();
  if (!text) { showError('Please enter text to analyze.'); return; }

  resetUI();
  setButtonLoading('analyzeTextBtn', true, 'ANALYZE TEXT');
  showProgressModal('Analyzing text...');
  updateProgress(5, 'Tokenizing content...');

  try {
    const data = await apiPost('/analyze/text', { text });

    if (data.task_id) {
      currentTaskId = data.task_id;
      updateProgress(20, 'Processing...');
      await new Promise((resolve, reject) => {
        streamTaskProgress(data.task_id,
          (pct, msg) => updateProgress(20 + pct * 0.75, msg),
          result => { displayAllResults(result, 'text'); resolve(); },
          err => reject(new Error(err))
        );
      });
    } else {
      updateProgress(100, 'Done.');
      displayAllResults(data, 'text');
    }
  } catch (err) {
    showError('Text analysis failed: ' + err.message);
  } finally {
    setButtonLoading('analyzeTextBtn', false, 'ANALYZE TEXT');
    hideProgressModal();
  }
}

// ── QR Analysis ──────────────────────────────────────────────

function handleQRFile(event) {
  const file = event.target.files[0];
  if (file) loadQRPreview(file);
}

function loadQRPreview(file) {
  currentQRFile = file;
  const reader = new FileReader();
  reader.onload = e => {
    const preview = document.getElementById('qrPreview');
    const nameEl = document.getElementById('qrFileName');
    preview.src = e.target.result;
    preview.classList.remove('hidden');
    nameEl.textContent = '📎 ' + file.name;
    nameEl.classList.remove('hidden');
  };
  reader.readAsDataURL(file);
}

function clearQR() {
  currentQRFile = null;
  const preview = document.getElementById('qrPreview');
  const nameEl = document.getElementById('qrFileName');
  const input = document.getElementById('qrFileInput');
  preview.src = '';
  preview.classList.add('hidden');
  nameEl.classList.add('hidden');
  if (input) input.value = '';
  resetUI();
}

async function analyzeQR() {
  if (!currentQRFile) { showError('Please upload a QR code image first.'); return; }

  resetUI();
  setButtonLoading('analyzeQrBtn', true, 'DECODE & SCAN');
  showProgressModal('Decoding QR code...');
  updateProgress(5, 'Decoding QR payload...');

  try {
    const formData = new FormData();
    formData.append('file', currentQRFile);
    // Explicitly add defaults as boolean strings so backend picks them up properly if needed
    formData.append('use_external_apis', 'true');
    formData.append('enable_behavioral', 'true');
    formData.append('enable_live_capture', 'true');

    const data = await apiPost('/analyze/qr', formData, true);

    if (data.task_id) {
      currentTaskId = data.task_id;
      updateProgress(20, 'Analyzing decoded content...');
      await new Promise((resolve, reject) => {
        streamTaskProgress(data.task_id,
          (pct, msg) => updateProgress(20 + pct * 0.75, msg),
          result => { displayAllResults(result, 'qr'); resolve(); },
          err => reject(new Error(err))
        );
      });
    } else {
      updateProgress(100, 'Done.');
      displayAllResults(data, 'qr');
    }
  } catch (err) {
    showError('QR analysis failed: ' + err.message);
  } finally {
    setButtonLoading('analyzeQrBtn', false, 'DECODE & SCAN');
    hideProgressModal();
  }
}

// ── Results Renderer ─────────────────────────────────────────

function displayAllResults(data, type) {
  const normalized = normalizeDetectionResult(data, type);
  lastResult = normalized;

  // Propagate Task ID from root
  if (data.task_id) currentTaskId = data.task_id;

  const block = document.getElementById('resultsBlock');
  if (block) {
    block.classList.remove('hidden');
    block.innerHTML = buildMainResultsHTML(normalized, type);
  }

  if (normalized.behavioral_analysis) {
    const bBlock = document.getElementById('behavioralBlock');
    if (bBlock) {
      bBlock.classList.remove('hidden');
      bBlock.innerHTML = buildBehavioralHTML(normalized.behavioral_analysis);
    }
  }

  if (normalized.technical_details || normalized.whois || normalized.ssl_info) {
    const tBlock = document.getElementById('technicalBlock');
    if (tBlock) {
      tBlock.classList.remove('hidden');
      tBlock.innerHTML = buildTechnicalHTML(normalized);
    }
  }

  if (normalized.external_apis || normalized.virustotal || normalized.urlscan || normalized.url_deep_scans) {
    const eBlock = document.getElementById('externalBlock');
    if (eBlock) {
      eBlock.classList.remove('hidden');
      eBlock.innerHTML = buildExternalAPIHTML(normalized);
      attachDeepScanListeners(normalized.url_deep_scans);
    }
  }

  if (normalized.honeypot_result) {
    const hBlock = document.getElementById('honeypotBlock');
    if (hBlock) {
      hBlock.classList.remove('hidden');
      hBlock.innerHTML = buildHoneypotHTML(normalized.honeypot_result);
    }
  }

  if (normalized.qr_codes) {
    const block = document.getElementById('resultsBlock');
    if (block) block.innerHTML += buildQRSection(normalized.qr_codes);
  }

  block?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function normalizeDetectionResult(data, type) {
  const llm = data.llm_analysis || {};
  const features = data.features || {};

  return {
    ...data,
    analysis_type: data.analysis_type || type,
    verdict: data.verdict || llm.classification || llm.verdict,
    risk_score: data.risk_score ?? llm.risk_score ?? llm.confidence_score,
    summary: data.summary || llm.summary || llm.reasoning || llm.explanation,
    indicators: data.indicators || llm.indicators || llm.key_findings || [],
    extracted_urls: data.extracted_urls || features.extracted_urls || features.links || [],
    technical_details: data.technical_details || features,
    whois: data.whois || features.whois,
    ssl_info: data.ssl_info || features.ssl,
    virustotal: data.virustotal || (data.external_apis ? data.external_apis.virustotal : null),
    urlscan: data.urlscan || (data.external_apis ? data.external_apis.urlscan : null),
  };
}

function buildMainResultsHTML(data, type) {
  const verdict = data.verdict || data.classification || 'UNKNOWN';
  const score = data.risk_score ?? data.score ?? null;
  const summary = data.summary || data.analysis || data.explanation || '';
  const indicators = data.indicators || data.red_flags || [];
  const urls = data.extracted_urls || data.urls || [];

  const scoreColor = score !== null ? riskColor(score) : 'var(--accent-cyan)';

  let html = `<div class="cyber-card">
    <div class="results-header">
      <div>
        <div class="card-title">Analysis Result</div>
        ${verdictBadge(verdict)}
      </div>
      ${score !== null ? `<div class="risk-display">
        <div class="risk-number" style="color:${scoreColor}">${score}</div>
        <div class="risk-label">RISK SCORE</div>
      </div>` : ''}
    </div>`;

  if (summary) {
    html += `<div class="ai-summary">${escapeHTML(summary)}</div>`;
  }

  if (indicators && indicators.length > 0) {
    html += `<div style="margin-top:18px">
      <div class="card-title" style="margin-bottom:10px">Threat Indicators</div>`;
    indicators.forEach(ind => {
      const text = typeof ind === 'string' ? ind : (ind.description || ind.name || JSON.stringify(ind));
      const sev = (ind.severity || '').toLowerCase();
      const cls = sev === 'critical' || sev === 'high' ? 'anomaly-item crit' : 'anomaly-item';
      html += `<div class="${cls}">${escapeHTML(text)}</div>`;
    });
    html += `</div>`;
  }

  if (data.detected_brands && data.detected_brands.length > 0) {
    html += `<div style="margin-top:14px">
      <div class="card-title" style="margin-bottom:8px">Impersonated Brands</div>
      <div class="brand-chips">`;
    data.detected_brands.forEach(brand => {
      html += `<span class="brand-chip">${escapeHTML(brand)}</span>`;
    });
    html += `</div></div>`;
  }

  if (urls && urls.length > 0) {
    html += `<div style="margin-top:14px">
      <div class="card-title" style="margin-bottom:8px">Extracted URLs</div>
      <div class="domains-scroll">`;
    urls.slice(0, 20).forEach(u => {
      html += `<div><code style="font-family:var(--font-mono);font-size:0.73rem;color:var(--accent-cyan)">${escapeHTML(typeof u === 'string' ? u : u.url || '')}</code></div>`;
    });
    html += `</div></div>`;
  }

  html += `<div style="margin-top:16px;text-align:right">
    <button class="btn-ghost" onclick="downloadReport()" id="exportReportBtn">⬇ Export PDF Report</button>
  </div>`;
  html += `</div>`;
  return html;
}

function buildBehavioralHTML(beh) {
  let html = `<div class="cyber-card"><div class="card-title">Browser Behavioral Analysis</div>`;

  // Summary stats
  const stats = [
    { lbl: 'Page Loads', val: beh.page_loads ?? beh.requests ?? '-' },
    { lbl: 'Forms Found', val: beh.form_count ?? beh.forms?.length ?? '-' },
    { lbl: 'Redirects', val: beh.redirect_count ?? beh.redirects ?? '-' },
    { lbl: 'Scripts', val: beh.script_count ?? beh.scripts?.length ?? '-' },
    { lbl: 'Iframes', val: beh.iframe_count ?? '-' },
    { lbl: 'Anomalies', val: beh.anomaly_count ?? beh.anomalies?.length ?? '-' },
  ];
  html += `<div class="b-sum-grid">`;
  stats.forEach(s => {
    const numVal = parseInt(s.val);
    const cls = !isNaN(numVal) && numVal > 0 && (s.lbl === 'Anomalies') ? 'danger' : '';
    html += `<div class="stat-card"><div class="val ${cls}">${s.val}</div><div class="lbl">${s.lbl}</div></div>`;
  });
  html += `</div>`;

  // PCAP Link handling
  if (beh.pcap_path) {
    const pcapFile = beh.pcap_path.split('/').pop();
    html += `<div class="b-section" style="margin-top: 15px;">
        <button class="btn-ghost" onclick="downloadPCAP('${pcapFile}')" style="color: var(--accent-green); border-color: var(--accent-green);">⬇ Download Captured PCAP</button>
    </div>`;
  }

  // Screenshot
  if (beh.screenshot) {
    html += `<div class="b-section">
      <h4>Screenshot</h4>
      <div class="screenshot-wrap" onclick="viewScreenshot('${beh.screenshot}')">
        <img src="${beh.screenshot}" alt="Page screenshot">
      </div>
    </div>`;
  }

  // Anomalies
  if (beh.anomalies && beh.anomalies.length > 0) {
    html += `<div class="b-section"><h4>Behavioral Anomalies</h4>`;
    beh.anomalies.forEach(a => {
      const text = typeof a === 'string' ? a : (a.description || a.message || JSON.stringify(a));
      const sev = (a.severity || '').toLowerCase();
      html += `<div class="${sev === 'critical' || sev === 'high' ? 'anomaly-item crit' : 'anomaly-item'}">${escapeHTML(text)}</div>`;
    });
    html += `</div>`;
  }

  // Forms
  if (beh.forms && beh.forms.length > 0) {
    html += `<div class="b-section"><h4>Detected Forms</h4>`;
    beh.forms.forEach((form, i) => {
      const risk = (form.risk || form.danger_level || '').toLowerCase();
      const cls = risk === 'dangerous' ? 'form-card dangerous' : (risk === 'suspicious' ? 'form-card suspicious' : 'form-card');
      html += `<div class="${cls}">
        <div class="form-card-head">
          <span>Form ${i+1}: ${escapeHTML(form.action || form.url || 'unknown action')}</span>
          ${risk ? `<span class="badge ${risk === 'dangerous' ? 'badge-danger' : risk === 'suspicious' ? 'badge-warn' : 'badge-safe'}">${risk.toUpperCase()}</span>` : ''}
        </div>`;
      if (form.fields && form.fields.length) {
        html += `<div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted)">Fields: ${form.fields.map(f => escapeHTML(f.name || f.type || f)).join(', ')}</div>`;
      }
      html += `</div>`;
    });
    html += `</div>`;
  }

  // Network activity
  if (beh.network || beh.network_activity) {
    const net = beh.network || beh.network_activity;
    html += `<div class="b-section"><h4>Network Activity</h4>
      <div class="net-mini">
        <div class="net-stat"><div class="lbl">Requests</div><div class="val">${net.request_count || net.requests || '-'}</div></div>
        <div class="net-stat"><div class="lbl">External Domains</div><div class="val">${net.external_domains?.length || net.external_count || '-'}</div></div>
        <div class="net-stat"><div class="lbl">Data Sent</div><div class="val">${net.data_sent || '-'}</div></div>
      </div>`;
    if (net.external_domains && net.external_domains.length > 0) {
      html += `<div class="domains-scroll" style="margin-top:10px">`;
      net.external_domains.forEach(d => {
        html += `<div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-secondary)">${escapeHTML(d)}</div>`;
      });
      html += `</div>`;
    }
    html += `</div>`;
  }

  html += `</div>`;
  return html;
}

function buildTechnicalHTML(data) {
  const tech = data.technical_details || {};
  let html = `<div class="cyber-card"><div class="card-title">Technical Details</div>
    <div class="tech-grid">`;

  const rows = [
    { label: 'IP Address', val: tech.ip || data.ip },
    { label: 'Hosting / ASN', val: tech.asn || tech.hosting || data.asn },
    { label: 'Country', val: tech.country || data.country },
    { label: 'Domain Age', val: tech.domain_age || data.domain_age },
    { label: 'Registrar', val: tech.registrar || data.registrar },
    { label: 'SSL Valid', val: tech.ssl_valid !== undefined ? (tech.ssl_valid ? '✓ Valid' : '✗ Invalid') : null },
    { label: 'SSL Issuer', val: tech.ssl_issuer || (data.ssl_info?.issuer) },
    { label: 'SSL Expiry', val: tech.ssl_expiry || (data.ssl_info?.expiry) },
    { label: 'Redirects', val: tech.redirect_chain?.join(' → ') || null },
    { label: 'Server', val: tech.server_header || tech.server },
    { label: 'Technologies', val: tech.technologies?.join(', ') || null },
  ].filter(r => r.val != null && r.val !== '' && r.val !== undefined);

  if (rows.length > 0) {
    rows.forEach(r => {
      html += `<div class="tech-item">
        <div class="tech-label">${r.label}</div>
        <div class="tech-value">${escapeHTML(String(r.val))}</div>
      </div>`;
    });
  }

  html += `</div>`;

  if (data.whois) {
    html += `<div style="margin-top:16px">
      <div class="card-title" style="margin-bottom:8px">WHOIS Data</div>
      <pre class="whois-block">${escapeHTML(typeof data.whois === 'string' ? data.whois : JSON.stringify(data.whois, null, 2))}</pre>
    </div>`;
  }

  html += `</div>`;
  return html;
}

function buildExternalAPIHTML(data) {
  const apis = data.external_apis || {};
  const vt = data.virustotal || apis.virustotal;
  const us = data.urlscan || apis.urlscan;
  const gsb = data.safe_browsing || apis.safe_browsing;

  let html = `<div class="cyber-card"><div class="card-title">Threat Intelligence</div>
    <div class="api-grid">`;

  if (vt) {
    const positives = vt.positives ?? vt.malicious ?? 0;
    const total = vt.total ?? vt.engines ?? 0;
    html += `<div class="api-card">
      <div class="api-name">VirusTotal</div>
      <div class="api-status ${positives > 0 ? 'danger' : 'safe'}">${positives}/${total} engines flagged</div>
      ${vt.permalink ? `<a href="${escapeHTML(vt.permalink)}" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:0.7rem;color:var(--accent-cyan)">View full report →</a>` : ''}
    </div>`;
  }

  if (us) {
    const score = us.score ?? us.verdicts?.overall?.score ?? '-';
    const verdict = us.verdict || us.verdicts?.overall?.malicious ? 'MALICIOUS' : 'CLEAN';
    html += `<div class="api-card">
      <div class="api-name">URLScan.io</div>
      <div class="api-status ${String(verdict).toLowerCase().includes('malicious') ? 'danger' : 'safe'}">${verdict} (score: ${score})</div>
      ${us.result ? `<a href="${escapeHTML(us.result)}" target="_blank" rel="noopener" style="font-family:var(--font-mono);font-size:0.7rem;color:var(--accent-cyan)">View scan →</a>` : ''}
    </div>`;
  }

  if (gsb) {
    const threat = gsb.threat_type || gsb.found;
    html += `<div class="api-card">
      <div class="api-name">Google Safe Browsing</div>
      <div class="api-status ${threat ? 'danger' : 'safe'}">${threat ? '⚠ ' + escapeHTML(String(threat)) : '✓ No threats found'}</div>
    </div>`;
  }

  // Deep scan tasks mapping logic fix
  if (data.url_deep_scans && data.url_deep_scans.length > 0) {
    html += `<div class="deep-scan-container" style="grid-column:1/-1; margin-top: 15px;">
      <div class="card-title" style="margin-bottom:10px">Deep Scan Background Tasks</div>`;
    data.url_deep_scans.forEach((scan, i) => {
      html += `<div class="deep-scan-item" style="display:flex; justify-content:space-between; align-items: center; border-bottom: 1px solid rgba(0,212,255,0.1); padding: 8px 0;">
        <span style="color:var(--text-secondary); font-family:var(--font-mono); font-size:0.75rem;">${escapeHTML(scan.url)}</span>
        <button class="btn-ghost d-scan-btn" data-task="${scan.task_id}" style="padding:4px 8px; font-size:0.7rem;">Monitor Result</button>
      </div>`;
    });
    html += `</div>`;
  }

  html += `</div></div>`;
  return html;
}

function attachDeepScanListeners(scans) {
  if (!scans || !scans.length) return;
  document.querySelectorAll('.d-scan-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const taskId = e.target.getAttribute('data-task');
      showProgressModal('Deep Scanning URL...');
      updateProgress(10, 'Monitoring task...');
      
      try {
        await new Promise((resolve, reject) => {
          streamTaskProgress(taskId,
            (pct, msg) => updateProgress(10 + pct * 0.9, msg),
            result => { hideProgressModal(); displayAllResults(result, 'url'); resolve(); },
            err => reject(new Error(err))
          );
        });
      } catch (err) {
        hideProgressModal();
        showError('Deep scan failed: ' + err.message);
      }
    });
  });
}

function buildHoneypotHTML(honeypot) {
  const triggered = honeypot.triggered || honeypot.data_submitted || false;
  const data_fields = honeypot.submitted_data || honeypot.captured_data || {};

  let html = `<div class="cyber-card"><div class="card-title">Honeypot Analysis</div>`;

  html += `<div class="honeypot-alert ${triggered ? 'crit' : 'safe'}">
    <div class="icon">${triggered ? '🚨' : '✅'}</div>
    <div>
      <h5>${triggered ? 'DATA EXFILTRATION DETECTED' : 'NO DATA SUBMISSION DETECTED'}</h5>
      <p>${triggered ? 'The page attempted to submit honeypot credentials. This confirms active phishing behavior.' : 'No credentials or data were submitted to external endpoints during emulation.'}</p>
    </div>
  </div>`;

  if (triggered && Object.keys(data_fields).length > 0) {
    html += `<div class="card-title" style="margin:16px 0 8px">Captured Exfiltration Data</div>`;
    Object.entries(data_fields).forEach(([k, v]) => {
      html += `<div class="exfil-item crit">
        <div class="exfil-header">
          <span class="badge badge-danger">${escapeHTML(k)}</span>
        </div>
        <div class="exfil-url"><code>${escapeHTML(String(v))}</code></div>
      </div>`;
    });
  }

  if (honeypot.endpoints && honeypot.endpoints.length > 0) {
    html += `<div class="card-title" style="margin:16px 0 8px">Submission Endpoints</div>`;
    honeypot.endpoints.forEach(ep => {
      html += `<div class="exfil-item high">
        <div class="exfil-url"><code>${escapeHTML(typeof ep === 'string' ? ep : ep.url || JSON.stringify(ep))}</code></div>
      </div>`;
    });
  }

  html += `</div>`;
  return html;
}

function buildQRSection(qrCodes) {
  if (!qrCodes || !qrCodes.length) return '';
  let html = `<div class="cyber-card mt-4"><div class="card-title">Decoded QR Payloads</div>`;
  qrCodes.forEach((qr, i) => {
    const isPhish = (qr.verdict || '').toLowerCase().includes('phish') || (qr.verdict || '').toLowerCase().includes('malicious');
    html += `<div class="qr-code-card ${isPhish ? 'suspicious' : ''}">
      <div class="card-title" style="margin-bottom:6px">QR Code ${i+1}</div>
      <div class="qr-url-disp"><code>${escapeHTML(qr.url || qr.data || qr.content || 'unknown')}</code></div>
      ${qr.verdict ? `<div style="margin-top:8px">${verdictBadge(qr.verdict)}</div>` : ''}
    </div>`;
  });
  html += `</div>`;
  return html;
}

// ── File Handlers ──────────────────────────────────────────

function viewScreenshot(src) {
  const modal = document.createElement('div');
  modal.className = 'screenshot-modal';
  modal.innerHTML = `<img src="${src}" alt="Screenshot">`;
  modal.onclick = () => document.body.removeChild(modal);
  document.body.appendChild(modal);
}

// ── Downloads ─────────────────────────────────────────────────

async function downloadReport() {
  if (currentTaskId) {
    const btn = document.getElementById('exportReportBtn');
    const og = btn.textContent;
    btn.textContent = '⏳ Compiling PDF...';
    try {
      const res = await fetch(`${API_URL}/report/${currentTaskId}/download`);
      if (!res.ok) throw new Error('Generation failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `Forensic_Report_${currentTaskId}.pdf`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      showError('Failed to retrieve PDF report: ' + e.message);
      // Fallback
      if (lastResult) downloadJSON(lastResult, `phishnet-report-${currentTaskId}.json`);
    } finally {
      btn.textContent = og;
    }
  } else if (lastResult) {
    // Immediate tasks without a server-side report endpoint
    const ts = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
    downloadJSON(lastResult, `phishnet-report-${ts}.json`);
  }
}

function downloadPCAP(filename) {
    const url = `${API_URL}/pcap/${filename}`;
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// ── Escape HTML ──────────────────────────────────────────────

function escapeHTML(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}
