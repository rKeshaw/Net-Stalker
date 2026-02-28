/* ============================================================
   PHISH-NET — Shared Utilities
   ============================================================ */

const API_URL = '';  // Same origin — backend serves frontend

// ── UI helpers ──────────────────────────────────────────────

function showError(msg) {
  const el = document.getElementById('errorBanner');
  if (!el) return;
  el.textContent = msg;
  el.style.display = 'block';
  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function hideError() {
  const el = document.getElementById('errorBanner');
  if (el) { el.style.display = 'none'; el.textContent = ''; }
}

function resetUI() {
  hideError();
  ['resultsBlock','behavioralBlock','technicalBlock','externalBlock','honeypotBlock'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.classList.add('hidden'); el.innerHTML = ''; }
  });
}

function setButtonLoading(btnId, loading, defaultText = 'SCAN') {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  btn.disabled = loading;
  if (loading) {
    btn.dataset.originalText = btn.textContent;
    btn.innerHTML = '<span style="opacity:0.6">⟳ SCANNING...</span>';
  } else {
    btn.textContent = btn.dataset.originalText || defaultText;
  }
}

// ── Progress modal ───────────────────────────────────────────

function showProgressModal(title = 'Analyzing...') {
  document.getElementById('progressTitle').textContent = title;
  document.getElementById('progressFill').style.width = '0%';
  document.getElementById('progressLabel').textContent = '0%';
  document.getElementById('progressLog').innerHTML = '';
  document.getElementById('progressModal').classList.remove('hidden');
}

function hideProgressModal() {
  document.getElementById('progressModal').classList.add('hidden');
}

function updateProgress(pct, logMsg = '') {
  const fill = document.getElementById('progressFill');
  const label = document.getElementById('progressLabel');
  if (fill) fill.style.width = Math.min(pct, 100) + '%';
  if (label) label.textContent = Math.round(pct) + '%';
  if (logMsg) {
    const log = document.getElementById('progressLog');
    if (log) {
      const line = document.createElement('div');
      line.style.cssText = 'font-family:var(--font-mono);font-size:0.7rem;color:var(--text-secondary);padding:2px 0';
      line.textContent = '> ' + logMsg;
      log.appendChild(line);
      log.scrollTop = log.scrollHeight;
    }
  }
}

// ── Task polling ─────────────────────────────────────────────

async function pollTaskStatus(taskId, onProgress, onDone, onError) {
  const pollInterval = setInterval(async () => {
    try {
      const res = await fetch(`${API_URL}/api/task-status/${taskId}`);
      if (!res.ok) throw new Error('Status check failed');
      const data = await res.json();

      if (data.progress !== undefined) onProgress(data.progress, data.message || '');

      if (data.status === 'completed') {
        clearInterval(pollInterval);
        onDone(data.result || data);
      } else if (data.status === 'failed') {
        clearInterval(pollInterval);
        onError(data.error || 'Analysis failed');
      }
    } catch (err) {
      clearInterval(pollInterval);
      onError(err.message);
    }
  }, 1200);
}

async function streamTaskProgress(taskId, onProgress, onDone, onError) {
  try {
    const res = await fetch(`${API_URL}/api/task-stream/${taskId}`);
    if (!res.ok) {
      // Fall back to polling
      pollTaskStatus(taskId, onProgress, onDone, onError);
      return;
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    const pump = async () => {
      const { done, value } = await reader.read();
      if (done) return;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.startsWith('data:')) continue;
        try {
          const evt = JSON.parse(line.slice(5).trim());
          if (evt.progress !== undefined) onProgress(evt.progress, evt.message || '');
          if (evt.status === 'completed') { onDone(evt.result || evt); return; }
          if (evt.status === 'failed') { onError(evt.error || 'Failed'); return; }
        } catch { /* skip malformed */ }
      }
      pump();
    };
    pump();
  } catch {
    pollTaskStatus(taskId, onProgress, onDone, onError);
  }
}

// ── Generic POST helper ──────────────────────────────────────

async function apiPost(endpoint, body, isFormData = false) {
  const opts = { method: 'POST' };
  if (isFormData) {
    opts.body = body;
  } else {
    opts.headers = { 'Content-Type': 'application/json' };
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(API_URL + endpoint, opts);
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { const d = await res.json(); msg = d.error || d.message || msg; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

// ── Verdict badge helper ─────────────────────────────────────

function verdictBadge(verdict) {
  const v = (verdict || '').toLowerCase();
  if (v.includes('phishing') || v.includes('malicious')) return `<span class="verdict-badge phishing">${verdict}</span>`;
  if (v.includes('suspicious')) return `<span class="verdict-badge suspicious">${verdict}</span>`;
  if (v.includes('safe') || v.includes('clean') || v.includes('legitimate')) return `<span class="verdict-badge safe">${verdict}</span>`;
  return `<span class="verdict-badge unknown">${verdict || 'UNKNOWN'}</span>`;
}

function riskColor(score) {
  if (score >= 70) return 'var(--accent-red)';
  if (score >= 40) return 'var(--accent-yellow)';
  return 'var(--accent-green)';
}

// ── Download helper ──────────────────────────────────────────

function downloadJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ── Collapsible sections ─────────────────────────────────────

function makeCollapsible(headerEl, contentEl) {
  headerEl.style.cursor = 'pointer';
  headerEl.addEventListener('click', () => {
    const isOpen = contentEl.style.display !== 'none';
    contentEl.style.display = isOpen ? 'none' : 'block';
  });
}
