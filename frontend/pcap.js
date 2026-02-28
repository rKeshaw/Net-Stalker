/* ============================================================
   PHISH-NET — PCAP Analysis Module
   ============================================================ */

let currentPcapFile = null;
let lastPcapResult = null;

const ECHARTS_THEME = {
  backgroundColor: 'transparent',
  textStyle: { color: '#5a7090', fontFamily: 'Share Tech Mono, monospace', fontSize: 11 },
  color: ['#00d4ff','#00ff88','#8b5cf6','#ff6a00','#ffd700','#ff2244','#00b4d8','#90e0ef'],
};

// ── File handling ────────────────────────────────────────────

function handlePcapFile(event) {
  const file = event.target.files[0];
  if (file) loadPcapFile(file);
}

function loadPcapFile(file) {
  currentPcapFile = file;
  const badge = document.getElementById('fileBadge');
  if (badge) {
    badge.innerHTML = `<span>📦 ${escapeHTML(file.name)}</span>
      <span style="color:var(--text-muted)">(${formatBytes(file.size)})</span>
      <button onclick="clearPcap()" title="Remove file">✕</button>`;
    badge.classList.remove('hidden');
  }
  document.getElementById('clearPcapBtn').style.display = 'inline-flex';
  document.getElementById('pcapResults').classList.add('hidden');
  hideError();
}

function clearPcap() {
  currentPcapFile = null;
  lastPcapResult = null;
  const badge = document.getElementById('fileBadge');
  if (badge) { badge.classList.add('hidden'); badge.innerHTML = ''; }
  document.getElementById('clearPcapBtn').style.display = 'none';
  document.getElementById('pcapFileInput').value = '';
  document.getElementById('pcapResults').classList.add('hidden');
  hideError();
}

// ── Analysis ─────────────────────────────────────────────────

async function analyzePcap() {
  if (!currentPcapFile) { showError('Please upload a PCAP file first.'); return; }

  hideError();
  setButtonLoading('analyzePcapBtn', true, 'ANALYZE PCAP');
  showProgressModal('Parsing packets...');
  updateProgress(5, 'Loading PCAP file...');

  try {
    const formData = new FormData();
    formData.append('file', currentPcapFile);

    const data = await apiPost('/analyze/pcap', formData, true);

    if (data.task_id) {
      updateProgress(15, 'Processing packets in background...');
      await new Promise((resolve, reject) => {
        streamTaskProgress(data.task_id,
          (pct, msg) => updateProgress(15 + pct * 0.8, msg),
          result => { renderPcapResults(result); resolve(); },
          err => reject(new Error(err))
        );
      });
    } else {
      updateProgress(100, 'Analysis complete.');
      renderPcapResults(data);
    }
  } catch (err) {
    showError('PCAP analysis failed: ' + err.message);
  } finally {
    setButtonLoading('analyzePcapBtn', false, 'ANALYZE PCAP');
    hideProgressModal();
  }
}

// ── Render results ───────────────────────────────────────────

function normalizePcapResult(data) {
  const stats = data.statistics || {};
  const flow = data.flow_analysis || {};

  return {
    ...data,
    protocols: data.protocols || stats.protocol_distribution || {},
    packet_lengths: data.packet_lengths || stats.packet_lengths || {},
    time_flow: data.time_flow || flow.time_flow || {},
    dns_queries: data.dns_queries || stats.dns_stats || [],
    http_requests: data.http_requests || stats.http_stats || [],
    geo_ips: data.geo_ips || (data.geo_map && data.geo_map.ip_data) || [],
    total_packets: data.total_packets || (data.metadata && data.metadata.packet_count) || stats.packet_count,
    duration: data.duration || (data.metadata && data.metadata.duration) || stats.duration_seconds,
    unique_ips: data.unique_ips || (data.geo_map && data.geo_map.ip_data ? data.geo_map.ip_data.length : null),
  };
}

function renderPcapResults(data) {
  const normalized = normalizePcapResult(data);
  lastPcapResult = normalized;
  const container = document.getElementById('pcapResults');
  container.classList.remove('hidden');

  renderThreatHeader(normalized);
  renderAISection(normalized);
  renderStatsSection(normalized);
  renderCharts(normalized);
  renderConnections(normalized);
  renderDNS(normalized);
  renderHTTP(normalized);
  renderGeoSection(normalized);
  renderThreats(normalized);

  container.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderThreatHeader(data) {
  const el = document.getElementById('pcapThreatHeader');
  if (!el) return;
  const verdict = (data.verdict || data.threat_level || 'unknown').toLowerCase();
  const cls = verdict.includes('malicious') || verdict.includes('high') ? 'malicious' :
              verdict.includes('suspicious') || verdict.includes('medium') ? 'suspicious' : 'clean';
  const score = data.risk_score ?? data.threat_score ?? null;
  el.innerHTML = `<div class="pcap-threat-header ${cls}">
    <div style="flex:1">
      <div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:4px">PCAP Threat Assessment</div>
      <div style="font-family:var(--font-display);font-size:1.1rem;letter-spacing:3px;color:${cls==='malicious'?'var(--accent-red)':cls==='suspicious'?'var(--accent-yellow)':'var(--accent-green)'}">${(data.verdict||data.threat_level||'CLEAN').toUpperCase()}</div>
    </div>
    ${score !== null ? `<div style="text-align:right">
      <div style="font-family:var(--font-display);font-size:2.5rem;color:${riskColor(score)};line-height:1">${score}</div>
      <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);letter-spacing:1px">RISK SCORE</div>
    </div>` : ''}
  </div>`;
}

function renderAISection(data) {
  const sec = document.getElementById('pcapAiSection');
  const txt = document.getElementById('pcapAiText');
  if (!sec || !txt) return;
  const analysis = data.ai_analysis || data.summary || data.analysis;
  if (!analysis) { sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  txt.innerHTML = `<p>${escapeHTML(String(analysis))}</p>`;
}

function renderStatsSection(data) {
  const sec = document.getElementById('pcapStatsSection');
  const grid = document.getElementById('pcapStatsGrid');
  if (!sec || !grid) return;
  const stats = data.stats || data.statistics || data.capture_info || {};
  if (!Object.keys(stats).length && !data.total_packets) { sec.classList.add('hidden'); return; }

  const items = [
    { label: 'Total Packets', val: data.total_packets || stats.total_packets || stats.packets },
    { label: 'Total Bytes', val: formatBytes(data.total_bytes || stats.total_bytes || stats.bytes) },
    { label: 'Duration', val: stats.duration || data.duration },
    { label: 'Start Time', val: stats.start_time || data.start_time },
    { label: 'Unique IPs', val: stats.unique_ips || data.unique_ips },
    { label: 'Protocols', val: stats.protocol_count || (data.protocols ? Object.keys(data.protocols).length : null) },
    { label: 'TCP Streams', val: stats.tcp_streams || data.tcp_streams },
    { label: 'UDP Flows', val: stats.udp_flows || data.udp_flows },
  ].filter(i => i.val != null && i.val !== '');

  if (!items.length) { sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  grid.innerHTML = items.map(i => `
    <div class="stat-card">
      <div class="val">${escapeHTML(String(i.val))}</div>
      <div class="lbl">${i.label}</div>
    </div>`).join('');
}

function renderCharts(data) {
  const sec = document.getElementById('chartsSection');
  const protocols = data.protocols || data.protocol_distribution || {};
  const packetLens = data.packet_lengths || data.packet_size_distribution || {};

  if (!Object.keys(protocols).length && !Object.keys(packetLens).length) {
    sec.style.display = 'none'; return;
  }
  sec.style.display = 'grid';

  // Protocol Pie Chart
  if (Object.keys(protocols).length > 0) {
    const chart = echarts.init(document.getElementById('protocolChart'), null, { renderer: 'canvas' });
    chart.setOption({
      ...ECHARTS_THEME,
      tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
      legend: { orient: 'vertical', right: '5%', top: 'center', textStyle: { color: '#5a7090', fontSize: 10 } },
      series: [{
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['40%', '50%'],
        data: Object.entries(protocols).map(([name, value]) => ({ name, value })),
        label: { show: false },
        emphasis: { itemStyle: { shadowBlur: 10, shadowColor: 'rgba(0,212,255,0.3)' } },
        itemStyle: { borderColor: '#060612', borderWidth: 2 },
      }]
    });
    window.addEventListener('resize', () => chart.resize());
  }

  // Packet length bar chart
  if (Object.keys(packetLens).length > 0) {
    const chart = echarts.init(document.getElementById('packetLenChart'), null, { renderer: 'canvas' });
    const keys = Object.keys(packetLens);
    const vals = Object.values(packetLens);
    chart.setOption({
      ...ECHARTS_THEME,
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
      grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
      xAxis: { type: 'category', data: keys, axisLine: { lineStyle: { color: '#2a3a50' } }, axisLabel: { color: '#5a7090', fontSize: 9 } },
      yAxis: { type: 'value', axisLine: { lineStyle: { color: '#2a3a50' } }, axisLabel: { color: '#5a7090', fontSize: 9 }, splitLine: { lineStyle: { color: '#0b0b1e' } } },
      series: [{ type: 'bar', data: vals, itemStyle: { color: '#00d4ff', borderRadius: [3,3,0,0] }, emphasis: { itemStyle: { color: '#00ff88' } } }]
    });
    window.addEventListener('resize', () => chart.resize());
  }

  // Time flow
  const timeFlow = data.time_flow || data.packets_per_second || data.traffic_timeline;
  const tfSec = document.getElementById('timeFlowSection');
  if (timeFlow && Object.keys(timeFlow).length > 0 && tfSec) {
    tfSec.classList.remove('hidden');
    const chart = echarts.init(document.getElementById('timeFlowChart'), null, { renderer: 'canvas' });
    const tfKeys = Object.keys(timeFlow);
    const tfVals = Object.values(timeFlow);
    chart.setOption({
      ...ECHARTS_THEME,
      tooltip: { trigger: 'axis' },
      grid: { left: '3%', right: '4%', bottom: '3%', top: '10%', containLabel: true },
      xAxis: { type: 'category', data: tfKeys, axisLabel: { color: '#5a7090', fontSize: 9 }, axisLine: { lineStyle: { color: '#2a3a50' } } },
      yAxis: { type: 'value', axisLabel: { color: '#5a7090', fontSize: 9 }, axisLine: { lineStyle: { color: '#2a3a50' } }, splitLine: { lineStyle: { color: '#0b0b1e' } } },
      series: [{
        type: 'line', data: tfVals, smooth: true,
        lineStyle: { color: '#00ff88', width: 2 },
        areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: 'rgba(0,255,136,0.3)' }, { offset: 1, color: 'rgba(0,255,136,0)' }] } },
        symbol: 'none',
      }]
    });
    window.addEventListener('resize', () => chart.resize());
  }
}

function renderConnections(data) {
  const sec = document.getElementById('connectionsSection');
  const tbody = document.getElementById('connectionsBody');
  if (!sec || !tbody) return;
  const conns = data.connections || data.top_connections || [];
  if (!conns.length) { sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  tbody.innerHTML = conns.slice(0, 30).map((c, i) => {
    const threat = (c.threat || c.flags || '').toLowerCase();
    const rowCls = threat.includes('malicious') ? 'malicious-row' : threat.includes('suspicious') ? 'suspicious-row' : '';
    return `<tr class="${rowCls}">
      <td>${i+1}</td>
      <td><code>${escapeHTML(c.src || c.source || '-')}</code></td>
      <td><code>${escapeHTML(c.dst || c.destination || '-')}</code></td>
      <td>${escapeHTML(c.protocol || c.proto || '-')}</td>
      <td>${c.packets || c.packet_count || '-'}</td>
      <td>${formatBytes(c.bytes || c.byte_count)}</td>
      <td>${c.flags || c.threat || ''}</td>
    </tr>`;
  }).join('');
}

function renderDNS(data) {
  const sec = document.getElementById('dnsSection');
  const content = document.getElementById('dnsContent');
  if (!sec || !content) return;
  const queries = data.dns_queries || data.dns || [];
  if (!queries.length) { sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  content.innerHTML = `<div class="domains-scroll">` +
    queries.slice(0, 40).map(q => {
      const domain = typeof q === 'string' ? q : (q.query || q.domain || q.name || JSON.stringify(q));
      const type = q.type || '';
      const suspicious = q.suspicious || false;
      return `<div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid rgba(0,212,255,0.05)">
        <code style="font-family:var(--font-mono);font-size:0.73rem;color:${suspicious?'var(--accent-red)':'var(--accent-cyan)'}">${escapeHTML(domain)}</code>
        ${type ? `<span class="badge badge-neutral">${escapeHTML(type)}</span>` : ''}
      </div>`;
    }).join('') + `</div>`;
}

function renderHTTP(data) {
  const sec = document.getElementById('httpSection');
  const content = document.getElementById('httpContent');
  if (!sec || !content) return;
  const reqs = data.http_requests || data.http || [];
  if (!reqs.length) { sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  content.innerHTML = reqs.slice(0, 20).map(r => {
    const method = r.method || 'GET';
    const url = r.url || r.host || '';
    const status = r.status || r.response_code || '';
    const suspicious = r.suspicious || false;
    return `<div style="padding:8px 10px;background:var(--bg-input);border-radius:var(--radius-sm);margin-bottom:6px;border-left:3px solid ${suspicious?'var(--accent-red)':'var(--border-dim)'}">
      <span class="badge ${method==='POST'?'badge-warn':'badge-neutral'}" style="margin-right:8px">${escapeHTML(method)}</span>
      <code style="font-family:var(--font-mono);font-size:0.73rem;color:var(--accent-cyan)">${escapeHTML(url)}</code>
      ${status ? `<span style="float:right;font-family:var(--font-mono);font-size:0.7rem;color:${parseInt(status)>=400?'var(--accent-red)':'var(--text-muted)'}">${status}</span>` : ''}
    </div>`;
  }).join('');
}

function renderGeoSection(data) {
  const sec = document.getElementById('geoSection');
  const list = document.getElementById('geoIpList');
  if (!sec || !list) return;
  const geos = data.geo_ips || data.geolocation || data.external_ips || [];
  if (!geos.length) { sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  list.innerHTML = geos.map(g => {
    const ip = typeof g === 'string' ? g : (g.ip || '-');
    const loc = g.country || g.city ? `${g.city||''}${g.city&&g.country?', ':''}${g.country||''}` : (g.location || '');
    const org = g.org || g.asn || '';
    return `<div class="geo-ip-item">
      <span class="ip">${escapeHTML(ip)}</span>
      <span class="loc">${escapeHTML(loc)} ${org ? '· '+escapeHTML(org) : ''}</span>
    </div>`;
  }).join('');
}

function renderThreats(data) {
  const sec = document.getElementById('threatsSection');
  const list = document.getElementById('threatsList');
  if (!sec || !list) return;
  const threats = data.threats || data.threat_indicators || data.alerts || [];
  if (!threats.length) { sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  list.innerHTML = threats.map(t => {
    const text = typeof t === 'string' ? t : (t.description || t.message || t.name || JSON.stringify(t));
    const sev = (t.severity || t.level || '').toLowerCase();
    return `<div class="${sev==='critical'||sev==='high'?'anomaly-item crit':'anomaly-item'}">${escapeHTML(text)}</div>`;
  }).join('');
}

// ── Geo collapse toggle ──────────────────────────────────────

function toggleGeoCollapse() {
  const content = document.getElementById('geoCollapseContent');
  const icon = document.getElementById('geoToggleIcon');
  if (!content) return;
  const collapsed = content.classList.contains('collapsed');
  content.classList.toggle('collapsed', !collapsed);
  if (icon) icon.textContent = collapsed ? '▴' : '▾';
}

// ── Download ─────────────────────────────────────────────────

function downloadPcapReport() {
  if (!lastPcapResult) return;
  const ts = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  downloadJSON(lastPcapResult, `phishnet-pcap-${ts}.json`);
}

// ── Helpers ──────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes == null || bytes === '') return '-';
  const n = parseInt(bytes);
  if (isNaN(n)) return String(bytes);
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
  return (n/1073741824).toFixed(2) + ' GB';
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function hideError() {
  const el = document.getElementById('errorBanner');
  if (el) { el.style.display = 'none'; el.textContent = ''; }
}
