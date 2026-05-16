let liveEnabled = true;
let telemetryTimer = null;

let cbomPage = 0;
let cbomPageSize = 20;
let cbomCache = { events: [], suggestions: [] };
let cbomGrouped = true;

// Load Chart.js from local file
// Load Chart.js from local file
const loadChartJS = () => {
  return new Promise((resolve, reject) => {
    if (typeof Chart !== 'undefined') {
      console.log('Chart.js already loaded');
      return resolve();
    }

    if (document.querySelector('script[src*="chart.min.js"]')) {
      console.log('Chart.js script tag found, waiting...');
      // Simple wait if it's loading
      setTimeout(() => {
        if (typeof Chart !== 'undefined') resolve();
        else reject(new Error('Chart.js tag found but Chart is undefined'));
      }, 1000);
      return;
    }

    console.log('Loading Chart.js from /static/js/chart.min.js');
    const script = document.createElement('script');
    script.src = '/static/js/chart.min.js';
    script.onload = () => {
      console.log('Chart.js loaded successfully');
      resolve();
    };
    script.onerror = (err) => {
      console.error('Failed to load Chart.js', err);
      reject(new Error('Failed to load Chart.js'));
    };
    document.head.appendChild(script);
  });
};

// Store chart instances
const siemCharts = {};

async function refreshSiemPanel() {
  const container = document.querySelector('[data-panel="security"]');
  if (!container) return;

  // Show loading state ONLY if we don't have charts yet
  // FIXED: Do not overwrite innerHTML here because it destroys the <canvas> elements defined in index.html
  // If we want a loader, we should overlay it, not replace content. For now, skipping visual loader to ensure canvas exists.

  try {
    // Ensure Chart.js is loaded
    await loadChartJS();

    const minsEl = document.getElementById('siem-window-mins');
    const totalEl = document.getElementById('siem-total');
    const critEl = document.getElementById('siem-critical');
    const harvEl = document.getElementById('siem-harvestable');

    // Set time window for SIEM events (in minutes)
    const windowMins = 60;
    if (minsEl) minsEl.textContent = String(windowMins);

    const since = new Date(Date.now() - windowMins * 60 * 1000).toISOString();
    console.log('Fetching SIEM events since', since);
    const data = await fetchDashboardJson(`/api/siem/events?limit=1000&since=${encodeURIComponent(since)}`);
    console.log('SIEM Data:', data);
    const events = Array.isArray(data.events) ? data.events : [];

    // Update summary metrics
    if (totalEl) totalEl.textContent = events.length;

    const criticalCount = events.filter(e => e.severity === 'critical').length;
    const harvestableCount = events.filter(e => e.harvestable).length;

    if (critEl) critEl.textContent = criticalCount;
    if (harvEl) harvEl.textContent = harvestableCount;

    // Process data for charts
    const cryptoCounts = {};
    const severityCounts = {};
    let pqcCount = 0;
    let classicalCount = 0;

    if (events.length === 0) {
      console.warn('No SIEM events found, showing placeholders');
      // Show placeholders if no data
      updatePieChart('crypto-pie-chart', 'Crypto Algorithms', { 'No Data': 1 });
      updatePieChart('severity-pie-chart', 'Event Severity', { 'No Data': 1 });
      updatePieChart('pqc-pie-chart', 'PQC Readiness', { 'No Data': 1 });
      return;
    }

    events.forEach(event => {
      // Count crypto algorithms
      const algo = event.crypto_algorithm || 'Unknown';
      cryptoCounts[algo] = (cryptoCounts[algo] || 0) + 1;

      // Count severities
      const severity = event.severity || 'info';
      severityCounts[severity] = (severityCounts[severity] || 0) + 1;

      // Count PQC vs Classical
      if (event.pqc_ready === true) {
        pqcCount++;
      } else if (event.pqc_ready === false) {
        classicalCount++;
      }
    });

    console.log('Updating charts with:', { cryptoCounts, severityCounts, pqcCount, classicalCount });

    // Create or update charts
    updatePieChart('crypto-pie-chart', 'Crypto Algorithms', cryptoCounts);
    updatePieChart('severity-pie-chart', 'Event Severity', severityCounts);
    updatePieChart('pqc-pie-chart', 'PQC Readiness', {
      'PQC-Ready': pqcCount,
      'Classical': classicalCount
    });

  } catch (err) {
    console.error('SIEM refresh failed:', err);
    container.innerHTML = `
      <div class="card">
        <div class="card-header">
          <h3>Error Loading SIEM Data</h3>
        </div>
        <p style="padding: 1rem;">Failed to load SIEM data: ${err.message}</p>
      </div>`;
  }
}

function updatePieChart(canvasId, title, data) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  const labels = Object.keys(data);
  const values = Object.values(data);

  // Generate distinct colors
  const backgroundColors = labels.map((_, i) => {
    const hue = (i * 137.508) % 360; // Golden angle for distinct colors
    return `hsl(${hue}, 70%, 60%)`;
  });

  // Special colors for severity chart
  if (canvasId === 'severity-pie-chart') {
    labels.forEach((label, i) => {
      if (label.toLowerCase() === 'critical') backgroundColors[i] = '#ff4d4f';
      if (label.toLowerCase() === 'warning') backgroundColors[i] = '#faad14';
      if (label.toLowerCase() === 'info') backgroundColors[i] = '#1890ff';
    });
  }

  // Special colors for PQC chart
  if (canvasId === 'pqc-pie-chart') {
    backgroundColors[0] = '#52c41a'; // Green for PQC
    backgroundColors[1] = '#fa8c16'; // Orange for Classical
  }

  const chartData = {
    labels: labels,
    datasets: [{
      data: values,
      backgroundColor: backgroundColors,
      borderWidth: 1,
      borderColor: 'rgba(255, 255, 255, 0.1)'
    }]
  };

  const config = {
    type: 'doughnut',
    data: chartData,
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#e2e8f0',
            font: {
              size: 12
            }
          }
        },
        title: {
          display: true,
          text: title,
          color: '#e2e8f0',
          font: {
            size: 14,
            weight: '600'
          },
          padding: {
            bottom: 10
          }
        },
        tooltip: {
          callbacks: {
            label: function (context) {
              const label = context.label || '';
              const value = context.raw || 0;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = Math.round((value / total) * 100);
              return `${label}: ${value} (${percentage}%)`;
            }
          },
          titleColor: '#e2e8f0',
          bodyColor: '#e2e8f0',
          backgroundColor: 'rgba(15, 23, 42, 0.95)',
          borderColor: 'rgba(148, 163, 184, 0.2)',
          borderWidth: 1
        }
      },
      cutout: '65%',
      radius: '90%'
    }
  };

  // Destroy existing chart if it exists
  if (siemCharts[canvasId]) {
    siemCharts[canvasId].destroy();
  }

  // Create new chart
  // ctx is the canvas element itself (from index.html)
  siemCharts[canvasId] = new Chart(ctx, config);
}

// Initialize charts when tab is shown
document.addEventListener('DOMContentLoaded', () => {
  // ... existing code ...

  // Add tab change handler for SIEM panel
  document.querySelectorAll('[data-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      const tabName = tab.getAttribute('data-tab');
      if (tabName === 'security') {
        // Small delay to ensure the tab is visible before rendering charts
        setTimeout(refreshSiemPanel, 100);
      }
    });
  });

  // Initial load if on SIEM tab
  if (document.querySelector('[data-tab="security"].active')) {
    setTimeout(refreshSiemPanel, 500);
  }
});

function renderCbomComponentsSummary(expected, seen) {
  const el = document.getElementById('cbom-components');
  if (!el) return;
  const exp = Array.isArray(expected) ? expected : [];
  const seenSet = new Set((Array.isArray(seen) ? seen : []).map(x => String(x || '').toLowerCase()));
  if (!exp.length) {
    el.innerHTML = '<span class="muted">No component metadata.</span>';
    return;
  }
  el.innerHTML = '';
  exp.forEach(c => {
    const name = String(c);
    const ok = seenSet.has(String(c).toLowerCase());
    const span = document.createElement('span');
    span.className = 'pill';
    span.textContent = ok ? `${name}: seen` : `${name}: missing`;
    el.appendChild(span);
  });
}
function renderCbomComponentDetails(events, expectedComponents) {
  const tbody = document.getElementById('cbom-component-details-body');
  if (!tbody) return;

  const validEvents = (events && events.length) ? events : [];
  const expected = (Array.isArray(expectedComponents) ? expectedComponents : []);

  if (!validEvents.length && !expected.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">No data available.</td></tr>';
    return;
  }

  const rows = new Map();

  function _normText(v) {
    const s = String(v == null ? '' : v).trim();
    return s || '—';
  }

  function _normProto(v) {
    const s = _normText(v);
    return s === '—' ? s : s.toUpperCase();
  }

  function _addToSet(set, value) {
    const v = _normText(value);
    if (!v || v === '—') return;
    set.add(v);
  }

  function _renderSet(set) {
    if (!set || set.size === 0) return '—';
    if (set.size === 1) return Array.from(set)[0];
    return 'Multiple';
  }

  function _renderList(set) {
    if (!set || set.size === 0) return '—';
    const vals = Array.from(set).map(v => String(v)).filter(Boolean).sort((a, b) => a.localeCompare(b));
    if (vals.length === 0) return '—';
    if (vals.length === 1) return vals[0];
    return `[${vals.join(', ')}]`;
  }

  function _algoFamily(algoText) {
    const s = String(algoText || '').trim().toLowerCase();
    if (!s || s === '—') return '—';
    if (s.includes('kyber')) return 'Kyber';
    if (s.includes('rsa')) return 'RSA';
    if (s.includes('tls')) return 'TLS';
    if (s.includes('none')) return 'None (Plaintext)';
    return String(algoText);
  }

  validEvents.forEach(e => {
    const crypto = e.crypto || {};
    const algoRaw = _normText(crypto.crypto_algorithm || e.crypto_algorithm);
    const algo = _algoFamily(algoRaw);
    const lib = _normText(crypto.library_tool || e.library_tool);
    const keyLen = _normText(crypto.key_length || e.key_length);
    const cert = _normText(crypto.cert_type || e.cert_type);
    const proto = _normProto(e.communication_protocol || '—');

    const pqcSupport = (crypto.pqc_support != null) ? crypto.pqc_support : e.pqc_support;
    const quantumReady = (crypto.quantum_ready != null) ? crypto.quantum_ready : e.quantum_ready;
    const algLower = String(algo).toLowerCase();
    const inferredPqc = (
      algLower.includes('kyber') ||
      algLower.includes('dilithium') ||
      algLower.includes('sphincs') ||
      algLower.includes('falcon') ||
      algLower.includes('mceliece')
    );
    const isPqc = (pqcSupport === true || quantumReady === true || inferredPqc);

    const comps = [e.source_component, e.destination_component];
    comps.forEach(c => {
      if (!c || c === 'unknown') return;

      let baseComp = String(c);
      const isNode = baseComp.startsWith('client-');
      if (isNode) baseComp = 'client';

      // Keep the inventory concise: these components should only show Kyber and RSA rows.
      if (baseComp === 'backend' || baseComp === 'client' || baseComp === 'proxy') {
        if (algo !== 'Kyber' && algo !== 'RSA') {
          return;
        }
      }

      // DB is modeled as plaintext SQL in this project (no TLS metadata at this layer).
      if (baseComp === 'db') {
        if (algo === '—') {
          return;
        }
      }

      const rowKey = `${baseComp}|${algo}`;

      if (!rows.has(rowKey)) {
        rows.set(rowKey, {
          component: baseComp,
          algo: algo,
          nodes: isNode ? new Set([String(c)]) : null,
          libs: new Set(),
          keyLens: new Set(),
          certs: new Set(),
          protos: new Set(),
          isPqc: false,
          found: true,
        });
      }

      const row = rows.get(rowKey);
      if (isNode) {
        if (!row.nodes) row.nodes = new Set();
        row.nodes.add(String(c));
      }

      _addToSet(row.libs, lib);
      _addToSet(row.keyLens, keyLen);
      _addToSet(row.certs, cert);
      _addToSet(row.protos, proto);
      row.isPqc = row.isPqc || isPqc;
    });
  });

  // Ensure all expected components are present
  expected.forEach(c => {
    if (!c) return;
    // For backend/client/proxy: always show 2 rows (Kyber + RSA)
    if (c === 'backend' || c === 'client' || c === 'proxy') {
      ['Kyber', 'RSA'].forEach(a => {
        const k = `${c}|${a}`;
        if (!rows.has(k)) {
          const libs = new Set();
          const keyLens = new Set();
          const certs = new Set();
          const protos = new Set();

          // Provide sensible defaults so placeholder rows are informative.
          // These are used when the current time window didn't capture any events for that component+algo.
          if (c === 'backend' && a === 'Kyber') {
            libs.add('kyber-py');
            keyLens.add('1024');
            certs.add('None');
            protos.add('HTTP');
          }
          if (c === 'backend' && a === 'RSA') {
            libs.add('pycryptodome');
            keyLens.add('2048');
            certs.add('X.509');
            protos.add('HTTP');
          }

          rows.set(k, {
            component: c,
            algo: a,
            nodes: null,
            libs,
            keyLens,
            certs,
            protos,
            isPqc: (a === 'Kyber'),
            found: false,
          });
        }
      });
      return;
    }

    // For db: show one row with the intended plaintext SQL metadata if missing.
    if (c === 'db') {
      const k = 'db|None (Plaintext)';
      if (!rows.has(k)) {
        const libs = new Set();
        libs.add('SQLAlchemy');
        const certs = new Set();
        certs.add('None');
        const protos = new Set();
        protos.add('SQL');
        rows.set(k, {
          component: 'db',
          algo: 'None (Plaintext)',
          nodes: null,
          libs,
          keyLens: new Set(),
          certs,
          protos,
          isPqc: false,
          found: false,
        });
      }
      return;
    }
  });

  if (rows.size === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">No component details found.</td></tr>';
    return;
  }

  tbody.innerHTML = '';
  const sortedRows = Array.from(rows.values()).sort((a, b) => {
    const c = a.component.localeCompare(b.component);
    if (c !== 0) return c;
    return String(a.algo || '').localeCompare(String(b.algo || ''));
  });

  sortedRows.forEach(r => {
    const tr = document.createElement('tr');
    let displayComp = r.component;
    if (r.nodes && r.nodes.size > 1) {
      displayComp = `${r.component} (${r.nodes.size} nodes)`;
    }
    const libText = _renderSet(r.libs);
    const keyLenText = _renderSet(r.keyLens);
    const certText = _renderSet(r.certs);
    const protoText = _renderList(r.protos);
    let pqcText = '—';
    if (r.found) {
      pqcText = r.isPqc ? 'Yes' : 'No';
    } else {
      const a = String(r.algo || '').toLowerCase();
      if (a === 'kyber') pqcText = 'Yes';
      else if (a === 'rsa' || a === 'tls' || a.includes('none')) pqcText = 'No';
    }
    tr.innerHTML = `
        <td>${displayComp}</td>
        <td>${r.algo || '—'}</td>
        <td>${libText}</td>
        <td>${keyLenText}</td>
        <td>${certText}</td>
        <td>${protoText}</td>
        <td>${pqcText}</td>
      `;
    tbody.appendChild(tr);
  });
}

async function downloadProxyPcap(e) {
  e.preventDefault();
  try {
    const resp = await fetch('/api/proxy/pcap/download', { credentials: 'same-origin' });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.error || `API error ${resp.status}`);
    }
    const blob = await resp.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'proxy_capture.pcap';
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    const metaEl = document.getElementById('pcap-download-meta');
    if (metaEl) metaEl.textContent = `Download failed: ${err.message}`;
  }
}

async function refreshCbomPanel() {
  const tbody = document.getElementById('cbom-events-body');
  const pageEl = document.getElementById('cbom-page');
  if (!tbody) return;

  tbody.innerHTML = '<tr><td colspan="14" class="muted">Loading...</td></tr>';

  try {
    const eventsPath = '/api/cboom/events/grouped?limit=2000&minutes=180';
    const [eventsData, suggData] = await Promise.all([
      fetchDashboardJson(eventsPath),
      fetchDashboardJson('/api/cboom/action-suggestions?minutes=180'),
    ]);

    cbomCache.events = Array.isArray(eventsData.events) ? eventsData.events : [];
    cbomCache.suggestions = Array.isArray(suggData.suggestions) ? suggData.suggestions : [];
    renderCbomComponentsSummary(eventsData.components_expected, eventsData.components_seen);
    renderCbomComponentDetails(cbomCache.events, eventsData.components_expected);
    cbomPage = 0;
    renderCbomPage();
    if (pageEl) pageEl.textContent = `Page ${cbomPage + 1}`;
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="14" class="muted">CBOM load failed: ${err.message}</td></tr>`;
  }
}

function _computeCbomPageSize() {
  const main = document.querySelector('.main');
  const header = document.querySelector('[data-panel="logs"] .panel-header');
  const tableHead = document.querySelector('#cbom-events-body')?.closest('table')?.querySelector('thead');
  const mainH = main ? main.clientHeight : window.innerHeight;
  const headerH = header ? header.clientHeight : 80;
  const theadH = tableHead ? tableHead.clientHeight : 44;
  const rowH = 44;
  const budget = Math.max(6, Math.floor((mainH - headerH - theadH - 60) / rowH));
  cbomPageSize = Math.min(35, Math.max(10, budget));
}

function renderCbomPage() {
  const tbody = document.getElementById('cbom-events-body');
  const pageEl = document.getElementById('cbom-page');
  if (!tbody) return;
  _computeCbomPageSize();

  const suggestions = cbomCache.suggestions || [];
  const events = cbomCache.events || [];

  const normalizeSuggestion = (raw) => {
    const s = String(raw || '').trim();
    if (!s) return { key: '—', display: '—', score: null };
    const m = s.match(/^(.*)\((\d+)\)\s*$/);
    const base = (m ? String(m[1]) : s).trim().replace(/\s+/g, ' ');
    const score = m ? Number(m[2]) : null;
    const parts = base
      .split(';')
      .map(p => String(p || '').trim())
      .filter(Boolean)
      .map(p => p.replace(/\s+/g, ' '));
    const normalized = (parts.length ? parts.sort((a, b) => a.localeCompare(b)).join('; ') : base);
    const key = normalized.toLowerCase();
    return { key, display: normalized, score };
  };

  const aggregateSuggestions = (items) => {
    const acc = new Map();
    (Array.isArray(items) ? items : []).forEach(it => {
      const count = Number(it && it.count != null ? it.count : 0) || 0;
      const { key, display, score } = normalizeSuggestion(it && it.suggestion);
      if (!acc.has(key)) {
        acc.set(key, { suggestion: display, count: 0, score: score });
      }
      const row = acc.get(key);
      row.count += count;
      if (score != null) {
        row.score = (row.score == null) ? score : Math.max(Number(row.score), score);
      }
    });
    return Array.from(acc.values())
      .sort((a, b) => (b.count - a.count) || String(a.suggestion).localeCompare(String(b.suggestion)))
      .map(r => ({
        suggestion: (r.score != null) ? `${r.suggestion} (${r.score})` : r.suggestion,
        count: r.count,
      }));
  };

  const suggestionRows = [];
  if (suggestions.length) {
    suggestionRows.push({ _kind: 'label', label: 'Hardening actions (summary)' });
    const aggregated = aggregateSuggestions(suggestions);
    aggregated.slice(0, 12).forEach(s => {
      suggestionRows.push({ _kind: 'suggestion', suggestion: String(s.suggestion || '').trim() || '—', count: Number(s.count || 0) });
    });
    suggestionRows.push({ _kind: 'label', label: 'Latest events' });
  }

  const allRows = suggestionRows.concat(events.map(e => ({ _kind: 'event', e })));
  const totalPages = Math.max(1, Math.ceil(allRows.length / cbomPageSize));
  if (cbomPage >= totalPages) cbomPage = totalPages - 1;
  if (cbomPage < 0) cbomPage = 0;
  const start = cbomPage * cbomPageSize;
  const pageRows = allRows.slice(start, start + cbomPageSize);

  tbody.innerHTML = '';
  if (!pageRows.length) {
    tbody.innerHTML = '<tr><td colspan="14" class="muted">No CBOM events yet.</td></tr>';
  } else {
    pageRows.forEach(r => {
      if (r._kind === 'label') {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td colspan="14" class="muted">${r.label}</td>`;
        tbody.appendChild(tr);
        return;
      }
      if (r._kind === 'suggestion') {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>—</td>
          <td>observer</td>
          <td>system</td>
          <td>NIST</td>
          <td>hardening_action</td>
          <td>info</td>
          <td>n/a</td>
          <td>n/a</td>
          <td>${r.suggestion} (${r.count})</td>
          <td>—</td>
        `;
        tbody.appendChild(tr);
        return;
      }
      const e = r.e;
      const tr = document.createElement('tr');
      const ts = (e.timestamp || e.last_seen) ? String(e.timestamp || e.last_seen).replace('T', ' ').replace('Z', '') : '—';
      const crypto = e.crypto || {};
      const cryptoLabel = (crypto.crypto_algorithm || e.crypto_algorithm || '—');
      const keyLen = (crypto.key_length || e.key_length);

      const pqcSupport = (crypto.pqc_support != null) ? crypto.pqc_support : e.pqc_support;
      const quantumReady = (crypto.quantum_ready != null) ? crypto.quantum_ready : e.quantum_ready;
      const algLower = String(cryptoLabel || '').toLowerCase();
      const inferredPqc = (
        algLower.includes('kyber') ||
        algLower.includes('dilithium') ||
        algLower.includes('sphincs') ||
        algLower.includes('falcon') ||
        algLower.includes('classic_mceliece') ||
        algLower.includes('mceliece')
      );
      const mode = (pqcSupport === true || quantumReady === true || inferredPqc) ? 'PQC' : 'Classical';
      const modePrefix = (cryptoLabel && cryptoLabel !== '—') ? `${mode} • ` : `${mode}`;
      const cryptoCell = keyLen ? `${modePrefix}${cryptoLabel} (${keyLen})` : `${modePrefix}${cryptoLabel}`;

      const ps = e.payload_summary || {};
      const method = ps.method || '';
      const sugg = e.action_suggestion || (e.suggestion || '—');

      const src = e.source_component || ps.source_component || 'unknown';
      const dst = e.destination_component || ps.destination_component || 'unknown';
      const proto = e.communication_protocol || ps.communication_protocol || '—';
      const typ = e.message_type || ps.message_type || (method ? `http_${method.toLowerCase()}` : 'event');
      const evId = e.representative_event_id || e.event_id || '';

      const count = (e.count != null) ? Number(e.count) : null;
      const lat = (e.avg_latency_ms != null)
        ? `${Number(e.avg_latency_ms).toFixed(1)} ms`
        : ((e.latency_ms != null) ? `${e.latency_ms} ms` : '—');
      const statusCell = (ps.status_code != null) ? `${e.status || '—'} (${ps.status_code})` : (e.status || '—');
      const typeCell = e.api_endpoint ? `${typ} ${e.api_endpoint}` : typ;

      const libraryTool = crypto.library_tool || e.library_tool || '—';
      const certType = crypto.cert_type || e.cert_type || '—';
      const pqcReady = (pqcSupport === true || quantumReady === true || inferredPqc) ? 'Yes' : 'No';

      tr.innerHTML = `
        <td>${ts}</td>
        <td>${src}</td>
        <td>${dst}</td>
        <td>${proto}</td>
        <td>${typeCell}${count != null ? ` <span class="muted">(x${count})</span>` : ''}</td>
        <td>${statusCell}</td>
        <td>${cryptoLabel}</td>
        <td>${keyLen || '—'}</td>
        <td>${libraryTool}</td>
        <td>${certType}</td>
        <td>${pqcReady}</td>
        <td>${lat}</td>
        <td>${sugg}</td>
        <td>${evId ? `<button type="button" class="cbom-analyze" data-event-id="${evId}">Analyze</button>` : '—'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  if (pageEl) pageEl.textContent = `Page ${cbomPage + 1} / ${totalPages} • Rows ${cbomPageSize}`;
}

function openGeminiModal() {
  const modal = document.getElementById('gemini-modal');
  if (modal) modal.style.display = 'block';
}

function closeGeminiModal() {
  const modal = document.getElementById('gemini-modal');
  if (modal) modal.style.display = 'none';
}

function renderGeminiResult(res) {
  const body = document.getElementById('gemini-body');
  const meta = document.getElementById('gemini-meta');
  if (!body) return;

  const result = res && res.result ? res.result : null;
  const model = res && res.model ? res.model : '—';
  const tpl = res && res.template ? res.template : '—';
  const created = res && res.created_at ? res.created_at : '—';
  if (meta) meta.textContent = `model=${model} • template=${tpl} • ${created}`;

  if (!result || typeof result !== 'object') {
    body.textContent = 'No structured response.';
    return;
  }

  const stripFences = (t) => {
    let s = String(t == null ? '' : t);
    // remove common ```json ... ``` wrappers
    s = s.replace(/^```(?:json)?\s*/i, '');
    s = s.replace(/```\s*$/i, '');
    return s.trim();
  };

  const tryUnwrapJsonString = (t) => {
    const s = stripFences(t);
    if (!s) return '';
    if (!(s.startsWith('{') && s.endsWith('}'))) return s;
    try {
      const obj = JSON.parse(s);
      if (obj && typeof obj === 'object') {
        if (typeof obj.action_summary === 'string' && obj.action_summary.trim()) {
          return stripFences(obj.action_summary);
        }
        return JSON.stringify(obj, null, 2);
      }
    } catch (e) {
      // ignore
    }
    return s;
  };

  const summary = tryUnwrapJsonString(result.action_summary || '—');
  const severity = stripFences(result.severity_level || '—');
  const steps = Array.isArray(result.detailed_steps) ? result.detailed_steps : [];
  const refs = Array.isArray(result.standards_references) ? result.standards_references : [];
  const checklist = Array.isArray(result.checklist) ? result.checklist : [];

  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  let html = '';
  html += `<div class="gemini-section"><div class="gemini-title">Summary</div><div class="gemini-text">${esc(summary)}</div></div>`;
  html += `<div class="gemini-section"><div class="gemini-title">Severity</div><div class="gemini-badge">${esc(severity)}</div></div>`;

  if (steps.length) {
    html += `<div class="gemini-section"><div class="gemini-title">Actionable steps</div><ol class="gemini-list">`;
    steps.forEach((s) => {
      html += `<li>${esc(tryUnwrapJsonString(s))}</li>`;
    });
    html += `</ol></div>`;
  }

  if (checklist.length) {
    html += `<div class="gemini-section"><div class="gemini-title">Checklist</div><ul class="gemini-checklist">`;
    checklist.forEach((c) => {
      const item = (c && c.item) ? c.item : String(c);
      html += `<li><label><input type="checkbox" disabled /> <span>${esc(tryUnwrapJsonString(item))}</span></label></li>`;
    });
    html += `</ul></div>`;
  }

  if (refs.length) {
    html += `<div class="gemini-section"><div class="gemini-title">Standards references</div><ul class="gemini-refs">`;
    refs.forEach((r) => {
      html += `<li>${esc(tryUnwrapJsonString(r))}</li>`;
    });
    html += `</ul></div>`;
  }

  body.innerHTML = html;
}

async function analyzeCbomEventWithGemini(eventId, force = false) {
  const body = document.getElementById('gemini-body');
  const meta = document.getElementById('gemini-meta');
  if (meta) meta.textContent = `event_id=${eventId}`;
  if (body) body.textContent = 'Loading Gemini insights...';
  openGeminiModal();
  try {
    const resp = await fetch('/api/cboom/gemini-insight', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_id: eventId, force: !!force }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      const err = data && (data.message || data.error) ? String(data.message || data.error) : `API error ${resp.status}`;
      const code = data && data.error ? String(data.error) : null;
      throw new Error(code && data.message ? `${code}: ${err}` : err);
    }
    renderGeminiResult(data);
  } catch (e) {
    if (body) body.textContent = `Gemini request failed: ${e.message}`;
  }
}

async function refreshPredictiveWidget() {
  const rHs = document.getElementById('predict-risk-handshake');
  const rOl = document.getElementById('predict-risk-overload');
  const upd = document.getElementById('predict-updated');
  const canvas = document.getElementById('predict-chart');
  if (!rHs || !rOl || !canvas) return;

  try {
    const data = await fetchDashboardJson('/api/alerts/predict?minutes=60&horizon=10');
    const hs = Number((data.risk && data.risk.handshake_failure) || 0);
    const ol = Number((data.risk && data.risk.overload) || 0);
    rHs.textContent = hs.toFixed(2);
    rOl.textContent = ol.toFixed(2);
    if (upd && data.updated_at) upd.textContent = new Date(data.updated_at).toLocaleTimeString();

    const hist = Array.isArray(data.history) ? data.history : [];
    const fc = Array.isArray(data.forecast) ? data.forecast : [];

    // Display: last N points of events_ewma + predicted events (scaled). If ewma missing, fall back to raw.
    const histVals = hist.map(p => Number(p.events_ewma ?? p.events ?? 0));
    const predVals = fc.map(p => Number(p.pred_events ?? 0));
    const values = histVals.slice(-20).concat(predVals);
    drawLineChart(canvas, values, (ol >= 0.75 || hs >= 0.75) ? 'rgba(239, 68, 68, 0.9)' : 'rgba(99, 102, 241, 0.9)');
  } catch (e) {
    rHs.textContent = '—';
    rOl.textContent = '—';
    if (upd) upd.textContent = '—';
  }
}

function drawBarChart(canvas, values, color) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const w = canvas.width = canvas.clientWidth;
  const h = canvas.height = canvas.getAttribute('height') ? parseInt(canvas.getAttribute('height'), 10) : 140;
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(...values, 1);
  const n = Math.max(values.length, 1);
  const gap = 2;
  const barW = Math.max(2, Math.floor((w - gap * (n - 1)) / n));
  ctx.fillStyle = color;
  values.forEach((v, i) => {
    const x = i * (barW + gap);
    const barH = Math.round((v / max) * (h - 12));
    ctx.fillRect(x, h - barH, barW, barH);
  });
}

function roleRank(role) {
  const order = { viewer: 1, auditor: 2, admin: 3 };
  return order[String(role || '').toLowerCase()] || 0;
}

function applyRoleVisibility() {
  const roleEl = document.getElementById('user-role');
  const role = roleEl ? roleEl.textContent.trim().toLowerCase() : 'viewer';
  const rank = roleRank(role);

  document.querySelectorAll('[data-min-role]').forEach(el => {
    const minRole = (el.getAttribute('data-min-role') || '').trim().toLowerCase();
    if (!minRole) return;
    const ok = rank >= roleRank(minRole);
    el.style.display = ok ? '' : 'none';
  });

  // If current tab becomes hidden, fall back to performance.
  const activeNav = document.querySelector('.nav-item.active');
  if (activeNav && activeNav.style.display === 'none') {
    const perf = document.querySelector('.nav-item[data-tab="performance"]');
    if (perf) perf.click();
  }
}

function getEventFilters() {
  const algo = (document.getElementById('filter-algorithm')?.value || '').trim().toLowerCase();
  const client = (document.getElementById('filter-client')?.value || '').trim();
  const path = (document.getElementById('filter-path')?.value || '').trim().toLowerCase();
  return { algo, client, path };
}

function filterRecentEvents(events) {
  const { algo, client, path } = getEventFilters();
  return (events || []).filter(ev => {
    if (client && String(ev.client_id || '') !== client) return false;
    const details = ev.details || {};
    const publicDetails = (details.public && typeof details.public === 'object') ? details.public : details;
    const evAlgo = String(publicDetails.algorithm || '').toLowerCase();
    if (algo && evAlgo !== algo) return false;
    const evPath = String(publicDetails.path || '').toLowerCase();
    if (path && !evPath.includes(path)) return false;
    return true;
  });
}

function getSessionFilters() {
  const algo = (document.getElementById('sessions-filter-algorithm')?.value || '').trim().toLowerCase();
  const client = (document.getElementById('sessions-filter-client')?.value || '').trim();
  return { algo, client };
}

function drawLineChart(canvas, values, color) {
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const w = canvas.width = canvas.clientWidth;
  const h = canvas.height = canvas.getAttribute('height') ? parseInt(canvas.getAttribute('height'), 10) : 140;
  ctx.clearRect(0, 0, w, h);
  const filtered = values.map(v => (v == null ? null : Number(v)));
  const nums = filtered.filter(v => v != null && !Number.isNaN(v));
  const max = Math.max(...nums, 1);
  const min = Math.min(...nums, 0);
  const n = Math.max(filtered.length, 1);
  const step = n > 1 ? (w / (n - 1)) : w;

  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.beginPath();
  let started = false;
  filtered.forEach((v, i) => {
    if (v == null || Number.isNaN(v)) return;
    const x = i * step;
    const norm = (v - min) / (max - min || 1);
    const y = h - Math.round(norm * (h - 12));
    if (!started) {
      ctx.moveTo(x, y);
      started = true;
    } else {
      ctx.lineTo(x, y);
    }
  });
  ctx.stroke();
}

async function refreshHistoryPanel() {
  const reqCanvas = document.getElementById('chart-requests');
  const latCanvas = document.getElementById('chart-latency');
  const failCanvas = document.getElementById('chart-failures');
  const algoEl = document.getElementById('history-algos');
  const updatedEl = document.getElementById('history-updated');
  if (!reqCanvas || !latCanvas || !failCanvas || !algoEl) return;

  try {
    const data = await fetchDashboardJson('/api/dashboard/history?minutes=120');
    const series = data.series || [];
    const requests = series.map(p => Number(p.requests || 0));
    const latencyAvg = series.map(p => p.latency_avg_ms);
    const failures = series.map(p => Number(p.handshake_failures || 0));

    drawBarChart(reqCanvas, requests, 'rgba(99, 102, 241, 0.85)');
    drawLineChart(latCanvas, latencyAvg, 'rgba(34, 197, 94, 0.85)');
    drawBarChart(failCanvas, failures, 'rgba(239, 68, 68, 0.8)');

    renderPills(algoEl, data.handshake_algorithms || {});
    if (updatedEl) updatedEl.textContent = new Date(data.updated_at).toLocaleTimeString();
  } catch (e) {
    if (updatedEl) updatedEl.textContent = `Error: ${e.message}`;
  }
}

async function fetchTelemetrySnapshot() {
  const resp = await fetch('/api/telemetry/overview?limit=80&minutes=180', { credentials: 'same-origin' });
  if (!resp.ok) throw new Error(`API error ${resp.status}`);
  return resp.json();
}

async function fetchDashboardJson(path) {
  const started = performance.now();
  let resp;
  let body;
  let errMsg = null;
  try {
    resp = await fetch(path, { credentials: 'same-origin' });
    body = await resp.json();
    if (!resp.ok) {
      errMsg = body && (body.error || body.message) ? (body.error || body.message) : `API error ${resp.status}`;
      throw new Error(errMsg);
    }
    return body;
  } catch (e) {
    errMsg = errMsg || (e && e.message) || 'request_failed';
    throw e;
  } finally {
    try {
      if (typeof path === 'string' && !path.startsWith('/api/cboom/')) {
        const latency = Math.round(performance.now() - started);
        const payload = {
          method: 'GET',
          path,
          status_code: resp ? resp.status : null,
          latency_ms: latency,
          error: resp && resp.ok ? null : errMsg,
        };
        fetch('/api/cboom/events/browser', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        }).catch(() => { });
      }
    } catch (_) {
      // ignore
    }
  }
}

function renderPills(container, data) {
  container.innerHTML = '';
  const entries = Object.entries(data || {});
  if (!entries.length) {
    container.innerHTML = '<span class="muted">No data yet</span>';
    return;
  }
  entries.forEach(([key, val]) => {
    const pill = document.createElement('span');
    pill.className = 'pill';
    pill.textContent = `${key}: ${val}`;
    container.appendChild(pill);
  });
}

function renderTimeline(buckets) {
  const timelineEl = document.getElementById('timeline');
  if (!timelineEl) return;
  timelineEl.innerHTML = '';
  if (!buckets.length) {
    timelineEl.innerHTML = '<p class="muted">No traffic yet.</p>';
    return;
  }
  const max = Math.max(...buckets.map(b => b.count), 1);
  buckets.forEach(b => {
    const card = document.createElement('div');
    card.className = 'timeline-bar';
    const barFill = document.createElement('div');
    barFill.className = 'bar-fill';
    const inner = document.createElement('div');
    inner.className = 'bar-fill-inner';
    const pct = Math.max(6, Math.round((b.count / max) * 100));
    inner.style.height = `${pct}%`;
    barFill.appendChild(inner);
    const label = document.createElement('span');
    const time = new Date(b.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    label.textContent = `${time} • ${b.count}`;
    card.appendChild(barFill);
    card.appendChild(label);
    timelineEl.appendChild(card);
  });
}

function renderTable(events) {
  const tbody = document.getElementById('recent-events-body');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">No events captured yet.</td></tr>';
    return;
  }
  events.forEach(ev => {
    const tr = document.createElement('tr');
    const ts = new Date(ev.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    tr.innerHTML = `
      <td>${ts}</td>
      <td><span class="badge info">${ev.component || 'n/a'}</span></td>
      <td><span class="badge success">${ev.event_type}</span></td>
      <td>${ev.session_id || '—'}</td>
      <td>${ev.client_id || '—'}</td>
      <td><code>${JSON.stringify(ev.details).slice(0, 160)}</code></td>
    `;
    tbody.appendChild(tr);
  });
}

async function refreshTelemetry() {
  const updatedEl = document.getElementById('dash-last-updated');
  try {
    const data = await fetchTelemetrySnapshot();
    renderTimeline(data.timeline);
    renderPills(document.getElementById('stat-by-component'), data.summary.by_component);
    renderPills(document.getElementById('stat-by-type'), data.summary.by_type);
    renderTable(filterRecentEvents(data.recent || []));
    updatedEl.textContent = `Updated ${new Date(data.last_updated).toLocaleTimeString()}`;
  } catch (err) {
    console.warn('Telemetry refresh failed', err);
    updatedEl.textContent = `Error: ${err.message}`;
  }
}

async function refreshTrafficWidget() {
  try {
    const data = await fetchDashboardJson('/api/dashboard/traffic?seconds=300');
    const totalEl = document.getElementById('traffic-total');
    const windowEl = document.getElementById('traffic-window');
    const sessionsEl = document.getElementById('traffic-sessions');
    const sourceEl = document.getElementById('traffic-source');
    if (totalEl) totalEl.textContent = data.requests || 0;
    if (windowEl) windowEl.textContent = data.window_seconds || 0;
    if (sessionsEl) sessionsEl.textContent = data.active_sessions || 0;
    if (sourceEl) sourceEl.textContent = data.source || '—';
    renderPills(document.getElementById('stat-by-component'), data.by_component);
    renderPills(document.getElementById('stat-by-type'), data.by_type);
  } catch (e) {
    // ignore
  }
}

async function refreshCryptoWidget() {
  const container = document.getElementById('crypto-algos');
  const activeEl = document.getElementById('crypto-active');
  const failuresEl = document.getElementById('crypto-failures');
  const sourceEl = document.getElementById('crypto-source');
  if (!container) return;
  try {
    const data = await fetchDashboardJson('/api/dashboard/crypto?minutes=2');
    const live = data.active_sessions_by_algorithm;
    const pills = (live && typeof live === 'object') ? live : data.handshake_algorithms;
    renderPills(container, pills);
    if (activeEl) activeEl.textContent = data.active_sessions_total != null ? data.active_sessions_total : '0';
    if (failuresEl) failuresEl.textContent = data.handshake_failures || 0;
    if (sourceEl) {
      const src = data.source;
      sourceEl.textContent = (src && typeof src === 'object') ? (src.active_sessions || src.handshakes || '—') : (src || '—');
    }
  } catch (e) {
    if (activeEl) activeEl.textContent = '—';
    if (failuresEl) failuresEl.textContent = '—';
    if (sourceEl) sourceEl.textContent = '—';
  }
}

async function refreshLatencyWidget() {
  const avgEl = document.getElementById('latency-avg');
  const minEl = document.getElementById('latency-min');
  const maxEl = document.getElementById('latency-max');
  const countEl = document.getElementById('latency-count');
  const sourceEl = document.getElementById('latency-source');
  if (!avgEl || !minEl || !maxEl || !countEl) return;
  try {
    const data = await fetchDashboardJson('/api/dashboard/latency?seconds=300');
    avgEl.textContent = data.avg_ms == null ? '—' : data.avg_ms;
    minEl.textContent = data.min_ms == null ? '—' : data.min_ms;
    maxEl.textContent = data.max_ms == null ? '—' : data.max_ms;
    countEl.textContent = data.count || 0;
    if (sourceEl) sourceEl.textContent = data.source || '—';
  } catch (e) {
    avgEl.textContent = '—';
    minEl.textContent = '—';
    maxEl.textContent = '—';
    countEl.textContent = '0';
    if (sourceEl) sourceEl.textContent = '—';
  }
}

async function refreshAlertsWidget() {
  const container = document.getElementById('alerts');
  const notif = document.getElementById('notif-count');
  if (!container) return;
  try {
    const data = await fetchDashboardJson('/api/dashboard/alerts?minutes=15');
    container.innerHTML = '';
    const alerts = data.alerts || [];
    if (notif) notif.textContent = alerts.length;
    if (!alerts.length) {
      container.innerHTML = '<span class="pill">No alerts</span>';
      return;
    }
    alerts.forEach((a, idx) => {
      const wrap = document.createElement('div');
      wrap.className = 'pill';
      wrap.style.width = '100%';
      wrap.style.borderRadius = '0.75rem';
      wrap.style.padding = '0.75rem';

      const header = document.createElement('div');
      header.style.display = 'flex';
      header.style.alignItems = 'center';
      header.style.justifyContent = 'space-between';
      header.style.gap = '0.75rem';

      const left = document.createElement('div');
      const title = document.createElement('div');
      title.className = `badge ${a.severity === 'error' ? 'error' : 'warn'}`;
      title.textContent = `${a.type}: ${a.count}`;
      const meta = document.createElement('div');
      meta.className = 'muted';
      const thr = a.threshold != null ? a.threshold : '—';
      const win = a.window_minutes != null ? a.window_minutes : '—';
      meta.textContent = `threshold ${thr} • window ${win}m`;
      left.appendChild(title);
      left.appendChild(meta);

      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = 'Details';
      btn.setAttribute('aria-expanded', 'false');

      header.appendChild(left);
      header.appendChild(btn);
      wrap.appendChild(header);

      const details = document.createElement('div');
      details.style.display = 'none';
      details.style.marginTop = '0.75rem';

      const chart = document.createElement('canvas');
      chart.className = 'chart';
      chart.setAttribute('height', '120');
      details.appendChild(chart);

      const series = Array.isArray(a.series) ? a.series : [];
      const values = series.map(p => Number(p.value || 0));
      drawLineChart(chart, values, a.severity === 'error' ? 'rgba(239, 68, 68, 0.9)' : 'rgba(245, 158, 11, 0.9)');

      const sess = Array.isArray(a.sessions) ? a.sessions : [];
      const sessWrap = document.createElement('div');
      sessWrap.style.marginTop = '0.75rem';
      if (!sess.length) {
        sessWrap.innerHTML = '<div class="muted">No affected sessions detected.</div>';
      } else {
        const table = document.createElement('table');
        table.className = 'data-table';
        table.innerHTML = `
          <thead>
            <tr>
              <th>Session</th>
              <th>Algorithm</th>
              <th>Status</th>
              <th>First Seen</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody></tbody>
        `;
        const tb = table.querySelector('tbody');
        sess.forEach(s => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td><code>${s.session_id || '—'}</code></td>
            <td>${s.algorithm || '—'}</td>
            <td>${s.status || '—'}</td>
            <td>${s.first_seen ? new Date(s.first_seen).toLocaleTimeString() : '—'}</td>
            <td>${s.last_seen ? new Date(s.last_seen).toLocaleTimeString() : '—'}</td>
          `;
          tb.appendChild(tr);
        });
        const tw = document.createElement('div');
        tw.className = 'table-wrapper';
        tw.appendChild(table);
        sessWrap.appendChild(tw);
      }
      details.appendChild(sessWrap);

      btn.addEventListener('click', () => {
        const open = details.style.display !== 'none';
        details.style.display = open ? 'none' : 'block';
        btn.setAttribute('aria-expanded', open ? 'false' : 'true');
        btn.textContent = open ? 'Details' : 'Hide';
      });

      wrap.appendChild(details);
      container.appendChild(wrap);
      if (idx < alerts.length - 1) {
        const spacer = document.createElement('div');
        spacer.style.height = '0.5rem';
        container.appendChild(spacer);
      }
    });
  } catch (e) {
    if (notif) notif.textContent = '0';
  }
}

async function refreshSessionsPanel() {
  const tbody = document.getElementById('sessions-body');
  if (!tbody) return;
  try {
    const data = await fetchDashboardJson('/api/dashboard/sessions?minutes=30&limit=50&source=proxy');
    let sessions = data.sessions || [];
    const { algo, client } = getSessionFilters();
    if (algo) {
      sessions = sessions.filter(s => String(s.algorithm || s.crypto || '').toLowerCase() === algo);
    }
    if (client) {
      sessions = sessions.filter(s => String(s.session_id || '') === client || String(s.client_id || '') === client);
    }
    tbody.innerHTML = '';
    if (!sessions.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">No sessions yet.</td></tr>';
      return;
    }
    sessions.forEach(s => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${s.session_id || '—'}</code></td>
        <td>${s.first_seen ? new Date(s.first_seen).toLocaleTimeString() : '—'}</td>
        <td>${s.last_seen ? new Date(s.last_seen).toLocaleTimeString() : '—'}</td>
        <td>${s.events || 0}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="4" class="muted">Error loading sessions.</td></tr>';
  }
}

async function refreshConfigPanel() {
  const pre = document.getElementById('config-json');
  if (!pre) return;
  try {
    const data = await fetchDashboardJson('/api/dashboard/config');
    pre.textContent = JSON.stringify(data, null, 2);

    const multiEl = document.getElementById('config-multi');
    const cryptoEl = document.getElementById('config-crypto');
    const rateEl = document.getElementById('config-rate');
    const wlEl = document.getElementById('config-whitelist');
    const updEl = document.getElementById('config-updated');

    const policies = (data && typeof data === 'object' && data.policies && typeof data.policies === 'object') ? data.policies : {};
    const multi = (data && data.multi_instance) ? String(data.multi_instance) : '—';
    const cryptoPolicy = (policies && policies.crypto_policy != null) ? String(policies.crypto_policy) : '—';
    const rateLimit = (policies && policies.rate_limit != null) ? String(policies.rate_limit) : '—';
    const whitelist = (policies && policies.whitelist != null) ? String(policies.whitelist) : '—';
    const updatedAt = (data && data.updated_at) ? String(data.updated_at) : '';

    const fmtUpdated = (iso) => {
      if (!iso) return '—';
      const d = new Date(iso);
      if (String(d) === 'Invalid Date') return iso;
      return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' });
    };

    const statusMark = (ok, text) => {
      const label = ok ? '⚡' : '❌';
      const cls = ok ? 'badge success' : 'badge warn';
      return `<span class="${cls}">${label}</span><span>${text}</span>`;
    };

    if (multiEl) multiEl.textContent = (multi.toLowerCase() === 'single') ? 'Single instance' : multi;

    if (cryptoEl) {
      const isKyber = cryptoPolicy.toLowerCase().includes('kyber');
      const desc = isKyber ? `${cryptoPolicy} (Post-Quantum Ready)` : cryptoPolicy;
      cryptoEl.innerHTML = statusMark(isKyber, desc);
    }

    if (rateEl) {
      const configured = rateLimit.toLowerCase() !== 'not_configured';
      rateEl.innerHTML = configured ? statusMark(true, rateLimit) : statusMark(false, 'Not configured');
    }

    if (wlEl) {
      const configured = whitelist.toLowerCase() !== 'not_configured';
      wlEl.innerHTML = configured ? statusMark(true, whitelist) : statusMark(false, 'Not configured');
    }

    if (updEl) updEl.textContent = fmtUpdated(updatedAt);
  } catch (e) {
    pre.textContent = 'Error loading config.';
    const cryptoEl = document.getElementById('config-crypto');
    const rateEl = document.getElementById('config-rate');
    const wlEl = document.getElementById('config-whitelist');
    if (cryptoEl) cryptoEl.textContent = '—';
    if (rateEl) rateEl.textContent = '—';
    if (wlEl) wlEl.textContent = '—';
  }
}

async function refreshFooterStatus() {
  const v = document.getElementById('footer-version');
  const last = document.getElementById('footer-last');
  const sec = document.getElementById('footer-security');
  try {
    const data = await fetchDashboardJson('/api/dashboard/status');
    if (v) v.textContent = data.version || 'dev';
    if (last) last.textContent = data.last_event_at ? new Date(data.last_event_at).toLocaleTimeString() : '—';
    if (sec) sec.textContent = data.security_status || '—';
  } catch (e) {
    // ignore
  }
}

function initTelemetryDashboard() {
  refreshTelemetry();
  refreshTrafficWidget();
  refreshCryptoWidget();
  refreshLatencyWidget();
  refreshHistoryPanel();
  refreshAlertsWidget();
  refreshPredictiveWidget();
  refreshSessionsPanel();
  refreshConfigPanel();
  refreshFooterStatus();
  telemetryTimer = setInterval(() => {
    if (liveEnabled) {
      refreshTelemetry();
      refreshTrafficWidget();
      refreshCryptoWidget();
      refreshLatencyWidget();
      refreshHistoryPanel();
      refreshAlertsWidget();
      refreshPredictiveWidget();
      refreshSessionsPanel();
      refreshFooterStatus();
    }
  }, 3000);

  const refreshBtn = document.getElementById('dash-refresh');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      await refreshTelemetry();
      await refreshTrafficWidget();
      await refreshCryptoWidget();
      await refreshLatencyWidget();
      await refreshAlertsWidget();
      await refreshSessionsPanel();
      await refreshFooterStatus();
    });
  }

  const toggleBtn = document.getElementById('toggle-stream');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      liveEnabled = !liveEnabled;
      toggleBtn.textContent = liveEnabled ? 'Pause Live' : 'Resume Live';
    });
  }
}

async function uploadPcap(e) {
  e.preventDefault();
  const fileInput = document.getElementById('pcap-file');
  if (!fileInput.files.length) return;
  const form = new FormData();
  form.append('file', fileInput.files[0]);
  const resp = await fetch('/api/pcap/upload', { method: 'POST', body: form, credentials: 'same-origin' });
  const body = await resp.json();
  const tbody = document.getElementById('pcap-body');
  tbody.innerHTML = '';
  if (!resp.ok) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">Error: ${body.error || body.message}</td></tr>`;
    return;
  }
  if (!body.flows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">No flows detected.</td></tr>';
    return;
  }
  body.flows.forEach(f => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${f.src}</td><td>${f.dst}</td><td>${f.sport}</td><td>${f.dport}</td>
      <td>${f.proto}</td><td>${f.pkts}</td><td>${f.bytes}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function refreshProxyPcapMeta() {
  const metaEl = document.getElementById('pcap-download-meta');
  const linkEl = document.getElementById('pcap-download');
  if (!metaEl || !linkEl) return;
  try {
    const resp = await fetch('/api/proxy/pcap/meta', { credentials: 'same-origin' });
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.error || `API error ${resp.status}`);

    if (!body.present) {
      metaEl.textContent = 'No proxy capture available yet.';
      linkEl.setAttribute('aria-disabled', 'true');
      linkEl.style.pointerEvents = 'none';
      linkEl.style.opacity = '0.6';
      return;
    }

    const kb = Math.round((body.size_bytes || 0) / 1024);
    metaEl.textContent = `Capture ready • ${kb} KB • updated ${new Date(body.updated_at).toLocaleTimeString()}`;
    linkEl.removeAttribute('aria-disabled');
    linkEl.style.pointerEvents = 'auto';
    linkEl.style.opacity = '1';
  } catch (err) {
    metaEl.textContent = `Capture status unavailable: ${err.message}`;
  }
}

async function refreshPcapAnalysis() {
  const metaEl = document.getElementById('pcap-analyze-meta');
  const pktsCanvas = document.getElementById('pcap-chart-pkts');
  const bytesCanvas = document.getElementById('pcap-chart-bytes');
  const protoEl = document.getElementById('pcap-protos');
  const tbody = document.getElementById('pcap-body');
  if (!pktsCanvas || !bytesCanvas || !tbody) return;

  try {
    const data = await fetchDashboardJson('/api/pcap/analyze?source=proxy');
    if (metaEl) {
      const kb = Math.round((data.size_bytes || 0) / 1024);
      metaEl.textContent = `Analyzed ${kb} KB • updated ${new Date(data.updated_at).toLocaleTimeString()}`;
    }

    const series = Array.isArray(data.series) ? data.series : [];
    const pkts = series.map(p => Number(p.pkts || 0));
    const bytes = series.map(p => Math.round(Number(p.bytes || 0) / 1024));
    drawLineChart(pktsCanvas, pkts, 'rgba(99, 102, 241, 0.9)');
    drawLineChart(bytesCanvas, bytes, 'rgba(34, 197, 94, 0.9)');

    renderPills(protoEl, data.protocols || {});

    const flows = Array.isArray(data.flows) ? data.flows : [];
    tbody.innerHTML = '';
    if (!flows.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="muted">No flows detected.</td></tr>';
      return;
    }
    flows.forEach(f => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${f.src}</td><td>${f.dst}</td><td>${f.sport}</td><td>${f.dport}</td>
        <td>${f.proto}</td><td>${f.pkts}</td><td>${f.bytes}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    if (metaEl) metaEl.textContent = `Analysis unavailable: ${err.message}`;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  applyRoleVisibility();

  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      navItems.forEach(i => i.classList.remove('active'));
      item.classList.add('active');
      const tab = item.getAttribute('data-tab');
      const mainEl = document.querySelector('.main');
      document.querySelectorAll('.panel').forEach(p => {
        p.classList.toggle('active', p.getAttribute('data-panel') === tab || (tab === 'performance' && p.getAttribute('data-panel') === 'performance'));
      });
      if (mainEl) mainEl.classList.toggle('cbom-fullscreen', tab === 'logs');
      if (tab === 'config') refreshConfigPanel();
      if (tab === 'sessions') refreshSessionsPanel();
      if (tab === 'history') refreshHistoryPanel();
      if (tab === 'pcap') {
        refreshProxyPcapMeta();
        refreshPcapAnalysis();
      }
      if (tab === 'security') refreshSiemPanel();
      if (tab === 'logs') refreshCbomPanel();
    });
  });
  initTelemetryDashboard();

  const siemRefresh = document.getElementById('siem-refresh');
  if (siemRefresh) siemRefresh.addEventListener('click', refreshSiemPanel);

  const filterAlgo = document.getElementById('filter-algorithm');
  const filterClient = document.getElementById('filter-client');
  const filterPath = document.getElementById('filter-path');
  const filterClear = document.getElementById('filter-clear');
  const reapply = () => refreshTelemetry();
  if (filterAlgo) filterAlgo.addEventListener('change', reapply);
  if (filterClient) filterClient.addEventListener('input', reapply);
  if (filterPath) filterPath.addEventListener('input', reapply);
  if (filterClear) filterClear.addEventListener('click', () => {
    if (filterAlgo) filterAlgo.value = '';
    if (filterClient) filterClient.value = '';
    if (filterPath) filterPath.value = '';
    refreshTelemetry();
  });

  const sAlgo = document.getElementById('sessions-filter-algorithm');
  const sClient = document.getElementById('sessions-filter-client');
  const sClear = document.getElementById('sessions-filter-clear');
  const sReapply = () => refreshSessionsPanel();
  if (sAlgo) sAlgo.addEventListener('change', sReapply);
  if (sClient) sClient.addEventListener('input', sReapply);
  if (sClear) sClear.addEventListener('click', () => {
    if (sAlgo) sAlgo.value = '';
    if (sClient) sClient.value = '';
    refreshSessionsPanel();
  });

  const historyRefresh = document.getElementById('history-refresh');
  if (historyRefresh) historyRefresh.addEventListener('click', refreshHistoryPanel);
  const pcapForm = document.getElementById('pcap-form');
  if (pcapForm) pcapForm.addEventListener('submit', uploadPcap);

  const pcapDownload = document.getElementById('pcap-download');
  if (pcapDownload) pcapDownload.addEventListener('click', downloadProxyPcap);

  const pcapRefresh = document.getElementById('pcap-refresh');
  if (pcapRefresh) {
    pcapRefresh.addEventListener('click', async () => {
      await refreshProxyPcapMeta();
      await refreshPcapAnalysis();
    });
  }

  const cbomRefresh = document.getElementById('cbom-refresh');
  if (cbomRefresh) cbomRefresh.addEventListener('click', refreshCbomPanel);

  const cbomToggle = document.getElementById('cbom-toggle-group');
  if (cbomToggle) {
    cbomGrouped = true;
    cbomToggle.textContent = 'Aggregated';
    cbomToggle.disabled = true;
  }

  const cbomPurge = document.getElementById('cbom-purge');
  if (cbomPurge) {
    cbomPurge.addEventListener('click', async () => {
      const ok = window.confirm('Delete CBOM history? This cannot be undone.');
      if (!ok) return;
      try {
        const resp = await fetch('/api/cboom/purge', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'all' }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          const msg = data && (data.message || data.error) ? String(data.message || data.error) : `API error ${resp.status}`;
          throw new Error(msg);
        }
        cbomCache.events = [];
        cbomCache.suggestions = [];
        renderCbomComponentsSummary([], []);
        cbomPage = 0;
        renderCbomPage();
        await refreshCbomPanel();
      } catch (e) {
        alert(`CBOM purge failed: ${e.message}`);
      }
    });
  }

  const cbomCompact = document.getElementById('cbom-compact');
  if (cbomCompact) {
    cbomCompact.addEventListener('click', () => {
      const mainEl = document.querySelector('.main');
      if (!mainEl) return;
      mainEl.classList.toggle('cbom-compact');
      renderCbomPage();
    });
  }

  const cbomPrev = document.getElementById('cbom-prev');
  if (cbomPrev) cbomPrev.addEventListener('click', () => { cbomPage -= 1; renderCbomPage(); });
  const cbomNext = document.getElementById('cbom-next');
  if (cbomNext) cbomNext.addEventListener('click', () => { cbomPage += 1; renderCbomPage(); });

  const gemClose = document.getElementById('gemini-close');
  if (gemClose) gemClose.addEventListener('click', closeGeminiModal);
  const gemModal = document.getElementById('gemini-modal');
  if (gemModal) {
    gemModal.addEventListener('click', (e) => {
      if (e.target === gemModal) closeGeminiModal();
    });
  }

  const cfgRefresh = document.getElementById('config-refresh');
  if (cfgRefresh) cfgRefresh.addEventListener('click', refreshConfigPanel);

  const cfgToggle = document.getElementById('config-toggle-raw');
  if (cfgToggle) {
    cfgToggle.addEventListener('click', () => {
      const raw = document.getElementById('config-raw');
      const isOpen = raw && raw.style.display !== 'none';
      if (raw) raw.style.display = isOpen ? 'none' : 'block';
      cfgToggle.textContent = isOpen ? 'Show Raw JSON ▼' : 'Hide Raw JSON ▲';
    });
  }

  const cfgCopy = document.getElementById('config-copy');
  if (cfgCopy) {
    cfgCopy.addEventListener('click', async () => {
      const pre = document.getElementById('config-json');
      const text = pre ? String(pre.textContent || '').trim() : '';
      if (!text) return;
      try {
        await navigator.clipboard.writeText(text);
        cfgCopy.textContent = 'Copied';
        setTimeout(() => { cfgCopy.textContent = 'Copy Snapshot'; }, 1200);
      } catch (e) {
        alert('Copy failed.');
      }
    });
  }

  const cfgEdit = document.getElementById('config-edit');
  const cfgModal = document.getElementById('config-modal');
  const cfgModalClose = document.getElementById('config-modal-close');
  if (cfgEdit && cfgModal) {
    cfgEdit.addEventListener('click', () => { cfgModal.style.display = 'block'; });
  }
  if (cfgModalClose && cfgModal) {
    cfgModalClose.addEventListener('click', () => { cfgModal.style.display = 'none'; });
  }
  if (cfgModal) {
    cfgModal.addEventListener('click', (e) => {
      if (e.target === cfgModal) cfgModal.style.display = 'none';
    });
  }

  document.addEventListener('click', (e) => {
    const btn = e.target && e.target.closest ? e.target.closest('.cbom-analyze') : null;
    if (!btn) return;
    const evId = btn.getAttribute('data-event-id');
    if (!evId || evId === '—') return;
    const force = !!(e && e.shiftKey);
    analyzeCbomEventWithGemini(evId, force);
  });

  refreshProxyPcapMeta();
  setInterval(refreshProxyPcapMeta, 5000);
});
