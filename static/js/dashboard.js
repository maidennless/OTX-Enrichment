'use strict';

// ── STATE ────────────────────────────────────────────────────────────────────
const State = {
  page: 'dashboard',
  iocPage: 1,
  iocType: '',
  iocSearch: '',
  ruleType: '',
  charts: {},
};

// ── ROUTER ───────────────────────────────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', e => {
    e.preventDefault();
    navigateTo(el.dataset.page);
  });
});

function navigateTo(page) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelector(`[data-page="${page}"]`)?.classList.add('active');
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById(`page-${page}`)?.classList.add('active');
  document.getElementById('page-title').textContent = {
    dashboard: 'Dashboard', iocs: 'IOC Explorer', pulses: 'Pulses',
    relationships: 'Relationships', rules: 'Detection Rules',
    stix: 'STIX Bundles', ingest: 'Sync / Ingest'
  }[page] || page;
  State.page = page;

  if (page === 'dashboard')     loadDashboard();
  if (page === 'iocs')          loadIOCs();
  if (page === 'pulses')        loadPulses();
  if (page === 'relationships') { loadClusters(); }
  if (page === 'rules')         loadRules();
  if (page === 'stix')          loadStixBundles();
  if (page === 'ingest')        loadSyncHistory();
}

// ── API HELPER ───────────────────────────────────────────────────────────────
async function api(path, opts = {}) {
  try {
    const r = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...opts });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    toast(`API error: ${e.message}`, 'error');
    return null;
  }
}

// ── TOAST ────────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  container.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ── SIDEBAR TOGGLE ───────────────────────────────────────────────────────────
function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  const mc = document.querySelector('.main-content');
  if (window.innerWidth <= 800) {
    sb.classList.toggle('mobile-open');
  } else {
    sb.classList.toggle('collapsed');
    mc.classList.toggle('expanded');
  }
}

// ── GLOBAL SEARCH ────────────────────────────────────────────────────────────
function globalSearch(e) {
  if (e.key === 'Enter') {
    const q = e.target.value.trim();
    if (q) {
      navigateTo('iocs');
      document.getElementById('ioc-search').value = q;
      State.iocSearch = q;
      State.iocPage = 1;
      loadIOCs();
    }
  }
}

// ── HELPERS ──────────────────────────────────────────────────────────────────
function typeBadge(type) {
  return `<span class="badge badge-${type}">${type}</span>`;
}

function tlpBadge(tlp) {
  return `<span class="badge badge-${(tlp||'white').toLowerCase()}">TLP:${(tlp||'WHITE').toUpperCase()}</span>`;
}

function severitySpan(sev) {
  return `<span class="sev-${sev}">${(sev||'').toUpperCase()}</span>`;
}

function fmtDate(d) {
  if (!d || d.startsWith('1970')) return '—';
  return new Date(d).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

function spinner() {
  return '<div class="spinner"></div>';
}

function emptyState(msg = 'No data found') {
  return `<div class="empty-state">
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    <p>${msg}</p>
  </div>`;
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard', 'success'));
}

// ── DASHBOARD ────────────────────────────────────────────────────────────────
async function loadDashboard() {
  const data = await api('/api/stats');
  if (!data) return;

  const s = data.summary || {};
  document.getElementById('s-iocs').textContent    = (s.total_iocs    || 0).toLocaleString();
  document.getElementById('s-pulses').textContent  = (s.total_pulses  || 0).toLocaleString();
  document.getElementById('s-ips').textContent     = (s.ip_count      || 0).toLocaleString();
  document.getElementById('s-domains').textContent = (s.domain_count  || 0).toLocaleString();
  document.getElementById('s-hashes').textContent  = (s.hash_count    || 0).toLocaleString();
  document.getElementById('s-rules').textContent   = (s.rule_count    || 0).toLocaleString();
  document.getElementById('s-rels').textContent    = (s.relationship_count || 0).toLocaleString();
  document.getElementById('s-clusters').textContent= (s.cluster_count || 0).toLocaleString();
  document.getElementById('last-updated').textContent = 'Updated ' + new Date().toLocaleTimeString();

  renderTypeDistChart(data.type_distribution || []);
  renderMalwareChart(data.malware_distribution || []);
  renderCountryChart(data.country_distribution || []);
  renderRecentIOCs(data.recent_iocs || []);
}

function renderTypeDistChart(data) {
  const ctx = document.getElementById('chart-type-dist');
  if (!ctx) return;
  if (State.charts.typeDist) State.charts.typeDist.destroy();
  if (!data.length) return;
  const COLORS = ['#ef4444','#3b82f6','#8b5cf6','#10b981','#f97316','#f59e0b','#14b8a6','#ec4899'];
  State.charts.typeDist = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: data.map(d => d.ioc_type),
      datasets: [{ data: data.map(d => d.cnt), backgroundColor: COLORS, borderWidth: 2, borderColor: '#fff' }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 10 } } }
    }
  });
}

function renderMalwareChart(data) {
  const ctx = document.getElementById('chart-malware');
  if (!ctx) return;
  if (State.charts.malware) State.charts.malware.destroy();
  if (!data.length) return;
  State.charts.malware = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => d.malware_family.length > 14 ? d.malware_family.slice(0,14)+'…' : d.malware_family),
      datasets: [{ data: data.map(d => d.cnt), backgroundColor: '#3b82f6', borderRadius: 4 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: { x: { grid: { color: '#f1f5f9' } }, y: { grid: { display: false } } }
    }
  });
}

function renderCountryChart(data) {
  const ctx = document.getElementById('chart-countries');
  if (!ctx) return;
  if (State.charts.countries) State.charts.countries.destroy();
  if (!data.length) return;
  const COLORS = ['#ef4444','#f97316','#f59e0b','#10b981','#14b8a6','#3b82f6','#6366f1','#8b5cf6','#ec4899','#64748b'];
  State.charts.countries = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: data.map(d => d.country),
      datasets: [{ data: data.map(d => d.cnt), backgroundColor: COLORS, borderWidth: 2, borderColor: '#fff' }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 10 } } }
    }
  });
}

function renderRecentIOCs(iocs) {
  const tbody = document.getElementById('recent-ioc-tbody');
  if (!tbody) return;
  if (!iocs.length) { tbody.innerHTML = `<tr><td colspan="7">${emptyState('No IOCs yet — sync some data!')}</td></tr>`; return; }
  tbody.innerHTML = iocs.map(ioc => `
    <tr onclick="openIOCDetail(${ioc.id})">
      <td class="indicator-cell" title="${ioc.indicator}">${ioc.indicator}</td>
      <td>${typeBadge(ioc.ioc_type)}</td>
      <td>${ioc.malware_family}</td>
      <td>${ioc.country}</td>
      <td><span class="pulse-tag">${(ioc.pulse_name||'').slice(0,28)}</span></td>
      <td>${tlpBadge(ioc.tlp)}</td>
      <td>${fmtDate(ioc.created)}</td>
    </tr>`).join('');
}

// ── IOC EXPLORER ─────────────────────────────────────────────────────────────
async function loadIOCs() {
  State.iocSearch = document.getElementById('ioc-search')?.value.trim() || '';
  State.iocType   = document.getElementById('ioc-type-filter')?.value || '';
  const tbody = document.getElementById('ioc-tbody');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="8">${spinner()}</td></tr>`;

  const qs = new URLSearchParams({
    page: State.iocPage, per_page: 25,
    ...(State.iocType   && { type: State.iocType }),
    ...(State.iocSearch && { search: State.iocSearch }),
  });
  const data = await api(`/api/iocs?${qs}`);
  if (!data) return;

  document.getElementById('ioc-total-badge').textContent = `${data.total.toLocaleString()} results`;

  if (!data.data.length) {
    tbody.innerHTML = `<tr><td colspan="8">${emptyState()}</td></tr>`;
    return;
  }

  tbody.innerHTML = data.data.map(ioc => `
    <tr onclick="openIOCDetail(${ioc.id})">
      <td class="indicator-cell" title="${ioc.indicator}">${ioc.indicator}</td>
      <td>${typeBadge(ioc.ioc_type)}</td>
      <td>${ioc.malware_family}</td>
      <td>${ioc.country}</td>
      <td><span style="font-size:11px;color:var(--text-4)">${ioc.asn.slice(0,22)}</span></td>
      <td><span class="pulse-tag" title="${ioc.pulse_name}">${(ioc.pulse_name||'').slice(0,24)}</span></td>
      <td>${tlpBadge(ioc.tlp)}</td>
      <td>${fmtDate(ioc.created)}</td>
    </tr>`).join('');

  renderPagination(data.total, data.page, 25, 'ioc-pagination', p => { State.iocPage = p; loadIOCs(); });
}

function renderPagination(total, current, perPage, containerId, onPage) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const pages = Math.ceil(total / perPage);
  if (pages <= 1) { container.innerHTML = ''; return; }
  const visible = [];
  for (let i = Math.max(1, current - 2); i <= Math.min(pages, current + 2); i++) visible.push(i);
  container.innerHTML = [
    `<button ${current===1?'disabled':''} onclick="(${onPage})(${current-1})">← Prev</button>`,
    ...visible.map(p => `<button class="${p===current?'active':''}" onclick="(${onPage})(${p})">${p}</button>`),
    `<button ${current===pages?'disabled':''} onclick="(${onPage})(${current+1})">Next →</button>`,
  ].join('');
}

// ── IOC DETAIL PANEL ─────────────────────────────────────────────────────────
async function openIOCDetail(iocId) {
  const overlay = document.getElementById('ioc-detail-overlay');
  const content = document.getElementById('detail-content');
  overlay.classList.add('open');
  content.innerHTML = spinner();

  const data = await api(`/api/iocs/${iocId}`);
  if (!data) { content.innerHTML = emptyState('Failed to load IOC'); return; }

  const ioc = data.ioc;
  const enr = data.enrichment || {};
  const rules = data.rules || [];
  const rels = data.relationships || [];

  // Summary shown immediately
  content.innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px;">
      ${typeBadge(ioc.ioc_type)} ${tlpBadge(ioc.tlp||'white')}
      <span class="badge badge-blue">${ioc.stix_type}</span>
    </div>
    <h2 style="font-size:16px;font-weight:800;margin:10px 0 4px;">${ioc.title}</h2>
    <div class="detail-indicator">${ioc.indicator}</div>
    <p style="font-size:13px;color:var(--text-3);margin-bottom:16px;">${ioc.description}</p>

    <div class="detail-meta-grid">
      <div class="detail-meta-item"><div class="detail-meta-label">Malware Family</div><div class="detail-meta-value" style="color:var(--red)">${ioc.malware_family}</div></div>
      <div class="detail-meta-item"><div class="detail-meta-label">Country</div><div class="detail-meta-value">${ioc.country}</div></div>
      <div class="detail-meta-item"><div class="detail-meta-label">ASN</div><div class="detail-meta-value" style="font-size:12px">${ioc.asn}</div></div>
      <div class="detail-meta-item"><div class="detail-meta-label">Reputation</div><div class="detail-meta-value" style="color:${ioc.reputation<0?'var(--red)':'var(--green)'}">${ioc.reputation}</div></div>
      <div class="detail-meta-item"><div class="detail-meta-label">First Seen</div><div class="detail-meta-value">${fmtDate(ioc.first_seen)}</div></div>
      <div class="detail-meta-item"><div class="detail-meta-label">Last Seen</div><div class="detail-meta-value">${fmtDate(ioc.last_seen)}</div></div>
      <div class="detail-meta-item"><div class="detail-meta-label">STIX ID</div><div class="detail-meta-value" style="font-size:11px;word-break:break-all">${ioc.stix_id||'—'}</div></div>
      <div class="detail-meta-item"><div class="detail-meta-label">Active</div><div class="detail-meta-value" style="color:${ioc.is_active?'var(--green)':'var(--red)'}">${ioc.is_active?'Yes':'No'}</div></div>
    </div>

    <!-- EXPANDABLE ENRICHMENT -->
    <div class="detail-section" id="detail-enrichment-section" style="display:none">
      <h4>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        Enrichment Details
      </h4>
      ${renderEnrichment(enr, ioc.ioc_type)}
    </div>

    <!-- EXPANDABLE RELATIONSHIPS -->
    <div class="detail-section" id="detail-rels-section" style="display:none">
      <h4>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
        Relationships (${rels.length})
      </h4>
      ${renderRelationships(rels)}
    </div>

    <!-- EXPANDABLE DETECTION RULES -->
    <div class="detail-section" id="detail-rules-section" style="display:none">
      <h4>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        Detection Rules (${rules.length})
      </h4>
      ${rules.length ? renderRulesInDetail(rules) : '<p style="color:var(--text-4);font-size:13px;">No rules generated yet.</p>'}
    </div>

    <!-- EXPANDABLE STIX JSON -->
    <div class="detail-section" id="detail-stix-section" style="display:none">
      <h4>STIX 2.1 Object</h4>
      <button class="code-copy-btn" onclick="copyToClipboard(document.getElementById('stix-code-block').textContent)">Copy</button>
      <div class="code-block" id="stix-code-block">${JSON.stringify(JSON.parse(ioc.stix_json||'{}'), null, 2)}</div>
    </div>

    <!-- EXPAND BUTTONS -->
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:16px;padding-top:14px;border-top:1px solid var(--border);">
      <button class="btn btn-outline btn-sm" onclick="toggleSection('detail-enrichment-section', this)">▶ Enrichment</button>
      <button class="btn btn-outline btn-sm" onclick="toggleSection('detail-rels-section', this)">▶ Relationships</button>
      <button class="btn btn-outline btn-sm" onclick="generateAndShowRules(${iocId})">▶ Generate Rules</button>
      <button class="btn btn-outline btn-sm" onclick="toggleSection('detail-stix-section', this)">▶ STIX JSON</button>
    </div>
  `;
}

function toggleSection(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  const open = el.style.display !== 'none';
  el.style.display = open ? 'none' : 'block';
  btn.textContent = (open ? '▶ ' : '▼ ') + btn.textContent.slice(2);
}

async function generateAndShowRules(iocId) {
  toast('Generating detection rules…', 'info');
  const rules = await api(`/api/iocs/${iocId}/rules`);
  if (!rules) return;
  const section = document.getElementById('detail-rules-section');
  if (section) {
    section.style.display = 'block';
    const ruleList = [
      { type: 'sigma',    content: rules.sigma    },
      { type: 'yara',     content: rules.yara     },
      { type: 'suricata', content: rules.suricata },
      { type: 'snort',    content: rules.snort    },
    ];
    section.querySelector('p, .rules-detail-content')?.remove();
    const existing = section.querySelector('.rules-detail-content');
    if (!existing) {
      const div = document.createElement('div');
      div.className = 'rules-detail-content';
      div.innerHTML = renderRulesInDetail(ruleList.map(r => ({ rule_type: r.type, rule_content: r.content, rule_name: r.type.toUpperCase() + ' Rule' })));
      section.appendChild(div);
    }
    toast('Rules generated!', 'success');
  }
}

function renderEnrichment(enr, iocType) {
  if (!enr || !Object.keys(enr).length) return '<p style="color:var(--text-4);font-size:13px;">No enrichment data available.</p>';
  const rows = [];
  if (enr.geo_country && enr.geo_country !== 'Unknown') rows.push(['Country', enr.geo_country]);
  if (enr.geo_city    && enr.geo_city    !== 'Unknown') rows.push(['City', enr.geo_city]);
  if (enr.geo_region  && enr.geo_region  !== 'Unknown') rows.push(['Region', enr.geo_region]);
  if (enr.asn_number  && enr.asn_number  !== 'Unknown') rows.push(['ASN', `${enr.asn_number} ${enr.asn_name}`]);
  if (enr.asn_cidr    && enr.asn_cidr    !== '0.0.0.0/0') rows.push(['CIDR', enr.asn_cidr]);
  if (enr.whois_registrar && enr.whois_registrar !== 'Unknown') rows.push(['Registrar', enr.whois_registrar]);
  if (enr.whois_org       && enr.whois_org       !== 'Unknown') rows.push(['Org', enr.whois_org]);
  if (enr.whois_created   && enr.whois_created   !== 'Unknown') rows.push(['WHOIS Created', enr.whois_created]);
  if (enr.file_hash_sha256 && enr.file_hash_sha256 !== '') rows.push(['SHA-256', enr.file_hash_sha256]);
  if (enr.file_hash_md5    && enr.file_hash_md5    !== '') rows.push(['MD5', enr.file_hash_md5]);
  if (enr.file_type && enr.file_type !== 'Unknown') rows.push(['File Type', enr.file_type]);
  if (enr.url_domain && enr.url_domain !== '') rows.push(['URL Domain', enr.url_domain]);
  if (enr.url_protocol && enr.url_protocol !== '') rows.push(['Protocol', enr.url_protocol]);
  if (!rows.length) return '<p style="color:var(--text-4);font-size:13px;">No enrichment fields populated.</p>';
  return `<div class="detail-meta-grid">${rows.map(([k,v]) => `
    <div class="detail-meta-item">
      <div class="detail-meta-label">${k}</div>
      <div class="detail-meta-value" style="font-size:12px;word-break:break-all">${v}</div>
    </div>`).join('')}</div>`;
}

function renderRelationships(rels) {
  if (!rels.length) return '<p style="color:var(--text-4);font-size:13px;">No relationships detected yet.</p>';
  return `<div style="display:flex;flex-direction:column;gap:8px;">
    ${rels.map(r => `
      <div style="background:var(--surface2);border:1px solid var(--border);border-radius:7px;padding:10px 12px;display:flex;align-items:center;gap:10px;">
        <span style="font-size:12px;font-weight:600;color:var(--blue)">${r.relationship_type}</span>
        <span style="font-size:11px;color:var(--text-4)">→</span>
        <code style="font-size:12px;color:var(--text-1)">${r.related_indicator}</code>
        ${typeBadge(r.related_type)}
        <span style="margin-left:auto;font-size:11px;color:var(--text-4)">conf: ${r.confidence}%</span>
      </div>`).join('')}
  </div>`;
}

function renderRulesInDetail(rules) {
  if (!rules.length) return '';
  const tabs = ['sigma', 'yara', 'suricata', 'snort'];
  const ruleMap = {};
  rules.forEach(r => { ruleMap[r.rule_type] = r.rule_content; });
  const uid = 'rt_' + Math.random().toString(36).slice(2);

  return `
    <div class="rule-tab-bar" id="${uid}-tabs">
      ${tabs.filter(t => ruleMap[t]).map((t,i) => `
        <button class="rule-tab ${i===0?'active':''}" onclick="switchRuleTab('${uid}','${t}',this)">${t.toUpperCase()}</button>
      `).join('')}
    </div>
    ${tabs.filter(t => ruleMap[t]).map((t,i) => `
      <div id="${uid}-${t}" style="${i!==0?'display:none':''}">
        <button class="code-copy-btn" onclick="copyToClipboard(document.getElementById('${uid}-code-${t}').textContent)">Copy</button>
        <div class="code-block" id="${uid}-code-${t}">${escHtml(ruleMap[t]||'')}</div>
      </div>
    `).join('')}
  `;
}

function switchRuleTab(uid, type, btn) {
  const tabs = ['sigma','yara','suricata','snort'];
  tabs.forEach(t => {
    const el = document.getElementById(`${uid}-${t}`);
    if (el) el.style.display = t === type ? 'block' : 'none';
  });
  document.querySelectorAll(`#${uid}-tabs .rule-tab`).forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

function escHtml(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function closeDetail(e) {
  if (e.target === document.getElementById('ioc-detail-overlay')) closeDetailPanel();
}
function closeDetailPanel() {
  document.getElementById('ioc-detail-overlay').classList.remove('open');
}

// ── PULSES ───────────────────────────────────────────────────────────────────
async function loadPulses() {
  const grid = document.getElementById('pulse-grid');
  if (!grid) return;
  grid.innerHTML = spinner();
  const data = await api('/api/pulses?limit=50');
  if (!data) return;
  document.getElementById('pulse-total-badge').textContent = `${data.length} pulses`;
  if (!data.length) { grid.innerHTML = emptyState('No pulses — sync data first!'); return; }

  grid.innerHTML = data.map(p => {
    const tags = JSON.parse(p.tags || '[]').slice(0, 5);
    const mf   = JSON.parse(p.malware_families || '[]').slice(0, 3);
    return `
      <div class="pulse-card" onclick="openPulseDetail('${p.id}')">
        <div class="pulse-card-header">
          <div class="pulse-card-title">${p.name}</div>
          ${tlpBadge(p.tlp)}
        </div>
        <div class="pulse-card-body">${p.description}</div>
        <div class="pulse-card-footer">
          <span class="pulse-ioc-count">${p.ioc_count} IOCs</span>
          ${p.adversary !== 'Unknown' ? `<span class="pulse-adversary">${p.adversary}</span>` : ''}
          <span class="pulse-card-meta">${fmtDate(p.modified)}</span>
        </div>
        ${tags.length ? `<div class="pulse-tags">${tags.map(t => `<span class="pulse-tag">${t}</span>`).join('')}</div>` : ''}
        ${mf.length  ? `<div class="pulse-tags" style="margin-top:4px">${mf.map(m => `<span class="pulse-tag" style="background:var(--red-light);color:var(--red)">${typeof m==='string'?m:m.display_name||m}</span>`).join('')}</div>` : ''}
      </div>`;
  }).join('');
}

async function openPulseDetail(pulseId) {
  // Navigate to IOC explorer filtered by this pulse
  navigateTo('iocs');
  await new Promise(r => setTimeout(r, 100));
  const qs = new URLSearchParams({ page: 1, per_page: 25, pulse_id: pulseId });
  const data = await api(`/api/iocs?${qs}`);
  if (!data) return;
  document.getElementById('ioc-total-badge').textContent = `${data.total.toLocaleString()} results (pulse filter)`;
  const tbody = document.getElementById('ioc-tbody');
  if (!data.data.length) { tbody.innerHTML = `<tr><td colspan="8">${emptyState()}</td></tr>`; return; }
  tbody.innerHTML = data.data.map(ioc => `
    <tr onclick="openIOCDetail(${ioc.id})">
      <td class="indicator-cell" title="${ioc.indicator}">${ioc.indicator}</td>
      <td>${typeBadge(ioc.ioc_type)}</td>
      <td>${ioc.malware_family}</td>
      <td>${ioc.country}</td>
      <td style="font-size:11px;color:var(--text-4)">${ioc.asn.slice(0,22)}</td>
      <td><span class="pulse-tag">${(ioc.pulse_name||'').slice(0,24)}</span></td>
      <td>${tlpBadge(ioc.tlp)}</td>
      <td>${fmtDate(ioc.created)}</td>
    </tr>`).join('');
}

// ── RELATIONSHIPS ─────────────────────────────────────────────────────────────
async function loadClusters() {
  const list = document.getElementById('cluster-list');
  if (!list) return;
  list.innerHTML = spinner();
  const data = await api('/api/relationships/clusters');
  if (!data) return;
  if (!data.length) {
    list.innerHTML = `<div class="empty-state"><p>No clusters detected yet. Run the detectors first.</p></div>`;
    return;
  }
  list.innerHTML = data.map(c => {
    const meta = JSON.parse(c.metadata || '{}');
    return `
      <div class="cluster-card" onclick="viewClusterGraph(${c.id})">
        <div class="cluster-header">
          <div class="cluster-name">${c.cluster_name}</div>
          <span class="cluster-type-badge ctype-${c.cluster_type}">${c.cluster_type.replace('_',' ')}</span>
        </div>
        <div class="cluster-desc">${c.description}</div>
        <div class="cluster-footer">
          ${severitySpan(c.severity)}
          <span>•</span>
          <span>${JSON.parse(c.ioc_ids||'[]').length} IOCs</span>
          <span>•</span>
          <span>${fmtDate(c.detected_at)}</span>
        </div>
      </div>`;
  }).join('');
}

async function detectRelationships() {
  const status = document.getElementById('rel-status');
  status.textContent = 'Running detectors…';
  const data = await api('/api/relationships/detect', { method: 'POST' });
  if (!data) return;
  status.textContent = `Found ${data.clusters} clusters, ${data.relationships} relationships`;
  toast(`Detected ${data.clusters} clusters!`, 'success');
  loadClusters();
}

async function buildGraph() {
  const status = document.getElementById('rel-status');
  status.textContent = 'Building graph…';
  const data = await api('/api/relationships/build-graph', { method: 'POST' });
  if (!data) return;
  const iframe = document.getElementById('graph-iframe');
  const placeholder = document.getElementById('graph-placeholder');
  iframe.src = data.path + '?t=' + Date.now();
  iframe.style.display = 'block';
  if (placeholder) placeholder.style.display = 'none';
  status.textContent = 'Graph built!';
  toast('Relationship graph ready', 'success');
}

async function viewClusterGraph(clusterId) {
  const status = document.getElementById('rel-status');
  status.textContent = 'Building cluster graph…';
  const data = await api(`/api/relationships/cluster-graph/${clusterId}`, { method: 'POST' });
  if (!data) return;
  const iframe = document.getElementById('graph-iframe');
  const placeholder = document.getElementById('graph-placeholder');
  iframe.src = data.path + '?t=' + Date.now();
  iframe.style.display = 'block';
  if (placeholder) placeholder.style.display = 'none';
  status.textContent = 'Cluster graph loaded';
}

// ── DETECTION RULES ───────────────────────────────────────────────────────────
async function loadRules() {
  const list = document.getElementById('rules-list');
  const summary = document.getElementById('rules-summary');
  if (!list) return;
  list.innerHTML = spinner();

  const [rules, sumData] = await Promise.all([
    api(`/api/rules${State.ruleType ? '?type=' + State.ruleType : ''}`),
    api('/api/rules/summary'),
  ]);

  if (sumData) {
    const byType = {};
    (sumData.by_type || []).forEach(r => { byType[r.rule_type] = r.cnt; });
    summary.innerHTML = ['sigma','yara','suricata','snort'].map(t => `
      <div class="rule-count-card">
        <div class="rule-count-num ${t}">${(byType[t]||0).toLocaleString()}</div>
        <div>
          <div style="font-weight:700;font-size:13px">${t.toUpperCase()}</div>
          <div style="font-size:11px;color:var(--text-4)">rules</div>
        </div>
      </div>`).join('');
  }

  if (!rules || !rules.length) {
    list.innerHTML = emptyState('No rules yet — generate them from IOCs!');
    return;
  }

  list.innerHTML = rules.map(r => `
    <div class="rule-card">
      <div class="rule-card-header" onclick="toggleRuleBody(this)">
        <span class="rule-type-tag rule-type-${r.rule_type}">${r.rule_type.toUpperCase()}</span>
        <span class="rule-name-text">${r.rule_name}</span>
        ${r.severity ? severitySpan(r.severity) : ''}
        <span style="margin-left:auto;font-size:11px;color:var(--text-4)">${fmtDate(r.created_at)}</span>
        <span style="color:var(--text-4);font-size:13px;margin-left:8px">▶</span>
      </div>
      <div class="rule-body">
        <p style="font-size:12px;color:var(--text-3);margin-bottom:8px">${r.description}</p>
        <button class="code-copy-btn" onclick="copyToClipboard(this.nextElementSibling.textContent)">Copy</button>
        <div class="code-block">${escHtml(r.rule_content)}</div>
      </div>
    </div>`).join('');

  // Wire up type tabs
  document.querySelectorAll('#rule-type-tabs .tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#rule-type-tabs .tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      State.ruleType = btn.dataset.type;
      loadRules();
    });
  });
}

function toggleRuleBody(header) {
  const body = header.nextElementSibling;
  const open = body.classList.toggle('open');
  header.querySelector('span:last-child').textContent = open ? '▼' : '▶';
}

async function generateAllRules() {
  const status = document.getElementById('rules-status');
  status.textContent = 'Generating rules for all IOCs…';
  const data = await api('/api/rules/generate-all', { method: 'POST' });
  if (!data) return;
  status.textContent = `Generated rules for ${data.rules_generated_for} IOCs`;
  toast(`Rules generated for ${data.rules_generated_for} IOCs!`, 'success');
  loadRules();
}

// ── STIX BUNDLES ──────────────────────────────────────────────────────────────
async function loadStixBundles() {
  const list = document.getElementById('stix-list');
  if (!list) return;
  list.innerHTML = spinner();
  const data = await api('/api/stix/bundles');
  if (!data || !data.length) { list.innerHTML = emptyState('No STIX bundles yet'); return; }

  list.innerHTML = data.map(b => `
    <div class="stix-bundle-card">
      <div class="stix-bundle-header">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
        <div>
          <div style="font-weight:700;font-size:13px">Bundle for Pulse</div>
          <div class="stix-bundle-id">${b.pulse_id}</div>
        </div>
        <span class="stix-object-count">${b.object_count} objects</span>
        <span style="margin-left:8px;font-size:11px;color:var(--text-4)">${fmtDate(b.created_at)}</span>
        <button class="btn btn-outline btn-sm stix-view-btn" onclick="viewStixBundle('${b.pulse_id}', this)">View JSON</button>
      </div>
      <div class="stix-bundle-body" id="stix-body-${b.id}" style="display:none;margin-top:10px"></div>
    </div>`).join('');
}

async function viewStixBundle(pulseId, btn) {
  const card = btn.closest('.stix-bundle-card');
  const body = card.querySelector('.stix-bundle-body');
  if (body.style.display !== 'none') { body.style.display = 'none'; btn.textContent = 'View JSON'; return; }
  body.innerHTML = spinner();
  body.style.display = 'block';
  btn.textContent = 'Hide';
  const data = await api(`/api/pulses/${pulseId}/stix-bundle`);
  if (!data) { body.innerHTML = emptyState('Failed to load'); return; }
  body.innerHTML = `
    <button class="code-copy-btn" onclick="copyToClipboard(this.nextElementSibling.textContent)">Copy JSON</button>
    <div class="code-block">${escHtml(JSON.stringify(data, null, 2))}</div>`;
}

// ── INGEST ────────────────────────────────────────────────────────────────────
async function ingestOTX() {
  const key = document.getElementById('otx-api-key').value.trim();
  const days = document.getElementById('otx-days-back').value;
  const result = document.getElementById('ingest-result');
  if (!key) { toast('Please enter your OTX API key', 'error'); return; }
  result.style.display = 'block';
  result.className = 'ingest-result loading';
  result.textContent = 'Fetching data from AlienVault OTX…';
  const data = await api('/api/ingest/otx', {
    method: 'POST',
    body: JSON.stringify({ api_key: key, days_back: parseInt(days) }),
  });
  if (!data) { result.className = 'ingest-result error'; result.textContent = 'Request failed.'; return; }
  if (data.status === 'success') {
    result.className = 'ingest-result success';
    result.textContent = `✓ Fetched ${data.pulses} pulses and ${data.iocs} IOCs successfully!`;
    toast(`Ingested ${data.iocs} IOCs from OTX`, 'success');
  } else {
    result.className = 'ingest-result error';
    result.textContent = `✗ Error: ${data.error}`;
  }
  loadSyncHistory();
}

async function loadDemo() {
  const result = document.getElementById('ingest-result');
  result.style.display = 'block';
  result.className = 'ingest-result loading';
  result.textContent = 'Loading demo threat intel data…';
  const data = await api('/api/ingest/demo', { method: 'POST' });
  if (data && data.status === 'success') {
    result.className = 'ingest-result success';
    result.textContent = `✓ Loaded ${data.pulses} demo pulses successfully!`;
    toast('Demo data loaded!', 'success');
  } else {
    result.className = 'ingest-result error';
    result.textContent = '✗ Failed to load demo data.';
  }
  loadSyncHistory();
}

async function loadSyncHistory() {
  const container = document.getElementById('sync-history');
  if (!container) return;
  const data = await api('/api/sync/history');
  if (!data || !data.length) { container.innerHTML = '<p style="color:var(--text-4);font-size:13px;">No sync history yet.</p>'; return; }
  container.innerHTML = `
    <table class="sync-history-table">
      <thead><tr><th>Type</th><th>Status</th><th>Pulses</th><th>IOCs</th><th>Started</th></tr></thead>
      <tbody>${data.map(r => `
        <tr>
          <td>${r.sync_type}</td>
          <td class="status-${r.status}">${r.status}</td>
          <td>${r.pulses_fetched}</td>
          <td>${r.iocs_fetched}</td>
          <td>${fmtDate(r.started_at)}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
}

// ── INIT ─────────────────────────────────────────────────────────────────────
navigateTo('dashboard');
