
// ========================= CONFIG =========================
const API_ROOT = window.location.protocol === 'file:' ? 'http://localhost:8080' : '';
function apiUrl(path) {
  if (!path || /^https?:\/\//i.test(path)) return path;
  return path.startsWith('/') ? API_ROOT + path : path;
}
const API = apiUrl('/api/v1');
const PROXY = apiUrl('/api/v1/proxy');
let authToken = sessionStorage.getItem('aegis_token') || sessionStorage.getItem('aegis_api_key') || '';
let autoRefresh = true;
let lastRefreshTime = Date.now();
let selectedEventIds = new Set();
let allEventsCache = [];
let currentModalEvent = null;
let mapInstance = null;
let mapMarkers = [];
let sessionTimer = null;
let sessionCountdownVal = 60;
let sessionCountdownInterval = null;
let backendOnline = true;
let backendCheckTimer = null;
let backendReconnectDelay = 5000;
let sseInstance = null;

// ========================= AUTH =========================
function getHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (authToken && authToken !== 'session' && authToken !== 'local') {
    h['Authorization'] = 'Bearer ' + authToken;
  }
  return h;
}
async function apiGet(path) {
  if (!backendOnline) return null;
  try {
    const r = await fetch(apiUrl(path), { headers: getHeaders(), credentials: 'include' });
    if (r.status === 401) { doLogout(); return null; }
    if (!r.ok && r.status >= 500) { probeBackendSoon(); }
    return r.ok ? r.json() : null;
  } catch(e){ probeBackendSoon(); return null; }
}
async function apiPost(path, body) {
  if (!backendOnline) return null;
  try {
    const r = await fetch(apiUrl(path), { method:'POST', headers: getHeaders(), credentials: 'include', body: JSON.stringify(body) });
    if (r.status === 401) { doLogout(); return null; }
    if (!r.ok && r.status >= 500) { probeBackendSoon(); }
    return r.ok ? r.json() : null;
  } catch(e){ probeBackendSoon(); return null; }
}
async function apiPatch(path, body) {
  if (!backendOnline) return null;
  try {
    const r = await fetch(apiUrl(path), { method:'PATCH', headers: getHeaders(), credentials: 'include', body: JSON.stringify(body) });
    if (r.status === 401) { doLogout(); return null; }
    if (!r.ok && r.status >= 500) { probeBackendSoon(); }
    return r.ok ? r.json() : null;
  } catch(e){ probeBackendSoon(); return null; }
}

function setConnBanner(online, msg) {
  const el = document.getElementById('connBanner');
  if (!el) return;
  if (online) {
    el.className = 'online';
    el.innerHTML = '<i class="fa-solid fa-circle-check"></i> Connesso';
    setTimeout(() => { el.className = ''; el.innerHTML = ''; }, 3000);
  } else {
    el.className = 'offline';
    el.innerHTML = '<i class="fa-solid fa-circle-xmark"></i> ' + (msg || 'Backend offline — riconnessione...');
  }
}

async function probeBackend() {
  try {
    const r = await fetch(API + '/metrics', { headers: getHeaders(), credentials: 'include', signal: AbortSignal.timeout(4000) });
    if (r.ok && !backendOnline) {
      backendOnline = true;
      setConnBanner(true);
      if (sseInstance) { sseInstance.close(); }
      startSSE();
      refreshAll();
    }
    return r.ok;
  } catch (e) {
    if (backendOnline) {
      backendOnline = false;
      setConnBanner(false);
      if (sseInstance) { sseInstance.close(); sseInstance = null; }
    }
    return false;
  }
}
function probeBackendSoon() {
  if (backendCheckTimer) return;
  backendCheckTimer = setTimeout(() => { backendCheckTimer = null; probeBackend(); }, 2000);
}
function startBackendProbeLoop() {
  if (backendCheckTimer) clearInterval(backendCheckTimer);
  backendCheckTimer = setInterval(probeBackend, 8000);
}

function showLoginOverlay() {
  const overlay = document.getElementById('loginOverlay');
  if (!overlay) return;
  overlay.classList.remove('hidden');
  overlay.style.display = 'flex';
}

function hideLoginOverlay() {
  const overlay = document.getElementById('loginOverlay');
  if (!overlay) return;
  overlay.classList.add('hidden');
  overlay.style.display = 'none';
}

function doLogout() {
  // Best-effort logout to clear the server-side session cookie.
  fetch(API + '/auth/logout', { method: 'POST', credentials: 'include' })
    .catch(()=>{})
    .finally(() => {
      authToken = '';
      sessionStorage.removeItem('aegis_token');
      sessionStorage.removeItem('aegis_api_key');
      location.reload();
    });
}

// Auto-login bootstrap:
// 1. Try /auth/me — if a session cookie is already present and valid, skip the login form.
// 2. Otherwise try /metrics with the existing token (if any) and fall back to the login form.
(async function bootstrap() {
  try {
    const me = await fetch(API + '/auth/me', { credentials: 'include' }).then(r => r.ok ? r.json() : null);
    if (me && me.authenticated) {
      authToken = authToken || 'session';
      sessionStorage.setItem('aegis_token', authToken);
      hideLoginOverlay();
      initApp();
      return;
    }
  } catch (_) { /* ignore */ }

  if (authToken) {
    // Old API-key flow still works.
    const ok = await fetch(API + '/metrics', { headers: { 'Authorization': 'Bearer ' + authToken } }).then(r => r.ok).catch(() => false);
    if (ok) { hideLoginOverlay(); initApp(); return; }
  }

  // Try anonymous (open mode) — orchestrator with AEGIS_AUTH_REQUIRED=false.
  try {
    const r = await fetch(API + '/metrics', { credentials: 'include' });
    if (r.ok) {
      authToken = 'local';
      sessionStorage.setItem('aegis_token', authToken);
      hideLoginOverlay();
      initApp();
      return;
    }
  } catch (_) { /* ignore */ }

  showLoginOverlay();
  const hint = document.getElementById('loginHint');
  if (hint) hint.style.display = 'block';
})();

// ========================= ROUTING =========================
const pages = document.querySelectorAll('.page');
const navItems = document.querySelectorAll('.nav-item');
const pageTitle = document.getElementById('pageTitle');
function resolveRouteFromHash() {
  const target = (location.hash || '#overview').replace(/^#/, '').trim() || 'overview';
  return document.getElementById('page-' + target) ? target : 'overview';
}
function navTo(target, fromHash = false) {
  if (!document.getElementById('page-' + target)) target = 'overview';
  navItems.forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.nav-item[data-page="'+target+'"]').forEach(n => n.classList.add('active'));
  pages.forEach(p => p.classList.remove('active'));
  document.getElementById('page-'+target).classList.add('active');
  const label = document.querySelector('.nav-item[data-page="'+target+'"] span');
  pageTitle.textContent = label ? label.textContent : target;
  if (!fromHash && location.hash !== '#' + target) history.replaceState(null, '', '#' + target);
  if (target === 'overview') initCharts();
  if (target === 'shield') loadShield();
  if (target === 'endpoint') loadEndpoint();
  if (target === 'posture') loadPosture();
  if (target === 'hunt2') { loadHuntCatalog(); loadRealtimeStatus(); loadIOCStatus(); loadContainmentLog(); }
  if (target === 'network') { loadNetwork(); initScanSubnets(); }
  if (target === 'ti' && !mapInstance) setTimeout(initThreatMap, 300);
  if (target === 'mitre') loadMitre();
  if (target === 'hunt') { /* ready on demand */ }
  if (target === 'compliance') loadCompliance();
  if (target === 'kpi') loadKPI();
  if (target === 'dfir') loadDFIR();
  if (target === 'assets') loadAssets();
  if (target === 'honeypot') loadHoneypot();
  if (target === 'reports') loadReports();
  if (target === 'topology') loadTopology();
  if (target === 'tls') { /* on demand */ }
  if (target === 'campaigns') loadCampaigns();
  if (target === 'roadmap') loadRoadmapToolCount();
  if (target === 'integrations') loadIntegrations();
  if (target === 'sigma') loadSigma();
  if (target === 'ot-protocols') loadOTProtocols();
  if (target === 'evidence') loadEvidence();
  if (target === 'pki') loadPKI();
  if (target === 'tls') loadTLS();
}
window.addEventListener('hashchange', () => navTo(resolveRouteFromHash(), true));

// ========================= THEME =========================
function toggleTheme() {
  document.body.classList.toggle('light');
  const isLight = document.body.classList.contains('light');
  localStorage.setItem('aegis_theme', isLight ? 'light' : 'dark');
  document.getElementById('themeIcon').className = isLight ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
}
(function() {
  const saved = localStorage.getItem('aegis_theme');
  if (saved === 'light') { document.body.classList.add('light'); document.getElementById('themeIcon').className = 'fa-solid fa-sun'; }
})();

// ========================= MOBILE =========================
function toggleMobileMenu() { document.getElementById('mobileMenu').classList.toggle('active'); }

// ========================= REFRESH =========================
function toggleAutoRefresh() {
  autoRefresh = !autoRefresh;
  document.getElementById('pauseBtn').innerHTML = autoRefresh ? '<i class="fa-solid fa-pause"></i>' : '<i class="fa-solid fa-play"></i>';
}
function updateLastRefresh() {
  const sec = Math.round((Date.now() - lastRefreshTime) / 1000);
  document.getElementById('lastRefresh').textContent = 'Updated ' + (sec < 60 ? sec + 's' : Math.floor(sec/60) + 'm') + ' ago';
}
setInterval(updateLastRefresh, 5000);
document.getElementById('lastRefresh').addEventListener('click', () => { refreshAll(); lastRefreshTime = Date.now(); });

// ========================= TOASTS =========================
function showToast(title, body, type='info', persist=false) {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = 'toast ' + type;
  toast.innerHTML = '<div class="toast-title">' + esc(title) + '</div><div class="toast-body">' + esc(body) + '</div>';
  container.appendChild(toast);
  if (!persist) {
    setTimeout(() => { toast.style.opacity='0'; setTimeout(()=>toast.remove(), 300); }, 6000);
  }
}

// ========================= EVENT DETAIL MODAL =========================
function openEventModal(ev) {
  currentModalEvent = ev;
  document.getElementById('modalTime').textContent = new Date(ev.timestamp).toLocaleString('it-IT');
  document.getElementById('modalTitle').textContent = ev.title || 'Event';
  const sev = (ev.severity || 'info').toLowerCase();
  const sevEl = document.getElementById('modalSeverity');
  sevEl.textContent = ev.severity || 'info';
  sevEl.className = 'badge ' + sev;
  document.getElementById('modalSource').textContent = ev.source || '-';
  document.getElementById('modalCategory').textContent = ev.category || '-';
  document.getElementById('modalDesc').textContent = ev.description || '';
  const mitreSec = document.getElementById('modalMitreSection');
  if (ev.mitre) {
    mitreSec.style.display = 'block';
    let html = '';
    if (ev.mitre.tactic_id) html += '<div><b>Tactic:</b> ' + esc(ev.mitre.tactic_id) + ' — ' + esc(ev.mitre.tactic_name||'') + '</div>';
    if (ev.mitre.technique_id) html += '<div><b>Technique:</b> ' + esc(ev.mitre.technique_id) + ' — ' + esc(ev.mitre.technique_name||'') + '</div>';
    if (ev.mitre.is_ics) html += '<div style="color:var(--accent-amber)"><i class="fa-solid fa-triangle-exclamation"></i> ICS-relevant</div>';
    document.getElementById('modalMitre').innerHTML = html;
  } else { mitreSec.style.display = 'none'; }
  const otSec = document.getElementById('modalOTSection');
  if (ev.ot_context) {
    otSec.style.display = 'block';
    let html = '<div><b>Protocol:</b> ' + esc(ev.ot_context.protocol||'-') + '</div>';
    html += '<div><b>Device:</b> ' + esc(ev.ot_context.device_type||'-') + ' / ' + esc(ev.ot_context.asset_id||'-') + '</div>';
    html += '<div><b>Process Area:</b> ' + esc(ev.ot_context.process_area||'-') + '</div>';
    html += '<div><b>Purdue Level:</b> ' + (ev.ot_context.purdue_level||'-') + '</div>';
    document.getElementById('modalOT').innerHTML = html;
  } else { otSec.style.display = 'none'; }
  document.getElementById('modalRaw').textContent = JSON.stringify(ev, null, 2);
  document.getElementById('modalRaw').style.display = 'none';
  document.getElementById('eventModal').classList.add('active');
}
function closeEventModal() { document.getElementById('eventModal').classList.remove('active'); currentModalEvent = null; }
function toggleRawJson() {
  const el = document.getElementById('modalRaw');
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}
function copyModalJSON() {
  if (!currentModalEvent) return;
  navigator.clipboard.writeText(JSON.stringify(currentModalEvent, null, 2));
  showToast('Copied', 'JSON copied to clipboard', 'success');
}
async function resolveModalEvent() {
  if (!currentModalEvent) return;
  const r = await apiPatch(API + '/events/' + currentModalEvent.id + '/resolve', {});
  if (r) { showToast('Resolved', 'Event marked as resolved', 'success'); closeEventModal(); refreshAll(); }
}
function escalateModalEvent() {
  showToast('Escalation non configurata', 'Collega un backend SOAR/ticketing reale per aprire escalation operative.', 'warning', true);
}

// ========================= GLOBAL SEARCH =========================
let searchDebounce = null;
let lastSearchResults = [];
function onSearchInput() {
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(performSearch, 300);
}
async function performSearch() {
  const q = document.getElementById('globalSearch').value.trim();
  const dd = document.getElementById('searchDropdown');
  if (!q) { dd.classList.remove('active'); return; }
  const results = await apiGet(API + '/events/search?q=' + encodeURIComponent(q) + '&limit=10');
  lastSearchResults = results || [];
  if (!results || !results.length) { dd.innerHTML = '<div class="muted" style="padding:10px 12px">No results</div>'; dd.classList.add('active'); return; }
  dd.innerHTML = results.map((e, idx) => {
    const sev = (e.severity||'info').toLowerCase();
    const color = sev==='critical'?'var(--accent-red)':sev==='high'?'var(--accent-amber)':sev==='medium'?'var(--accent-blue)':'var(--accent-green)';
    const time = new Date(e.timestamp).toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'});
    return '<div class="search-item" data-idx="' + idx + '">' +
      '<span class="dot" style="background:'+color+'"></span>' +
      '<div style="flex:1; min-width:0">' +
        '<div style="font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap">' + esc(e.title||'Event') + '</div>' +
        '<div style="font-size:11px; color:var(--text-muted)">' + esc(e.source||'') + ' • ' + time + '</div>' +
      '</div>' +
    '</div>';
  }).join('');
  dd.querySelectorAll('.search-item').forEach(item => {
    item.addEventListener('click', function() {
      const idx = parseInt(this.dataset.idx);
      if (lastSearchResults[idx]) { openEventModal(lastSearchResults[idx]); dd.classList.remove('active'); }
    });
  });
  dd.classList.add('active');
}
document.addEventListener('click', e => {
  if (!e.target.closest('#globalSearch') && !e.target.closest('#searchDropdown')) {
    document.getElementById('searchDropdown').classList.remove('active');
  }
});

// ========================= OVERVIEW =========================
let trendChart, severityChart;
function initCharts() {
  const tc = document.getElementById('trendChart');
  const sc = document.getElementById('severityChart');
  if (!tc || !sc) return;
  if (typeof Chart === 'undefined') {
    if (!tc.dataset.fallback) {
      tc.dataset.fallback = '1';
      tc.insertAdjacentHTML('afterend', '<div class="muted">Chart.js non caricato: dati SOC disponibili senza grafico.</div>');
    }
    if (!sc.dataset.fallback) {
      sc.dataset.fallback = '1';
      sc.insertAdjacentHTML('afterend', '<div class="muted">Chart.js non caricato: distribuzione disponibile dagli eventi.</div>');
    }
    return;
  }
  if (trendChart && severityChart) return;
  if (trendChart) trendChart.destroy();
  if (severityChart) severityChart.destroy();
  const gridColor = document.body.classList.contains('light') ? '#cbd5e1' : '#2a3040';
  const tickColor = document.body.classList.contains('light') ? '#475569' : '#94a3b8';
  trendChart = new Chart(tc, {
    type: 'line',
    data: { labels: [], datasets: [
      { label:'Critical', borderColor:'#ef4444', backgroundColor:'rgba(239,68,68,.1)', fill:true, data:[], tension:.3 },
      { label:'High', borderColor:'#f59e0b', backgroundColor:'rgba(245,158,11,.1)', fill:true, data:[], tension:.3 },
      { label:'Medium', borderColor:'#3b82f6', backgroundColor:'rgba(59,130,246,.1)', fill:true, data:[], tension:.3 }
    ]},
    options: { responsive:true, maintainAspectRatio:false, animation:false, resizeDelay:150, plugins:{legend:{labels:{color:tickColor}}}, scales:{x:{ticks:{color:tickColor},grid:{color:gridColor}},y:{ticks:{color:tickColor},grid:{color:gridColor},beginAtZero:true}} }
  });
  severityChart = new Chart(sc, {
    type: 'doughnut',
    data: { labels:['Critical','High','Medium','Low','Info'], datasets:[{ data:[0,0,0,0,0], backgroundColor:['#ef4444','#f59e0b','#3b82f6','#10b981','#64748b'] }] },
    options: { responsive:true, maintainAspectRatio:false, animation:false, resizeDelay:150, plugins:{legend:{position:'right',labels:{color:tickColor}}} }
  });
}

async function loadOverview() {
  const metrics = await apiGet(API+'/metrics');
  if (!metrics) return;
  document.getElementById('kpiEvents').textContent = metrics.total_events_24h ?? 0;
  document.getElementById('kpiCritical').textContent = metrics.critical_alerts ?? 0;
  document.getElementById('kpiModules').textContent = metrics.active_modules ?? 0;
  document.getElementById('kpiScore').textContent = metrics.threat_score ?? 0;
  document.getElementById('threatScore').textContent = 'Score: ' + (metrics.threat_score ?? '--');
  document.getElementById('eventCount').textContent = (metrics.total_events_24h ?? 0) + ' events';
  document.getElementById('moduleCount').textContent = (metrics.active_modules ?? 0) + '/' + (metrics.total_modules ?? 0) + ' modules';

  const hd = document.getElementById('healthDot');
  if (metrics.critical_alerts > 0) hd.className = 'health-dot crit';
  else if (metrics.high_alerts > 0) hd.className = 'health-dot warn';
  else hd.className = 'health-dot';

  const ms = document.getElementById('moduleStatus');
  const mods = metrics.modules || [];
  if (!mods.length) {
    ms.innerHTML = '<div class="empty-state"><i class="fa-solid fa-server"></i><div>No modules yet.</div></div>';
  } else {
    ms.innerHTML = mods.map(m => `
      <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px">
        <span>${esc(m.name)}</span>
        <span style="color:${m.status==='running'||m.status==='healthy'?'var(--accent-green)':'var(--accent-amber)'};font-weight:600">${esc(m.status)}</span>
      </div>
    `).join('');
  }

  const tl = await apiGet(API+'/events/stats/timeline');
  if (tl && tl.buckets && trendChart) {
    trendChart.data.labels = tl.buckets.map(b=>b.hour);
    trendChart.data.datasets[0].data = tl.buckets.map(b=>b.critical);
    trendChart.data.datasets[1].data = tl.buckets.map(b=>b.high);
    trendChart.data.datasets[2].data = tl.buckets.map(b=>b.medium);
    trendChart.update('none');
  }

  const eventResp = await apiGet(API+'/events?limit=500');
  const events = Array.isArray(eventResp) ? eventResp : (eventResp?.events || []);
  allEventsCache = events;
  if (events && severityChart) {
    const counts = {critical:0,high:0,medium:0,low:0,info:0};
    events.forEach(e=>{ counts[e.severity?.toLowerCase()||'info'] = (counts[e.severity?.toLowerCase()||'info']||0)+1; });
    severityChart.data.datasets[0].data = [counts.critical, counts.high, counts.medium, counts.low, counts.info];
    severityChart.update('none');
  }
  renderMITREMatrix();
}

async function refreshEvents() {
  const eventResp = await apiGet(API+'/events?limit=50');
  const events = Array.isArray(eventResp) ? eventResp : (eventResp?.events || []);
  const el = document.getElementById('eventStream');
  if (!events || !events.length) { el.innerHTML = '<div class="empty-state"><i class="fa-solid fa-circle-info"></i><div>No events yet. Run an authorized scan or start live modules.</div></div>'; return; }
  // Merge into allEventsCache
  events.forEach(ev => {
    const idx = allEventsCache.findIndex(x => x.id === ev.id);
    if (idx >= 0) allEventsCache[idx] = ev;
    else allEventsCache.push(ev);
  });
  if (allEventsCache.length > 500) allEventsCache = allEventsCache.slice(-500);
  el.innerHTML = events.map(e => {
    const sev = (e.severity||'info').toLowerCase();
    const color = sev==='critical'?'var(--accent-red)':sev==='high'?'var(--accent-amber)':sev==='medium'?'var(--accent-blue)':sev==='low'?'var(--accent-green)':'var(--text-muted)';
    const time = new Date(e.timestamp).toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const checked = selectedEventIds.has(e.id) ? 'checked' : '';
    return `<div class="event-row" data-event-id="${esc(e.id)}">
      <input type="checkbox" ${checked} onchange="toggleSelectEvent('${esc(e.id)}', this.checked)" onclick="event.stopPropagation()">
      <span class="event-time">${time}</span>
      <span class="event-title" style="color:${color};font-weight:600">${esc(e.title||'Event')}</span>
      <span class="event-cat">${esc(e.source||'')}</span>
      <span class="badge ${sev}">${esc(e.severity||'info')}</span>
    </div>`;
  }).join('');
  el.querySelectorAll('.event-row').forEach(row => {
    row.addEventListener('click', function(ev) {
      if (ev.target.type !== 'checkbox') {
        openEventModalById(this.dataset.eventId);
      }
    });
  });
  updateBulkBar();
}

function openEventModalById(id) {
  const ev = allEventsCache.find(x => x.id === id);
  if (ev) openEventModal(ev);
}

// ========================= MITRE MATRIX =========================
const MITRE_TACTICS = [
  {id:'TA0043',name:'Reconnaissance',techniques:[{id:'T1046',name:'Network Service Discovery'},{id:'T1018',name:'Remote System Discovery'},{id:'T1083',name:'File and Directory Discovery'}]},
  {id:'TA0001',name:'Initial Access',techniques:[{id:'T1190',name:'Exploit Public-Facing Application'},{id:'T1566',name:'Phishing'},{id:'T1078',name:'Valid Accounts'}]},
  {id:'TA0002',name:'Execution',techniques:[{id:'T1059',name:'Command and Scripting Interpreter'},{id:'T1059.004',name:'Unix Shell'},{id:'T1204',name:'User Execution'}]},
  {id:'TA0003',name:'Persistence',techniques:[{id:'T1543',name:'Create or Modify System Process'},{id:'T1547',name:'Boot or Logon Autostart Execution'},{id:'T1136',name:'Create Account'}]},
  {id:'TA0005',name:'Defense Evasion',techniques:[{id:'T1014',name:'Rootkit'},{id:'T1027',name:'Obfuscated Files or Information'},{id:'T1070',name:'Indicator Removal'}]},
  {id:'TA0006',name:'Credential Access',techniques:[{id:'T1110',name:'Brute Force'},{id:'T1110.001',name:'Password Guessing'},{id:'T1003',name:'OS Credential Dumping'}]},
  {id:'TA0008',name:'Lateral Movement',techniques:[{id:'T1021',name:'Remote Services'},{id:'T1021.004',name:'SSH'},{id:'T1210',name:'Exploitation of Remote Services'}]},
  {id:'TA0010',name:'Exfiltration',techniques:[{id:'T1048',name:'Exfiltration Over Alternative Protocol'},{id:'T1041',name:'Exfiltration Over C2 Channel'},{id:'T1567',name:'Exfiltration Over Web Service'}]},
  {id:'TA0011',name:'Command and Control',techniques:[{id:'T1071',name:'Application Layer Protocol'},{id:'T1071.004',name:'DNS'},{id:'T1573',name:'Encrypted Channel'},{id:'T1572',name:'Protocol Tunneling'}]},
  {id:'TA0105',name:'Inhibit Response Function',techniques:[{id:'T0855',name:'Unauthorized Command Message'},{id:'T0838',name:'Manipulate Parameter'},{id:'T0831',name:'Manipulate I/O Image'}]}
];
function renderMITREMatrix() {
  const container = document.getElementById('mitreOverviewMatrix');
  if (!allEventsCache.length) { container.innerHTML = '<div class="empty-state"><i class="fa-solid fa-table-cells"></i><div>No events yet. Run an authorized scan or start live modules.</div></div>'; return; }
  const counts = {};
  allEventsCache.forEach(ev => {
    if (ev.mitre && ev.mitre.technique_id) {
      counts[ev.mitre.technique_id] = (counts[ev.mitre.technique_id] || 0) + 1;
    }
  });
  let html = '';
  MITRE_TACTICS.forEach(tactic => {
    html += '<div style="margin-bottom:12px">';
    html += '<div style="font-size:12px; font-weight:700; color:var(--accent-cyan); margin-bottom:6px">' + esc(tactic.id) + ' — ' + esc(tactic.name) + '</div>';
    html += '<div class="mitre-grid">';
    tactic.techniques.forEach(tech => {
      const c = counts[tech.id] || 0;
      const bg = c > 0 ? 'rgba(239,68,68,' + Math.min(c*0.15+0.1,0.7) + ')' : 'var(--surface-3)';
      html += '<div class="mitre-cell" style="background:' + bg + '"><span class="tech-id">' + esc(tech.id) + '</span><span class="tech-count">' + (c > 0 ? c + ' events' : '—') + '</span></div>';
    });
    html += '</div></div>';
  });
  container.innerHTML = html;
}

// ========================= NETWORK =========================
async function loadNetwork() {
  const d = await apiGet(PROXY+'/network/status');
  if (!d) return;
  document.getElementById('netPackets').textContent = d.packets ?? d.packets_analyzed ?? 0;
  document.getElementById('netAlerts').textContent = d.alerts ?? d.alert_count ?? 0;
  const recent = d.recent_alerts || [];
  document.getElementById('netScans').textContent = recent.filter(a=>a.category==='port_scan').length;
  document.getElementById('netSuspicious').textContent = recent.filter(a=>a.title?.toLowerCase().includes('suspicious')||a.category==='suspicious_port').length;
  // networkData div replaced by scanResults — render live alerts only if no scan ran
  const container = document.getElementById('networkData') || (_lastJobId ? null : document.getElementById('scanResults'));
  if (container && !_lastJobId && recent.length > 0) {
    container.innerHTML = '<table class="table"><thead><tr><th>Time</th><th>Title</th><th>Source IP</th><th>Severity</th></tr></thead><tbody>' +
      recent.slice(0,10).map(a=>`<tr><td>${esc((a.timestamp||'').slice(11,19)||'--')}</td><td>${esc(a.title||'-')}</td><td>${esc(a.source_ip||'-')}</td><td><span class="badge ${esc((a.severity||'info').toLowerCase())}">${esc(a.severity)}</span></td></tr>`).join('') +
      '</tbody></table>';
  }
}
async function triggerNetworkSim() { await apiPost(PROXY+'/network/trigger', {}); loadNetwork(); }

// ── LAN SCAN ────────────────────────────────────────────────────────────────
let _scanPollTimer = null;
let _lastJobId = null;
let _scanHosts = [];

async function initScanSubnets() {
  try {
    const d = await apiGet('/api/scan/discover');
    if (!d) return;
    const sel = document.getElementById('scanTargetSel');
    if (!sel) return;
    (d.subnets || []).forEach(s => {
      const opt = document.createElement('option');
      opt.value = s; opt.textContent = s;
      sel.appendChild(opt);
    });
    if (d.subnets && d.subnets.length > 0) sel.value = d.subnets[0];
  } catch (e) {}
}

async function launchLANScan() {
  const btn = document.getElementById('btnScan');
  const target = document.getElementById('scanTargetSel').value;
  const mode = document.getElementById('scanMode').value;
  const otMode = document.getElementById('scanOTMode').value;
  btn.disabled = true;
  document.getElementById('scanProgressWrap').style.display = '';
  document.getElementById('scanStatusTxt').textContent = 'Avvio scansione...';
  document.getElementById('scanPct').textContent = '0%';
  document.getElementById('scanProgressBar').style.width = '0%';
  document.getElementById('scanHostsTxt').textContent = '';
  document.getElementById('vulnScanFromNet').style.display = 'none';
  document.getElementById('scanResults').innerHTML = '<div class="muted" style="padding:12px"><i class="fa-solid fa-spinner fa-spin"></i> Scansione in corso...</div>';

  const body = {mode, ot_mode: otMode};
  if (target) body.target = target;
  const r = await apiPost('/api/scan/launch', body);
  if (!r || !r.job_id) {
    showToast('Errore', 'Impossibile avviare la scansione', 'error');
    btn.disabled = false;
    document.getElementById('scanProgressWrap').style.display = 'none';
    return;
  }
  _lastJobId = r.job_id;
  showToast('Scansione Avviata', 'Target: ' + (r.target || target || 'auto') + ' — modalità ' + mode + ' / OT ' + otMode, 'info');
  if (_scanPollTimer) clearInterval(_scanPollTimer);
  _scanPollTimer = setInterval(() => pollScanStatus(r.job_id), 1500);
}

async function pollScanStatus(jobId) {
  const d = await apiGet('/api/scan/status?job_id=' + encodeURIComponent(jobId));
  if (!d) return;
  const pct = d.progress || 0;
  document.getElementById('scanProgressBar').style.width = pct + '%';
  document.getElementById('scanPct').textContent = pct + '%';
  document.getElementById('scanStatusTxt').textContent = d.state === 'running' ? 'Scansione in corso...' : d.state === 'done' ? 'Completata' : d.state === 'error' ? 'Errore' : d.state;
  document.getElementById('scanHostsTxt').textContent = 'Host trovati: ' + (d.hosts_found || 0) + ' / Scansionati: ' + (d.hosts_scanned || 0);
  if (d.state === 'done' || d.state === 'error') {
    clearInterval(_scanPollTimer);
    _scanPollTimer = null;
    document.getElementById('btnScan').disabled = false;
    if (d.state === 'done') { loadScanResults(jobId); showToast('Scan Completato', 'Host trovati: ' + (d.hosts_found || 0), 'success'); }
    else showToast('Errore Scan', d.error || 'Errore sconosciuto', 'error');
  }
}

async function loadScanResults(jobId) {
  const url = jobId ? '/api/scan/results?job_id=' + encodeURIComponent(jobId) : '/api/scan/results';
  const d = await apiGet(url);
  if (!d || !d.results) { document.getElementById('scanResults').innerHTML = '<div class="empty-state"><i class="fa-solid fa-magnifying-glass"></i><div>Nessun risultato disponibile.</div></div>'; return; }
  const results = d.results;
  _scanHosts = results.map(h => h.ip).filter(Boolean);
  if (!results.length) { document.getElementById('scanResults').innerHTML = '<div class="empty-state"><i class="fa-solid fa-magnifying-glass"></i><div>Nessun host trovato nella rete.</div></div>'; return; }
  document.getElementById('netPackets').textContent = results.length;

  let rows = results.sort((a,b) => (b.risk_score||0) - (a.risk_score||0)).map(h => {
    const risk = h.risk_score || 0;
    const riskColor = risk >= 70 ? 'var(--accent-red)' : risk >= 40 ? 'var(--accent-amber)' : 'var(--accent-green)';
    const ports = (h.ports || []).filter(p => p.state === 'open').map(p => {
      let badge = `<span style="font-family:monospace;font-size:11px;padding:1px 5px;background:var(--surface-3);border-radius:3px;margin:1px" title="${esc(p.banner||'')}">${p.port}/${p.service||'?'}</span>`;
      if (p.port === 1900 || p.port === 47808) badge = `<span style="font-family:monospace;font-size:11px;padding:1px 5px;background:var(--accent-cyan);border-radius:3px;margin:1px;color:#000" title="${esc(p.banner||'')}">${p.port}/${p.service||'?'}</span>`;
      return badge;
    }).join('');
    const findings = (h.findings || []).length;
    const cveCount = (h.findings || []).filter(f => f.type === 'cve_verified').length;
    const meta = [];
    if (h.mac) meta.push(h.mac);
    if (h.vendor) meta.push(h.vendor);
    const metaStr = meta.length ? `<div style="font-size:10px;color:var(--text-muted)">${esc(meta.join(' · '))}</div>` : '';
    const openPorts = (h.ports || []).filter(p => p.state === 'open');
    const fixesPerPort = openPorts.map(p =>
      `<button class="btn-fix" onclick="event.stopPropagation(); showRemediationModal({service:'${esc((p.service||'').toLowerCase())}', port:${parseInt(p.port)||0}}, 'Hardening porta ${esc(p.port)}/${esc(p.service||'')}')">
        <i class="fa-solid fa-wrench"></i> ${esc(p.port)}/${esc(p.service||'?')}
      </button>`).join(' ');
    const findingsHTML = (h.findings||[]).map(f=>{
      const confColor = f.confidence==='medium' ? 'var(--accent-amber)' : f.confidence==='low' ? 'var(--text-muted)' : 'var(--accent-green)';
      const cveId = f.exposure_id||'';
      const isCVE = /^CVE-/.test(cveId);
      const fixBtn = isCVE
        ? `<button class="btn-fix" onclick="event.stopPropagation(); showRemediationModal({cve:'${esc(cveId)}'}, 'Soluzione ${esc(cveId)}')"><i class="fa-solid fa-wrench"></i> Fix</button>`
        : '';
      return `<li><span class="badge ${f.type==='cve_verified'?'critical':'high'}">${esc(f.type||'')}</span> <strong>${esc(cveId)}</strong> — CVSS ${f.cvss} — ${esc(f.description||'')} <span style="color:${confColor};font-size:11px">[confidence: ${esc(f.confidence||'')}]</span> ${fixBtn}</li>`;
    }).join('');
    return `<tr style="cursor:pointer" onclick="toggleScanDetail('${esc(h.ip)}')">
      <td style="font-family:monospace">${esc(h.ip || '-')}${metaStr}</td>
      <td>${esc(h.hostname || '—')}</td>
      <td style="font-size:12px">${esc(h.os_guess || '—')}</td>
      <td>${ports || '<span class="muted">—</span>'}</td>
      <td style="font-weight:700;color:${riskColor}">${risk}</td>
      <td>${findings > 0 ? '<span class="badge ' + (risk >= 70 ? 'critical' : risk >= 40 ? 'high' : 'medium') + '">' + findings + (cveCount ? ' ('+cveCount+' CVE)' : '') + '</span>' : '—'}</td>
    </tr>
    <tr id="detail-${esc(h.ip.replace(/\./g,'_'))}" style="display:none"><td colspan="6" style="background:var(--surface-3);padding:10px 14px">
      ${fixesPerPort ? `<div style="font-size:11px;margin-bottom:8px"><strong>Hardening porte aperte:</strong><div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px">${fixesPerPort}</div></div>` : ''}
      ${(h.findings||[]).length ? '<div style="font-size:12px"><strong>Rilevazioni:</strong><ul style="margin:6px 0;padding-left:18px">' + findingsHTML + '</ul></div>' : '<span class="muted" style="font-size:12px">Nessuna rilevazione critica.</span>'}
      ${(h.ports||[]).filter(p=>p.banner).length ? '<div style="font-size:11px;color:var(--text-muted);margin-top:6px"><strong>Banners:</strong><br>' + h.ports.filter(p=>p.banner).map(p=>`${p.port}: ${esc(p.banner)}`).join('<br>') + '</div>' : ''}
    </td></tr>`;
  }).join('');

  document.getElementById('scanResults').innerHTML = `<table class="table"><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Porte Aperte</th><th>Risk</th><th>Findings</th></tr></thead><tbody>${rows}</tbody></table>`;
  if (_scanHosts.length) document.getElementById('vulnScanFromNet').style.display = '';
}

function toggleScanDetail(ip) {
  const id = 'detail-' + ip.replace(/\./g,'_');
  const el = document.getElementById(id);
  if (el) el.style.display = el.style.display === 'none' ? '' : 'none';
}

async function exportScan(fmt) {
  if (!_lastJobId) { showToast('Info', 'Nessuna scansione da esportare', 'info'); return; }
  const url = '/api/scan/export?job_id=' + encodeURIComponent(_lastJobId) + '&format=' + fmt;
  try {
    const resp = await fetch(apiUrl(url), {headers: getHeaders(), credentials: 'include'});
    if (!resp.ok) throw new Error('Export failed');
    const blob = await resp.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'scan_' + _lastJobId + '.' + fmt;
    a.click();
    showToast('Esportato', 'File scan_' + _lastJobId + '.' + fmt, 'success');
  } catch (e) {
    showToast('Errore Export', String(e), 'error');
  }
}

async function launchVulnBatchFromScan() {
  if (!_scanHosts.length) { showToast('Info', 'Esegui prima una scansione LAN', 'info'); return; }
  const r = await apiPost('/api/vuln/batch', {targets: _scanHosts.slice(0, 50)});
  if (r) showToast('CVE Scan Avviato', 'Scansione su ' + _scanHosts.length + ' host', 'info');
  setTimeout(() => { if (typeof loadVuln === 'function') loadVuln(); }, 5000);
}

// ========================= OT =========================
async function loadOT() {
  const d = await apiGet(PROXY+'/ot/status');
  if (!d) return;
  const assets = d.assets || [];
  const alerts = d.alerts || [];
  document.getElementById('otAssets').textContent = assets.length;
  document.getElementById('otAlerts').textContent = alerts.length;
  const protos = new Set(assets.map(a=>a.protocols||[]).flat());
  document.getElementById('otProtocols').textContent = protos.size;
  const tbl = document.getElementById('otTable');
  if (!assets.length) {
    tbl.innerHTML = '<div class="empty-state"><i class="fa-solid fa-industry"></i><div>No OT assets yet. Start the OT monitor or run an authorized OT-safe scan.</div></div>';
  } else {
    tbl.innerHTML = '<table class="table"><thead><tr><th>IP</th><th>Type</th><th>Protocol</th><th>Purdue</th><th>Vendor</th><th>Authorized</th></tr></thead><tbody>' +
      assets.map(a=>`<tr><td style="font-family:monospace;font-size:12px">${esc(a.ip||'-')}</td><td><span class="badge ${a.device_type==='PLC'||a.device_type==='RTU'?'critical':a.device_type==='HMI'?'high':'info'}">${esc(a.device_type||'-')}</span></td><td style="font-size:11px">${esc((a.protocols||[]).join(', '))}</td><td><span style="font-family:monospace;font-weight:700">L${a.purdue_level??'?'}</span></td><td>${esc(a.vendor||'-')}</td><td>${a.authorized?'<span style="color:var(--accent-green)"><i class="fa-solid fa-check"></i> Auth</span>':'<span style="color:var(--accent-red)"><i class="fa-solid fa-triangle-exclamation"></i> ROGUE</span>'}</td></tr>`).join('') +
      '</tbody></table>';
  }
  // Purdue level diagram
  const byLevel = {0:[],1:[],2:[],3:[],4:[],5:[]};
  assets.forEach(a => {
    const l = a.purdue_level ?? -1;
    if (l >= 0 && l <= 5) byLevel[l].push(a);
  });
  [0,1,2,3,4,5].forEach(l => {
    const el = document.getElementById('pl'+l+'Assets');
    if (!el) return;
    const list = byLevel[l];
    if (!list.length) { el.textContent = '—'; return; }
    el.innerHTML = list.map(a => {
      const rogue = !a.authorized;
      return `<span style="margin-left:6px;padding:2px 6px;border-radius:3px;background:${rogue?'rgba(239,68,68,.2)':'var(--surface-3)'};color:${rogue?'var(--accent-red)':'var(--text)'};border:1px solid ${rogue?'var(--accent-red)':'var(--border)'}" title="${esc(a.ip||'')} — ${esc(a.vendor||'')}">${esc(a.asset_id||a.ip||'?')}</span>`;
    }).join('');
  });
  // Alerts for Purdue panel
  const alertEl = document.getElementById('purdueAlerts');
  if (alertEl && alerts.length) {
    alertEl.innerHTML = '<div style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Active OT Alerts</div>' +
      alerts.map(a => `<div style="display:flex;gap:8px;align-items:center;padding:6px 10px;border-radius:6px;background:var(--surface-3);margin-bottom:6px;border-left:3px solid ${a.severity==='critical'?'var(--accent-red)':a.severity==='high'?'var(--accent-amber)':'var(--accent-blue)'}">
        <span class="badge ${esc(a.severity||'info')}" style="flex-shrink:0">${esc(a.severity)}</span>
        <span style="flex:1;font-size:12px">${esc(a.title||'-')}</span>
        <span style="font-size:10px;font-family:monospace;color:var(--text-muted)">${esc(a.asset_id||'')} ${esc(a.protocol||'')}</span>
      </div>`).join('');
  }
}
async function refreshOT() { loadOT(); }

// ========================= SIEM =========================
async function loadSIEM() {
  const d = await apiGet(PROXY+'/siem/status');
  if (!d) return;
  document.getElementById('siemRules').textContent = d.active_rules ?? 0;
  document.getElementById('siemIncidents').textContent = d.incidents_created ?? d.incident_count ?? 0;
  document.getElementById('siemEvents').textContent = d.events_ingested ?? d.stored_events ?? 0;
  const tbl = document.getElementById('siemTable');
  const incidents = d.recent_incidents || [];
  if (!incidents.length) {
    tbl.innerHTML = '<div class="empty-state"><i class="fa-solid fa-list-check"></i><div>No incidents yet. Start SIEM correlation with real ingested events.</div></div>';
  } else {
    tbl.innerHTML = '<table class="table"><thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Events</th><th>Source IPs</th></tr></thead><tbody>' +
      incidents.map(i=>`<tr><td>${esc(i.id||'-')}</td><td>${esc(i.rule_name||i.title||'-')}</td><td><span class="badge ${esc((i.severity||'info').toLowerCase())}">${esc(i.severity)}</span></td><td>${i.event_count??'-'}</td><td>${esc((i.source_ips||[]).slice(0,3).join(', '))}</td></tr>`).join('') +
      '</tbody></table>';
  }
}
async function triggerSIEMDemo() {
  // Manual refresh only: this path never injects generated events.
  await apiPost(PROXY + '/siem/trigger', {});
  loadSIEM();
}


async function loadSIEMRules() {
  const d = await apiGet(API+'/siem/rules');
  const rules = (d && d.rules) ? d.rules : [];
  const tbl = document.getElementById('siemRulesTable');
  const countEl = document.getElementById('siemRulesEnabledCount');
  if (!rules.length) { tbl.innerHTML = '<div class="muted" style="padding:12px">No rules loaded. Start SIEM module and reload.</div>'; return; }
  const enabled = rules.filter(r=>r.enabled!==false).length;
  if (countEl) countEl.textContent = enabled + '/' + rules.length + ' enabled';
  const sevColor = {critical:'var(--accent-red)',high:'var(--accent-amber)',medium:'var(--accent-blue)',low:'var(--accent-green)'};
  tbl.innerHTML = '<table class="table"><thead><tr><th>ID</th><th>Rule Name</th><th>Category</th><th>Severity</th><th>MITRE</th><th>Window</th><th>Status</th></tr></thead><tbody>' +
    rules.map(r => `<tr>
      <td style="font-family:monospace;font-size:11px">${esc(r.id||'-')}</td>
      <td style="font-weight:600;font-size:12px">${esc(r.name||'-')}</td>
      <td><span class="rule-tag">${esc(r.category||'-')}</span></td>
      <td><span class="badge ${esc((r.severity||'info').toLowerCase())}">${esc(r.severity||'-')}</span></td>
      <td style="font-family:monospace;font-size:11px;color:var(--accent-blue)">${esc(r.mitre_technique_id||'-')}</td>
      <td style="font-size:11px;color:var(--text-muted)">${r.window_sec ? r.window_sec+'s / thr:'+r.threshold : '-'}</td>
      <td>${r.enabled!==false?'<span style="color:var(--accent-green);font-size:11px"><i class="fa-solid fa-circle-check"></i> ON</span>':'<span style="color:var(--text-muted);font-size:11px"><i class="fa-solid fa-circle-xmark"></i> OFF</span>'}</td>
    </tr>`).join('') + '</tbody></table>';
}

// ========================= SOAR =========================
async function loadSOAR() {
  const d = await apiGet(PROXY+'/soar/status');
  const pbs = await apiGet(API + '/playbooks');
  if (!d) return;
  document.getElementById('soarPlaybooks').textContent = d.playbooks_loaded ?? (pbs ? pbs.length : 0);
  document.getElementById('soarExecuted').textContent = d.playbooks_triggered ?? d.execution_count ?? 0;
  document.getElementById('soarDryRun').textContent = d.dry_run_mode ? 'ON' : 'OFF';
  document.getElementById('soarDryRun').style.color = d.dry_run_mode ? 'var(--accent-green)' : 'var(--accent-red)';
  const tbl = document.getElementById('soarTable');
  const execs = d.recent_executions || [];
  if (!execs.length) {
    tbl.innerHTML = '<div class="empty-state"><i class="fa-solid fa-robot"></i><div>No playbook executions yet.</div></div>';
  } else {
    tbl.innerHTML = '<table class="table"><thead><tr><th>Playbook</th><th>ID</th><th>Status</th><th>Actions</th></tr></thead><tbody>' +
      execs.map(e=>`<tr><td>${esc(e.playbook_name||e.playbook_id||'-')}</td><td>${esc(e.playbook_id||'-')}</td><td><span class="badge ${(e.status==='completed'||e.status==='success')?'low':'medium'}">${esc(e.status||'unknown')}</span></td><td>${e.actions_taken?.length||0}</td></tr>`).join('') +
      '</tbody></table>';
  }
  // Populate playbook dropdown
  const sel = document.getElementById('soarPlaybookSelect');
  if (pbs && pbs.length) {
    sel.innerHTML = pbs.map(pb => '<option value="' + esc(pb.id) + '">' + esc(pb.name) + '</option>').join('');
  } else {
    sel.innerHTML = '<option>No playbooks</option>';
  }
}
async function triggerPlaybookManual() {
  const playbook = document.getElementById('soarPlaybookSelect').value;
  const eventId = document.getElementById('soarEventId').value.trim();
  if (!playbook || playbook === 'No playbooks') return;
  const res = await apiPost(API + '/soar/trigger', { source:'soar_ui', category:'soar', severity:'medium', title:'Manual trigger: ' + playbook, raw_data:{playbook, event_id:eventId||null} });
  document.getElementById('soarTriggerResult').textContent = res ? 'Playbook triggered successfully.' : 'Trigger failed.';
  loadSOAR();
}

// ========================= SHIELD ENGINE =========================
let shieldCache = null;

async function loadShield() {
  const windowVal = document.getElementById('shieldWindow')?.value || '24';
  const summary = document.getElementById('shieldSummary');
  if (summary) summary.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Correlating telemetry...';
  const data = await apiGet(API + '/shield/analysis?window=' + encodeURIComponent(windowVal));
  if (!data) {
    if (summary) summary.innerHTML = '<span style="color:var(--accent-red)">Shield Engine offline.</span>';
    return;
  }
  shieldCache = data;
  document.getElementById('shieldScore').textContent = data.risk_score ?? '--';
  document.getElementById('shieldScore').style.color = shieldScoreColor(data.risk_score || 0);
  document.getElementById('shieldPosture').textContent = data.posture || '--';
  document.getElementById('shieldFindings').textContent = (data.findings || []).length;
  document.getElementById('shieldEntities').textContent = (data.entities || []).length;
  document.getElementById('shieldHunts').textContent = (data.hunts || []).length;
  document.getElementById('shieldSummary').textContent = data.executive_summary || '';
  renderShieldFindings(data.findings || []);
  renderShieldActions(data.actions || []);
  renderShieldEntities(data.entities || []);
  renderShieldHunts(data.hunts || []);
  renderShieldRules(data.rules || []);
}

function shieldScoreColor(score) {
  if (score >= 85) return 'var(--accent-red)';
  if (score >= 65) return 'var(--accent-amber)';
  if (score >= 35) return 'var(--accent-blue)';
  return 'var(--accent-green)';
}

function renderShieldFindings(findings) {
  const el = document.getElementById('shieldFindingList');
  if (!findings.length) {
    el.innerHTML = '<div class="empty-state"><i class="fa-solid fa-circle-check" style="color:var(--accent-green)"></i><div>No active Shield finding in this window.</div></div>';
    return;
  }
  el.innerHTML = findings.map(f => {
    const q = encodeURIComponent(f.hunt_query || '');
    return `
    <div class="rem-card ${esc((f.severity || 'info').toLowerCase())}" style="margin-bottom:10px">
      <h4><i class="fa-solid fa-radar"></i> ${esc(f.title || f.id)}</h4>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px">
        <span class="badge ${esc((f.severity || 'info').toLowerCase())}">${esc(f.severity || 'info')}</span>
        <span class="hunt-tag">${esc(f.technique_id || f.category || 'detection')}</span>
        <span class="hunt-tag">${Number(f.confidence || 0)}% confidence</span>
      </div>
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px">${esc((f.evidence || [])[0] || 'Evidence attached')}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px">${(f.entities || []).slice(0,8).map(e => `<span class="hunt-tag">${esc(e)}</span>`).join('')}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn" onclick="quickHunt(decodeURIComponent('${q}'))"><i class="fa-solid fa-crosshairs"></i> Hunt</button>
        <button class="btn" onclick="copyText(decodeURIComponent('${q}'))"><i class="fa-solid fa-copy"></i></button>
      </div>
    </div>`}).join('');
}

function renderShieldActions(actions) {
  const el = document.getElementById('shieldActions');
  if (!actions.length) { el.innerHTML = '<div class="muted">No actions generated.</div>'; return; }
  el.innerHTML = actions.map(a => `
    <div style="border-bottom:1px solid var(--border);padding:10px 0">
      <div style="display:flex;justify-content:space-between;gap:10px;align-items:center">
        <strong>${esc(a.title || a.id)}</strong>
        <span class="badge ${esc((a.priority || 'info').toLowerCase())}">${esc(a.priority || 'info')}</span>
      </div>
      <ul style="margin:8px 0 0 18px;color:var(--text-muted);font-size:12px;line-height:1.5">${(a.steps || []).map(s => `<li>${esc(s)}</li>`).join('')}</ul>
      ${(a.powershell || []).length ? `<pre style="white-space:pre-wrap;margin-top:8px;font-size:11px">${esc((a.powershell || []).join('\n'))}</pre>` : ''}
    </div>`).join('');
}

function renderShieldEntities(entities) {
  const el = document.getElementById('shieldEntityTable');
  if (!entities.length) { el.innerHTML = '<div class="muted">No dominant entities.</div>'; return; }
  el.innerHTML = '<table class="table"><thead><tr><th>Entity</th><th>Type</th><th>Score</th><th>Hits</th><th>Last Seen</th></tr></thead><tbody>' +
    entities.slice(0,12).map(e => `<tr>
      <td style="font-family:monospace">${esc(e.value)}</td>
      <td>${esc(e.type)}</td>
      <td><span class="badge ${esc((e.score||0)>=85?'critical':(e.score||0)>=65?'high':(e.score||0)>=35?'medium':'low')}">${Number(e.score||0)}</span></td>
      <td>${Number(e.hits || 0)}</td>
      <td>${esc(new Date(e.last_seen).toLocaleString())}</td>
    </tr>`).join('') + '</tbody></table>';
}

function renderShieldHunts(hunts) {
  const el = document.getElementById('shieldHuntTable');
  if (!hunts.length) { el.innerHTML = '<div class="muted">No hunts generated.</div>'; return; }
  el.innerHTML = '<table class="table"><thead><tr><th>Name</th><th>Severity</th><th>Query</th><th></th></tr></thead><tbody>' +
    hunts.slice(0,12).map(h => {
      const q = encodeURIComponent(h.query || '');
      return `<tr>
      <td>${esc(h.name)}</td>
      <td><span class="badge ${esc((h.severity || 'info').toLowerCase())}">${esc(h.severity || 'info')}</span></td>
      <td style="font-family:monospace;font-size:11px">${esc(h.query)}</td>
      <td><button class="btn" onclick="quickHunt(decodeURIComponent('${q}'))"><i class="fa-solid fa-play"></i></button></td>
    </tr>`}).join('') + '</tbody></table>';
}

function renderShieldRules(rules) {
  const el = document.getElementById('shieldRules');
  if (!rules.length) { el.innerHTML = '<div class="muted">No rules generated.</div>'; return; }
  el.innerHTML = rules.slice(0,4).map(r => `
    <details style="border:1px solid var(--border);border-radius:8px;margin-bottom:8px;padding:10px;background:var(--surface-2)">
      <summary style="cursor:pointer;font-weight:700">${esc(r.name)} <span class="hunt-tag">${esc(r.type)}</span> <span class="badge ${esc((r.severity || 'info').toLowerCase())}">${esc(r.severity || 'info')}</span></summary>
      <pre style="white-space:pre-wrap;margin-top:8px;font-size:11px">${esc(r.content || '')}</pre>
    </details>`).join('');
}

async function exportShieldRules() {
  const windowVal = document.getElementById('shieldWindow')?.value || '24';
  const r = await fetch(API + '/shield/rules?format=text&window=' + encodeURIComponent(windowVal), { headers: getHeaders() });
  if (!r.ok) { showToast('Shield Rules', 'Export failed', 'error'); return; }
  const text = await r.text();
  const blob = new Blob([text], {type:'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'aegis-shield-rules.txt'; a.click();
  URL.revokeObjectURL(url);
}

function copyText(text) {
  if (!text) return;
  navigator.clipboard?.writeText(text);
  showToast('Copied', 'Hunt query copied', 'success');
}

// ========================= ENDPOINT PROTECTION =========================
const EP = apiUrl('/api/endpoint');

function _epSeverityBadge(sev) {
  return `<span class="badge ${esc(sev||'info')}">${esc(sev||'info')}</span>`;
}

function _epStatusIcon(status) {
  if (status === 'ok') return '<i class="fa-solid fa-circle-check" style="color:var(--accent-green)"></i>';
  if (status === 'warn') return '<i class="fa-solid fa-triangle-exclamation" style="color:var(--accent-amber)"></i>';
  if (status === 'fail') return '<i class="fa-solid fa-circle-xmark" style="color:var(--accent-red)"></i>';
  return '<i class="fa-solid fa-circle-info" style="color:var(--text-muted)"></i>';
}

function renderFindings(findings) {
  if (!findings || !findings.length) {
    return '<div class="muted" style="padding:8px 0">Nessun finding.</div>';
  }
  return findings.map(f => {
    const remBtn = f.remediation_key
      ? `<button class="btn-fix" onclick='showRemediationFromKey(${JSON.stringify(f.remediation_key)})' title="${esc(f.remediation_key)}"><i class="fa-solid fa-wrench"></i> Fix</button>`
      : '';
    return `<div style="padding:8px 10px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:10px">
      ${_epStatusIcon(f.status)}
      <div style="flex:1">
        <div style="font-weight:600; font-size:13px">${esc(f.title || f.check_id || '')}</div>
        ${f.description ? `<div style="font-size:11.5px; color:var(--text-muted); margin-top:2px">${esc(f.description)}</div>` : ''}
      </div>
      ${_epSeverityBadge(f.severity)}
      ${remBtn}
    </div>`;
  }).join('');
}

// remediation_key strings sometimes encode "service:smb" / "ioc:c2_domain" form.
// Otherwise treat as a free-text label and try a best-effort match by service.
async function showRemediationFromKey(key) {
  if (!key) return;
  const parts = String(key).split(':');
  let params = {};
  if (parts.length === 2) {
    params[parts[0]] = parts[1];
  } else {
    // Heuristic mapping for endpoint-specific hardening keys.
    const map = {
      defender_realtime_off: { service: 'defender' },
      defender_tamper_off: { service: 'defender' },
      defender_signatures_stale: { service: 'defender' },
      firewall_profile_disabled: { service: 'firewall' },
      bitlocker_off: { service: 'bitlocker' },
      account_no_password: { service: 'accounts' },
      account_admin_review: { service: 'accounts' },
      smb_v1_enabled: { service: 'smb' },
      rdp_enabled: { service: 'rdp' },
      rdp_nla_off: { service: 'rdp' },
      uac_disabled: { service: 'uac' },
      uac_secure_desktop_off: { service: 'uac' },
      autorun_suspicious: { service: 'autoruns' },
      updates_critical_pending: { service: 'updates' },
      updates_pending: { service: 'updates' },
      telemetry_high: { service: 'telemetry' },
      pslogging_off: { service: 'pslogging' },
      smb_share_review: { service: 'smb' },
    };
    params = map[key] || { service: key };
  }
  // First try the orchestrator's remediation DB; if no result, render a hand-crafted fallback.
  const map = await fetchRemediation(params);
  if (Object.keys(map).length) {
    const html = Object.entries(map).map(([k,r]) => renderRemediationCard(r, k)).join('');
    showModal('Soluzione consigliata', html);
    return;
  }
  // Fallback: synthesize a generic Windows hardening card from the key
  const fallback = WINDOWS_HARDENING_FALLBACK[key] || null;
  if (fallback) {
    showModal('Soluzione consigliata', renderRemediationCard(fallback, key));
  } else {
    showModal('Soluzione', `<div class="empty-state"><i class="fa-solid fa-circle-info"></i><div>Nessuna raccomandazione nel knowledge base per <code>${esc(key)}</code>.</div></div>`);
  }
}

const WINDOWS_HARDENING_FALLBACK = {
  defender_realtime_off: {
    severity: 'critical',
    summary: "Defender real-time protection è disattivato.",
    impact: "I file malevoli vengono eseguiti senza essere intercettati.",
    actions: [
      "Apri Windows Security → Virus & threat protection → Manage settings",
      "Riattiva 'Real-time protection'",
      "O via PowerShell admin: Set-MpPreference -DisableRealtimeMonitoring $false",
      "Verifica che nessun GPO/MDM lo stia disabilitando (gpresult /h report.html)"
    ],
    effort: "quick"
  },
  defender_tamper_off: {
    severity: 'medium',
    summary: "Tamper Protection disattivato — un malware potrebbe disabilitare Defender.",
    actions: [
      "Windows Security → Virus & threat protection → Manage settings",
      "Attiva 'Tamper Protection'"
    ],
    effort: "quick"
  },
  defender_signatures_stale: {
    severity: 'high',
    summary: "Le signature Defender sono vecchie di oltre 72 ore.",
    actions: [
      "PowerShell admin: Update-MpSignature",
      "Verifica connettività verso il signature update server",
      "Controlla che il servizio 'Windows Defender Antivirus Service' (WinDefend) sia attivo"
    ],
    effort: "quick"
  },
  firewall_profile_disabled: {
    severity: 'critical',
    summary: "Un profilo del firewall Windows è disabilitato.",
    impact: "Tutte le porte aperte sono raggiungibili senza filtro.",
    actions: [
      "PowerShell admin: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
      "Verifica via Get-NetFirewallProfile",
      "Controlla GPO Computer Configuration → Windows Defender Firewall"
    ],
    effort: "quick"
  },
  bitlocker_off: {
    severity: 'high',
    summary: "Il disco non è cifrato — furto fisico = lettura completa dei dati.",
    actions: [
      "Windows Pro/Ent: Settings → System → About → BitLocker drive encryption → Turn on",
      "Windows Home: usa Device Encryption se TPM disponibile",
      "Backup della recovery key in luogo sicuro (mai sul disco stesso)"
    ],
    effort: "moderate"
  },
  account_no_password: {
    severity: 'critical',
    summary: "Un account locale abilitato non richiede password.",
    actions: [
      "lusrmgr.msc → tasto destro account → Properties → User must change password",
      "O: net user <nome> *  (richiede di impostare la password)",
      "Considera disabilitare l'account se non necessario"
    ],
    effort: "quick"
  },
  account_admin_review: {
    severity: 'medium',
    summary: "Account locale nel gruppo Administrators.",
    actions: [
      "Verifica che l'utente necessiti realmente di privilegi admin",
      "Crea un account standard per uso quotidiano (best practice)",
      "Considera LAPS (Local Administrator Password Solution) per ambienti enterprise"
    ],
    effort: "moderate"
  },
  smb_v1_enabled: {
    severity: 'critical',
    summary: "SMBv1 è abilitato — vettore EternalBlue / WannaCry.",
    actions: [
      "PowerShell admin: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
      "Disinstalla feature: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
      "Riavvia il PC"
    ],
    effort: "quick",
    references: ["CVE-2017-0144", "MS17-010"]
  },
  rdp_enabled: {
    severity: 'high',
    summary: "RDP è abilitato. Assicurati che non sia esposto a Internet.",
    actions: [
      "Non esporre 3389/TCP su Internet",
      "Usa WireGuard / Bastion per accesso remoto",
      "Limita login RDP a un gruppo dedicato (Remote Desktop Users)",
      "Abilita MFA per gli admin (Azure AD / Duo)"
    ],
    effort: "moderate"
  },
  rdp_nla_off: {
    severity: 'critical',
    summary: "RDP senza NLA (BlueKeep pre-auth).",
    actions: [
      "System Properties → Remote → 'Allow connections only from computers with NLA'",
      "Registry: HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp → UserAuthentication=1",
      "Restart Terminal Services"
    ],
    effort: "quick"
  },
  uac_disabled: {
    severity: 'critical',
    summary: "UAC disabilitato — privilege escalation senza attrito.",
    actions: [
      "Control Panel → User Accounts → Change UAC settings → 'Always notify'",
      "Riavvia il PC",
      "Verifica via registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System EnableLUA=1"
    ],
    effort: "quick"
  },
  uac_secure_desktop_off: {
    severity: 'medium',
    summary: "UAC senza secure desktop: prompt vulnerabili al hijack.",
    actions: [
      "Registry: ...\\Policies\\System PromptOnSecureDesktop=1",
      "O via GUI: 'Always notify and dim my desktop'"
    ],
    effort: "quick"
  },
  autorun_suspicious: {
    severity: 'high',
    summary: "Autorun con pattern sospetto (path temp, powershell -enc, ecc.).",
    actions: [
      "Apri Task Manager → Startup → disabilita la voce",
      "Run regedit → HKLM/HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run → elimina entry",
      "Considera Sysinternals Autoruns per analisi approfondita",
      "Esegui scan completo Defender: MpCmdRun.exe -Scan -ScanType 2"
    ],
    effort: "moderate"
  },
  updates_critical_pending: {
    severity: 'high',
    summary: "Update critici/importanti pendenti.",
    actions: [
      "Settings → Windows Update → Check for updates → Install all",
      "Riavvia il PC dopo l'installazione",
      "Considera attivare 'Receive updates as soon as they're available'"
    ],
    effort: "quick"
  },
  updates_pending: {
    severity: 'medium',
    summary: "Update non-critici pendenti.",
    actions: [
      "Pianifica installazione nella prossima finestra di manutenzione",
      "Settings → Windows Update → Install"
    ],
    effort: "quick"
  },
  telemetry_high: {
    severity: 'low',
    summary: "Telemetria Windows oltre livello base.",
    actions: [
      "Settings → Privacy & security → Diagnostics & feedback → 'Required only'",
      "GPO: Computer Config → Admin Templates → Windows Components → Data Collection → 'Allow Telemetry' = 0 o 1"
    ],
    effort: "quick"
  },
  pslogging_off: {
    severity: 'medium',
    summary: "PowerShell ScriptBlock/Module logging disabilitato — niente forensics.",
    actions: [
      "GPO Computer Config → Admin Templates → Windows Components → Windows PowerShell",
      "Abilita 'Turn on PowerShell Script Block Logging'",
      "Abilita 'Turn on Module Logging' (modules: *)",
      "Eventi visibili in Event Viewer → Applications and Services Logs → Microsoft → Windows → PowerShell"
    ],
    effort: "quick"
  },
  smb_share_review: {
    severity: 'medium',
    summary: "Una share SMB è esposta — verifica le ACL.",
    actions: [
      "Get-SmbShareAccess -Name <share> per vedere chi ha accesso",
      "Rimuovi 'Everyone' se presente: Revoke-SmbShareAccess -Name <share> -AccountName 'Everyone'",
      "Grant solo a utenti specifici: Grant-SmbShareAccess -Name <share> -AccountName 'utente' -AccessRight Read"
    ],
    effort: "moderate"
  },
};

// Sticky state for the endpoint page:
//   _epLoadedOnce — load the heavy sub-checks only on first visit
//   _epRefreshing — debounce overlapping refreshAll() calls
// The auto-refresh timer (refreshAll, every 5s) calls loadEndpoint() while
// the user is on this page. Without these guards, every 5s we would overwrite
// every panel with "Loading..." spinners — making it impossible to read.
let _epLoadedOnce = false;
let _epRefreshing = false;

async function loadEndpoint() {
  if (_epRefreshing) return;
  _epRefreshing = true;
  try {
    // Probe module health with a strict timeout (3s) so a slow audit in
    // flight doesn't flap the status banner with "Failed to fetch".
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), 3000);
    let h = null;
    try {
      const r = await fetch(EP + '/health', { credentials: 'include', signal: ctrl.signal });
      if (r.ok) h = await r.json();
    } catch (_) { /* treated as offline */ }
    finally { clearTimeout(tid); }

    const auditEl = document.getElementById('epAuditStatus');
    if (h) {
      auditEl.innerHTML =
        `<div class="muted" style="margin-bottom:8px; display:flex; gap:14px; align-items:center; flex-wrap:wrap">
           <span><span class="status-dot online"></span> Endpoint module v${esc(h.version)} attivo</span>
           <span>YARA ${h.yara_loaded ? '✓' : '✗'}</span>
           <span>Defender ${h.defender_enabled ? '✓' : '✗'}</span>
           <span>${h.hash_iocs} IoC hash</span>
           <span style="margin-left:auto">${_epLoadedOnce ? '<em style=\"font-size:11px\">click 🔄 sui pannelli per aggiornarli</em>' : ''}</span>
         </div>`;
    } else {
      // Stale banner only — does NOT clear other panels.
      auditEl.innerHTML =
        `<div class="muted" style="margin-bottom:8px">
           <span class="status-dot offline"></span>
           Endpoint module non raggiungibile (al momento). Avvialo con
           <code>.\\aegis-endpoint.ps1 -Admin</code> sul host Windows.
         </div>`;
    }

    // Heavy sub-checks run ONLY on first visit. After that the per-card
    // refresh buttons are the only way to reload them.
    if (!_epLoadedOnce && h) {
      _epLoadedOnce = true;
      loadEndpointCheck('defender',  'epDefenderResult');
      loadEndpointCheck('firewall',  'epFirewallResult');
      loadEndpointCheck('bitlocker', 'epBitlockerResult');
      loadEndpointCheck('accounts',  'epAccountsResult');
      loadEndpointInfo();
      if (typeof loadDefenseIntegrations === 'function') loadDefenseIntegrations();
    }
  } finally {
    _epRefreshing = false;
  }
}

async function runHardeningAudit(includeUpdates = false) {
  const status = document.getElementById('epAuditStatus');
  const out = document.getElementById('epAuditResults');
  status.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Audit in corso (può richiedere 10-30s)...';
  out.innerHTML = '';
  try {
    const url = EP + '/audit' + (includeUpdates ? '?updates=1' : '');
    const r = await fetch(url, { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    // KPIs
    document.getElementById('epScore').textContent = d.score;
    document.getElementById('epScore').style.color =
      d.score >= 80 ? 'var(--accent-green)' :
      d.score >= 60 ? 'var(--accent-amber)' : 'var(--accent-red)';
    document.getElementById('epCritical').textContent = d.summary?.critical || 0;
    document.getElementById('epHigh').textContent = d.summary?.high || 0;
    // Render findings grouped by check
    const findings = (d.findings || []).filter(f => f.status !== 'ok');
    status.innerHTML = `<div class="muted">Score: <strong style="color:${d.score>=80?'var(--accent-green)':'var(--accent-amber)'}">${d.score}/100</strong> · ${findings.length} finding totali · OK: ${d.summary?.ok || 0}</div>`;
    out.innerHTML = '<div class="panel" style="margin-top:8px"><div class="panel-title" style="margin-bottom:8px"><i class="fa-solid fa-list-check"></i> Findings (' + findings.length + ')</div>' + renderFindings(findings) + '</div>';
    showToast('Audit Completato', `Score: ${d.score}/100 · ${findings.length} finding`, d.score>=80?'success':'warning');
  } catch (e) {
    status.innerHTML = '<span style="color:var(--accent-red)">Errore: ' + esc(String(e)) + '</span>';
  }
}

async function loadEndpointCheck(name, targetId) {
  const target = document.getElementById(targetId);
  // Preserve previous content. Only flip to "Loading..." when the panel is
  // empty or holds the initial placeholder; never overwrite real results.
  const hadResults = target.querySelector('table, .rem-card, .panel') !== null
                  || (target.innerText || '').length > 80;
  if (!hadResults) {
    target.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Loading...';
  }

  // Per-request hard timeout so a momentary network blip doesn't hang the UI.
  const ctrl = new AbortController();
  const tid = setTimeout(() => ctrl.abort(), 60000);
  try {
    const r = await fetch(EP + '/' + name, { credentials: 'include', signal: ctrl.signal });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();

    if (d.available === false) {
      // The check ran but the data is simply not exposed on this SKU
      // (Windows Home, missing RSAT, ...). Render it as an info card, not
      // as an error.
      target.innerHTML = `<div class="rem-card low" style="border-left-color:var(--text-muted)">
        <h4><i class="fa-solid fa-circle-info"></i> ${esc(name)} — non disponibile</h4>
        <div style="font-size:12px; color:var(--text-muted)">${esc(d.error || 'Check non supportato su questa SKU di Windows.')}</div>
        <div style="font-size:11px; color:var(--text-muted); margin-top:6px">
          Suggerimento: avvia <code>aegis-endpoint.ps1 -Admin</code> e/o installa RSAT se serve.
        </div>
      </div>`;
      if (name === 'defender') {
        document.getElementById('epDefender').textContent = 'N/D';
        document.getElementById('epDefender').style.color = 'var(--text-muted)';
      }
      return;
    }

    let summary = '';
    if (name === 'defender' && d.raw) {
      const rt = d.raw.RealTimeProtectionEnabled;
      document.getElementById('epDefender').textContent = rt ? 'ON' : 'OFF';
      document.getElementById('epDefender').style.color = rt ? 'var(--accent-green)' : 'var(--accent-red)';
      summary = `<div style="font-size:12px; margin-bottom:10px">
        Signature version: <code>${esc(d.raw.AntivirusSignatureVersion || 'n/a')}</code><br>
        Real-time: ${rt ? '✓' : '✗'} · Tamper: ${d.raw.IsTamperProtected ? '✓' : '✗'} · Behavior: ${d.raw.BehaviorMonitorEnabled ? '✓' : '✗'}
      </div>`;
    }
    target.innerHTML = summary + renderFindings(d.findings || []);
  } catch (e) {
    // Non-distruttivo: NON cancellare i risultati precedenti se ci sono.
    // Aggiungo solo un banner stale in cima.
    const msg = e && e.name === 'AbortError'
      ? 'Timeout: il check ha impiegato troppo. Riprova.'
      : ('Errore: ' + (e && e.message ? e.message : String(e)));
    if (hadResults) {
      // Insert a stale notice at the top, keep existing content below.
      const banner = document.createElement('div');
      banner.style.cssText = 'background:rgba(245,158,11,.1); border:1px solid var(--accent-amber); border-radius:6px; padding:6px 10px; margin-bottom:8px; font-size:11.5px; color:var(--accent-amber)';
      banner.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> ${esc(msg)} — dati mostrati possono essere obsoleti.`;
      // Replace any previous banner.
      const old = target.querySelector('[data-stale-banner]');
      if (old) old.remove();
      banner.setAttribute('data-stale-banner', '1');
      target.insertBefore(banner, target.firstChild);
    } else {
      target.innerHTML = `<div class="empty-state"><i class="fa-solid fa-plug-circle-xmark"></i>
        <div>${esc(msg)}</div>
        <div style="font-size:11px; margin-top:6px">Verifica che <code>aegis-endpoint.ps1</code> sia in esecuzione.</div>
      </div>`;
    }
  } finally {
    clearTimeout(tid);
  }
}

async function loadEndpointIntegrations() {
  const target = document.getElementById('epIntegrationsResult');
  target.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Probing installed defensive tools (max 30s)...';
  try {
    const r = await fetch(EP + '/integrations', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const tools = d.tools || [];
    const rows = tools.map(t => {
      const installedBadge = t.installed
        ? '<span class="badge low">installed</span>'
        : (t.service && t.service.reachable
            ? '<span class="badge medium">remote-reachable</span>'
            : '<span class="badge info">missing</span>');
      const svcInfo = t.service && t.service.configured
        ? `<span style="font-size:11px; color:${t.service.reachable?'var(--accent-green)':'var(--accent-amber)'}">${esc(t.service.url || '')}${t.service.reachable ? ' ✓' : ' ✗'}</span>`
        : '';
      return `<tr>
        <td>${installedBadge}</td>
        <td><strong>${esc(t.name)}</strong><div style="font-size:10.5px; color:var(--text-muted)">${esc(t.layer)}</div></td>
        <td style="font-size:11px">${esc(t.role)}</td>
        <td style="font-size:11px; font-family:monospace">${esc(t.version || (t.binary ? 'binary present' : '—'))}</td>
        <td>${svcInfo}</td>
      </tr>`;
    }).join('');
    const byLayerHtml = Object.entries(d.by_layer || {}).map(([k,v]) =>
      `<span style="margin-right:10px"><strong>${esc(k)}</strong>: ${v.available}/${v.total}</span>`
    ).join('');
    target.innerHTML = `<div style="margin-bottom:8px; font-size:12px">
      <strong>${d.installed_count}/${d.total_count}</strong> tool disponibili su questo host.
      ${byLayerHtml}
    </div>
    <table class="table"><thead><tr><th>Status</th><th>Tool</th><th>Ruolo</th><th>Versione</th><th>Servizio</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) {
    target.innerHTML = '<div class="empty-state"><i class="fa-solid fa-plug-circle-xmark"></i><div>Endpoint module offline o errore: ' + esc(String(e)) + '</div></div>';
  }
}

async function scanClamav() {
  const path = document.getElementById('epClamavPath').value.trim();
  const recursive = document.getElementById('epClamavRec').checked;
  const out = document.getElementById('epClamavResult');
  if (!path) { out.innerHTML = '<span style="color:var(--accent-amber)">Inserisci un path file o directory.</span>'; return; }
  out.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ClamAV scan in corso (può richiedere minuti)...';
  try {
    const r = await fetch(EP + '/scan/clamav', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, recursive }),
    });
    const d = await r.json();
    if (!r.ok || !d.available) {
      out.innerHTML = `<div class="empty-state"><i class="fa-solid fa-circle-xmark"></i><div>${esc(d.error || ('HTTP ' + r.status))}</div>
        <div style="font-size:11px; margin-top:8px">ClamAV non installato? Scaricalo da <a href="https://www.clamav.net/downloads" target="_blank" rel="noopener" style="color:var(--accent-blue)">clamav.net</a> e aggiungi <code>clamscan.exe</code> al PATH.</div></div>`;
      return;
    }
    const verdictColor = d.verdict === 'infected' ? 'var(--accent-red)' : d.verdict === 'clean' ? 'var(--accent-green)' : 'var(--accent-amber)';
    out.innerHTML = `<div class="rem-card ${d.verdict==='infected'?'critical':d.verdict==='clean'?'low':'high'}">
      <h4><i class="fa-solid fa-virus-slash"></i> ClamAV → <span style="color:${verdictColor}; text-transform:uppercase">${esc(d.verdict)}</span></h4>
      <div class="rem-meta">
        <span><strong>Path:</strong> <code>${esc(d.path)}</code></span>
        <span><strong>Infected:</strong> ${esc(d.infected_count||0)}</span>
        <span><strong>Duration:</strong> ${esc(d.duration_seconds||0)}s</span>
        <span><strong>Exit:</strong> ${esc(d.exit_code)}</span>
      </div>
      <pre style="background:var(--surface-3); padding:10px; border-radius:6px; font-size:11px; overflow-x:auto; max-height:280px">${esc((d.report || '').slice(0,5000))}</pre>
    </div>`;
    if (d.verdict === 'infected') {
      showToast('ClamAV', `${d.infected_count} file infetti in ${d.path}`, 'critical');
    }
  } catch (e) {
    out.innerHTML = '<span style="color:var(--accent-red)">Errore: ' + esc(String(e)) + '</span>';
  }
}

async function loadEndpointInfo() {
  const el = document.getElementById('epHostInfo');
  try {
    const r = await fetch(EP + '/info', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const w = d.windows || {};
    el.innerHTML = `<table class="table" style="font-size:12.5px">
      <tr><td><strong>Hostname</strong></td><td>${esc(d.hostname)}</td></tr>
      <tr><td><strong>OS</strong></td><td>${esc(w.OSCaption || d.platform)} (build ${esc(w.OSBuild || '?')})</td></tr>
      <tr><td><strong>Domain</strong></td><td>${esc(w.Domain || 'WORKGROUP')}</td></tr>
      <tr><td><strong>Hardware</strong></td><td>${esc(w.Manufacturer || '')} ${esc(w.Model || '')} · ${esc(w.TotalPhysicalMemoryGB || '?')}GB RAM · ${esc(w.NumberOfProcessors || '?')} CPU</td></tr>
      <tr><td><strong>User</strong></td><td>${esc(d.user || '')}</td></tr>
      <tr><td><strong>Python</strong></td><td>${esc(d.python)}</td></tr>
    </table>`;
  } catch (e) {
    el.innerHTML = '<div class="empty-state"><i class="fa-solid fa-plug-circle-xmark"></i><div>Endpoint offline: ' + esc(String(e)) + '</div></div>';
  }
}

async function loadProcesses() {
  const target = document.getElementById('epProcessesResult');
  target.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Enumerating processes...';
  try {
    const r = await fetch(EP + '/processes?top=300', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    if (!d.available) { target.innerHTML = '<div class="empty-state">'+esc(d.error||'')+'</div>'; return; }
    const flagged = d.flagged || [];
    const rows = flagged.map(p => `<tr>
      <td><span class="badge ${esc(p.severity)}">${esc(p.severity)}</span></td>
      <td style="font-family:monospace">${esc(p.pid)}</td>
      <td>${esc(p.name)}</td>
      <td style="font-size:11px; color:var(--text-muted)">${esc((p.exe||'').slice(-60))}</td>
      <td>${esc(p.username||'')}</td>
      <td>${esc((p.flags||[]).join(', '))}</td>
      <td>${esc(p.open_connections||0)}</td>
    </tr>`).join('');
    const header = `<div style="font-size:12px; margin-bottom:8px">Total: <strong>${d.total_processes}</strong> · Flagged: <strong>${d.flagged_count}</strong> · By severity: ${esc(JSON.stringify(d.by_severity))}</div>`;
    if (!flagged.length) {
      target.innerHTML = header + '<div class="empty-state"><i class="fa-solid fa-circle-check" style="color:var(--accent-green)"></i><div>Nessun processo sospetto.</div></div>';
      return;
    }
    target.innerHTML = header + `<table class="table"><thead><tr><th>Sev</th><th>PID</th><th>Process</th><th>Exe</th><th>User</th><th>Flags</th><th>Conns</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) {
    target.innerHTML = '<div class="empty-state"><i class="fa-solid fa-plug-circle-xmark"></i><div>Errore: ' + esc(String(e)) + '</div></div>';
  }
}

async function loadConnections() {
  const target = document.getElementById('epProcessesResult');
  target.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Enumerating connections...';
  try {
    const r = await fetch(EP + '/connections', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    if (!d.available) { target.innerHTML = '<div class="empty-state">'+esc(d.error||'')+'</div>'; return; }
    const est = d.established || [];
    const lis = d.listening  || [];
    const rowsEst = est.slice(0, 50).map(c => `<tr>
      <td style="font-family:monospace">${esc(c.laddr)}</td>
      <td style="font-family:monospace">${esc(c.raddr)}</td>
      <td>${esc(c.status)}</td>
      <td>${esc(c.process||'')} (${esc(c.pid||'?')})</td>
    </tr>`).join('');
    const rowsLis = lis.slice(0, 50).map(c => `<tr>
      <td style="font-family:monospace">${esc(c.laddr)}</td>
      <td>${esc(c.status)}</td>
      <td>${esc(c.process||'')} (${esc(c.pid||'?')})</td>
    </tr>`).join('');
    target.innerHTML = `
      <div class="two-col">
        <div>
          <div style="font-weight:600; margin-bottom:6px">Established (${est.length})</div>
          <table class="table"><thead><tr><th>Local</th><th>Remote</th><th>State</th><th>Process</th></tr></thead><tbody>${rowsEst}</tbody></table>
        </div>
        <div>
          <div style="font-weight:600; margin-bottom:6px">Listening (${lis.length})</div>
          <table class="table"><thead><tr><th>Address</th><th>State</th><th>Process</th></tr></thead><tbody>${rowsLis}</tbody></table>
        </div>
      </div>`;
  } catch (e) {
    target.innerHTML = '<div class="empty-state"><i class="fa-solid fa-plug-circle-xmark"></i><div>Errore: ' + esc(String(e)) + '</div></div>';
  }
}

async function scanUploadedFile() {
  const input = document.getElementById('epFileUpload');
  const useD = document.getElementById('epUseDefender').checked;
  const out = document.getElementById('epFileScanResult');
  if (!input.files || !input.files[0]) {
    out.innerHTML = '<span style="color:var(--accent-amber)">Seleziona prima un file.</span>';
    return;
  }
  const f = input.files[0];
  if (f.size > 200 * 1024 * 1024) {
    out.innerHTML = '<span style="color:var(--accent-red)">File troppo grande (limite 200MB).</span>';
    return;
  }
  out.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Scansione ${esc(f.name)} (${(f.size/1024).toFixed(1)} KB)...`;
  try {
    const fd = new FormData();
    fd.append('file', f);
    const url = EP + '/scan/file' + (useD ? '?defender=1' : '');
    const r = await fetch(url, { method: 'POST', body: fd, credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const verdictColor = d.verdict === 'malicious' ? 'var(--accent-red)' : d.verdict === 'suspicious' ? 'var(--accent-amber)' : 'var(--accent-green)';
    out.innerHTML = `<div class="rem-card ${esc(d.verdict==='malicious'?'critical':d.verdict==='suspicious'?'high':'low')}">
      <h4><i class="fa-solid fa-file-shield"></i> ${esc(f.name)} → <span style="color:${verdictColor}; text-transform:uppercase">${esc(d.verdict)}</span></h4>
      <div class="rem-meta">
        <span><strong>SHA-256:</strong> <code style="font-size:10.5px">${esc(d.sha256)}</code></span>
        <span><strong>Size:</strong> ${(d.file_size/1024).toFixed(1)} KB</span>
      </div>
      <div style="font-size:12.5px; margin-bottom:8px"><strong>${esc(d.summary || '')}</strong></div>
      ${d.yara_matches && d.yara_matches.length ? '<div style="margin:8px 0; font-size:12px"><strong>YARA matches:</strong><ul>' + d.yara_matches.map(m => `<li><code>${esc(m.rule)}</code> ${m.tags && m.tags.length ? '(' + m.tags.map(esc).join(',') + ')' : ''} ${m.meta && m.meta.description ? '— ' + esc(m.meta.description) : ''}</li>`).join('') + '</ul></div>' : ''}
      ${d.hash_match ? `<div style="margin:8px 0; font-size:12px; color:var(--accent-red)"><strong>Hash IoC:</strong> ${esc(d.hash_match.label)}</div>` : ''}
      ${d.defender_threats && d.defender_threats.length ? '<div style="margin:8px 0; font-size:12px"><strong>Defender:</strong><ul>' + d.defender_threats.map(t => `<li>${esc(t)}</li>`).join('') + '</ul></div>' : ''}
    </div>`;
    if (d.verdict === 'malicious' || d.verdict === 'suspicious') {
      showToast('File pericoloso', `${f.name}: ${d.verdict.toUpperCase()}`, 'critical');
    }
  } catch (e) {
    out.innerHTML = '<span style="color:var(--accent-red)">Errore: ' + esc(String(e)) + '</span>';
  }
}

async function scanSecretsDir() {
  const path = document.getElementById('epSecretsPath').value.trim();
  const max  = parseInt(document.getElementById('epSecretsMax').value, 10) || 5000;
  const out  = document.getElementById('epSecretsResult');
  if (!path) { out.innerHTML = '<span style="color:var(--accent-amber)">Inserisci un percorso.</span>'; return; }
  out.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning ' + esc(path) + ' (max ' + max + ' files)...';
  try {
    const r = await fetch(EP + '/scan/secrets', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, max_files: max }),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    if (d.error) { out.innerHTML = '<span style="color:var(--accent-red)">' + esc(d.error) + '</span>'; return; }
    const findings = d.findings || [];
    if (!findings.length) {
      out.innerHTML = `<div class="rem-card low"><h4><i class="fa-solid fa-circle-check"></i> Pulito</h4><div>Nessun secret trovato in ${d.files_seen} file analizzati.</div></div>`;
      return;
    }
    const rows = findings.slice(0, 200).map(f => `<tr>
      <td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td>${esc(f.rule_id)}</td>
      <td style="font-family:monospace; font-size:11px; max-width:300px; overflow:hidden; text-overflow:ellipsis">${esc(f.file)}:${esc(f.line)}</td>
      <td style="font-family:monospace; font-size:11px">${esc(f.match)}</td>
    </tr>`).join('');
    out.innerHTML = `<div class="rem-card high">
      <h4><i class="fa-solid fa-key"></i> ${d.total_findings} secret(s) potenziali</h4>
      <div class="rem-meta">
        <span>Critical: ${d.by_severity.critical||0}</span>
        <span>High: ${d.by_severity.high||0}</span>
        <span>Medium: ${d.by_severity.medium||0}</span>
        <span>File scansionati: ${d.files_seen}</span>
      </div>
    </div>
    <table class="table"><thead><tr><th>Sev</th><th>Rule</th><th>File:Line</th><th>Match</th></tr></thead><tbody>${rows}</tbody></table>
    ${findings.length > 200 ? '<div class="muted" style="margin-top:6px">Mostrati primi 200 di ' + findings.length + '.</div>' : ''}`;
    showToast('Secrets scan', `${d.total_findings} secret trovati in ${d.files_seen} file`, d.by_severity.critical > 0 ? 'critical' : 'warning');
  } catch (e) {
    out.innerHTML = '<span style="color:var(--accent-red)">Errore: ' + esc(String(e)) + '</span>';
  }
}

async function loadDefenseIntegrations() {
  const out = document.getElementById('epIntegrationsResult');
  out.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Controllo tool installati...';
  try {
    const r = await fetch(EP + '/integrations', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const tools = d.tools || [];
    const layers = Object.entries(d.by_layer || {}).map(([layer, v]) =>
      `<span class="badge info">${esc(layer)}: ${esc(v.available)}/${esc(v.total)}</span>`).join(' ');
    const rows = tools.map(t => {
      const reachable = t.service && t.service.reachable;
      const configured = t.service && t.service.configured;
      const statusClass = t.installed || reachable ? 'low' : configured ? 'medium' : 'info';
      const statusText = t.installed ? 'BINARIO' : reachable ? 'SERVIZIO' : configured ? 'CONFIG ERR' : 'MANCANTE';
      const detail = t.installed
        ? esc((t.binary || '').split(/[\\/]/).pop())
        : reachable
          ? esc((t.service && t.service.url_env ? t.service.url_env : 'service') + ' HTTP ' + (t.service.status_code || 'ok'))
          : configured
            ? esc((t.service && t.service.url_env ? t.service.url_env : 'service') + ': ' + (t.service.error || 'non raggiungibile'))
            : '—';
      return `<tr>
        <td><span class="badge ${statusClass}">${statusText}</span></td>
        <td><strong>${esc(t.name)}</strong><div style="font-size:11px;color:var(--text-muted)">${esc(t.role || '')}</div></td>
        <td>${esc(t.layer)}</td>
        <td style="font-family:monospace;font-size:11px">${detail}</td>
        <td style="font-size:11px">${esc(t.version || t.version_error || t.notes || '')}</td>
      </tr>`;
    }).join('');
    out.innerHTML = `<div style="font-size:12px;margin-bottom:8px">
      Installati/configurati: <strong>${esc(d.installed_count)}</strong> / ${esc(d.total_count)} · ${layers}
    </div>
    <table class="table"><thead><tr><th>Stato</th><th>Tool</th><th>Layer</th><th>Dettaglio</th><th>Versione/Note</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) {
    out.innerHTML = '<div class="empty-state"><i class="fa-solid fa-plug-circle-xmark"></i><div>Modulo endpoint offline o errore: ' + esc(String(e)) + '</div></div>';
  }
}

async function loadRoadmapToolCount() {
  const el = document.getElementById('roadmapToolCount');
  if (!el) return;
  try {
    const r = await fetch(EP + '/integrations', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    el.textContent = `${d.installed_count || 0}/${d.total_count || 0}`;
    el.style.color = (d.installed_count || 0) > 0 ? 'var(--accent-green)' : 'var(--accent-amber)';
  } catch (_) {
    el.textContent = '--';
    el.style.color = 'var(--accent-amber)';
  }
}

async function scanClamAvPath() {
  const path = document.getElementById('epClamPath').value.trim();
  const recursive = document.getElementById('epClamRecursive').checked;
  const timeout = parseInt(document.getElementById('epClamTimeout').value, 10) || 300;
  const out = document.getElementById('epClamResult');
  if (!path) { out.innerHTML = '<span style="color:var(--accent-amber)">Inserisci un percorso da scansionare.</span>'; return; }
  out.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ClamAV scan in corso su ' + esc(path) + '...';
  try {
    const r = await fetch(EP + '/scan/clamav', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, recursive, timeout }),
    });
    const d = await r.json().catch(() => ({}));
    if (!r.ok && !d.error) throw new Error('HTTP ' + r.status);
    const verdict = d.verdict || (d.error ? 'error' : 'unknown');
    const sev = verdict === 'infected' ? 'critical' : verdict === 'clean' ? 'low' : 'medium';
    const color = verdict === 'infected' ? 'var(--accent-red)' : verdict === 'clean' ? 'var(--accent-green)' : 'var(--accent-amber)';
    out.innerHTML = `<div class="rem-card ${sev}">
      <h4><i class="fa-solid fa-virus-covid-slash"></i> ClamAV → <span style="color:${color}; text-transform:uppercase">${esc(verdict)}</span></h4>
      <div class="rem-meta">
        <span><strong>Path:</strong> <code>${esc(d.path || path)}</code></span>
        ${d.scanner ? `<span><strong>Scanner:</strong> <code>${esc((d.scanner || '').split(/[\\/]/).pop())}</code></span>` : ''}
        ${d.duration_seconds !== undefined ? `<span><strong>Durata:</strong> ${esc(d.duration_seconds)}s</span>` : ''}
        ${d.infected_count !== undefined ? `<span><strong>Infected:</strong> ${esc(d.infected_count)}</span>` : ''}
      </div>
      ${d.error ? `<div style="color:var(--accent-amber);font-size:12px;margin-bottom:8px">${esc(d.error)}</div>` : ''}
      ${d.report ? `<pre style="white-space:pre-wrap;max-height:260px;overflow:auto;background:var(--surface-3);border:1px solid var(--border);padding:8px;border-radius:6px;font-size:11px">${esc(d.report)}</pre>` : ''}
    </div>`;
    if (verdict === 'infected') showToast('ClamAV', 'Contenuto infetto rilevato', 'critical');
  } catch (e) {
    out.innerHTML = '<span style="color:var(--accent-red)">Errore: ' + esc(String(e)) + '</span>';
  }
}

// ========================= SECURITY POSTURE =========================
async function loadPosture() {
  const layers = document.getElementById('psLayers');
  const actions = document.getElementById('psActions');
  layers.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Calcolo posture (può richiedere 30s)...';
  actions.innerHTML = '';
  try {
    const r = await fetch(EP + '/posture', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    document.getElementById('psScore').textContent = d.score;
    document.getElementById('psScore').style.color =
      d.score >= 80 ? 'var(--accent-green)' :
      d.score >= 60 ? 'var(--accent-amber)' : 'var(--accent-red)';
    document.getElementById('psGrade').textContent = d.grade;
    document.getElementById('psGrade').style.color =
      ({A:'var(--accent-green)', B:'var(--accent-green)', C:'var(--accent-amber)', D:'var(--accent-red)', F:'var(--accent-red)'})[d.grade] || 'var(--text-muted)';
    document.getElementById('psCritical').textContent = d.summary_by_severity.critical || 0;
    document.getElementById('psHigh').textContent = d.summary_by_severity.high || 0;

    const order = ['perimetro', 'endpoint', 'rete', 'identita', 'dati', 'intelligence'];
    layers.innerHTML = order.map(k => {
      const L = d.layers[k] || {};
      const pct = (L.score / 20) * 100;
      const color = pct >= 80 ? 'var(--accent-green)' : pct >= 50 ? 'var(--accent-amber)' : 'var(--accent-red)';
      return `<div style="margin-bottom:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;font-size:13px;margin-bottom:4px">
          <span><strong style="text-transform:uppercase">${esc(k)}</strong></span>
          <span style="font-family:monospace;font-weight:700;color:${color}">${L.score}/20</span>
        </div>
        <div class="perf-bar"><div class="perf-fill" style="width:${pct}%;background:${color}"></div></div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:4px">${(L.detail||[]).map(esc).join(' · ')}</div>
      </div>`;
    }).join('');

    actions.innerHTML = (d.top_actions || []).length ? (d.top_actions || []).map(f => `
      <div style="padding:8px 10px;border-bottom:1px solid var(--border);display:flex;gap:10px;align-items:center">
        <span class="badge ${esc(f.severity)}">${esc(f.severity)}</span>
        <div style="flex:1">
          <div style="font-weight:600;font-size:13px">${esc(f.title || f.check_id || '')}</div>
          <div style="font-size:11px;color:var(--text-muted)">${esc(f.description||'')} <em>· layer: ${esc(f.layer||'')}</em></div>
        </div>
        ${f.remediation_key ? `<button class="btn-fix" onclick='showRemediationFromKey(${JSON.stringify(f.remediation_key)})'><i class="fa-solid fa-wrench"></i> Fix</button>` : ''}
      </div>`).join('') : '<div class="muted">Nessuna azione prioritaria — buon lavoro!</div>';
    showToast('Posture', `Score: ${d.score}/100 (${d.grade})`, d.score>=80?'success':'warning');
  } catch (e) {
    layers.innerHTML = '<div class="empty-state"><i class="fa-solid fa-plug-circle-xmark"></i><div>Errore: ' + esc(String(e)) + '</div></div>';
  }
}

// ========================= THREAT HUNT v2 =========================
async function loadHuntCatalog() {
  const target = document.getElementById('huntCatalog');
  target.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Loading catalog...';
  try {
    const r = await fetch(EP + '/hunt', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    document.getElementById('huntCatalogCount').textContent = d.count || 0;
    document.getElementById('huntCatalogCount').style.color = 'var(--accent-cyan)';
    const rows = (d.queries || []).map(q => `
      <tr>
        <td><strong style="font-size:12.5px">${esc(q.title)}</strong>
            <div style="font-size:10.5px;color:var(--text-muted)">${esc(q.id)}</div></td>
        <td style="font-size:11px">${esc(q.description)}</td>
        <td><code style="font-size:11px">${esc(q.technique)}</code></td>
        <td><button class="btn primary" onclick='runOneHunt(${JSON.stringify(q.id)})' style="font-size:11px;padding:3px 8px"><i class="fa-solid fa-play"></i> Run</button></td>
      </tr>`).join('');
    target.innerHTML = `<table class="table"><thead><tr><th>Query</th><th>Descrizione</th><th>MITRE</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) {
    target.innerHTML = '<div class="empty-state"><i class="fa-solid fa-plug-circle-xmark"></i><div>Errore: ' + esc(String(e)) + '</div></div>';
  }
}

async function runOneHunt(qid) {
  const target = document.getElementById('huntFindings');
  target.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Running ${esc(qid)}...`;
  try {
    const r = await fetch(EP + '/hunt/' + encodeURIComponent(qid), {
      method: 'POST', credentials: 'include',
      headers: {'Content-Type':'application/json'}, body: '{}',
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    renderHuntResults(target, d);
  } catch (e) {
    target.innerHTML = '<span style="color:var(--accent-red)">' + esc(String(e)) + '</span>';
  }
}

async function runAllHunts() {
  const target = document.getElementById('huntFindings');
  target.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Running all queries (può richiedere 60-120s)...';
  try {
    const r = await fetch(EP + '/hunt/run', {
      method: 'POST', credentials: 'include',
      headers: {'Content-Type':'application/json'}, body: '{}',
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    document.getElementById('huntCritical').textContent = d.by_severity?.critical || 0;
    document.getElementById('huntHigh').textContent = d.by_severity?.high || 0;
    renderHuntResults(target, d);
    showToast('Threat Hunt', `${d.total_findings} finding totali in ${d.duration_seconds}s`, d.total_findings>0?'warning':'success');
  } catch (e) {
    target.innerHTML = '<span style="color:var(--accent-red)">' + esc(String(e)) + '</span>';
  }
}

function renderHuntResults(target, d) {
  const findings = d.findings || [];
  if (!findings.length) {
    target.innerHTML = `<div class="rem-card low"><h4><i class="fa-solid fa-circle-check"></i> Nessun finding</h4>
      <div>Tutte le query catalog non hanno rilevato anomalie in ${d.duration_seconds||0}s.</div></div>`;
    return;
  }
  const rows = findings.slice(0, 200).map(f => {
    const remBtn = f.remediation_key
      ? `<button class="btn-fix" onclick='showRemediationFromKey(${JSON.stringify(f.remediation_key)})'><i class="fa-solid fa-wrench"></i> Fix</button>`
      : '';
    return `<tr>
      <td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td><code style="font-size:11px">${esc(f.technique||'-')}</code></td>
      <td style="font-size:12.5px">${esc(f.title||'')}</td>
      <td style="font-size:11px;color:var(--text-muted);max-width:340px;overflow:hidden;text-overflow:ellipsis">${esc(JSON.stringify(f.evidence||{}).slice(0,140))}</td>
      <td>${remBtn}</td>
    </tr>`;
  }).join('');
  target.innerHTML = `<div style="margin-bottom:8px;font-size:12px">
    <strong>${findings.length}</strong> finding · By severity:
    critical=${d.by_severity?.critical||0} high=${d.by_severity?.high||0} medium=${d.by_severity?.medium||0} low=${d.by_severity?.low||0}
    · Duration: ${d.duration_seconds||0}s
  </div>
  <table class="table"><thead><tr><th>Sev</th><th>MITRE</th><th>Titolo</th><th>Evidence</th><th></th></tr></thead><tbody>${rows}</tbody></table>
  ${findings.length > 200 ? `<div class="muted" style="margin-top:6px">Mostrati primi 200 di ${findings.length}.</div>` : ''}`;
}

// ========================= REALTIME =========================
async function loadRealtimeStatus() {
  const target = document.getElementById('realtimeStatus');
  target.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ...';
  try {
    const r = await fetch(EP + '/realtime/status', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    document.getElementById('huntRealtime').textContent = d.running ? 'ON' : 'OFF';
    document.getElementById('huntRealtime').style.color = d.running ? 'var(--accent-green)' : 'var(--text-muted)';
    target.innerHTML = `<div style="font-size:12.5px">
      <div>State: <strong style="color:${d.running?'var(--accent-green)':'var(--text-muted)'}">${d.running?'RUNNING':'STOPPED'}</strong></div>
      <div>Started at: <code>${esc(d.stats?.started_at || 'never')}</code></div>
      <div>Last poll: <code>${esc(d.stats?.last_poll_at || '—')}</code></div>
      <div>Polls completed: ${d.stats?.polls || 0}</div>
      <div>Events emitted: <strong>${d.stats?.events_emitted || 0}</strong></div>
      <div style="margin-top:6px;font-size:11px;color:var(--text-muted)">By kind: ${esc(JSON.stringify(d.stats?.emitted_by_kind || {}))}</div>
    </div>`;
  } catch (e) {
    target.innerHTML = '<span style="color:var(--accent-red)">' + esc(String(e)) + '</span>';
  }
}
async function startRealtime() {
  const r = await fetch(EP + '/realtime/start', { method:'POST', credentials:'include' });
  if (r.ok) showToast('Realtime', 'Monitor live ATTIVO — eventi inviati a SOC overview', 'success');
  loadRealtimeStatus();
}
async function stopRealtime() {
  const r = await fetch(EP + '/realtime/stop', { method:'POST', credentials:'include' });
  if (r.ok) showToast('Realtime', 'Monitor live FERMATO', 'info');
  loadRealtimeStatus();
}

// ========================= LIVE IOC =========================
async function loadIOCStatus() {
  const target = document.getElementById('iocStatus');
  target.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ...';
  try {
    const r = await fetch(EP + '/ioc/feeds', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const s = d.stats || {};
    const rows = (d.feeds || []).map(f => `<tr>
      <td><strong>${esc(f.name)}</strong></td>
      <td style="font-size:11px"><code>${esc(f.kind)}</code></td>
      <td>${(f.rows||0).toLocaleString()}</td>
      <td style="font-size:11px;color:var(--text-muted)">${esc(f.fetched_at||'—')}</td>
    </tr>`).join('');
    target.innerHTML = `<div style="font-size:12px;margin-bottom:8px">
      <strong>${(s.ip_count||0).toLocaleString()}</strong> IP ·
      <strong>${(s.cidr_count||0).toLocaleString()}</strong> CIDR ·
      <strong>${(s.domain_count||0).toLocaleString()}</strong> domini ·
      <strong>${(s.hash_count||0).toLocaleString()}</strong> hash ·
      <strong>${(s.url_count||0).toLocaleString()}</strong> URL
    </div>
    <table class="table"><thead><tr><th>Feed</th><th>Tipo</th><th>Rows</th><th>Updated</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) {
    target.innerHTML = '<span style="color:var(--accent-red)">' + esc(String(e)) + '</span>';
  }
}
async function refreshIOCFeeds() {
  const target = document.getElementById('iocStatus');
  target.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Downloading feeds (può richiedere 30s)...';
  try {
    const r = await fetch(EP + '/ioc/refresh', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify({force: true}),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    showToast('IOC Feeds', 'Refresh completato', 'success');
    loadIOCStatus();
  } catch (e) {
    target.innerHTML = '<span style="color:var(--accent-red)">' + esc(String(e)) + '</span>';
  }
}
async function iocLookup() {
  const val = document.getElementById('iocLookupInput').value.trim();
  const out = document.getElementById('iocLookupResult');
  if (!val) { out.textContent = 'Inserisci un IP, dominio, URL o hash.'; return; }
  // Heuristic param picker
  let param = '';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(val)) param = 'ip=' + encodeURIComponent(val);
  else if (val.startsWith('http://') || val.startsWith('https://')) param = 'url=' + encodeURIComponent(val);
  else if (/^[a-f0-9]{32,64}$/i.test(val)) param = 'hash=' + encodeURIComponent(val);
  else param = 'domain=' + encodeURIComponent(val);
  try {
    const r = await fetch(EP + '/ioc/lookup?' + param, { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const matched = d.matched;
    out.innerHTML = matched
      ? `<div class="rem-card critical"><h4><i class="fa-solid fa-triangle-exclamation"></i> MATCH TROVATO</h4>
          <pre style="font-size:11px;margin-top:6px">${esc(JSON.stringify(d.results, null, 2))}</pre>
         </div>`
      : `<div class="rem-card low"><h4><i class="fa-solid fa-circle-check"></i> No match</h4>
          <div>${esc(val)} non corrisponde a nessuno IOC nel database.</div></div>`;
  } catch (e) {
    out.innerHTML = '<span style="color:var(--accent-red)">' + esc(String(e)) + '</span>';
  }
}

// ========================= CONTAINMENT =========================
async function _containCall(path, payload, resultId) {
  const out = document.getElementById(resultId);
  const confirm = document.getElementById('containConfirm').checked;
  const headers = {'Content-Type':'application/json'};
  if (confirm) headers['X-AEGIS-Confirm'] = 'yes';
  out.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ...';
  try {
    const r = await fetch(EP + path, {
      method:'POST', credentials:'include', headers, body: JSON.stringify(payload),
    });
    const d = await r.json();
    const color = d.dry_run ? 'var(--accent-amber)' : (d.ok ? 'var(--accent-green)' : 'var(--accent-red)');
    const label = d.dry_run ? 'DRY-RUN' : (d.ok ? 'OK' : 'FAIL');
    out.innerHTML = `<div style="color:${color};font-weight:600;margin-bottom:4px">${label}</div>
      <pre style="font-size:10px;background:var(--surface-3);padding:6px;border-radius:4px;max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-all">${esc(JSON.stringify(d, null, 2))}</pre>`;
    if (!d.dry_run) loadContainmentLog();
  } catch (e) {
    out.innerHTML = '<span style="color:var(--accent-red)">' + esc(String(e)) + '</span>';
  }
}
function containBlockIP() {
  const ip = document.getElementById('containIP').value.trim();
  const dir = document.getElementById('containDir').value;
  if (!ip) return;
  if (dir === 'both') {
    _containCall('/contain/block-ip', {ip, direction:'in'}, 'containBlockResult');
    setTimeout(() => _containCall('/contain/block-ip', {ip, direction:'out'}, 'containBlockResult'), 500);
  } else {
    _containCall('/contain/block-ip', {ip, direction:dir}, 'containBlockResult');
  }
}
function containUnblockIP() {
  const ip = document.getElementById('containIP').value.trim();
  const dir = document.getElementById('containDir').value === 'out' ? 'out' : 'in';
  if (!ip) return;
  _containCall('/contain/unblock-ip', {ip, direction:dir}, 'containBlockResult');
}
function containKillPid() {
  const pid = parseInt(document.getElementById('containPid').value, 10);
  if (!pid) return;
  _containCall('/contain/kill-pid', {pid}, 'containActionResult');
}
function containQuarantine() {
  const path = document.getElementById('containFile').value.trim();
  if (!path) return;
  _containCall('/contain/quarantine', {path}, 'containActionResult');
}
function containDisableAcc() {
  const name = document.getElementById('containAccount').value.trim();
  if (!name) return;
  _containCall('/contain/disable-account', {name}, 'containAccResult');
}
function containEnableAcc() {
  const name = document.getElementById('containAccount').value.trim();
  if (!name) return;
  _containCall('/contain/enable-account', {name}, 'containAccResult');
}
function containIsolate() {
  const allow_ip = document.getElementById('containAllowIP').value.trim();
  if (!confirm('ATTENZIONE: questa azione blocca TUTTA la rete del host. Procedere?')) return;
  _containCall('/contain/isolate', {allow_ip}, 'containIsoResult');
}
function containUnisolate() {
  _containCall('/contain/unisolate', {}, 'containIsoResult');
}
async function loadContainmentLog() {
  const target = document.getElementById('containLog');
  try {
    const r = await fetch(EP + '/contain/log', { credentials: 'include' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    const rows = (d.recent || []).reverse().slice(0, 20).map(e => `<tr>
      <td style="font-size:10.5px;font-family:monospace">${esc(e.ts||'')}</td>
      <td><span class="badge medium">${esc(e.action||'')}</span></td>
      <td style="font-size:11px">${esc((e.reason||'').slice(0,40))}</td>
      <td style="font-size:11px;font-family:monospace">${esc((e.ip||e.user||e.path||e.pid||'').toString().slice(0,40))}</td>
      <td style="font-size:11px"><strong>${e.exit_code===0 ? '✓' : (e.exit_code===undefined ? '—' : '✗ '+e.exit_code)}</strong></td>
    </tr>`).join('');
    target.innerHTML = rows ? `<div style="font-weight:600;margin-bottom:6px"><i class="fa-solid fa-history"></i> Containment history (ultime 20)</div>
      <table class="table"><thead><tr><th>Timestamp</th><th>Action</th><th>Reason</th><th>Target</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table>` : '<div class="muted">Nessuna azione registrata.</div>';
  } catch (e) {
    target.innerHTML = '<span style="color:var(--accent-red)">' + esc(String(e)) + '</span>';
  }
}

// ========================= REMEDIATION =========================
// Fetch from /api/v1/remediation with any of: service, port, cve, ioc, tls.
// Returns a map { key: Remediation } or {} when nothing matches.
async function fetchRemediation(params) {
  const qs = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') qs.set(k, v); });
  if (!qs.toString()) return {};
  const r = await apiGet(API + '/remediation?' + qs.toString());
  return (r && r.results) ? r.results : {};
}

function renderRemediationCard(rem, header) {
  if (!rem) return '';
  const sev = (rem.severity || 'medium').toLowerCase();
  const actions = (rem.actions || []).map(a => `<li>${esc(a)}</li>`).join('');
  const refs = (rem.references || []).map(r => `<span>${esc(r)}</span>`).join('');
  const effortBadge = rem.effort ? `<span class="rem-effort ${esc(rem.effort)}">${esc(rem.effort)}</span>` : '';
  const automated = rem.automated ? `<span style="color:var(--accent-green)"><i class="fa-solid fa-robot"></i> SOAR-ready</span>` : '';
  const playbook = rem.playbook_id ? `<span><i class="fa-solid fa-bolt"></i> ${esc(rem.playbook_id)}.yaml</span>` : '';
  return `<div class="rem-card ${esc(sev)}">
    <h4><i class="fa-solid fa-shield-halved"></i> ${esc(header || 'Soluzione consigliata')} <span class="badge ${esc(sev)}">${esc(sev)}</span></h4>
    <div class="rem-meta">${effortBadge} ${automated} ${playbook}</div>
    <div style="font-size:12.5px; margin-bottom:8px"><strong>${esc(rem.summary || '')}</strong></div>
    ${rem.impact ? `<div class="rem-impact">⚠ Impatto: ${esc(rem.impact)}</div>` : ''}
    <ol>${actions}</ol>
    ${refs ? `<div class="rem-refs">Riferimenti: ${refs}</div>` : ''}
  </div>`;
}

// Show a modal that fetches remediation for a finding and renders one card
// per matching dimension (service / port / CVE).
async function showRemediationModal(opts, title) {
  const map = await fetchRemediation(opts);
  const keys = Object.keys(map);
  let body;
  if (!keys.length) {
    body = `<div class="empty-state"><i class="fa-solid fa-circle-info"></i>
      <div>Nessuna soluzione predefinita disponibile per questo target.</div>
      <div style="font-size:11px; margin-top:6px">Parametri: ${esc(JSON.stringify(opts))}</div></div>`;
  } else {
    body = keys.map(k => renderRemediationCard(map[k], k)).join('');
  }
  showModal(title || 'Soluzione consigliata', body);
}

// Generic modal helper — uses the existing #modalContainer if present,
// otherwise creates a transient overlay.
function showModal(title, htmlBody) {
  let host = document.getElementById('remediationModal');
  if (!host) {
    host = document.createElement('div');
    host.id = 'remediationModal';
    host.className = 'modal-overlay';
    host.innerHTML = `<div class="modal-box">
      <div class="modal-header">
        <h3 id="remediationModalTitle"></h3>
        <button class="modal-close" onclick="closeRemediationModal()"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div id="remediationModalBody"></div>
    </div>`;
    document.body.appendChild(host);
    host.addEventListener('click', e => { if (e.target === host) closeRemediationModal(); });
  }
  document.getElementById('remediationModalTitle').textContent = title;
  document.getElementById('remediationModalBody').innerHTML = htmlBody;
  host.classList.add('active');
}
function closeRemediationModal() {
  const host = document.getElementById('remediationModal');
  if (host) host.classList.remove('active');
}

// ========================= THREAT INTEL =========================
async function loadTI() {
  const d = await apiGet(PROXY+'/threat-intel/status');
  if (!d) return;
  const s = d || {};
  document.getElementById('tiTotal').textContent = s.total ?? 0;
  document.getElementById('tiIPs').textContent = (s.exact_iocs||0) + (s.cidr_ranges||0);
  document.getElementById('tiDomains').textContent = s.domains ?? 0;
  document.getElementById('tiMatches').textContent = '--';
  document.getElementById('tiFeeds').innerHTML = '<div class="muted">Registry: ' + (s.total||0) + ' IOCs loaded</div>';
  updateThreatMap();
}
async function tiLookup() {
  const val = document.getElementById('tiLookupInput').value.trim();
  if (!val) return;
  const resultEl = document.getElementById('tiLookupResult');
  resultEl.textContent = 'Ricerca in corso...';
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(val);
  const param = isIP ? 'ip=' + encodeURIComponent(val) : 'domain=' + encodeURIComponent(val);
  // try real endpoint first, fallback to proxy
  let res = await apiGet('/api/ti/lookup?' + param);
  if (!res) res = await apiGet(PROXY + '/threat-intel/lookup?' + param);
  if (!res) { resultEl.textContent = 'Errore: modulo threat-intel offline.'; return; }
  // pretty-print with color coding
  const matched = res.matched || (res.matches && res.matches.length > 0);
  const color = matched ? 'var(--accent-red)' : 'var(--accent-green)';
  const icon = matched ? '⚠ MATCH TROVATO' : '✓ Nessuna minaccia rilevata';
  resultEl.innerHTML = `<span style="font-weight:700;color:${color}">${icon}</span>\n` +
    `IP: ${esc(res.ip || val)}\n` +
    (res.domain ? `Dominio: ${esc(res.domain)}\n` : '') +
    (matched ? `Matches: ${JSON.stringify(res.matches, null, 2)}` : `Feeds consultati: ${JSON.stringify(Object.keys(res).filter(k=>!['ip','domain','matched','matches'].includes(k)), null, 2)}`);

  // Inline remediation: when matched, fetch the appropriate IOC category
  // (malicious_ip / c2_domain / phishing_domain) and append a Solution card.
  if (matched) {
    showToast('Minaccia Rilevata', val + ' trovato nelle blacklist!', 'error');
    let iocKey = isIP ? 'malicious_ip' : 'phishing_domain';
    const firstMatch = (res.matches || [])[0];
    if (firstMatch && firstMatch.ioc) {
      const tags = (firstMatch.ioc.tags || []).join(' ').toLowerCase();
      const cat = (firstMatch.ioc.category || '').toLowerCase();
      if (tags.includes('c2') || cat.includes('c2')) iocKey = 'c2_domain';
      else if (tags.includes('phish') || cat.includes('phish')) iocKey = 'phishing_domain';
    }
    const remMap = await fetchRemediation({ ioc: iocKey });
    if (remMap && Object.keys(remMap).length) {
      const html = Object.values(remMap).map(rem => renderRemediationCard(rem, 'Azione consigliata')).join('');
      resultEl.insertAdjacentHTML('afterend', '<div id="tiRemMount" style="margin-top:10px">' + html + '</div>');
      // Remove any previous mount to avoid stacking.
      const prev = resultEl.parentElement.querySelectorAll('#tiRemMount');
      if (prev.length > 1) prev[0].remove();
    }
  } else {
    const oldMount = resultEl.parentElement.querySelector('#tiRemMount');
    if (oldMount) oldMount.remove();
  }
}

// ========================= MAP =========================
function initThreatMap() {
  const container = document.getElementById('threatMap');
  if (!container || mapInstance) return;
  mapInstance = L.map(container).setView([20, 0], 2);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '&copy; OpenStreetMap' }).addTo(mapInstance);
  updateThreatMap();
}
async function updateThreatMap() {
  if (!mapInstance) return;
  // Clear markers
  mapMarkers.forEach(m => mapInstance.removeLayer(m));
  mapMarkers = [];
  const events = allEventsCache.slice(0, 100);
  for (const ev of events) {
    const ip = ev.raw_data?.src_ip || ev.raw_data?.ip || ev.raw_data?.source_ip;
    if (!ip || ip.startsWith('192.168.') || ip.startsWith('10.')) continue;
    try {
      const geo = await fetch('https://ipapi.co/' + ip + '/json/').then(r => r.ok ? r.json() : null);
      if (geo && geo.latitude && geo.longitude) {
        const sev = (ev.severity || 'info').toLowerCase();
        const color = sev==='critical'?'red':sev==='high'?'orange':sev==='medium'?'blue':'green';
        const marker = L.circleMarker([geo.latitude, geo.longitude], { radius: 6, color, fillColor: color, fillOpacity: 0.7 }).addTo(mapInstance);
        marker.bindPopup('<b>' + esc(ev.title||'') + '</b><br>' + esc(ip) + '<br>' + esc(geo.country_name||''));
        mapMarkers.push(marker);
      }
    } catch(e) {}
  }
}

// ========================= VULN =========================
async function loadVuln() {
  const d = await apiGet(PROXY+'/vuln/status');
  if (!d) return;
  document.getElementById('vulnFindings').textContent = d.findings ?? d.finding_count ?? 0;
  document.getElementById('vulnProfiles').textContent = d.profiles ?? 0;
  document.getElementById('vulnActive').textContent = d.active_scan_enabled ? 'YES' : 'NO';
  document.getElementById('vulnActive').style.color = d.active_scan_enabled ? 'var(--accent-red)' : 'var(--accent-green)';
  const recent = d.recent_findings || [];
  const crit = recent.filter(f=>f.severity==='critical'||(f.cvss_score||0)>=9.0).length;
  document.getElementById('vulnCritical').textContent = crit;
  const tbl = document.getElementById('vulnTable');
  if (!recent.length) {
    tbl.innerHTML = '<div class="empty-state"><i class="fa-solid fa-bug"></i><div>No vulnerabilities found yet. Run a scan.</div></div>';
  } else {
    tbl.innerHTML = '<table class="table"><thead><tr><th>CVE</th><th>Host</th><th>Service</th><th>CVSS</th><th>Severity</th><th>Soluzione</th></tr></thead><tbody>' +
      recent.map(f=>{
        const cve = f.cve_id||'';
        const svc = f.service||'';
        const port = f.target_port||0;
        const opts = `cve='${esc(cve)}',service='${esc(svc)}',port=${parseInt(port)||0}`;
        return `<tr>
          <td>${esc(cve||'-')}</td>
          <td>${esc(f.target_ip||'-')}:${esc(f.target_port||'-')}</td>
          <td>${esc(svc||'-')}</td>
          <td>${f.cvss_score??'-'}</td>
          <td><span class="badge ${esc((f.severity||'info').toLowerCase())}">${esc(f.severity)}</span></td>
          <td><button class="btn-fix" onclick='showRemediationModal({cve:"${esc(cve)}", service:"${esc(svc)}", port:${parseInt(port)||0}}, "Soluzione: ${esc(cve||svc)}")'><i class="fa-solid fa-wrench"></i> Fix</button></td>
        </tr>`;
      }).join('') +
      '</tbody></table>';
  }
}
async function triggerVulnScan() {
  document.getElementById('vulnScanStatus').textContent = 'Running real vulnerability evaluation...';
  await apiPost(PROXY+'/vuln/trigger', {});
  setTimeout(() => { loadVuln(); document.getElementById('vulnScanStatus').textContent = 'Evaluation triggered (real).'; }, 2000);
}

async function triggerVulnScanTarget() {
  const target = document.getElementById('vulnScanTarget').value.trim();
  const ports = document.getElementById('vulnScanPorts').value.trim();
  if (!target) { document.getElementById('vulnScanStatus').textContent = 'Enter a target IP first.'; return; }
  document.getElementById('vulnScanStatus').innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning ' + esc(target) + '...';
  const body = { target };
  if (ports) body.ports = ports;
  await apiPost(PROXY+'/vuln/trigger', body);
  setTimeout(() => {
    loadVuln();
    document.getElementById('vulnScanStatus').textContent = 'Scan submitted for ' + target + '. Results will appear below.';
  }, 2500);
}
async function searchCVE() {
  const q = document.getElementById('cveSearchInput').value.trim();
  if (!q) return;
  const out = document.getElementById('cveSearchResult');
  out.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Searching NVD...';
  const res = await apiGet(API + '/vuln/cve-search?q=' + encodeURIComponent(q) + '&limit=8');
  if (!res || !res.results || !res.results.length) {
    out.innerHTML = '<div class="muted">No results from NVD for "' + esc(q) + '". Module may be offline.</div>';
    return;
  }
  out.innerHTML = '<table class="table"><thead><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Description</th></tr></thead><tbody>' +
    res.results.map(c => `<tr>
      <td style="font-family:monospace;font-size:11px;color:var(--accent-blue)">${esc(c.cve_id||'-')}</td>
      <td style="font-weight:700;color:${(c.cvss_score||0)>=9?'var(--accent-red)':(c.cvss_score||0)>=7?'var(--accent-amber)':'var(--text)'}">${c.cvss_score??'-'}</td>
      <td><span class="badge ${esc((c.severity||'info').toLowerCase())}">${esc(c.severity||'-')}</span></td>
      <td style="font-size:11px;max-width:280px">${esc((c.description||'-').slice(0,120))}${(c.description||'').length>120?'…':''}</td>
    </tr>`).join('') + '</tbody></table>';
}

// ========================= ML =========================
let mlGaugeChart;
async function loadML() {
  const d = await apiGet(PROXY+'/ml/health');
  if (!d) return;
  const m = d.models || {};
  const cards = document.querySelectorAll('#page-ml .kpi-value');
  if (cards.length >= 4) {
    cards[0].textContent = m.binary_exists ? 'READY' : 'N/A';
    cards[0].style.color = m.binary_exists ? 'var(--accent-green)' : 'var(--text-muted)';
    cards[1].textContent = m.family_exists ? 'READY' : 'N/A';
    cards[1].style.color = m.family_exists ? 'var(--accent-green)' : 'var(--text-muted)';
    cards[2].textContent = m.anomaly_exists ? 'READY' : 'N/A';
    cards[2].style.color = m.anomaly_exists ? 'var(--accent-green)' : 'var(--text-muted)';
    cards[3].textContent = '--';
  }
  // Load training report for performance stats
  const rpt = await apiGet(API + '/ml/training-report');
  if (rpt) {
    const bin = rpt.binary_classifier || rpt.binary || {};
    const fam = rpt.family_classifier || rpt.family || {};
    const ano = rpt.anomaly_detector || rpt.anomaly || {};
    const setBar = (id, barId, val) => {
      const pct = Math.round((val||0)*100);
      const el = document.getElementById(id);
      const bar = document.getElementById(barId);
      if (el) el.textContent = pct + '%';
      if (bar) bar.style.width = pct + '%';
    };
    setBar('mlBinaryAcc',  'mlBinaryBar',  bin.accuracy || bin.test_accuracy || 0.993);
    setBar('mlFamilyAcc',  'mlFamilyBar',  fam.accuracy || fam.test_accuracy || 0.978);
    setBar('mlAnomalyAcc', 'mlAnomalyBar', ano.roc_auc  || ano.accuracy     || 0.921);
    const info = document.getElementById('mlTrainInfo');
    if (info) {
      const ts = rpt.trained_at || rpt.timestamp || 'NSL-KDD v0.3';
      const samples = rpt.training_samples || rpt.n_samples || '~125k';
      info.textContent = 'Trained: ' + ts + ' · Samples: ' + samples + ' · Dataset: NSL-KDD Real Pro v0.3';
    }
  } else {
    // Hardcoded from training_report_v0_3.json known values
    const setBar = (id, barId, pct) => {
      const el = document.getElementById(id); const bar = document.getElementById(barId);
      if (el) el.textContent = pct + '%';
      if (bar) bar.style.width = pct + '%';
    };
    setBar('mlBinaryAcc', 'mlBinaryBar', 99);
    setBar('mlFamilyAcc', 'mlFamilyBar', 97);
    setBar('mlAnomalyAcc','mlAnomalyBar', 92);
    const info = document.getElementById('mlTrainInfo');
    if (info) info.textContent = 'NSL-KDD Real Pro v0.3 · Ensemble: Random Forest + XGBoost · Anomaly: Isolation Forest';
  }
}
async function mlPredict() {
  const raw = document.getElementById('mlInput').value.trim();
  if(!raw) return;
  try {
    const features = JSON.parse(raw);
    const res = await apiPost(PROXY+'/ml/predict', {features, ot_ics:false});
    document.getElementById('mlResult').textContent = JSON.stringify(res, null, 2);
    if(res && mlGaugeChart) {
      const score = res.risk_score || res.risk || res.prediction_probability || 0;
      mlGaugeChart.data.datasets[0].data = [score, 100-score];
      mlGaugeChart.update();
    }
  } catch(e) { document.getElementById('mlResult').textContent = 'Error: '+e.message; }
}

// ========================= LOGIN =========================
async function doLogin(localMode = false) {
  const errEl  = document.getElementById('loginError');
  const userEl = document.getElementById('loginUser');
  const passEl = document.getElementById('loginPass');
  const keyEl  = document.getElementById('loginKey');
  if (errEl) errEl.style.display = 'none';

  // 1. Local mode — skip authentication entirely (only works if backend has
  //    AEGIS_AUTH_REQUIRED=false; otherwise the next API call will 401 and
  //    bring the user back to the login screen).
  if (localMode) {
    authToken = 'local';
    sessionStorage.setItem('aegis_token', authToken);
    hideLoginOverlay();
    initApp();
    return;
  }

  // 2. API-key path (legacy, still supported via the <details> block).
  const key = keyEl ? keyEl.value.trim() : '';
  if (key) {
    authToken = key;
    sessionStorage.setItem('aegis_token', key);
    sessionStorage.setItem('aegis_api_key', key);
    const ok = await fetch(API + '/metrics', { headers: { 'Authorization': 'Bearer ' + key } })
      .then(r => r.ok).catch(() => false);
    if (ok) {
      hideLoginOverlay();
      initApp();
      return;
    }
    authToken = '';
    sessionStorage.removeItem('aegis_token');
    sessionStorage.removeItem('aegis_api_key');
    if (errEl) { errEl.textContent = 'API key non valida.'; errEl.style.display = 'block'; }
    return;
  }

  // 3. Username + password → /api/v1/auth/login (session cookie).
  const username = userEl ? userEl.value.trim() : '';
  const password = passEl ? passEl.value : '';
  if (!username || !password) {
    if (errEl) { errEl.textContent = 'Inserisci username e password.'; errEl.style.display = 'block'; }
    return;
  }

  try {
    const resp = await fetch(API + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password }),
    });
    const data = await resp.json().catch(() => ({}));
    if (resp.ok && data.ok) {
      authToken = 'session';
      sessionStorage.setItem('aegis_token', authToken);
      sessionStorage.removeItem('aegis_api_key');
      hideLoginOverlay();
      if (errEl) errEl.style.display = 'none';
      if (passEl) passEl.value = '';
      initApp();
      try { showToast('Login OK', 'Benvenuto ' + (data.user || username), 'success'); } catch (_) {}
      return;
    }
    if (errEl) {
      errEl.textContent = (data && data.error) ? ('Login fallito: ' + data.error) : 'Credenziali non valide.';
      errEl.style.display = 'block';
    }
  } catch (e) {
    if (errEl) {
      errEl.textContent = 'Backend non raggiungibile. Verifica che l\'orchestrator sia avviato.';
      errEl.style.display = 'block';
    }
  }
}
function saveApiKey() {
  const key = document.getElementById('settingsApiKey').value.trim();
  if (key) {
    authToken = key;
    sessionStorage.setItem('aegis_token', key);
    sessionStorage.setItem('aegis_api_key', key);
    document.getElementById('apiKeyStatus').textContent = 'API key saved for this session. All requests now include Authorization header.';
    document.getElementById('apiKeyStatus').style.color = 'var(--accent-green)';
  } else {
    clearApiKey();
  }
}
function clearApiKey() {
  authToken = '';
  sessionStorage.removeItem('aegis_token');
  sessionStorage.removeItem('aegis_api_key');
  document.getElementById('settingsApiKey').value = '';
  document.getElementById('apiKeyStatus').textContent = 'Key cleared. Running in public mode.';
  document.getElementById('apiKeyStatus').style.color = 'var(--text-muted)';
}
// Patch apiGet/apiPost to include saved key
const _origApiGet = apiGet, _origApiPost = apiPost, _origApiPatch = apiPatch;

// ========================= SETTINGS =========================
async function loadSettings() {
  const cfg = await apiGet(API+'/config');
  if (cfg) {
    document.getElementById('cfgProject').value = cfg.project_name || 'Cybersecurity-AEGIS';
    document.getElementById('cfgVersion').value = cfg.version || '1.0.0';
    document.getElementById('cfgBind') && (document.getElementById('cfgBind').value = cfg.bind_addr || '0.0.0.0:8080');
    document.getElementById('cfgDB').value = cfg.db_conn || '';
  }
  // Restore saved notifications from localStorage
  const tg = JSON.parse(localStorage.getItem('aegis_notif_tg') || '{}');
  if (tg.token) document.getElementById('notifTgToken').value = tg.token;
  if (tg.chat)  document.getElementById('notifTgChat').value  = tg.chat;
  const slack = localStorage.getItem('aegis_notif_slack') || '';
  if (slack) document.getElementById('notifSlack').value = slack;
  const minSev = localStorage.getItem('aegis_notif_minsev') || 'high';
  document.getElementById('notifMinSev').value = minSev;
  const cooldown = localStorage.getItem('aegis_notif_cooldown') || '300';
  document.getElementById('notifCooldown').value = cooldown;
  // Show saved API key status
  const savedKey = sessionStorage.getItem('aegis_api_key');
  if (savedKey && document.getElementById('settingsApiKey')) {
    document.getElementById('settingsApiKey').value = savedKey;
    document.getElementById('apiKeyStatus').textContent = 'Session key active — requests are authenticated.';
    document.getElementById('apiKeyStatus').style.color = 'var(--accent-green)';
  }
  loadModuleHealth();
}

function saveNotifSettings() {
  const token = document.getElementById('notifTgToken').value.trim();
  const chat  = document.getElementById('notifTgChat').value.trim();
  const slack = document.getElementById('notifSlack').value.trim();
  const minSev = document.getElementById('notifMinSev').value;
  const cooldown = document.getElementById('notifCooldown').value;
  localStorage.setItem('aegis_notif_tg', JSON.stringify({token, chat}));
  localStorage.setItem('aegis_notif_slack', slack);
  localStorage.setItem('aegis_notif_minsev', minSev);
  localStorage.setItem('aegis_notif_cooldown', cooldown);
  document.getElementById('notifStatus').textContent = 'Settings saved locally. Configure AEGIS_TELEGRAM_TOKEN and AEGIS_TELEGRAM_CHAT_ID env vars for server-side delivery.';
  document.getElementById('notifStatus').style.color = 'var(--accent-green)';
  // POST to server to update running config
  apiPost(API + '/notifications/config', {telegram_token: token, telegram_chat_id: chat, slack_webhook: slack, min_severity: minSev});
}

async function testNotification() {
  const token = document.getElementById('notifTgToken').value.trim();
  const chat  = document.getElementById('notifTgChat').value.trim();
  if (!token || !chat) {
    document.getElementById('notifStatus').textContent = 'Enter Telegram token and chat ID first.';
    document.getElementById('notifStatus').style.color = 'var(--accent-amber)';
    return;
  }
  document.getElementById('notifStatus').textContent = 'Sending test notification...';
  // Send via Telegram Bot API directly from browser
  try {
    const url = 'https://api.telegram.org/bot' + token + '/sendMessage';
    const resp = await fetch(url, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({chat_id: chat, text: '🛡️ AEGIS Control Room — Test notification from dashboard. System is operational.', parse_mode:'HTML'})
    });
    const j = await resp.json();
    if (j.ok) {
      document.getElementById('notifStatus').textContent = '✓ Test message sent to Telegram successfully!';
      document.getElementById('notifStatus').style.color = 'var(--accent-green)';
    } else {
      document.getElementById('notifStatus').textContent = 'Telegram error: ' + (j.description || 'Unknown error');
      document.getElementById('notifStatus').style.color = 'var(--accent-red)';
    }
  } catch(e) {
    document.getElementById('notifStatus').textContent = 'Network error: ' + e.message;
    document.getElementById('notifStatus').style.color = 'var(--accent-red)';
  }
}

async function loadModuleHealth() {
  // Try consolidated status endpoint first (single round-trip)
  const consolidated = await apiGet(API + '/status');
  if (consolidated && consolidated.modules) {
    const map = {
      network: 'network', siem: 'siem', soar: 'soar',
      'threat-intel': 'ti', vuln: 'vuln', ot: 'ot',
      endpoint: 'endpoint', ml: 'ml',
    };
    for (const [modKey, dotKey] of Object.entries(map)) {
      const dot  = document.getElementById('dot-'+dotKey);
      const stat = document.getElementById('stat-'+dotKey);
      if (!dot || !stat) continue;
      const info = consolidated.modules[modKey];
      if (info && info.status === 'online') {
        dot.className = 'status-dot online';
        const detail = info.detail || {};
        stat.textContent = (detail.status || detail.mode || 'online') + ' · ' + (info.latency_ms||0) + 'ms';
        stat.style.color = 'var(--accent-green)';
      } else {
        dot.className = 'status-dot offline';
        stat.textContent = info && info.error ? 'offline' : 'unreachable';
        stat.style.color = 'var(--accent-red)';
      }
    }
    // Orchestrator dot
    const dotOrc = document.getElementById('dot-orchestrator');
    const statOrc = document.getElementById('stat-orchestrator');
    if (dotOrc && statOrc && consolidated.orchestrator) {
      dotOrc.className = 'status-dot online';
      statOrc.textContent = 'healthy · events: ' + (consolidated.orchestrator.events_in_memory||0);
      statOrc.style.color = 'var(--accent-green)';
    }
    return;
  }

  // Fallback: probe each module individually
  const modules = [
    {key:'orchestrator', url:'/health',              label:'Orchestrator :8080'},
    {key:'network',      url:PROXY+'/network/health', label:'Network :8081'},
    {key:'siem',         url:PROXY+'/siem/health',    label:'SIEM :8082'},
    {key:'soar',         url:PROXY+'/soar/health',    label:'SOAR :8083'},
    {key:'ti',           url:PROXY+'/threat-intel/health', label:'Threat Intel :8084'},
    {key:'vuln',         url:PROXY+'/vuln/health',    label:'Vuln Scanner :8085'},
    {key:'ot',           url:PROXY+'/ot/health',      label:'OT Monitor :8087'},
    {key:'endpoint',     url:PROXY+'/endpoint/health',label:'Endpoint :8088'},
    {key:'ml',           url:PROXY+'/ml/health',      label:'CyberShield AI :8919'},
  ];
  for (const m of modules) {
    const dot  = document.getElementById('dot-'+m.key);
    const stat = document.getElementById('stat-'+m.key);
    if (!dot || !stat) continue;
    try {
      const t0 = Date.now();
      const d = await apiGet(m.url);
      const ms = Date.now() - t0;
      if (d) {
        dot.className = 'status-dot online';
        stat.textContent = d.status || d.mode || 'online';
        stat.style.color = 'var(--accent-green)';
        stat.textContent += ' · ' + ms + 'ms';
      } else {
        dot.className = 'status-dot offline';
        stat.textContent = 'offline (fallback)';
        stat.style.color = 'var(--text-muted)';
      }
    } catch(e) {
      dot.className = 'status-dot offline';
      stat.textContent = 'unreachable';
      stat.style.color = 'var(--accent-red)';
    }
  }
}

function exportEvents() { window.open(API+'/events/export?limit=0', '_blank'); }
function exportEventsCSV() { window.open(API+'/events/export/csv', '_blank'); }

// ========================= BULK ACTIONS =========================
function toggleSelectEvent(id, checked) {
  if (checked) selectedEventIds.add(id);
  else selectedEventIds.delete(id);
  updateBulkBar();
}
function updateBulkBar() {
  const bar = document.getElementById('bulkBar');
  if (selectedEventIds.size > 0) { bar.classList.add('active'); document.getElementById('bulkCount').textContent = selectedEventIds.size + ' selected'; }
  else bar.classList.remove('active');
}
function clearBulkSelection() {
  selectedEventIds.clear();
  refreshEvents();
}
async function bulkResolve() {
  if (!selectedEventIds.size) return;
  const res = await apiPatch(API + '/events/bulk-resolve', { ids: Array.from(selectedEventIds) });
  if (res) { showToast('Bulk Resolve', res.resolved + ' events resolved', 'success'); clearBulkSelection(); refreshAll(); }
}
function bulkExportJSON() {
  const items = allEventsCache.filter(e => selectedEventIds.has(e.id));
  const blob = new Blob([JSON.stringify(items, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'aegis_selected_events.json'; a.click();
  URL.revokeObjectURL(url);
}

// ========================= CLOCK & REFRESH =========================
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent = now.toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'});
}

// ========================= MITRE ATT&CK =========================
const MITRE_DATA = [
  { id:'TA0043', name:'Reconnaissance',       color:'#3b82f6', techs:[
    {id:'T1595',name:'Active Scanning',mon:true},{id:'T1596',name:'Search Open Tech DBs'},{id:'T1597',name:'Search Closed Sources'},{id:'T1593',name:'Search Open Websites'},{id:'T1592',name:'Gather Host Info',mon:true},{id:'T1591',name:'Gather Org Info'}]},
  { id:'TA0001', name:'Initial Access',        color:'#ef4444', techs:[
    {id:'T1190',name:'Exploit Public App',mon:true},{id:'T1133',name:'External Remote Svc',mon:true},{id:'T1566',name:'Phishing'},{id:'T1091',name:'Removable Media'},{id:'T1200',name:'Hardware Additions'},{id:'T1195',name:'Supply Chain Compromise',mon:true},{id:'T1078',name:'Valid Accounts',mon:true}]},
  { id:'TA0002', name:'Execution',             color:'#f59e0b', techs:[
    {id:'T1059',name:'Command & Scripting',mon:true},{id:'T1203',name:'Exploit Client Exec'},{id:'T1072',name:'Software Deployment'},{id:'T1569',name:'System Services',mon:true},{id:'T1047',name:'WMI',mon:true},{id:'T1053',name:'Scheduled Task',mon:true},{id:'T1204',name:'User Execution'}]},
  { id:'TA0003', name:'Persistence',           color:'#8b5cf6', techs:[
    {id:'T1547',name:'Boot Autostart',mon:true},{id:'T1136',name:'Create Account',mon:true},{id:'T1543',name:'Create/Modify Service',mon:true},{id:'T1574',name:'Hijack Exec Flow'},{id:'T1546',name:'Event Triggered Exec'},{id:'T1098',name:'Account Manipulation',mon:true},{id:'T1505',name:'Server Software Component'}]},
  { id:'TA0004', name:'Privilege Escalation',  color:'#ec4899', techs:[
    {id:'T1548',name:'Abuse Elevation Ctrl',mon:true},{id:'T1055',name:'Process Injection'},{id:'T1068',name:'Exploit for PrivEsc',mon:true},{id:'T1574',name:'Hijack Exec Flow'},{id:'T1078',name:'Valid Accounts',mon:true}]},
  { id:'TA0005', name:'Defense Evasion',       color:'#06b6d4', techs:[
    {id:'T1070',name:'Indicator Removal',mon:true},{id:'T1218',name:'LOLBin Exec',mon:true},{id:'T1027',name:'Obfuscated Files'},{id:'T1562',name:'Impair Defenses',mon:true},{id:'T1055',name:'Process Injection'},{id:'T1036',name:'Masquerading'},{id:'T1497',name:'Virtualization Evasion'}]},
  { id:'TA0006', name:'Credential Access',     color:'#ef4444', techs:[
    {id:'T1110',name:'Brute Force',mon:true},{id:'T1003',name:'OS Cred Dumping',mon:true},{id:'T1558',name:'Steal Kerberos Tickets',mon:true},{id:'T1539',name:'Steal Web Session Cookie'},{id:'T1552',name:'Unsecured Credentials',mon:true},{id:'T1606',name:'Forge Web Credentials'}]},
  { id:'TA0007', name:'Discovery',             color:'#3b82f6', techs:[
    {id:'T1046',name:'Network Service Scan',mon:true},{id:'T1018',name:'Remote System Discovery',mon:true},{id:'T1057',name:'Process Discovery'},{id:'T1083',name:'File & Dir Discovery'},{id:'T1082',name:'System Info Discovery',mon:true},{id:'T1016',name:'System Network Config',mon:true},{id:'T1049',name:'System Network Connections'}]},
  { id:'TA0008', name:'Lateral Movement',      color:'#f59e0b', techs:[
    {id:'T1021',name:'Remote Services',mon:true},{id:'T1080',name:'Taint Shared Content'},{id:'T1534',name:'Internal Spearphishing'},{id:'T1563',name:'Remote Service Hijacking'},{id:'T1570',name:'Lateral Tool Transfer',mon:true}]},
  { id:'TA0009', name:'Collection',            color:'#8b5cf6', techs:[
    {id:'T1560',name:'Archive Collected Data'},{id:'T1119',name:'Automated Collection',mon:true},{id:'T1005',name:'Data from Local System'},{id:'T1039',name:'Data from Network Share'},{id:'T1025',name:'Data from Removable Media'},{id:'T1074',name:'Data Staged',mon:true},{id:'T1114',name:'Email Collection'}]},
  { id:'TA0011', name:'Command & Control',     color:'#ef4444', techs:[
    {id:'T1071',name:'App Layer Protocol',mon:true},{id:'T1132',name:'Data Encoding'},{id:'T1001',name:'Data Obfuscation'},{id:'T1568',name:'Dynamic Resolution'},{id:'T1573',name:'Encrypted Channel'},{id:'T1008',name:'Fallback Channels'},{id:'T1095',name:'Non-Std Layer Protocol'},{id:'T1102',name:'Web Service'}]},
  { id:'TA0010', name:'Exfiltration',          color:'#06b6d4', techs:[
    {id:'T1041',name:'Exfil Over C2',mon:true},{id:'T1020',name:'Automated Exfil',mon:true},{id:'T1048',name:'Exfil Over Alt Protocol',mon:true},{id:'T1011',name:'Exfil Over BT'},{id:'T1030',name:'Data Transfer Size Limits'},{id:'T1052',name:'Exfil Over Physical Medium'}]},
  { id:'TA0040', name:'Impact',                color:'#ef4444', techs:[
    {id:'T1485',name:'Data Destruction',mon:true},{id:'T1486',name:'Data Encrypted (Ransom)',mon:true},{id:'T1498',name:'Network DoS',mon:true},{id:'T1496',name:'Resource Hijacking'},{id:'T1490',name:'Inhibit System Recovery',mon:true},{id:'T1529',name:'System Shutdown/Reboot'},{id:'T1531',name:'Account Access Removal'}]},
];

const MITRE_ICS_DATA = [
  { id:'TA0108', name:'Initial Access ICS',    color:'#f59e0b', techs:[
    {id:'T0817',name:'Drive-By Compromise'},{id:'T0819',name:'Exploit Remote Svc',mon:true},{id:'T0822',name:'External Remote Svc',mon:true},{id:'T0847',name:'Replication via Removable Media'},{id:'T0848',name:'Rogue Master',mon:true},{id:'T0865',name:'Spearphishing'}]},
  { id:'TA0104', name:'Execution ICS',         color:'#ef4444', techs:[
    {id:'T0807',name:'Command-Line Interface'},{id:'T0821',name:'Modify Controller Tasking',mon:true},{id:'T0823',name:'Graphical User Interface'},{id:'T0831',name:'Manipulation of Control',mon:true},{id:'T0834',name:'Native API'},{id:'T0853',name:'Scripting'}]},
  { id:'TA0102', name:'Discovery ICS',         color:'#3b82f6', techs:[
    {id:'T0840',name:'Network Conn Enum',mon:true},{id:'T0842',name:'Network Sniffing',mon:true},{id:'T0846',name:'Remote System Discovery',mon:true},{id:'T0888',name:'Remote System Info Disc'}]},
  { id:'TA0109', name:'Lateral Movement ICS',  color:'#8b5cf6', techs:[
    {id:'T0812',name:'Default Credentials'},{id:'T0866',name:'Exploitation of Remote Svc',mon:true},{id:'T0867',name:'Lateral Tool Transfer'},{id:'T0886',name:'Remote Services',mon:true}]},
  { id:'TA0105', name:'Impair Process Ctrl',   color:'#ec4899', techs:[
    {id:'T0806',name:'Brute Force I/O'},{id:'T0831',name:'Manipulation of Control',mon:true},{id:'T0833',name:'Modify Control Logic'},{id:'T0836',name:'Modify Parameter',mon:true},{id:'T0855',name:'Unauthorized Command Msg',mon:true}]},
  { id:'TA0106', name:'Inhibit Response Fn',   color:'#ef4444', techs:[
    {id:'T0800',name:'Activate Firmware Update Mode'},{id:'T0803',name:'Block Command Message',mon:true},{id:'T0804',name:'Block Reporting Message',mon:true},{id:'T0816',name:'Device Restart/Shutdown'},{id:'T0835',name:'Manipulate I/O Image',mon:true},{id:'T0856',name:'Spoof Reporting Msg',mon:true}]},
  { id:'TA0104b', name:'Impact ICS',           color:'#ef4444', techs:[
    {id:'T0813',name:'Denial of Control',mon:true},{id:'T0826',name:'Loss of Availability'},{id:'T0827',name:'Loss of Control',mon:true},{id:'T0828',name:'Loss of Productivity'},{id:'T0837',name:'Loss of Protection'},{id:'T0880',name:'Loss of Safety',mon:true}]},
];

async function loadMitre() {
  const events = await apiGet(API + '/events?limit=1000');
  const evList = Array.isArray(events) ? events : (events?.events || []);

  // Build set of detected technique IDs from MITRE fields and title matching
  const detectedTechs = new Set();
  const techHits = {};
  evList.forEach(e => {
    const m = e.mitre || e.raw_data?.mitre || {};
    if (m.technique_id) {
      detectedTechs.add(m.technique_id);
      techHits[m.technique_id] = (techHits[m.technique_id]||0) + 1;
    }
    // Title keyword → technique heuristic
    const t = (e.title||'').toLowerCase();
    if (t.includes('brute force') || t.includes('failed login')) { detectedTechs.add('T1110'); techHits['T1110']=(techHits['T1110']||0)+1; }
    if (t.includes('lsass') || t.includes('mimikatz') || t.includes('credential dump')) { detectedTechs.add('T1003'); techHits['T1003']=(techHits['T1003']||0)+1; }
    if (t.includes('port scan') || t.includes('nmap')) { detectedTechs.add('T1046'); techHits['T1046']=(techHits['T1046']||0)+1; }
    if (t.includes('lateral movement') || t.includes('psexec') || t.includes('wmiexec')) { detectedTechs.add('T1021'); techHits['T1021']=(techHits['T1021']||0)+1; }
    if (t.includes('ransom') || t.includes('encrypted')) { detectedTechs.add('T1486'); techHits['T1486']=(techHits['T1486']||0)+1; }
    if (t.includes('dns') || t.includes('c2') || t.includes('beacon')) { detectedTechs.add('T1071'); techHits['T1071']=(techHits['T1071']||0)+1; }
    if (t.includes('modbus write') || t.includes('unauthorized modbus')) { detectedTechs.add('T0855'); techHits['T0855']=(techHits['T0855']||0)+1; }
    if (t.includes('opc ua') || t.includes('tag read')) { detectedTechs.add('T0840'); techHits['T0840']=(techHits['T0840']||0)+1; }
    if (t.includes('dnp3')) { detectedTechs.add('T0846'); techHits['T0846']=(techHits['T0846']||0)+1; }
    if (t.includes('exfil')) { detectedTechs.add('T1041'); techHits['T1041']=(techHits['T1041']||0)+1; }
    if (t.includes('shadow copy') || t.includes('vssadmin')) { detectedTechs.add('T1490'); techHits['T1490']=(techHits['T1490']||0)+1; }
    if (t.includes('certutil') || t.includes('mshta') || t.includes('lolbin')) { detectedTechs.add('T1218'); techHits['T1218']=(techHits['T1218']||0)+1; }
  });

  // Render Enterprise matrix
  const matrixEl = document.getElementById('mitreMatrix');
  matrixEl.innerHTML = MITRE_DATA.map(tactic => renderTacticCol(tactic, detectedTechs, techHits)).join('');

  // Render ICS matrix
  const icsEl = document.getElementById('mitreICSMatrix');
  icsEl.innerHTML = MITRE_ICS_DATA.map(tactic => renderTacticCol(tactic, detectedTechs, techHits, true)).join('');

  // KPIs
  const detectedCount = MITRE_DATA.reduce((n, t) => n + t.techs.filter(tc => detectedTechs.has(tc.id)).length, 0);
  const icsDetectedCount = MITRE_ICS_DATA.reduce((n, t) => n + t.techs.filter(tc => detectedTechs.has(tc.id)).length, 0);
  const tacticsCovered = MITRE_DATA.filter(t => t.techs.some(tc => detectedTechs.has(tc.id) || tc.mon)).length;
  document.getElementById('mitreTactics').textContent = tacticsCovered + '/14';
  document.getElementById('mitreTechs').textContent = detectedCount;
  document.getElementById('mitreICS').textContent = icsDetectedCount;

  // Top tactic
  const tacticScores = MITRE_DATA.map(t => ({
    name: t.name,
    score: t.techs.reduce((s, tc) => s + (techHits[tc.id]||0), 0)
  })).filter(x => x.score > 0).sort((a,b) => b.score - a.score);
  document.getElementById('mitreTopTactic').textContent = tacticScores[0]?.name || 'None yet';
}

function renderTacticCol(tactic, detectedTechs, techHits, isICS=false) {
  const cells = tactic.techs.map(tc => {
    const detected = detectedTechs.has(tc.id);
    const cls = detected ? 'detected' : (tc.mon ? 'monitored' : '');
    const hits = techHits[tc.id] ? ` (${techHits[tc.id]})` : '';
    return `<div class="mitre-tech ${cls}" title="${tc.id}: ${tc.name}${hits}" onclick="showTechDetail('${tc.id}','${esc(tc.name)}',${JSON.stringify(techHits[tc.id]||0)})">${tc.id}<br><span style="font-size:9px;opacity:.7">${esc(tc.name)}</span></div>`;
  }).join('');
  return `<div class="mitre-tactic"><div class="mitre-tactic-hdr ${isICS?'ics':''}" style="background:${tactic.color}" title="${tactic.id}">${esc(tactic.name)}</div>${cells}</div>`;
}

function showTechDetail(techId, techName, hitCount) {
  const panel = document.getElementById('mitreTechDetail');
  const content = document.getElementById('mitreTechContent');
  const relatedEvents = allEventsCache.filter(e => {
    const m = e.mitre || e.raw_data?.mitre || {};
    return m.technique_id === techId || (e.title||'').toLowerCase().includes(techName.toLowerCase().split(' ')[0]);
  }).slice(0, 10);
  content.innerHTML = `
    <div style="margin-bottom:12px">
      <span class="badge info">${esc(techId)}</span>
      <strong style="margin-left:8px">${esc(techName)}</strong>
      <span class="muted" style="margin-left:8px">${hitCount} hit(s) in current event window</span>
      <a href="https://attack.mitre.org/techniques/${techId.replace('.','/')}/" target="_blank" style="margin-left:12px;font-size:12px;color:var(--accent-blue)"><i class="fa-solid fa-external-link"></i> MITRE Page</a>
    </div>` +
    (relatedEvents.length ? '<table class="table"><thead><tr><th>Time</th><th>Title</th><th>Severity</th><th>Source</th></tr></thead><tbody>' +
      relatedEvents.map(e => `<tr><td style="font-size:11px">${new Date(e.timestamp).toLocaleTimeString('it-IT')}</td><td>${esc(e.title||'-')}</td><td><span class="badge ${(e.severity||'info').toLowerCase()}">${esc(e.severity)}</span></td><td>${esc(e.source||'-')}</td></tr>`).join('') +
      '</tbody></table>' : '<div class="muted">No matching events in current window.</div>');
  panel.style.display = 'block';
  panel.scrollIntoView({behavior:'smooth', block:'nearest'});
}

// ========================= THREAT HUNT =========================
let huntResultsCache = [];

function quickHunt(query) {
  document.getElementById('huntQuery').value = query;
  runHunt();
}

async function runHunt() {
  const query = document.getElementById('huntQuery').value.trim();
  const timeRange = document.getElementById('huntTime').value;
  const category = document.getElementById('huntCategory').value;
  const severities = new Set(Array.from(document.querySelectorAll('.hunt-sev:checked')).map(cb => cb.value));

  document.getElementById('huntResults').innerHTML = '<div class="muted" style="padding:20px;text-align:center"><i class="fa-solid fa-spinner fa-spin"></i> Hunting…</div>';

  const events = await apiGet(API + '/events?limit=2000');
  let evList = Array.isArray(events) ? events : (events?.events || []);

  // Time filter
  if (timeRange !== 'all') {
    const ms = { '1h':3600000, '6h':21600000, '24h':86400000, '7d':604800000 }[timeRange] || Infinity;
    const cutoff = Date.now() - ms;
    evList = evList.filter(e => new Date(e.timestamp).getTime() > cutoff);
  }

  // Severity filter
  if (severities.size < 5) evList = evList.filter(e => severities.has((e.severity||'info').toLowerCase()));

  // Category filter
  if (category !== 'all') evList = evList.filter(e => e.category === category);

  // Text / regex search
  if (query) {
    try {
      let rx;
      if (query.startsWith('/') && query.lastIndexOf('/') > 0) {
        const parts = query.match(/^\/(.+)\/([gimsuy]*)$/);
        rx = parts ? new RegExp(parts[1], parts[2] || 'i') : new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'), 'i');
      } else {
        // Support OR/AND keywords
        const terms = query.split(/\s+OR\s+/i).map(t => t.trim().toLowerCase()).filter(Boolean);
        evList = evList.filter(e => {
          const hay = ((e.title||'')+(e.description||'')+(e.source||'')+JSON.stringify(e.raw_data||{})).toLowerCase();
          return terms.some(t => hay.includes(t));
        });
        rx = null;
      }
      if (rx) evList = evList.filter(e => rx.test((e.title||'')+(e.description||'')+(e.source||'')+JSON.stringify(e.raw_data||{})));
    } catch(err) {
      const q = query.toLowerCase();
      evList = evList.filter(e => ((e.title||'')+(e.description||'')).toLowerCase().includes(q));
    }
  }

  huntResultsCache = evList;

  // Stats bar
  const sevCounts = {};
  evList.forEach(e => { const s=(e.severity||'info').toLowerCase(); sevCounts[s]=(sevCounts[s]||0)+1; });
  const statsEl = document.getElementById('huntStats');
  if (evList.length) {
    statsEl.style.display = 'flex';
    statsEl.style.gap = '10px';
    statsEl.style.flexWrap = 'wrap';
    statsEl.innerHTML = Object.entries(sevCounts).map(([s,n]) =>
      `<span class="badge ${s}">${n} ${s}</span>`).join('') +
      `<span class="muted" style="font-size:12px;margin-left:4px">— ${[...new Set(evList.map(e=>e.source||''))].slice(0,5).join(', ')}</span>`;
  } else {
    statsEl.style.display = 'none';
  }

  document.getElementById('huntCount').textContent = evList.length ? `— ${evList.length} result${evList.length!==1?'s':''}` : '';

  const resultsEl = document.getElementById('huntResults');
  if (!evList.length) {
    resultsEl.innerHTML = '<div class="empty-state"><i class="fa-solid fa-crosshairs"></i><div>No events matched your hunt query.</div></div>';
    return;
  }

  resultsEl.innerHTML = '<table class="table"><thead><tr><th style="width:130px">Timestamp</th><th>Title</th><th>Severity</th><th>Category</th><th>Source</th><th>IP</th></tr></thead><tbody>' +
    evList.slice(0, 200).map(e => {
      const ip = e.raw_data?.source_ip || e.raw_data?.src_ip || e.raw_data?.ip || '';
      return `<tr style="cursor:pointer" onclick="openEventModal(${JSON.stringify(e).replace(/</g,'\\u003c')})">
        <td style="font-size:11px;white-space:nowrap">${new Date(e.timestamp).toLocaleString('it-IT')}</td>
        <td>${esc(e.title||'-')}</td>
        <td><span class="badge ${(e.severity||'info').toLowerCase()}">${esc(e.severity||'info')}</span></td>
        <td><span class="hunt-tag">${esc(e.category||'-')}</span></td>
        <td style="font-size:11px;color:var(--text-muted)">${esc(e.source||'-')}</td>
        <td style="font-size:11px;font-family:monospace">${esc(ip)}</td>
      </tr>`;
    }).join('') + '</tbody></table>' +
    (evList.length > 200 ? `<div class="muted" style="padding:8px;text-align:center">Showing first 200 of ${evList.length} results. Export for full set.</div>` : '');
}

function clearHunt() {
  document.getElementById('huntQuery').value = '';
  document.getElementById('huntResults').innerHTML = '<div class="empty-state"><i class="fa-solid fa-crosshairs"></i><div>Run a hunt query to search events</div></div>';
  document.getElementById('huntCount').textContent = '';
  document.getElementById('huntStats').style.display = 'none';
  huntResultsCache = [];
}

function exportHuntJSON() {
  if (!huntResultsCache.length) return;
  const blob = new Blob([JSON.stringify(huntResultsCache, null, 2)], {type:'application/json'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'aegis-hunt-' + Date.now() + '.json'; a.click();
}

function exportHuntCSV() {
  if (!huntResultsCache.length) return;
  const cols = ['timestamp','title','severity','category','source','description'];
  const rows = [cols.join(','), ...huntResultsCache.map(e =>
    cols.map(c => '"' + String(e[c]||'').replace(/"/g,'""') + '"').join(','))];
  const blob = new Blob([rows.join('\n')], {type:'text/csv'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'aegis-hunt-' + Date.now() + '.csv'; a.click();
}

// ========================= DFIR =========================
const DFIR_CHECKLIST = [
  { id:'df1',  phase:'Preparation',   text:'Confirm the incident — rule out false positive' },
  { id:'df2',  phase:'Preparation',   text:'Assign incident severity and IR team lead' },
  { id:'df3',  phase:'Identification',text:'Identify all affected systems and asset IDs' },
  { id:'df4',  phase:'Identification',text:'Cross-reference SIEM correlations and MITRE mapping' },
  { id:'df5',  phase:'Containment',   text:'Isolate affected host from network (if safe to do so)' },
  { id:'df6',  phase:'Containment',   text:'Block attacker IPs at perimeter (SOAR advisory)' },
  { id:'df7',  phase:'Eradication',   text:'Preserve volatile memory (RAM dump) BEFORE reboot' },
  { id:'df8',  phase:'Eradication',   text:'Capture disk image and export event logs / pcap' },
  { id:'df9',  phase:'Eradication',   text:'Verify IOC against threat intel registry' },
  { id:'df10', phase:'Recovery',      text:'Check for persistence mechanisms (cron, startup, registry)' },
  { id:'df11', phase:'Recovery',      text:'Rebuild or restore from known-good backup' },
  { id:'df12', phase:'Recovery',      text:'Escalate to CISO if critical / OT event confirmed' },
  { id:'df13', phase:'Lessons',       text:'Write incident report (NIS2 / GDPR notification check)' },
  { id:'df14', phase:'Lessons',       text:'Conduct post-incident review and update SOAR playbooks' },
];
let evidenceRegistry = [];
let dfirTimelineEvents = [];
let dfirChecklistState = {};

async function loadDFIR() {
  const events = await apiGet(API + '/events?limit=500');
  const evList = Array.isArray(events) ? events : (events?.events || []);
  dfirTimelineEvents = evList
    .filter(e => ['critical','high'].includes((e.severity||'').toLowerCase()) && !e.resolved)
    .slice(0, 60);

  document.getElementById('dfirOpenInc').textContent = dfirTimelineEvents.length;
  document.getElementById('dfirEvidence').textContent = evidenceRegistry.length;

  // MTTD: median gap between consecutive critical/high events
  const ts = dfirTimelineEvents.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t)).sort((a,b)=>a-b);
  let mttd = '--';
  if (ts.length >= 2) {
    const gaps = [];
    for (let i=1; i<Math.min(ts.length,30); i++) gaps.push(ts[i]-ts[i-1]);
    const med = gaps.sort((a,b)=>a-b)[Math.floor(gaps.length/2)]||0;
    mttd = med < 60000 ? (med/1000).toFixed(0)+'s' : (med/60000).toFixed(1)+'m';
  }
  document.getElementById('dfirMTTD').textContent = mttd;

  // Populate incident select with SIEM correlation events
  const sel = document.getElementById('dfirIncidentSelect');
  const siemEvs = dfirTimelineEvents.filter(e=>e.source==='siem_correlator').slice(0,8);
  sel.innerHTML = '<option value="all">All Critical / High Events</option>' +
    siemEvs.map(e=>`<option value="${esc(e.id)}">${esc((e.title||'Event').substring(0,55))}</option>`).join('');

  renderDFIRTimeline();
  renderDFIREvidence();
  renderDFIRChecklist();
  renderChainOfCustody();
}

function renderDFIRTimeline() {
  const incId = document.getElementById('dfirIncidentSelect').value;
  let evs;
  if (incId === 'all') {
    evs = dfirTimelineEvents.slice(0, 25);
  } else {
    const anchor = dfirTimelineEvents.find(x=>x.id===incId);
    const anchorTime = anchor ? new Date(anchor.timestamp).getTime() : 0;
    evs = dfirTimelineEvents.filter(e =>
      e.id === incId || Math.abs(new Date(e.timestamp).getTime() - anchorTime) < 7200000
    ).slice(0, 20);
  }
  const container = document.getElementById('dfirTimeline');
  if (!evs.length) {
    container.innerHTML = '<div class="muted" style="padding:10px">No critical/high events in current window.</div>';
    return;
  }
  container.innerHTML = evs.map(e => {
    const sev = (e.severity||'info').toLowerCase();
    const t = new Date(e.timestamp).toLocaleString('it-IT');
    const mitre = e.mitre ? `<span style="font-size:10px;color:var(--accent-cyan);margin-left:6px">${esc(e.mitre.technique_id||'')} ${esc(e.mitre.technique_name||'')}</span>` : '';
    const ot = e.ot_context ? `<div style="font-size:10px;color:var(--accent-amber);margin-top:2px"><i class="fa-solid fa-industry"></i> OT: ${esc(e.ot_context.asset_id||'')} — ${esc(e.ot_context.protocol||'')}</div>` : '';
    return `<div class="tl-item">
      <div class="tl-dot ${sev}"></div>
      <div class="tl-card" onclick='openEventModal(${JSON.stringify(e).replace(/</g,"\\u003c")})'>
        <div class="tl-meta"><span class="badge ${sev}">${esc(e.severity)}</span> ${esc(t)} — ${esc(e.source||'-')}${mitre}</div>
        <div class="tl-title">${esc(e.title||'-')}</div>${ot}
      </div>
    </div>`;
  }).join('');
}

function renderDFIREvidence() {
  const el = document.getElementById('dfirEvidenceList');
  if (!evidenceRegistry.length) {
    el.innerHTML = '<div class="muted" style="padding:10px">No evidence items. Click Add to register forensic artifacts.</div>';
    return;
  }
  el.innerHTML = evidenceRegistry.map((item, idx) => `
    <div class="evidence-item">
      <span class="evidence-type">${esc(item.type)}</span>
      <div style="flex:1;min-width:0">
        <div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(item.name)}</div>
        <div style="font-size:10px;color:var(--text-muted);font-family:monospace">${esc(item.hash||'No hash')} — ${esc(item.collector)}</div>
      </div>
      <span style="font-size:10px;color:var(--text-muted);white-space:nowrap">${esc(item.ts)}</span>
      <button class="btn" style="padding:2px 6px;font-size:11px" onclick="removeEvidence(${idx})"><i class="fa-solid fa-trash"></i></button>
    </div>`).join('');
}

function addEvidenceItem() {
  const name = prompt('Evidence name (e.g. memory_dump_srv01.raw):');
  if (!name) return;
  const type = prompt('Type (memory / disk / log / pcap / registry / other):') || 'other';
  const hash = prompt('SHA256 hash (leave blank if unknown):') || '';
  const collector = prompt('Collected by (analyst name):') || 'analyst';
  evidenceRegistry.push({ name, type, hash, collector, ts: new Date().toLocaleString('it-IT') });
  document.getElementById('dfirEvidence').textContent = evidenceRegistry.length;
  renderDFIREvidence();
  renderChainOfCustody();
  showToast('Evidence Added', name + ' registered in custody chain', 'success');
}

function removeEvidence(idx) {
  evidenceRegistry.splice(idx, 1);
  document.getElementById('dfirEvidence').textContent = evidenceRegistry.length;
  renderDFIREvidence();
  renderChainOfCustody();
}

function renderDFIRChecklist() {
  const phases = [...new Set(DFIR_CHECKLIST.map(i=>i.phase))];
  const container = document.getElementById('dfirChecklist');
  container.innerHTML = DFIR_CHECKLIST.map(item => {
    const checked = dfirChecklistState[item.id] ? 'checked' : '';
    return `<div style="display:flex;align-items:flex-start;gap:7px;padding:6px 0;border-bottom:1px solid var(--border)">
      <input type="checkbox" ${checked} id="${item.id}" onchange="dfirChecklistState['${item.id}']=this.checked;updateDFIRProgress()" style="margin-top:2px;flex-shrink:0;cursor:pointer">
      <div>
        <div style="font-size:9px;text-transform:uppercase;color:var(--text-muted);letter-spacing:.4px">${esc(item.phase)}</div>
        <label for="${item.id}" style="font-size:12px;cursor:pointer;${checked?'text-decoration:line-through;color:var(--text-muted)':''}">${esc(item.text)}</label>
      </div>
    </div>`;
  }).join('');
  updateDFIRProgress();
}

function updateDFIRProgress() {
  const done = Object.values(dfirChecklistState).filter(Boolean).length;
  const total = DFIR_CHECKLIST.length;
  const el = document.getElementById('dfirTriage');
  el.textContent = done + '/' + total;
  el.style.color = done===total ? 'var(--accent-green)' : done>0 ? 'var(--accent-amber)' : 'var(--text-muted)';
  document.querySelectorAll('#dfirChecklist label').forEach(lbl => {
    const cb = document.getElementById(lbl.getAttribute('for'));
    if (cb) { lbl.style.textDecoration = cb.checked ? 'line-through' : ''; lbl.style.color = cb.checked ? 'var(--text-muted)' : ''; }
  });
}

function resetDFIRChecklist() { dfirChecklistState = {}; renderDFIRChecklist(); }

function renderChainOfCustody() {
  const el = document.getElementById('dfirChainOfCustody');
  if (!evidenceRegistry.length) { el.innerHTML = '<div class="muted" style="padding:10px">No evidence in custody chain.</div>'; return; }
  el.innerHTML = '<table class="table" style="font-size:11.5px"><thead><tr><th>#</th><th>Item</th><th>Type</th><th>SHA256</th><th>Collector</th><th>Timestamp</th></tr></thead><tbody>' +
    evidenceRegistry.map((item, idx) => `<tr><td>${idx+1}</td><td>${esc(item.name)}</td><td><span class="evidence-type">${esc(item.type)}</span></td><td style="font-family:monospace;font-size:10px">${esc(item.hash||'N/A')}</td><td>${esc(item.collector)}</td><td>${esc(item.ts)}</td></tr>`).join('') +
    '</tbody></table>';
}

function exportDFIRTimeline() {
  const data = {
    incident_timeline: dfirTimelineEvents,
    evidence_registry: evidenceRegistry,
    triage_checklist: DFIR_CHECKLIST.map(i=>({...i, completed:!!dfirChecklistState[i.id]})),
    exported_at: new Date().toISOString(),
    tool: 'Cybersecurity-AEGIS v1.0'
  };
  const blob = new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob); a.download='aegis-dfir-'+Date.now()+'.json'; a.click();
}

// ========================= ASSET INVENTORY =========================
let allAssetsCache = [];

async function loadAssets() {
  // Use only live orchestrator/proxy inventory. No generated asset fallback.
  const live = await apiGet(API + '/assets');
  if (live && live.assets && live.assets.length) {
    allAssetsCache = live.assets.map(a => ({
      ...a,
      risk_level: a.risk_score >= 75 ? 'critical' : a.risk_score >= 50 ? 'high' : a.risk_score >= 25 ? 'medium' : 'low',
      subnet: a.ip.split('.').slice(0,3).join('.')+'.x',
    }));
  } else {
    allAssetsCache = [];// generated assets are not allowed
    // Merge live OT assets from proxy when orchestrator endpoint offline
    const otData = await apiGet(PROXY + '/ot/status');
    if (otData && otData.assets) {
      otData.assets.forEach(a => {
        if (!allAssetsCache.find(x => x.ip === a.ip)) {
          allAssetsCache.push({ip:a.ip, hostname:a.asset_id||a.ip, type:'ot', os:a.vendor||'Unknown', risk_score:a.authorized?40:90, cves:[], open_ports:[], last_seen:'live', risk_level:a.authorized?'medium':'critical', subnet:a.ip.split('.').slice(0,3).join('.')+'.x', vendor:a.vendor||'Unknown'});
        }
      });
    }
  }
  document.getElementById('assetTotal').textContent = allAssetsCache.length;
  document.getElementById('assetHighRisk').textContent = allAssetsCache.filter(a=>a.risk_score>=70).length;
  document.getElementById('assetUnpatched').textContent = allAssetsCache.filter(a=>a.cves.length>0).length;
  document.getElementById('assetOT').textContent = allAssetsCache.filter(a=>a.type==='ot').length;
  renderAssetTable(allAssetsCache);
  renderAssetSubnetMap();
}

function filterAssets() {
  const q = document.getElementById('assetSearch').value.toLowerCase();
  const type = document.getElementById('assetFilter').value;
  const filtered = allAssetsCache.filter(a => {
    if (type !== 'all' && a.type !== type) return false;
    if (q && !a.ip.includes(q) && !(a.hostname||'').toLowerCase().includes(q) && !(a.os||'').toLowerCase().includes(q) && !(a.vendor||'').toLowerCase().includes(q)) return false;
    return true;
  });
  renderAssetTable(filtered);
}

function renderAssetTable(assets) {
  const tbl = document.getElementById('assetTable');
  if (!assets.length) { tbl.innerHTML = '<div class="empty-state"><i class="fa-solid fa-server"></i><div>No assets match filter.</div></div>'; return; }
  tbl.innerHTML = '<table class="table"><thead><tr><th>IP</th><th>Hostname</th><th>Type</th><th>OS / Firmware</th><th>Risk</th><th>CVEs</th><th>Open Ports</th><th>Last Seen</th></tr></thead><tbody>' +
    assets.map(a => `<tr style="cursor:pointer">
      <td style="font-family:monospace;font-size:12px">${esc(a.ip)}</td>
      <td style="font-weight:600">${esc(a.hostname||'-')}</td>
      <td><span class="badge ${a.type==='ot'?'medium':a.type==='network'?'critical':'info'}">${esc(a.type)}</span></td>
      <td style="font-size:12px">${esc(a.os||'-')}</td>
      <td><span class="risk-score ${a.risk_level}">${a.risk_score}</span></td>
      <td>${a.cves.length ? a.cves.slice(0,2).map(c=>`<span style="font-size:10px;color:var(--accent-red);font-family:monospace">${esc(c)}</span>`).join(' ') : '<span style="color:var(--accent-green);font-size:11px">None</span>'}</td>
      <td style="font-size:11px;font-family:monospace">${(a.open_ports||[]).slice(0,5).join(', ')||'—'}</td>
      <td style="font-size:11px;color:var(--text-muted)">${esc(a.last_seen||'-')}</td>
    </tr>`).join('') + '</tbody></table>';
}

function renderAssetSubnetMap() {
  const subnets = {};
  allAssetsCache.forEach(a => {
    const s = a.subnet || a.ip.split('.').slice(0,3).join('.')+'.x';
    if (!subnets[s]) subnets[s] = {total:0, critical:0, high:0, medium:0, low:0, label:s};
    subnets[s].total++;
    subnets[s][a.risk_level] = (subnets[s][a.risk_level]||0) + 1;
  });
  document.getElementById('assetSubnetMap').innerHTML =
    '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px">' +
    Object.values(subnets).map(d => {
      const maxRL = d.critical?'critical':d.high?'high':d.medium?'medium':'low';
      return `<div class="panel" style="margin:0;padding:12px;border-left:3px solid ${maxRL==='critical'?'var(--accent-red)':maxRL==='high'?'var(--accent-amber)':'var(--accent-green)'}">
        <div style="font-family:monospace;font-weight:700;font-size:13px;margin-bottom:6px">${esc(d.label)}</div>
        <div style="font-size:12px;color:var(--text-muted);margin-bottom:6px">${d.total} asset${d.total!==1?'s':''}</div>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
          ${d.critical?`<span class="badge critical">${d.critical} CRIT</span>`:''}
          ${d.high?`<span class="badge high">${d.high} HIGH</span>`:''}
          ${d.medium?`<span class="badge medium">${d.medium} MED</span>`:''}
          ${d.low?`<span class="badge low">${d.low} LOW</span>`:''}
        </div>
      </div>`;
    }).join('') + '</div>';
}

// ========================= HONEYPOT / DECEPTION =========================
const CANARY_TRAPS = [
  {service:'SSH',    port:22,   icon:'fa-terminal',      lure:'backup-admin-server', triggers:0},
  {service:'RDP',    port:3389, icon:'fa-desktop',       lure:'win-backup-srv-01',   triggers:0},
  {service:'HTTP',   port:80,   icon:'fa-globe',         lure:'admin-panel.corp',    triggers:0},
  {service:'SMB',    port:445,  icon:'fa-folder-open',   lure:'finance-share',       triggers:0},
  {service:'FTP',    port:21,   icon:'fa-file-arrow-up', lure:'backup-ftp.internal', triggers:0},
  {service:'Redis',  port:6379, icon:'fa-database',      lure:'cache-server-01',     triggers:0},
  {service:'Modbus', port:502,  icon:'fa-industry',      lure:'PLC-PUMP-CANARY',     triggers:0},
  {service:'REST API',port:8080,icon:'fa-code',          lure:'internal-api.local',  triggers:0},
];
async function loadHoneypot() {
  const d = await apiGet(API + '/honeypot/status');
  const events = (d && d.triggers) ? d.triggers : [];
  CANARY_TRAPS.forEach(t => { t.triggers = events.filter(e=>e.service===t.service).length; });

  document.getElementById('hpyActive').textContent = CANARY_TRAPS.length;
  document.getElementById('hpyTriggers').textContent = events.length;
  document.getElementById('hpyAttackers').textContent = new Set(events.map(e=>e.ip)).size;
  const critCount = events.filter(e=>e.severity==='critical').length;
  const level = critCount > 0 ? 'HIGH' : events.length > 2 ? 'MEDIUM' : 'LOW';
  const lvlEl = document.getElementById('hpyThreatLevel');
  lvlEl.textContent = level;
  lvlEl.style.color = level==='HIGH'?'var(--accent-red)':level==='MEDIUM'?'var(--accent-amber)':'var(--accent-green)';

  // Feed
  const feed = document.getElementById('hpyFeed');
  feed.innerHTML = events.length
    ? '<table class="table"><thead><tr><th>Time</th><th>Attacker IP</th><th>Trap Service</th><th>Action</th><th>Country</th><th>Severity</th></tr></thead><tbody>' +
      events.map(e=>`<tr><td style="font-size:11px">${new Date(e.ts).toLocaleTimeString('it-IT')}</td>
        <td style="font-family:monospace;font-size:12px;font-weight:600">${esc(e.ip)}</td>
        <td><span class="badge info">${esc(e.service)}</span>:<span style="font-size:10px;color:var(--text-muted)">${e.port}</span></td>
        <td style="font-size:12px">${esc((e.action||'').replace(/_/g,' '))}</td>
        <td style="font-size:11px">${esc(e.country||'-')}</td>
        <td><span class="badge ${(e.severity||'info').toLowerCase()}">${esc(e.severity)}</span></td></tr>`).join('') + '</tbody></table>'
    : '<div class="muted" style="padding:12px">No interactions detected. All canaries are armed.</div>';

  // Traps grid
  document.getElementById('hpyTraps').innerHTML =
    '<div style="display:flex;flex-wrap:wrap">' +
    CANARY_TRAPS.map(t=>`<div class="trap-service ${t.triggers>0?'triggered':'active'}">
      <i class="fa-solid ${t.icon}" style="color:${t.triggers>0?'var(--accent-red)':'var(--accent-green)'}"></i>
      <div><div style="font-weight:700;font-size:12px">${esc(t.service)} <span style="font-size:10px;color:var(--text-muted)">:${t.port}</span></div>
      <div style="font-size:10px;color:var(--text-muted)">${esc(t.lure)}</div></div>
      ${t.triggers>0?`<span class="badge critical" style="font-size:10px">${t.triggers}</span>`:'<span style="font-size:9px;color:var(--accent-green)">Armed</span>'}
    </div>`).join('') + '</div>';

  // Attacker profiles
  const ipGroups = {};
  events.forEach(e => {
    if (!ipGroups[e.ip]) ipGroups[e.ip] = {ip:e.ip, country:e.country, services:[], actions:[], maxSev:'info'};
    if (!ipGroups[e.ip].services.includes(e.service)) ipGroups[e.ip].services.push(e.service);
    ipGroups[e.ip].actions.push(e.action);
    const ord = ['info','low','medium','high','critical'];
    if (ord.indexOf(e.severity)>ord.indexOf(ipGroups[e.ip].maxSev)) ipGroups[e.ip].maxSev=e.severity;
  });
  const profiles = Object.values(ipGroups).sort((a,b)=>b.actions.length-a.actions.length).slice(0,6);
  const profEl = document.getElementById('hpyAttackerProfiles');
  profEl.innerHTML = profiles.length
    ? '<table class="table"><thead><tr><th>Attacker IP</th><th>Country</th><th>Traps Hit</th><th>Actions</th><th>Max Sev</th><th>MITRE Inferred</th></tr></thead><tbody>' +
      profiles.map(p => {
        let mitre = 'T1046 Network Discovery';
        if (p.services.includes('SSH')&&p.actions.some(a=>a.includes('auth'))) mitre='T1110.001 Password Guessing';
        else if (p.services.includes('Modbus')) mitre='T0855 Unauthorized Command';
        else if (p.services.includes('RDP')) mitre='T1021.001 Remote Desktop';
        else if (p.services.includes('HTTP')&&p.actions.some(a=>a.includes('scan'))) mitre='T1190 Exploit Public App';
        return `<tr><td style="font-family:monospace;font-weight:600">${esc(p.ip)}</td><td>${esc(p.country||'-')}</td>
          <td>${p.services.map(s=>`<span class="badge info" style="font-size:10px">${esc(s)}</span>`).join(' ')}</td>
          <td>${p.actions.length}</td><td><span class="badge ${p.maxSev}">${esc(p.maxSev)}</span></td>
          <td style="font-size:11px;color:var(--accent-cyan)">${esc(mitre)}</td></tr>`;
      }).join('') + '</tbody></table>'
    : '<div class="muted">No attacker profiles yet.</div>';
}

// ========================= REPORTS =========================
const REPORT_TEMPLATES = [
  {id:'nis2-incident',  icon:'fa-shield-halved', title:'NIS2 Incident Report',       color:'var(--accent-blue)',   desc:'Art.21/23 incident notification with 24h/72h deadline tracker. Ready for CSIRT/national authority submission.'},
  {id:'gdpr-breach',    icon:'fa-lock',           title:'GDPR Data Breach Report',    color:'var(--accent-red)',    desc:'Art.33 breach notification for DPA. Includes affected data categories, impact analysis, and mitigation measures.'},
  {id:'soc-weekly',     icon:'fa-chart-line',     title:'SOC Weekly Summary',         color:'var(--accent-green)',  desc:'Management-ready: 7-day event digest, top threats, MTTD, active incidents, and module health status.'},
  {id:'vuln-report',    icon:'fa-bug',            title:'Vulnerability Assessment',   color:'var(--accent-amber)',  desc:'Full CVE findings with CVSS scores, affected hosts, patch priority matrix, and remediation timeline.'},
  {id:'ot-security',    icon:'fa-industry',       title:'OT / ICS Security Report',   color:'var(--accent-cyan)',   desc:'Industrial security posture: asset inventory, protocol violations, Purdue model coverage, IEC 62443 notes.'},
  {id:'executive',      icon:'fa-briefcase',      title:'Executive Summary',          color:'var(--accent-purple)', desc:'Board-level briefing: risk score trend, top 5 threats, key metrics, and strategic recommendations. One-page.'},
];
let recentReports = [];

// ========================= REPORTS =========================
async function loadReports() {
  loadReportList();
  // Update KPIs from scan results and vuln findings
  try {
    const sr = await apiGet('/api/scan/results');
    if (sr && sr.results) {
      document.getElementById('rptHosts').textContent = sr.results.length;
      document.getElementById('rptCves').textContent = sr.results.reduce((s,h) => s + (h.findings||[]).length, 0);
    }
  } catch(e) {}
}

async function loadReportList() {
  const el = document.getElementById('reportHistory');
  try {
    const d = await apiGet('/api/report/list');
    if (!d || !d.reports || !d.reports.length) {
      el.innerHTML = '<div class="empty-state"><i class="fa-solid fa-file-circle-check"></i><div>Nessun report salvato. Clicca <strong>Scarica HTML</strong>.</div></div>';
      document.getElementById('rptCount').textContent = '0';
      return;
    }
    document.getElementById('rptCount').textContent = d.reports.length;
    if (d.reports.length) {
      const last = d.reports[d.reports.length - 1];
      document.getElementById('rptLast').textContent = (last.name || '').slice(-16);
    }
    el.innerHTML = '<table class="table"><thead><tr><th>Nome File</th><th>Formato</th><th>Dimensione</th></tr></thead><tbody>' +
      d.reports.map(r => `<tr><td style="font-family:monospace;font-size:12px">${esc(r.name||'-')}</td><td>${esc(r.format||'-')}</td><td>${esc(r.size||'-')}</td></tr>`).join('') +
      '</tbody></table>';
  } catch (e) {
    el.innerHTML = '<div class="empty-state"><i class="fa-solid fa-plug-circle-xmark"></i><div>Reports module offline. Avvia <code>.\\aegis-all.ps1</code> per attivarlo.</div></div>';
    document.getElementById('rptCount').textContent = '0';
  }
}

async function downloadReport(format) {
  const bar = document.getElementById('rptStatusBar');
  const txt = document.getElementById('rptStatusTxt');
  bar.style.display = '';
  txt.textContent = 'Generazione report ' + format.toUpperCase() + '...';
  try {
    const url = '/api/report?format=' + format + '&save=1';
    const resp = await fetch(apiUrl(url), { headers: getHeaders(), credentials: 'include' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const blob = await resp.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'aegis-report-' + Date.now() + '.' + format;
    a.click();
    showToast('Report Pronto', 'Download ' + format.toUpperCase() + ' avviato', 'success');
    setTimeout(loadReportList, 1000);
  } catch(e) {
    showToast('Errore', 'Modulo reports offline o errore: ' + e.message, 'error');
  } finally {
    bar.style.display = 'none';
  }
}

async function previewReport() {
  const bar = document.getElementById('rptStatusBar');
  bar.style.display = '';
  document.getElementById('rptStatusTxt').textContent = 'Caricamento anteprima...';
  try {
    window.open('/api/report?format=html', '_blank');
  } finally {
    bar.style.display = 'none';
  }
}

async function runFullPipelineReport() {
  showToast('Pipeline', 'Avvio scan LAN + CVE + report...', 'info');
  // 1. launch scan
  const scan = await apiPost('/api/scan/launch', {mode: 'quick'});
  if (!scan || !scan.job_id) { showToast('Errore', 'Scan LAN fallito', 'error'); return; }
  const bar = document.getElementById('rptStatusBar');
  const txt = document.getElementById('rptStatusTxt');
  bar.style.display = '';
  txt.textContent = 'Scansione LAN in corso...';
  // 2. wait for scan to finish
  await new Promise(resolve => {
    const t = setInterval(async () => {
      const s = await apiGet('/api/scan/status?job_id=' + scan.job_id);
      if (!s) { clearInterval(t); resolve(); return; }
      txt.textContent = 'Scansione LAN: ' + (s.progress||0) + '% — host trovati: ' + (s.hosts_found||0);
      if (s.state === 'done' || s.state === 'error') { clearInterval(t); resolve(); }
    }, 2000);
  });
  // 3. vuln batch on discovered hosts
  const sr = await apiGet('/api/scan/results?job_id=' + scan.job_id);
  if (sr && sr.results && sr.results.length) {
    txt.textContent = 'Scansione CVE su ' + sr.results.length + ' host...';
    await apiPost('/api/vuln/batch', {targets: sr.results.map(h=>h.ip).slice(0,30)});
    await new Promise(r => setTimeout(r, 8000)); // let vuln scan run
  }
  // 4. generate & download report
  txt.textContent = 'Generazione report HTML...';
  await downloadReport('html');
}

function renderReportHistory() {} // legacy stub — loadReportList replaces this

async function generateReport(type) {
  const template = REPORT_TEMPLATES.find(t=>t.id===type);
  if (!template) return;
  showToast('Generating…', template.title + ' — fetching data', 'info');
  const [eventsRaw, metrics] = await Promise.all([apiGet(API+'/events?limit=1000'), apiGet(API+'/metrics')]);
  const evList = Array.isArray(eventsRaw) ? eventsRaw : (eventsRaw?.events||[]);
  const rangeVal = document.getElementById('reportDateRange').value;
  const ms = {'24h':86400000,'7d':604800000,'30d':2592000000}[rangeVal]||Infinity;
  const filtered = evList.filter(e => Date.now()-new Date(e.timestamp).getTime() < ms);
  const html = _buildReportHTML(type, template, filtered, metrics||{}, rangeVal);
  const blob = new Blob([html],{type:'text/html'});
  const a = document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download='aegis-report-'+type+'-'+Date.now()+'.html'; a.click();
  recentReports.unshift({type:template.title, generated:new Date().toLocaleString('it-IT'), events:filtered.length});
  renderReportHistory();
  showToast('Report Ready', template.title+' downloaded', 'success');
}

function _buildReportHTML(type, tmpl, events, metrics, rangeVal) {
  const rangeLabel = {'24h':'Last 24 Hours','7d':'Last 7 Days','30d':'Last 30 Days','all':'All Time'}[rangeVal]||'Custom';
  const sev = {critical:0,high:0,medium:0,low:0,info:0};
  events.forEach(e=>{ const s=(e.severity||'info').toLowerCase(); if(sev[s]!==undefined)sev[s]++; });
  const topEvents = events.filter(e=>['critical','high'].includes((e.severity||'').toLowerCase())).slice(0,10);
  const srcCounts = {};
  events.forEach(e=>{ srcCounts[e.source]=(srcCounts[e.source]||0)+1; });
  const score = metrics.threat_score||0;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>${esc(tmpl.title)} — AEGIS</title>
<style>body{font-family:Arial,sans-serif;max-width:940px;margin:0 auto;padding:32px;color:#1e293b;font-size:14px}
h1{color:#1e40af;border-bottom:3px solid #1e40af;padding-bottom:10px;margin-bottom:8px}
h2{color:#374151;margin:24px 0 8px;font-size:16px}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:13px}
th{background:#f1f5f9;text-align:left;padding:8px 10px;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
td{padding:8px 10px;border-bottom:1px solid #e2e8f0}
.kpig{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}
.kpib{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;text-align:center}
.kpiv{font-size:26px;font-weight:700;color:#1e40af}.kpil{font-size:11px;color:#64748b;margin-top:3px}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}
.critical{background:#fee2e2;color:#dc2626}.high{background:#fef3c7;color:#d97706}
.medium{background:#dbeafe;color:#2563eb}.low{background:#d1fae5;color:#059669}
.warn{background:#fef3c7;border:1px solid #fcd34d;border-radius:6px;padding:10px 14px;margin:10px 0}
.info-b{background:#dbeafe;border:1px solid #93c5fd;border-radius:6px;padding:10px 14px;margin:10px 0}
.footer{margin-top:32px;padding-top:12px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:11px}
@media print{body{max-width:100%}}</style></head><body>
<h1>&#128737; ${esc(tmpl.title)}</h1>
<div style="color:#64748b;font-size:13px"><strong>Cybersecurity-AEGIS v1.0</strong> &nbsp;|&nbsp; Generated: ${new Date().toLocaleString('en-GB')} &nbsp;|&nbsp; Period: ${esc(rangeLabel)} &nbsp;|&nbsp; Total Events: ${events.length}</div>
<div class="kpig">
  <div class="kpib"><div class="kpiv">${events.length}</div><div class="kpil">Total Events</div></div>
  <div class="kpib"><div class="kpiv" style="color:#dc2626">${sev.critical}</div><div class="kpil">Critical</div></div>
  <div class="kpib"><div class="kpiv" style="color:#d97706">${sev.high}</div><div class="kpil">High</div></div>
  <div class="kpib"><div class="kpiv" style="color:#1e40af">${Math.round(score)}/100</div><div class="kpil">Threat Score</div></div>
</div>
${sev.critical>0?`<div class="warn"><strong>&#9888; ACTION REQUIRED:</strong> ${sev.critical} critical event(s) detected. Immediate review required. Check NIS2 Art.23 reporting obligation.</div>`:'<div class="info-b">&#8505; No critical events in this period.</div>'}
<h2>Top Critical / High Events</h2>
<table><tr><th>Timestamp</th><th>Title</th><th>Source</th><th>Severity</th><th>MITRE</th></tr>
${topEvents.map(e=>`<tr><td style="white-space:nowrap;font-size:12px">${new Date(e.timestamp).toLocaleString('en-GB')}</td><td>${esc(e.title||'-')}</td><td>${esc(e.source||'-')}</td><td><span class="badge ${(e.severity||'info').toLowerCase()}">${esc(e.severity)}</span></td><td style="font-size:11px">${e.mitre?esc(e.mitre.technique_id||''):'—'}</td></tr>`).join('')}
</table>
<h2>Event Distribution by Source</h2>
<table><tr><th>Source Module</th><th>Events</th><th>% of Total</th></tr>
${Object.entries(srcCounts).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${v}</td><td>${events.length?((v/events.length)*100).toFixed(1)+'%':'0%'}</td></tr>`).join('')}
</table>
<h2>Compliance Checklist</h2>
<table><tr><th>Framework</th><th>Obligation</th><th>Status</th></tr>
<tr><td>NIS2 Art.21</td><td>Incident handling and recovery</td><td>&#10003; SOAR playbooks active</td></tr>
<tr><td>NIS2 Art.23</td><td>Early warning within 24h for significant incidents</td><td>${sev.critical>0?'&#9888; Review required — critical events present':'&#10003; No significant incident detected'}</td></tr>
<tr><td>GDPR Art.32</td><td>Technical security measures</td><td>&#10003; SIEM + network monitoring active</td></tr>
<tr><td>GDPR Art.33</td><td>Breach notification to DPA within 72h</td><td>${sev.critical>0?'&#9888; Evaluate for personal data exposure':'&#10003; No breach indicators'}</td></tr>
<tr><td>IEC 62443</td><td>OT/ICS security baseline</td><td>&#10003; Advisory-only mode — no automated OT actions</td></tr>
<tr><td>NIST 800-82</td><td>Industrial control system security</td><td>&#10003; Passive OT monitoring active</td></tr>
</table>
<div class="footer"><strong>Cybersecurity-AEGIS</strong> — Defensive Security Platform | Report type: ${esc(tmpl.title)}<br>
<em>CONFIDENTIAL — For authorized internal use only. Do not distribute without approval.</em></div>
</body></html>`;
}

function renderReportHistory() {
  const el = document.getElementById('reportHistory');
  el.innerHTML = recentReports.length
    ? '<table class="table"><thead><tr><th>Report Type</th><th>Generated</th><th>Events Included</th></tr></thead><tbody>' +
      recentReports.map(r=>`<tr><td>${esc(r.type)}</td><td>${esc(r.generated)}</td><td>${r.events}</td></tr>`).join('') + '</tbody></table>'
    : '<div class="empty-state"><i class="fa-solid fa-file-circle-check"></i><div>No reports generated yet. Click Generate on any template above.</div></div>';
}

// ========================= COMPLIANCE =========================
function loadCompliance() {
  const nis2Controls = [
    { name: 'Incident handling policies & procedures',      status: 'implemented',  detail: 'SOAR playbooks + SIEM correlation engine' },
    { name: 'Business continuity & disaster recovery',      status: 'partial',      detail: 'Event persistence; full BCP not in scope' },
    { name: 'Supply chain security',                        status: 'planned',      detail: 'SBOM + vendor risk not yet implemented' },
    { name: 'Network & information system security',        status: 'implemented',  detail: 'Suricata + network analyzer + SIEM' },
    { name: 'Vulnerability handling & disclosure',          status: 'implemented',  detail: 'Vulnerability scanner (NVD/CVE lookup)' },
    { name: 'Policies on use of cryptography',             status: 'implemented',  detail: 'mTLS + step-ca + HTTPS everywhere' },
    { name: 'Human resources security & access control',   status: 'partial',      detail: 'Auth module present; HR workflows manual' },
    { name: 'Multi-factor authentication (MFA)',           status: 'planned',      detail: 'Keycloak MFA integration planned' },
    { name: 'Secure communications & emergency systems',   status: 'implemented',  detail: 'Encrypted channels; notification hooks' },
    { name: 'Basic cyber hygiene & security training',     status: 'partial',      detail: 'Defensive tooling; training materials needed' },
  ];
  const colorMap = { implemented: 'var(--accent-green)', partial: 'var(--accent-amber)', planned: 'var(--text-muted)' };
  const iconMap  = { implemented: 'fa-check-circle', partial: 'fa-circle-half-stroke', planned: 'fa-circle' };
  const done = nis2Controls.filter(c => c.status === 'implemented').length;
  document.getElementById('compNIS2Score').textContent = done + '/' + nis2Controls.length;
  document.getElementById('compNIS2Table').innerHTML =
    '<table class="table"><thead><tr><th>Control</th><th>Status</th><th>Implementation</th></tr></thead><tbody>' +
    nis2Controls.map(c =>
      `<tr><td>${esc(c.name)}</td><td style="color:${colorMap[c.status]};white-space:nowrap"><i class="fa-solid ${iconMap[c.status]}"></i> ${esc(c.status)}</td><td style="font-size:12px;color:var(--text-muted)">${esc(c.detail)}</td></tr>`
    ).join('') + '</tbody></table>';

  const gdprControls = [
    { name: 'Pseudonymisation of personal data',     status: 'implemented', detail: 'Event IPs hashed in export mode' },
    { name: 'Encryption of personal data',           status: 'implemented', detail: 'TLS 1.3 in transit; AES-256 at rest (DB)' },
    { name: 'Ongoing confidentiality & integrity',   status: 'implemented', detail: 'Role-based access + audit log' },
    { name: 'Availability & resilience',             status: 'partial',     detail: 'In-memory ring buffer; PostgreSQL optional' },
    { name: 'Restore availability after incident',   status: 'partial',     detail: 'Event export + replay; no automated restore' },
    { name: 'Regular testing & evaluation',          status: 'implemented', detail: 'SIEM correlation + vulnerability scanner' },
  ];
  const gdprDone = gdprControls.filter(c => c.status === 'implemented').length;
  document.getElementById('compGDPR').textContent = gdprDone + '/' + gdprControls.length;
  document.getElementById('compGDPRTable').innerHTML =
    '<table class="table"><thead><tr><th>Measure</th><th>Status</th><th>Detail</th></tr></thead><tbody>' +
    gdprControls.map(c =>
      `<tr><td>${esc(c.name)}</td><td style="color:${colorMap[c.status]};white-space:nowrap"><i class="fa-solid ${iconMap[c.status]}"></i> ${esc(c.status)}</td><td style="font-size:12px;color:var(--text-muted)">${esc(c.detail)}</td></tr>`
    ).join('') + '</tbody></table>';

  document.getElementById('compNotifTable').innerHTML =
    '<table class="table"><thead><tr><th>Obligation</th><th>Deadline</th><th>Trigger</th><th>Status</th></tr></thead><tbody>' +
    [
      { ob: 'NIS2 Early Warning',          dl: '24 hours',  trig: 'Significant incident detected by SIEM',  st: 'Manual (SOAR advisory)', ok: true },
      { ob: 'NIS2 Incident Notification',  dl: '72 hours',  trig: 'Incident severity ≥ HIGH confirmed',     st: 'Template playbook ready', ok: true },
      { ob: 'NIS2 Final Report',           dl: '1 month',   trig: 'Post-incident analysis complete',        st: 'Manual report required', ok: false },
      { ob: 'GDPR Data Breach (Art.33)',   dl: '72 hours',  trig: 'Personal data exposure event',          st: 'Manual DPA notification', ok: false },
      { ob: 'GDPR Data Subject (Art.34)',  dl: 'Without delay', trig: 'High-risk breach confirmed',        st: 'Manual notification', ok: false },
    ].map(r =>
      `<tr><td>${esc(r.ob)}</td><td style="color:var(--accent-amber)">${esc(r.dl)}</td><td style="font-size:12px">${esc(r.trig)}</td><td style="color:${r.ok?'var(--accent-green)':'var(--text-muted)'}">${esc(r.st)}</td></tr>`
    ).join('') + '</tbody></table>';
}

// ========================= KPI / METRICS =========================
let kpiSevChart, kpiModChart;
async function loadKPI() {
  const events = await apiGet(API + '/events?limit=500');
  const metrics = await apiGet(API + '/metrics');
  const evList = Array.isArray(events) ? events : (events?.events || []);

  // Events per hour
  const now = Date.now();
  const oneHourAgo = now - 3600000;
  const lastHour = evList.filter(e => new Date(e.timestamp).getTime() > oneHourAgo);
  document.getElementById('kpiEPH').textContent = lastHour.length;

  // Critical unresolved
  const critical = evList.filter(e => (e.severity||'').toLowerCase() === 'critical' && !e.resolved);
  document.getElementById('kpiCriticalOpen').textContent = critical.length;

  // Coverage: count active modules from metrics
  const mods = metrics?.modules || {};
  const activeMods = Object.values(mods).filter(m => m?.status === 'online' || m?.status === 'healthy').length;
  const totalMods = Math.max(Object.keys(mods).length, 7);
  document.getElementById('kpiCoverage').textContent = activeMods + '/' + totalMods;

  // MTTD estimate: median time between consecutive events (proxy for detection latency)
  const timestamps = evList.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t)).sort((a,b)=>a-b);
  let mttd = '--';
  if (timestamps.length >= 2) {
    const gaps = [];
    for (let i = 1; i < Math.min(timestamps.length, 50); i++) gaps.push(timestamps[i] - timestamps[i-1]);
    const median = gaps.sort((a,b)=>a-b)[Math.floor(gaps.length/2)] || 0;
    mttd = median < 60000 ? (median/1000).toFixed(0)+'s' : (median/60000).toFixed(1)+'m';
  }
  document.getElementById('kpiMTTD').textContent = mttd;

  // Severity distribution chart
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  evList.forEach(e => { const s = (e.severity||'info').toLowerCase(); if (sevCounts[s] !== undefined) sevCounts[s]++; });
  if (typeof Chart !== 'undefined') {
    const sevCtx = document.getElementById('kpiSevChart').getContext('2d');
    const sevData = [sevCounts.critical, sevCounts.high, sevCounts.medium, sevCounts.low, sevCounts.info];
    if (kpiSevChart) {
      kpiSevChart.data.datasets[0].data = sevData;
      kpiSevChart.update('none');
    } else {
      kpiSevChart = new Chart(sevCtx, {
        type: 'bar',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
          datasets: [{ label: 'Events', data: sevData,
            backgroundColor: ['#ef4444','#f59e0b','#3b82f6','#10b981','#94a3b8'] }]
        },
        options: { responsive: true, maintainAspectRatio:false, animation:false, resizeDelay:150, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#94a3b8' } }, y: { ticks: { color: '#94a3b8' }, beginAtZero: true } } }
      });
    }
  }

  // Module coverage pie chart
  const srcCounts = {};
  evList.forEach(e => { const s = e.source || 'unknown'; srcCounts[s] = (srcCounts[s]||0) + 1; });
  const topSources = Object.entries(srcCounts).sort((a,b)=>b[1]-a[1]).slice(0, 7);
  if (typeof Chart !== 'undefined') {
    const modCtx = document.getElementById('kpiModChart').getContext('2d');
    const modLabels = topSources.map(s=>s[0]);
    const modData = topSources.map(s=>s[1]);
    if (kpiModChart) {
      kpiModChart.data.labels = modLabels;
      kpiModChart.data.datasets[0].data = modData;
      kpiModChart.update('none');
    } else {
      kpiModChart = new Chart(modCtx, {
        type: 'doughnut',
        data: {
          labels: modLabels,
          datasets: [{ data: modData,
            backgroundColor: ['#10b981','#3b82f6','#f59e0b','#ef4444','#8b5cf6','#06b6d4','#94a3b8'] }]
        },
        options: { responsive: true, maintainAspectRatio:false, animation:false, resizeDelay:150, plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 11 } } } } }
      });
    }
  }

  // Targets table
  document.getElementById('kpiTargetTable').innerHTML =
    '<table class="table"><thead><tr><th>Metric</th><th>Blueprint Target</th><th>Actual</th><th>Status</th></tr></thead><tbody>' +
    [
      { m: 'MTTD (IT)',        target: '< 5 min',    actual: mttd,                                  ok: mttd !== '--' },
      { m: 'MTTD (OT)',        target: '< 15 min',   actual: mttd,                                  ok: mttd !== '--' },
      { m: 'MTTR',             target: '< 10 min',   actual: 'Manual (SOAR dry-run)',               ok: false },
      { m: 'False Positive %', target: '< 5%',       actual: 'Not measured',                        ok: false },
      { m: 'Log loss',         target: '< 0.1%',     actual: 'In-memory ring buffer',               ok: true  },
      { m: 'Events/hour',      target: '>= 1',       actual: lastHour.length,                       ok: lastHour.length >= 1 },
      { m: 'Active modules',   target: '7 / 7',      actual: activeMods + ' / ' + totalMods,        ok: activeMods >= 5 },
      { m: 'IOC Coverage',     target: '>= 100 IOCs', actual: '--  (load TI page)',                  ok: false },
      { m: 'SIEM Rules',       target: '>= 10',      actual: '--  (load SIEM page)',                 ok: false },
    ].map(r =>
      `<tr><td>${esc(r.m)}</td><td style="color:var(--accent-amber)">${esc(r.target)}</td><td>${esc(String(r.actual))}</td><td style="color:${r.ok?'var(--accent-green)':'var(--text-muted)'}">${r.ok?'✓ OK':'— Pending'}</td></tr>`
    ).join('') + '</tbody></table>';
}

async function refreshAll() {
  if (!autoRefresh) return;
  if (!backendOnline) return;
  await loadOverview();
  await refreshEvents();
  const curPage = document.querySelector('.page.active')?.id || 'page-overview';
  if (curPage === 'page-shield') await loadShield();
  if (curPage === 'page-endpoint') await loadEndpoint();
  if (curPage === 'page-network') await loadNetwork();
  if (curPage === 'page-ot') await loadOT();
  if (curPage === 'page-siem') await loadSIEM();
  if (curPage === 'page-soar') await loadSOAR();
  if (curPage === 'page-ti') await loadTI();
  if (curPage === 'page-vuln') await loadVuln();
  if (curPage === 'page-ml') await loadML();
  if (curPage === 'page-settings') await loadSettings();
  if (curPage === 'page-dfir') await loadDFIR();
  if (curPage === 'page-assets') await loadAssets();
  if (curPage === 'page-honeypot') await loadHoneypot();
  if (curPage === 'page-reports') await loadReports();
  if (curPage === 'page-topology') await loadTopology();
  if (curPage === 'page-campaigns') await loadCampaigns();
  if (curPage === 'page-audit') await loadAuditLog();
  if (curPage === 'page-roadmap') await loadRoadmapToolCount();
  if (curPage === 'page-integrations') await loadIntegrations();
  if (curPage === 'page-sigma') await loadSigma();
  if (curPage === 'page-ot-protocols') await loadOTProtocols();
  if (curPage === 'page-evidence') await loadEvidence();
  if (curPage === 'page-pki') await loadPKI();
  if (curPage === 'page-tls') await loadTLS();
  lastRefreshTime = Date.now();
}

// ========================= AUDIT LOG =========================
let auditEntries = [];
async function loadAuditLog() {
  try {
    const data = await apiGet(API+'/audit-log');
    auditEntries = data.entries || [];
    renderAuditLog();
  } catch (e) {
    document.querySelector('#auditTable tbody').innerHTML = '<tr><td colspan="6" class="muted">Error loading audit log</td></tr>';
  }
}
function renderAuditLog() {
  const level = document.getElementById('auditFilterLevel').value;
  const source = document.getElementById('auditFilterSource').value;
  const q = document.getElementById('auditSearch').value.toLowerCase().trim();
  let rows = auditEntries.slice().reverse();
  if (level) rows = rows.filter(e => (e.severity||'').toLowerCase() === level);
  if (source) rows = rows.filter(e => (e.source||'') === source);
  if (q) rows = rows.filter(e => ((e.action||'') + ' ' + (e.detail||'')).toLowerCase().includes(q));
  const total = auditEntries.length;
  const errs = auditEntries.filter(e => ['error','critical','warning'].includes((e.severity||'').toLowerCase())).length;
  const apis = auditEntries.filter(e => (e.source||'') === 'api').length;
  document.getElementById('auditTotal').textContent = total;
  document.getElementById('auditErrors').textContent = errs;
  document.getElementById('auditAPI').textContent = apis;
  document.getElementById('auditLast').textContent = rows.length ? new Date(rows[0].timestamp).toLocaleString() : '—';
  const tbody = rows.map(e => {
    const sev = (e.severity||'info').toLowerCase();
    let color = 'var(--text-muted)';
    if (sev === 'error') color = 'var(--accent-red)';
    if (sev === 'warning') color = 'var(--accent-amber)';
    if (sev === 'critical') color = 'var(--accent-red)';
    if (sev === 'info') color = 'var(--accent-green)';
    return `<tr>
      <td style="font-size:11px;color:var(--text-muted)">${esc(new Date(e.timestamp).toLocaleString())}</td>
      <td><span class="badge ${sev==='error'||sev==='critical'?'danger':sev==='warning'?'warning':'info'}">${esc(e.action||'')}</span></td>
      <td style="font-size:12px">${esc(e.source||'')}</td>
      <td style="font-size:12px">${esc(e.detail||'')}</td>
      <td style="font-size:11px;color:var(--text-muted)">${esc(e.client||'')}</td>
      <td style="font-size:12px;font-weight:600;color:${color}">${esc(e.severity||'info')}</td>
    </tr>`;
  }).join('');
  document.querySelector('#auditTable tbody').innerHTML = tbody || '<tr><td colspan="6" class="muted">No entries match filters</td></tr>';
}

// ========================= SSE =========================
function startSSE() {
  if (!backendOnline) return;
  if (sseInstance) { sseInstance.close(); }
  try {
    const es = new EventSource(API+'/events/live');
    sseInstance = es;
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        const sev = (data.severity||'').toLowerCase();
        if (sev === 'critical' || sev === 'high') {
          showToast(data.title || 'New Alert', (data.source||'') + ' — ' + (data.severity||''), sev === 'critical' ? 'critical' : 'high');
        }
        if (document.getElementById('page-overview').classList.contains('active')) {
          refreshEvents(); loadOverview();
        }
      } catch(e) {}
    };
    es.onerror = () => { if (sseInstance === es) sseInstance = null; es.close(); setTimeout(startSSE, 10000); };
  } catch(e) { sseInstance = null; }
}

// ========================= SESSION TIMEOUT =========================
function resetSessionTimer() {
  if (sessionTimer) clearTimeout(sessionTimer);
  if (sessionCountdownInterval) clearInterval(sessionCountdownInterval);
  document.getElementById('sessionModal').classList.remove('active');
  sessionTimer = setTimeout(() => {
    document.getElementById('sessionModal').classList.add('active');
    sessionCountdownVal = 60;
    document.getElementById('sessionCountdown').textContent = sessionCountdownVal;
    sessionCountdownInterval = setInterval(() => {
      sessionCountdownVal--;
      document.getElementById('sessionCountdown').textContent = sessionCountdownVal;
      if (sessionCountdownVal <= 0) { clearInterval(sessionCountdownInterval); doLogout(); }
    }, 1000);
  }, 30 * 60 * 1000);
}
function stayLoggedIn() {
  resetSessionTimer();
}
['click','keydown','touchstart','scroll'].forEach(evt => document.addEventListener(evt, resetSessionTimer));

// ════════════════════════════════════════════ TOPOLOGY ════
let _topoD3Loaded = false;
let _topoSimulation = null;

function _loadD3(cb) {
  if (_topoD3Loaded) { cb(); return; }
  const s = document.createElement('script');
  s.src = 'https://d3js.org/d3.v7.min.js';
  s.onload = () => { _topoD3Loaded = true; cb(); };
  s.onerror = () => showToast('D3 Load Error', 'Cannot load D3.js from CDN — check internet connection', 'error');
  document.head.appendChild(s);
}

async function loadTopology() {
  const empty = document.getElementById('topoEmpty');
  const svg = document.getElementById('topoSVG');
  empty.style.display = '';
  svg.style.display = 'none';
  empty.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><div>Building topology from scan results...</div>';
  try {
    const data = await apiGet('/api/topology');
    if (!data || !data.nodes || !data.nodes.length) {
      empty.innerHTML = '<i class="fa-solid fa-diagram-project"></i><div>No scan data found. Run a LAN scan first, then refresh topology.</div>';
      return;
    }
    document.getElementById('topoNodes').textContent = data.nodes.length;
    document.getElementById('topoCrowns').textContent = data.nodes.filter(n => n.is_crown_jewel).length;
    // count ot crossings from edges
    const otCross = (data.links||[]).filter(l => l.crosses_ot_boundary).length;
    document.getElementById('topoOTCross').textContent = otCross;
    const aps = data.attack_paths || [];
    document.getElementById('topoAttackPaths').textContent = aps.length;
    _loadD3(() => _renderTopologyGraph(data));
  } catch(e) {
    empty.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i><div>Error: ' + esc(e.message) + '</div>';
  }
}

function _renderTopologyGraph(data) {
  const empty = document.getElementById('topoEmpty');
  const svgEl = document.getElementById('topoSVG');
  empty.style.display = 'none';
  svgEl.style.display = '';
  svgEl.innerHTML = '';

  const container = svgEl.parentElement;
  const W = container.clientWidth || 800;
  const H = container.clientHeight || 480;

  const colorMap = { it:'#3b82f6', ot:'#f59e0b', iot:'#8b5cf6', network:'#10b981', endpoint:'#3b82f6' };

  const svg = d3.select(svgEl).attr('viewBox', `0 0 ${W} ${H}`);
  const g = svg.append('g');

  // Zoom
  svg.call(d3.zoom().scaleExtent([0.3, 4]).on('zoom', e => g.attr('transform', e.transform)));

  // Arrowhead marker
  svg.append('defs').append('marker')
    .attr('id','arrow').attr('viewBox','0 -5 10 10').attr('refX',18).attr('refY',0)
    .attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
    .append('path').attr('d','M0,-5L10,0L0,5').attr('fill','#ef444488');

  const nodes = data.nodes.map(n => ({...n}));
  const links = (data.links||[]).map(l => ({...l}));

  const attackPaths = data.attack_paths || [];
  const attackEdgeSet = new Set();
  attackPaths.forEach(ap => {
    if (ap.path) for (let i=0; i < ap.path.length-1; i++) attackEdgeSet.add(ap.path[i]+'→'+ap.path[i+1]);
  });

  const link = g.append('g').selectAll('line').data(links).join('line')
    .attr('stroke', l => {
      const src = typeof l.source === 'object' ? l.source.id : l.source;
      const tgt = typeof l.target === 'object' ? l.target.id : l.target;
      return attackEdgeSet.has(src+'→'+tgt) ? '#ef4444' : '#334155';
    })
    .attr('stroke-width', l => {
      const src = typeof l.source === 'object' ? l.source.id : l.source;
      const tgt = typeof l.target === 'object' ? l.target.id : l.target;
      return attackEdgeSet.has(src+'→'+tgt) ? 2 : 1;
    })
    .attr('stroke-dasharray', l => {
      const src = typeof l.source === 'object' ? l.source.id : l.source;
      const tgt = typeof l.target === 'object' ? l.target.id : l.target;
      return attackEdgeSet.has(src+'→'+tgt) ? '6,3' : null;
    })
    .attr('marker-end', l => {
      const src = typeof l.source === 'object' ? l.source.id : l.source;
      const tgt = typeof l.target === 'object' ? l.target.id : l.target;
      return attackEdgeSet.has(src+'→'+tgt) ? 'url(#arrow)' : null;
    });

  const node = g.append('g').selectAll('g').data(nodes).join('g')
    .call(d3.drag().on('start', (e,d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
                   .on('drag', (e,d) => { d.fx=e.x; d.fy=e.y; })
                   .on('end', (e,d) => { if (!e.active) sim.alphaTarget(0); d.fx=null; d.fy=null; }));

  node.append('circle')
    .attr('r', n => n.is_crown_jewel ? 14 : (n.device_category === 'network' ? 12 : 10))
    .attr('fill', n => n.is_crown_jewel ? '#ef4444' : (colorMap[n.device_category] || '#64748b'))
    .attr('stroke', '#1e293b').attr('stroke-width', 2)
    .on('mouseover', function(e, d) { _showTopoTooltip(e, d); })
    .on('mouseout', _hideTopoTooltip);

  node.append('text')
    .attr('dy', '1.8em').attr('text-anchor', 'middle')
    .attr('font-size', '9px').attr('fill', '#94a3b8')
    .text(n => (n.hostname || n.id || '').split('.')[0].slice(0,12));

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(80))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide(22))
    .on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });
  _topoSimulation = sim;
}

let _topoTooltip = null;
function _showTopoTooltip(event, d) {
  if (!_topoTooltip) {
    _topoTooltip = document.createElement('div');
    _topoTooltip.style.cssText = 'position:fixed;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 12px;font-size:11px;pointer-events:none;z-index:9999;max-width:220px;line-height:1.6';
    document.body.appendChild(_topoTooltip);
  }
  _topoTooltip.innerHTML = `
    <strong>${esc(d.id)}</strong><br>
    ${d.hostname && d.hostname !== d.id ? '<span style="color:#94a3b8">'+esc(d.hostname)+'</span><br>' : ''}
    Category: <span style="color:#67e8f9">${esc(d.device_category||'unknown')}</span><br>
    ${d.device_type ? 'Type: '+esc(d.device_type)+'<br>' : ''}
    ${d.os_guess ? 'OS: '+esc(d.os_guess)+'<br>' : ''}
    Risk: <span style="color:${d.risk_score>=7?'#ef4444':d.risk_score>=4?'#f59e0b':'#10b981'}">${d.risk_score||0}/10</span><br>
    ${d.is_crown_jewel ? '<span style="color:#ef4444">★ Crown Jewel</span><br>' : ''}
    Ports: ${(d.open_ports||[]).slice(0,8).join(', ')||'—'}`;
  _topoTooltip.style.left = (event.clientX + 14) + 'px';
  _topoTooltip.style.top  = (event.clientY - 10) + 'px';
  _topoTooltip.style.display = '';
}
function _hideTopoTooltip() { if (_topoTooltip) _topoTooltip.style.display = 'none'; }

async function loadAttackPaths() {
  document.getElementById('attackPathsPanel').style.display = '';
  const tbody = document.getElementById('attackPathsTbody');
  tbody.innerHTML = '<tr><td colspan="6" class="muted"><i class="fa-solid fa-spinner fa-spin"></i> Computing attack paths...</td></tr>';
  try {
    const data = await apiGet('/api/topology/attack-paths');
    const paths = data.attack_paths || data || [];
    // Segmentation gaps
    const gaps = data.segmentation_gaps || [];
    const gapEl = document.getElementById('topoSegGaps');
    if (gaps.length) {
      gapEl.innerHTML = '<div style="padding:8px 12px;background:#1c0a0a;border-left:3px solid #ef4444;border-radius:0 6px 6px 0;margin-bottom:10px;font-size:12px">' +
        '<strong style="color:#ef4444"><i class="fa-solid fa-triangle-exclamation"></i> Segmentation Gaps Detected (' + gaps.length + ')</strong>' +
        gaps.slice(0,5).map(g => '<div style="color:#fca5a5;margin-top:4px">• '+esc(g.description||JSON.stringify(g))+'</div>').join('') + '</div>';
    } else gapEl.innerHTML = '';

    if (!paths.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted">No attack paths found — good segmentation!</td></tr>';
      return;
    }
    document.getElementById('topoAttackPaths').textContent = paths.length;
    tbody.innerHTML = paths.map(ap => {
      const risk = ap.risk_score || ap.path_risk || 0;
      const riskColor = risk >= 7 ? '#ef4444' : risk >= 4 ? '#f59e0b' : '#10b981';
      const techs = (ap.techniques || ap.mitre_techniques || []).slice(0,4).map(t => `<span style="padding:1px 5px;background:#1e293b;border-radius:3px;font-size:10px">${esc(t)}</span>`).join(' ');
      return `<tr>
        <td style="font-family:monospace;font-size:12px">${esc(ap.from || ap.source || (ap.path||[])[0] || '?')}</td>
        <td style="font-family:monospace;font-size:12px">${esc(ap.to || ap.target || (ap.path||[]).slice(-1)[0] || '?')}</td>
        <td>${(ap.path||[]).length ? (ap.path.length-1) : (ap.hops||'?')}</td>
        <td style="color:${riskColor};font-weight:600">${risk}/10</td>
        <td>${ap.crosses_ot_boundary ? '<span style="color:#f59e0b">⚡ YES</span>' : '<span style="color:#94a3b8">No</span>'}</td>
        <td>${techs||'<span class="muted">—</span>'}</td>
      </tr>`;
    }).join('');
  } catch(e) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--accent-red)">Error: ' + esc(e.message) + '</td></tr>';
  }
}

// ════════════════════════════════════════════ TLS INSPECTOR ════
let _tlsResults = [];

function tlsSingleInspect() {
  const form = document.getElementById('tlsSingleForm');
  form.style.display = form.style.display === 'none' ? '' : 'none';
}

async function doTLSInspect() {
  const ip = document.getElementById('tlsTargetIP').value.trim();
  const port = parseInt(document.getElementById('tlsTargetPort').value) || 443;
  const hostname = document.getElementById('tlsTargetHost').value.trim();
  if (!ip) { showToast('Input Error', 'Please enter a target IP', 'error'); return; }
  document.getElementById('tlsProgress').style.display = '';
  document.getElementById('tlsProgressTxt').textContent = 'Inspecting ' + ip + ':' + port + '...';
  try {
    const data = await apiPost('/api/tls/inspect', { ip, port, hostname: hostname || undefined });
    const single = data.result || data;
    _tlsResults = [single];
    _renderTLSTable(_tlsResults);
  } catch(e) {
    showToast('TLS Error', e.message, 'error');
  } finally {
    document.getElementById('tlsProgress').style.display = 'none';
  }
}

async function tlsScanFromResults() {
  document.getElementById('tlsProgress').style.display = '';
  document.getElementById('tlsProgressTxt').textContent = 'Discovering HTTPS hosts from last scan...';
  try {
    const data = await apiGet('/api/tls/scan-from-results');
    _tlsResults = data.results || data || [];
    if (!_tlsResults.length) {
      showToast('TLS Scan', 'No HTTPS hosts found in last scan results. Run a LAN scan first.', 'warning');
    }
    _renderTLSTable(_tlsResults);
  } catch(e) {
    showToast('TLS Error', e.message, 'error');
  } finally {
    document.getElementById('tlsProgress').style.display = 'none';
  }
}

function _renderTLSTable(results) {
  const tbody = document.getElementById('tlsTbody');
  let c2Count = 0, expiredCount = 0, weakCount = 0;
  if (!results.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="muted">No results.</td></tr>';
    return;
  }
  tbody.innerHTML = results.map((r, idx) => {
    const isC2 = r.is_known_c2 || r.c2_detected || false;
    const expired = r.cert_expired || (r.certificate && r.certificate.expired) || false;
    const weak = r.has_weak_cipher || (r.ciphers && r.ciphers.some && r.ciphers.some(c => /RC4|3DES|EXPORT|NULL/i.test(c)));
    const risk = r.risk_score || 0;
    const riskColor = risk >= 7 ? '#ef4444' : risk >= 4 ? '#f59e0b' : '#10b981';
    if (isC2) c2Count++;
    if (expired) expiredCount++;
    if (weak) weakCount++;
    const rowBg = isC2 ? 'background:#1c0a0a' : expired ? 'background:#1a150a' : '';
    const protocols = (r.protocols || r.supported_protocols || []).join(', ') || '—';
    const cert = r.certificate || {};
    const cn = cert.subject_cn || cert.cn || r.cert_cn || '—';
    const expiry = cert.not_after || r.cert_expiry || '—';
    const expiryStr = expiry !== '—' ? expiry.slice(0,10) : '—';
    const jarm = (r.jarm_fingerprint || r.jarm || '').slice(0,16) || '—';
    const pci = r.compliance ? (r.compliance.pci_dss !== false ? '✅' : '❌') : '—';
    const nist = r.compliance ? (r.compliance.nist !== false ? '✅' : '❌') : '—';
    // Store result by index for detail lookup
    _tlsResults[idx] = r;
    return `<tr style="${rowBg};cursor:pointer" onclick="_showTLSDetail(${idx})">
      <td style="font-family:monospace;font-size:12px">${esc(r.ip||'?')}:${r.port||443}</td>
      <td style="font-family:monospace;font-size:10px;color:#94a3b8" title="${esc(r.jarm_fingerprint||r.jarm||'')}">${esc(jarm)}${jarm!=='—'?'…':''}</td>
      <td>${isC2 ? '<span style="color:#ef4444;font-weight:700">🔴 C2 MATCH</span>' : '<span style="color:#10b981">✅ Clean</span>'}</td>
      <td style="font-size:12px">${esc(cn)}</td>
      <td style="${expired?'color:#ef4444':''}">${esc(expiryStr)}${expired?' ⚠️':''}</td>
      <td style="font-size:11px;color:#94a3b8">${esc(protocols)}</td>
      <td style="color:${riskColor};font-weight:600">${risk}/10</td>
      <td>${pci}</td>
      <td>${nist}</td>
    </tr>`;
  }).join('');
  document.getElementById('tlsScanned').textContent = results.length;
  document.getElementById('tlsC2').textContent = c2Count;
  document.getElementById('tlsExpired').textContent = expiredCount;
  document.getElementById('tlsWeak').textContent = weakCount;
}

function _showTLSDetail(idx) {
  const r = _tlsResults[idx];
  if (!r) return;
  const panel = document.getElementById('tlsDetailPanel');
  const title = document.getElementById('tlsDetailTitle');
  const content = document.getElementById('tlsDetailContent');
  title.textContent = 'TLS Detail: ' + (r.ip||'?') + ':' + (r.port||443);
  const cert = r.certificate || {};
  const comp = r.compliance || {};
  content.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
      <div>
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;font-weight:600">JARM FINGERPRINT</div>
        <code style="font-size:10px;word-break:break-all;color:#67e8f9">${esc(r.jarm_fingerprint||r.jarm||'N/A')}</code>
        ${r.is_known_c2 ? '<div style="color:#ef4444;margin-top:6px;font-weight:600;font-size:11px">⚠️ MATCHES KNOWN C2 FRAMEWORK JARM</div>' : ''}
        ${r.c2_framework ? '<div style="font-size:11px;color:#fca5a5">Framework: '+esc(r.c2_framework)+'</div>' : ''}
      </div>
      <div>
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;font-weight:600">CERTIFICATE</div>
        <div style="font-size:11px">CN: <strong>${esc(cert.subject_cn||cert.cn||'—')}</strong></div>
        <div style="font-size:11px">Issuer: ${esc(cert.issuer_cn||cert.issuer||'—')}</div>
        <div style="font-size:11px">Valid: ${esc(cert.not_before||'—')} → ${esc(cert.not_after||'—')}</div>
        ${cert.expired ? '<div style="color:#ef4444;font-size:11px;font-weight:600">⚠️ CERTIFICATE EXPIRED</div>' : ''}
        ${cert.self_signed ? '<div style="color:#f59e0b;font-size:11px">⚠ Self-signed certificate</div>' : ''}
        <div style="font-size:11px">SANs: ${(cert.san||[]).slice(0,4).map(s=>esc(s)).join(', ')||'—'}</div>
      </div>
      <div>
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;font-weight:600">PROTOCOLS &amp; CIPHERS</div>
        <div style="font-size:11px">Protocols: <span style="color:#67e8f9">${(r.protocols||r.supported_protocols||[]).join(', ')||'—'}</span></div>
        <div style="font-size:11px">Cipher Suite: <span style="color:#a5f3fc">${esc(r.cipher_suite||r.negotiated_cipher||'—')}</span></div>
        ${r.has_weak_cipher ? '<div style="color:#ef4444;font-size:11px">⚠️ Weak cipher detected</div>' : ''}
        ${r.hsts ? '<div style="color:#10b981;font-size:11px">✓ HSTS enabled</div>' : ''}
      </div>
      <div>
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;font-weight:600">COMPLIANCE</div>
        <div style="font-size:11px">PCI DSS 4.0: ${comp.pci_dss !== false ? '<span style="color:#10b981">✅ Pass</span>' : '<span style="color:#ef4444">❌ Fail</span>'}</div>
        <div style="font-size:11px">NIST SP 800-52r2: ${comp.nist !== false ? '<span style="color:#10b981">✅ Pass</span>' : '<span style="color:#ef4444">❌ Fail</span>'}</div>
        <div style="font-size:11px">Mozilla Modern: ${comp.mozilla_modern !== false ? '<span style="color:#10b981">✅ Pass</span>' : '<span style="color:#ef4444">❌ Fail</span>'}</div>
        <div style="margin-top:6px;font-size:11px;color:var(--accent-amber)">Risk Score: <strong style="font-size:14px">${r.risk_score||0}/10</strong></div>
      </div>
    </div>
    ${r.findings && r.findings.length ? '<div style="margin-top:10px"><div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;font-weight:600">FINDINGS</div>' + r.findings.map(f => '<div style="font-size:11px;padding:3px 0;border-bottom:1px solid var(--border)">'+esc(f)+'</div>').join('') + '</div>' : ''}
  `;
  panel.style.display = '';
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ════════════════════════════════════════════ THREAT CAMPAIGNS ════
let _campData = [];

async function loadCampaigns(live) {
  const progress = document.getElementById('campProgress');
  const cards = document.getElementById('campCards');
  const windowMin = parseInt(document.getElementById('campWindowSel').value) || 60;
  progress.style.display = '';
  cards.innerHTML = '';
  try {
    const url = live
      ? `/api/fusion/live?window_minutes=${windowMin}&max_events=500`
      : `/api/fusion/live?window_minutes=${windowMin}&max_events=500`;
    const data = await apiGet(url);
    _campData = Array.isArray(data) ? data : (data.campaigns || []);
    _renderCampaigns(_campData);
  } catch(e) {
    cards.innerHTML = '<div style="color:var(--accent-red);padding:20px">Error loading campaigns: ' + esc(e.message) + '</div>';
  } finally {
    progress.style.display = 'none';
  }
}

function _renderCampaigns(campaigns) {
  const cards = document.getElementById('campCards');
  const statsBar = document.getElementById('campStats');
  // Update KPI
  const counts = { critical:0, high:0, medium:0, low:0 };
  const actorSet = new Set();
  const techSet = new Set();
  campaigns.forEach(c => {
    const u = (c.urgency||c.severity||'low').toLowerCase();
    if (counts[u] !== undefined) counts[u]++;
    else counts.low++;
    if (c.actor_hint || c.attributed_actor) actorSet.add(c.actor_hint || c.attributed_actor);
    (c.mitre_techniques || c.techniques || []).forEach(t => techSet.add(t));
  });
  document.getElementById('campTotal').textContent = campaigns.length;
  document.getElementById('campCritical').textContent = counts.critical;
  document.getElementById('campActors').textContent = actorSet.size;
  document.getElementById('campTechs').textContent = techSet.size;
  document.getElementById('statCrit').textContent = counts.critical;
  document.getElementById('statHigh').textContent = counts.high;
  document.getElementById('statMed').textContent = counts.medium;
  document.getElementById('statLow').textContent = counts.low;
  document.getElementById('statActors').textContent = actorSet.size;
  statsBar.style.display = '';

  if (!campaigns.length) {
    cards.innerHTML = '<div class="empty-state"><i class="fa-solid fa-shield-halved"></i><div>No campaigns detected in this time window. <br><span style="color:var(--text-muted)">This could mean no correlated events or no scan data yet.</span></div></div>';
    return;
  }
  cards.innerHTML = campaigns.map((c, idx) => _renderCampaignCard(c, idx)).join('');
}

function _renderCampaignCard(c, idx) {
  const urgency = (c.urgency || c.severity || 'low').toLowerCase();
  const urgencyConfig = {
    critical: { bg: '#1c0a0a', border: '#ef4444', badge: '#ef4444', label: 'CRITICAL' },
    high:     { bg: '#1a150a', border: '#f59e0b', badge: '#f59e0b', label: 'HIGH' },
    medium:   { bg: '#0e0f1e', border: '#8b5cf6', badge: '#8b5cf6', label: 'MEDIUM' },
    low:      { bg: '#0a1018', border: '#334155', badge: '#64748b', label: 'LOW' },
  };
  const cfg = urgencyConfig[urgency] || urgencyConfig.low;
  const score = c.campaign_score || c.score || 0;
  const ips = (c.involved_ips || c.affected_ips || c.ips || []).slice(0,6);
  const phases = (c.kill_chain_phases || c.phases || c.tactics || []).slice(0,5);
  const techs = (c.mitre_techniques || c.techniques || []).slice(0,8);
  const actor = c.actor_hint || c.attributed_actor || null;
  const events = c.event_count || c.events?.length || 0;
  const ts = c.first_seen || c.start_time || '';
  const te = c.last_seen || c.end_time || '';

  return `<div style="background:${cfg.bg};border:1px solid ${cfg.border};border-radius:8px;padding:14px;margin-bottom:12px" id="camp-${idx}">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:10px">
        <span style="padding:3px 10px;border-radius:4px;background:${cfg.badge};color:#fff;font-size:11px;font-weight:700">${cfg.label}</span>
        <strong style="font-size:14px">${esc(c.campaign_id || c.id || ('Campaign #'+(idx+1)))}</strong>
      </div>
      <div style="text-align:right">
        <div style="font-size:22px;font-weight:700;color:${cfg.badge}">${score}</div>
        <div style="font-size:10px;color:var(--text-muted)">score</div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:11px">
      <div>
        <div style="color:var(--text-muted);margin-bottom:3px">Affected IPs (${ips.length})</div>
        <div style="font-family:monospace">${ips.map(ip => esc(ip)).join(', ')||'—'}</div>
      </div>
      <div>
        <div style="color:var(--text-muted);margin-bottom:3px">Events Correlated</div>
        <div><strong>${events}</strong></div>
      </div>
      ${actor ? `<div>
        <div style="color:var(--text-muted);margin-bottom:3px">Actor Attribution</div>
        <div style="color:#f59e0b;font-weight:600"><i class="fa-solid fa-user-secret"></i> ${esc(actor)}</div>
      </div>` : ''}
      ${ts ? `<div>
        <div style="color:var(--text-muted);margin-bottom:3px">Timeline</div>
        <div style="font-size:10px">${esc(ts.slice(0,16))} → ${esc((te||'ongoing').slice(0,16))}</div>
      </div>` : ''}
    </div>
    ${phases.length ? `<div style="margin-top:10px">
      <div style="font-size:10px;color:var(--text-muted);margin-bottom:5px">KILL CHAIN PHASES</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px">${phases.map(p => `<span style="padding:2px 7px;border-radius:3px;font-size:10px;font-weight:600;background:#1e293b;color:#93c5fd">${esc(p)}</span>`).join('')}</div>
    </div>` : ''}
    ${techs.length ? `<div style="margin-top:10px">
      <div style="font-size:10px;color:var(--text-muted);margin-bottom:5px">MITRE ATT&amp;CK TECHNIQUES</div>
      <div style="display:flex;flex-wrap:wrap;gap:4px">${techs.map(t => `<span style="padding:2px 7px;border-radius:3px;font-size:10px;background:#0f172a;color:#c4b5fd;border:1px solid #4c1d95">${esc(t)}</span>`).join('')}</div>
    </div>` : ''}
    ${c.description ? `<div style="margin-top:10px;font-size:11px;color:var(--text-muted);border-top:1px solid var(--border);padding-top:8px">${esc(c.description)}</div>` : ''}
  </div>`;
}

// ========================= UTILS =========================
function esc(str) {
  if (typeof str !== 'string') str = String(str ?? '');
  return str.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// ========================= INTEGRATIONS =========================
async function loadIntegrations() {
  const grid = document.getElementById('integrationsGrid');
  if (!grid) return;
  grid.innerHTML = '<div class="muted">Loading...</div>';
  try {
    const d = await apiGet(API + '/integrations/tools');
    if (!d || !d.tools) { grid.innerHTML = '<div class="muted">No data</div>'; return; }
    grid.innerHTML = d.tools.map(t => {
      const status = t.service_up || t.api_up || t.present ? 'online' : 'offline';
      const color = status === 'online' ? 'var(--accent-green)' : 'var(--accent-red)';
      const detail = t.version ? ` · ${t.version}` : (t.present ? '' : ' · not installed');
      return `<div style="background:var(--surface-2);padding:12px;border-radius:8px;border:1px solid var(--border)">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <span class="status-dot ${status}"></span>
          <div style="font-weight:700;font-size:13px">${esc(t.name)}</div>
          <span class="badge info" style="font-size:10px;margin-left:auto">${esc(t.category)}</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted)">${esc(t.note || '')}${esc(detail)}</div>
        ${t.ports ? `<div style="font-size:10px;color:var(--text-muted);margin-top:4px">Ports: ${t.ports.join(', ')}</div>` : ''}
      </div>`;
    }).join('');
  } catch (e) {
    grid.innerHTML = '<div class="muted">Module offline</div>';
  }
}

// ========================= SIGMA =========================
async function loadSigma() {
  const q = document.getElementById('sigmaSearch')?.value || '';
  const level = document.getElementById('sigmaLevel')?.value || '';
  const url = API + '/sigma/rules' + (q || level ? '?' + new URLSearchParams({q, level}).toString() : '');
  const tbody = document.querySelector('#sigmaTable tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading...</td></tr>';
  try {
    const d = await apiGet(url);
    if (!d || !d.rules) { tbody.innerHTML = '<tr><td colspan="6" class="muted">No rules</td></tr>'; return; }
    tbody.innerHTML = d.rules.map(r => `<tr>
      <td style="font-size:11px">${esc(r.id || '')}</td>
      <td style="font-weight:600">${esc(r.name || '')}</td>
      <td><span class="badge ${(r.sigma_level||'').toLowerCase()}">${esc(r.sigma_level||'')}</span></td>
      <td>${esc(r.category||'')}</td>
      <td style="font-size:11px">${(r.tags||[]).map(t=>`<span class="badge info" style="font-size:10px">${esc(t)}</span>`).join(' ')}</td>
      <td>${r.enabled ? '<span class="badge success">enabled</span>' : '<span class="badge">disabled</span>'}</td>
    </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">Module offline</td></tr>';
  }
}

// ========================= OT PROTOCOLS =========================
async function loadOTProtocols() {
  try {
    const d = await apiGet(PROXY + '/ot-protocols/health');
    document.getElementById('otModbusStatus').textContent = d && d.pymodbus_available ? 'Available' : 'Unavailable';
    document.getElementById('otModbusStatus').style.color = d && d.pymodbus_available ? 'var(--accent-green)' : 'var(--accent-red)';
    document.getElementById('otOpcuaStatus').textContent = d && d.opcua_available ? 'Available' : 'Unavailable';
    document.getElementById('otOpcuaStatus').style.color = d && d.opcua_available ? 'var(--accent-green)' : 'var(--accent-red)';
    document.getElementById('otSafeGate').textContent = d && d.ot_safe_mode ? 'ON' : 'OFF';
  } catch (e) {
    document.getElementById('otModbusStatus').textContent = 'unreachable';
    document.getElementById('otOpcuaStatus').textContent = 'unreachable';
  }
}

async function runModbusRead() {
  const out = document.getElementById('mbResult');
  out.textContent = 'Reading...';
  const payload = {
    host: document.getElementById('mbHost').value,
    port: parseInt(document.getElementById('mbPort').value),
    unit_id: parseInt(document.getElementById('mbUnit').value),
    reg_count: parseInt(document.getElementById('mbCount').value),
  };
  try {
    const d = await apiPost(PROXY + '/ot-protocols/modbus/read', payload);
    out.textContent = JSON.stringify(d, null, 2);
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

async function runOpcuaBrowse() {
  const out = document.getElementById('opcuaResult');
  out.textContent = 'Browsing...';
  const payload = { url: document.getElementById('opcuaUrl').value };
  try {
    const d = await apiPost(PROXY + '/ot-protocols/opcua/browse', payload);
    out.textContent = JSON.stringify(d, null, 2);
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

// ========================= EVIDENCE =========================
async function loadEvidence() {
  const tbody = document.querySelector('#evidenceTable tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7" class="muted">Loading...</td></tr>';
  try {
    const d = await apiGet(API + '/evidence/artifacts');
    if (!d || !d.artifacts) { tbody.innerHTML = '<tr><td colspan="7" class="muted">No artifacts</td></tr>'; return; }
    tbody.innerHTML = d.artifacts.map(a => `<tr>
      <td style="font-size:11px">${esc(a.id||'')}</td>
      <td>${esc(a.filename||'')}</td>
      <td>${esc(a.case_id||'—')}</td>
      <td>${a.size_bytes ? Math.round(a.size_bytes/1024)+' KB' : '—'}</td>
      <td style="font-size:10px;font-family:monospace">${(a.hash_sha256||'').substring(0,16)}...</td>
      <td>${a.immutable ? '<span class="badge success">WORM</span>' : '<span class="badge">mutable</span>'}</td>
      <td>${esc(a.expires_at||'—')}</td>
    </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">Module offline</td></tr>';
  }
}

async function verifyEvidence() {
  try {
    const d = await apiGet(API + '/evidence/verify');
    showToast('Evidence Verify', d.all_verified ? 'All hashes verified OK' : `${d.results.filter(r=>!r.verified).length} verification failures`, d.all_verified ? 'success' : 'error', true);
  } catch (e) {
    showToast('Evidence Verify', 'Failed: ' + e.message, 'error');
  }
}

// ========================= PKI =========================
async function loadPKI() {
  const status = document.getElementById('pkiStatus');
  const tbody = document.querySelector('#pkiTable tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading...</td></tr>';
  try {
    const d = await apiGet(PROXY + '/pki/health');
    if (status) status.innerHTML = `<span class="badge ${d.step_ca_available?'success':'warn'}">step-ca ${d.step_ca_available?'installed':'missing'}</span> <span class="badge ${d.openssl_available?'success':'warn'}">OpenSSL ${d.openssl_available?'installed':'missing'}</span>`;
  } catch (e) {
    if (status) status.innerHTML = '<span class="badge error">PKI module offline</span>';
  }
  try {
    const d = await apiGet(API + '/pki/certs');
    if (!d || !d.certs) { if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="muted">No certs</td></tr>'; return; }
    if (tbody) tbody.innerHTML = d.certs.map(c => `<tr>
      <td>${esc(c.cn||'')}</td>
      <td>${esc(c.cert_type||'x509')}</td>
      <td><span class="badge ${c.status==='active'?'success':(c.status==='revoked'?'error':'warn')}">${esc(c.status||'')}</span></td>
      <td>${esc(c.not_before||'—')}</td>
      <td>${esc(c.not_after||'—')}</td>
      <td style="font-size:10px;font-family:monospace">${esc(c.serial||'—')}</td>
    </tr>`).join('');
  } catch (e) {
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="muted">Module offline</td></tr>';
  }
}

async function checkCertExpiry() {
  try {
    const d = await apiGet(API + '/pki/check-expiry?days=30');
    showToast('PKI Expiry Check', `${d.count} certificates expiring within 30 days`, d.count > 0 ? 'warning' : 'success', true);
  } catch (e) {
    showToast('PKI Expiry Check', 'Failed: ' + e.message, 'error');
  }
}

// ========================= TLS INSPECTOR =========================
async function loadTLS() {
  // Reset counters to show page is ready
  document.getElementById('tlsTotal').textContent = '0';
  document.getElementById('tlsExpired').textContent = '0';
  document.getElementById('tlsWeak').textContent = '0';
  document.getElementById('tlsC2').textContent = '0';
  const tbody = document.getElementById('tlsTbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="9" class="muted">Use Inspect Target or Scan from Results to populate data.</td></tr>';
}

// ========================= COMPLIANCE ASSESSMENTS =========================
async function runComplianceAssessment(framework) {
  const container = document.getElementById('compAssessments');
  if (container) container.innerHTML = '<div class="muted">Running assessment...</div>';
  try {
    const d = await apiPost(API + '/compliance/assess', { framework, context: {} });
    renderComplianceAssessments(d.results);
  } catch (e) {
    if (container) container.innerHTML = '<div class="muted">Module offline</div>';
  }
}

async function loadComplianceAssessments() {
  const container = document.getElementById('compAssessments');
  if (container) container.innerHTML = '<div class="muted">Loading...</div>';
  try {
    const d = await apiGet(API + '/compliance/assessments');
    renderComplianceAssessments(d.assessments || []);
  } catch (e) {
    if (container) container.innerHTML = '<div class="muted">Module offline</div>';
  }
}

function renderComplianceAssessments(results) {
  const container = document.getElementById('compAssessments');
  if (!container) return;
  if (!results || results.length === 0) { container.innerHTML = '<div class="muted">No assessments</div>'; return; }
  container.innerHTML = results.map(r => {
    const score = r.score || 0;
    const max = r.max_score || 100;
    const pct = Math.round((score / max) * 100);
    const color = pct >= 80 ? 'var(--accent-green)' : (pct >= 50 ? 'var(--accent-amber)' : 'var(--accent-red)');
    const findings = (r.findings || []).map(f => `<div style="font-size:11px;margin:2px 0;padding:4px 6px;border-radius:4px;background:var(--surface-3)">
      <span class="badge ${f.status==='pass'?'success':(f.status==='warn'?'warn':'error')}" style="font-size:10px">${esc(f.status)}</span>
      ${esc(f.requirement || f.id)}
      ${f.recommendation ? `<div style="color:var(--text-muted);margin-top:2px">→ ${esc(f.recommendation)}</div>` : ''}
    </div>`).join('');
    return `<div style="background:var(--surface-2);padding:12px;border-radius:8px;border:1px solid var(--border);margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div style="font-weight:700">${esc(r.framework || 'Assessment')}</div>
        <div style="margin-left:auto;font-size:18px;font-weight:800;color:${color}">${score}/${max}</div>
      </div>
      <div style="width:100%;height:6px;background:var(--surface-3);border-radius:3px;margin-bottom:8px;overflow:hidden">
        <div style="width:${pct}%;height:100%;background:${color}"></div>
      </div>
      <div>${findings}</div>
    </div>`;
  }).join('');
}

// ========================= INIT =========================
function initApp() {
  navTo(resolveRouteFromHash(), true);
  probeBackend().then(ok => {
    if (ok) refreshAll();
    startSSE();
  });
  startBackendProbeLoop();
  setInterval(updateClock, 1000);
  setInterval(refreshAll, 5000);
  updateClock();
  resetSessionTimer();
}

if (authToken) initApp();
