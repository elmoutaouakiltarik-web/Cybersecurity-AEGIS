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
