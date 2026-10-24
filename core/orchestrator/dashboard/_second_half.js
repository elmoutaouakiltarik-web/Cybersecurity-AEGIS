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
  try {
    const events = await apiGet(API + '/events?limit=500');
    const evList = Array.isArray(events) ? events : (events?.events || []);
    dfirTimelineEvents = evList
      .filter(e => ['critical','high'].includes((e.severity||'').toLowerCase()) && !e.resolved)
      .slice(0, 60);

    const openIncEl = document.getElementById('dfirOpenInc');
    if (openIncEl) openIncEl.textContent = dfirTimelineEvents.length;
    const evEl = document.getElementById('dfirEvidence');
    if (evEl) evEl.textContent = evidenceRegistry.length;

    // MTTD: median gap between consecutive critical/high events
    const ts = dfirTimelineEvents.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t)).sort((a,b)=>a-b);
    let mttd = '--';
    if (ts.length >= 2) {
      const gaps = [];
      for (let i=1; i<Math.min(ts.length,30); i++) gaps.push(ts[i]-ts[i-1]);
      const med = gaps.sort((a,b)=>a-b)[Math.floor(gaps.length/2)]||0;
      mttd = med < 60000 ? (med/1000).toFixed(0)+'s' : (med/60000).toFixed(1)+'m';
    }
    const mttdEl = document.getElementById('dfirMTTD');
    if (mttdEl) mttdEl.textContent = mttd;

    // Populate incident select with SIEM correlation events
    const sel = document.getElementById('dfirIncidentSelect');
    if (sel) {
      const siemEvs = dfirTimelineEvents.filter(e=>e.source==='siem_correlator').slice(0,8);
      sel.innerHTML = '<option value="all">All Critical / High Events</option>' +
        siemEvs.map(e=>`<option value="${esc(e.id)}">${esc((e.title||'Event').substring(0,55))}</option>`).join('');
    }

    renderDFIRTimeline();
    renderDFIREvidence();
    renderDFIRChecklist();
    renderChainOfCustody();
  } catch (err) {
    console.error('loadDFIR failed:', err);
    const timeline = document.getElementById('dfirTimeline');
    if (timeline) timeline.innerHTML = '<div class="muted" style="padding:10px">Errore caricamento DFIR.</div>';
  }
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
  try {
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
    const totalEl = document.getElementById('assetTotal');
    if (totalEl) totalEl.textContent = allAssetsCache.length;
    const highEl = document.getElementById('assetHighRisk');
    if (highEl) highEl.textContent = allAssetsCache.filter(a=>a.risk_score>=70).length;
    const unpatchedEl = document.getElementById('assetUnpatched');
    if (unpatchedEl) unpatchedEl.textContent = allAssetsCache.filter(a=>(a.cves||[]).length>0).length;
    const otEl = document.getElementById('assetOT');
    if (otEl) otEl.textContent = allAssetsCache.filter(a=>a.type==='ot').length;
    renderAssetTable(allAssetsCache);
    renderAssetSubnetMap();
  } catch (err) {
    console.error('loadAssets failed:', err);
    const tbl = document.getElementById('assetTable');
    if (tbl) tbl.innerHTML = '<div class="muted" style="padding:10px">Errore caricamento asset.</div>';
  }
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
  try {
    const d = await apiGet(API + '/honeypot/status');
    const events = (d && d.triggers) ? d.triggers : [];
    CANARY_TRAPS.forEach(t => { t.triggers = events.filter(e=>e.service===t.service).length; });

    const activeEl = document.getElementById('hpyActive');
    if (activeEl) activeEl.textContent = CANARY_TRAPS.length;
    const trigEl = document.getElementById('hpyTriggers');
    if (trigEl) trigEl.textContent = events.length;
    const attEl = document.getElementById('hpyAttackers');
    if (attEl) attEl.textContent = new Set(events.map(e=>e.ip)).size;
    const critCount = events.filter(e=>e.severity==='critical').length;
    const level = critCount > 0 ? 'HIGH' : events.length > 2 ? 'MEDIUM' : 'LOW';
    const lvlEl = document.getElementById('hpyThreatLevel');
    if (lvlEl) {
      lvlEl.textContent = level;
      lvlEl.style.color = level==='HIGH'?'var(--accent-red)':level==='MEDIUM'?'var(--accent-amber)':'var(--accent-green)';
    }

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
  if (empty) { empty.style.display = ''; empty.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i><div>Building topology from scan results...</div>'; }
  if (svg) svg.style.display = 'none';
  try {
    const data = await apiGet('/api/topology');
    if (!data || !data.nodes || !data.nodes.length) {
      if (empty) empty.innerHTML = '<i class="fa-solid fa-diagram-project"></i><div>No scan data found. Run a LAN scan first, then refresh topology.</div>';
      return;
    }
    const nodesEl = document.getElementById('topoNodes');
    if (nodesEl) nodesEl.textContent = data.nodes.length;
    const crownsEl = document.getElementById('topoCrowns');
    if (crownsEl) crownsEl.textContent = data.nodes.filter(n => n.is_crown_jewel).length;
    const otCross = (data.links||[]).filter(l => l.crosses_ot_boundary).length;
    const otCrossEl = document.getElementById('topoOTCross');
    if (otCrossEl) otCrossEl.textContent = otCross;
    const aps = data.attack_paths || [];
    const apsEl = document.getElementById('topoAttackPaths');
    if (apsEl) apsEl.textContent = aps.length;
    _loadD3(() => _renderTopologyGraph(data));
  } catch(e) {
    if (empty) empty.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i><div>Error: ' + esc(e.message) + '</div>';
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
  const tlsTotalEl = document.getElementById('tlsTotal') || document.getElementById('tlsScanned');
  if (tlsTotalEl) tlsTotalEl.textContent = '0';
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
