const fs = require('fs');
const html = fs.readFileSync('index.html', 'utf8');

const htmlIds = new Set();
const idRegex = /id="([^"]+)"/g;
let m;
while ((m = idRegex.exec(html)) !== null) {
  htmlIds.add(m[1]);
}

const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
if (!scriptMatch) {
  console.log('Nessun tag <script> trovato');
  process.exit(1);
}
const js = scriptMatch[1];

console.log('=== VERIFICA SINTASSI JS GLOBALE ===');
try {
  new Function(js);
  console.log('JS globale: SINTASSI VALIDA');
} catch (e) {
  console.log('JS globale: ERRORE DI SINTASSI -> ' + e.message);
  const linesBefore = js.substring(0, e.pos || 0).split('\n').length;
  console.log('Riga approssimativa errore: ' + linesBefore);
}

const funcRegex = /(?:async\s+)?function\s+(\w+)\s*\(/g;
const functions = [];
let fm;
while ((fm = funcRegex.exec(js)) !== null) {
  functions.push({ name: fm[1], index: fm.index });
}

function extractFunctionBody(startIndex) {
  let i = startIndex;
  while (i < js.length && js[i] !== '{') i++;
  if (i >= js.length) return '';
  let brace = 1;
  i++;
  const start = i;
  while (i < js.length && brace > 0) {
    if (js[i] === '/' && js[i+1] === '/') {
      while (i < js.length && js[i] !== '\n') i++;
      continue;
    }
    if (js[i] === '/' && js[i+1] === '*') {
      i += 2;
      while (i < js.length && !(js[i] === '*' && js[i+1] === '/')) i++;
      i += 2;
      continue;
    }
    if (js[i] === '`') {
      i++;
      while (i < js.length && js[i] !== '`') {
        if (js[i] === '\') i += 2; else i++;
      }
      i++;
      continue;
    }
    if (js[i] === '"' || js[i] === "'") {
      const quote = js[i];
      i++;
      while (i < js.length && js[i] !== quote) {
        if (js[i] === '\') i += 2; else i++;
      }
      i++;
      continue;
    }
    if (js[i] === '{') brace++;
    if (js[i] === '}') brace--;
    i++;
  }
  return js.substring(start, i - 1);
}

const loadFunctions = {
  'loadDFIR': ['loadDFIR','renderDFIRTimeline','renderDFIREvidence','renderDFIRChecklist','renderChainOfCustody','updateDFIRProgress','addEvidenceItem','removeEvidence','exportDFIRTimeline','resetDFIRChecklist'],
  'loadAssets': ['loadAssets','filterAssets','renderAssetTable','renderAssetSubnetMap'],
  'loadHoneypot': ['loadHoneypot'],
  'loadReports': ['loadReports','loadReportList','downloadReport','previewReport','runFullPipelineReport','generateReport','_buildReportHTML','renderReportHistory'],
  'loadTopology': ['loadTopology','_renderTopologyGraph','_showTopoTooltip','_hideTopoTooltip','loadAttackPaths'],
  'loadTLS': ['loadTLS','tlsSingleInspect','doTLSInspect','tlsScanFromResults','_renderTLSTable','_showTLSDetail'],
  'loadCampaigns': ['loadCampaigns','_renderCampaigns','_renderCampaignCard'],
  'loadIntegrations': ['loadIntegrations'],
  'loadSigma': ['loadSigma'],
  'loadOTProtocols': ['loadOTProtocols','runModbusRead','runOpcuaBrowse'],
  'loadEvidence': ['loadEvidence','verifyEvidence'],
  'loadPKI': ['loadPKI','checkCertExpiry']
};

const funcMap = {};
for (const f of functions) {
  if (!funcMap[f.name]) funcMap[f.name] = f.index;
}

console.log('\n=== ANALISI DOM ID PER PAGINA ===\n');

for (const [pageName, funcNames] of Object.entries(loadFunctions)) {
  console.log('--- PAGINA: ' + pageName + ' ---');
  const allIds = new Set();
  const allQuerySelectors = new Set();
  let syntaxError = null;
  
  for (const fn of funcNames) {
    if (!funcMap[fn]) {
      console.log('  FUNZIONE MANCANTE: ' + fn);
      continue;
    }
    const body = extractFunctionBody(funcMap[fn]);
    try {
      new Function(body);
    } catch (e) {
      if (!syntaxError) syntaxError = { fn: fn, msg: e.message };
    }
    const idMatches = body.match(/getElementById\(['"]([^'"]+)['"]\)/g);
    if (idMatches) {
      idMatches.forEach(match => {
        const id = match.replace(/getElementById\(['"]/, '').replace(/['"]\)/, '');
        allIds.add(id);
      });
    }
    const qsMatches = body.match(/querySelector\(['"](#[^'"]+)['"]\)/g);
    if (qsMatches) {
      qsMatches.forEach(match => {
        const sel = match.replace(/querySelector\(['"]/, '').replace(/['"]\)/, '');
        allQuerySelectors.add(sel);
      });
    }
  }
  
  if (syntaxError) {
    console.log('  ERRORE SINTASSI in ' + syntaxError.fn + ': ' + syntaxError.msg);
  } else {
    console.log('  Sintassi: OK');
  }
  
  const missingIds = [];
  for (const id of allIds) {
    if (!htmlIds.has(id)) missingIds.push(id);
  }
  const missingSelectors = [];
  for (const sel of allQuerySelectors) {
    const id = sel.substring(1);
    if (!htmlIds.has(id)) missingSelectors.push(sel);
  }
  
  if (missingIds.length === 0 && missingSelectors.length === 0) {
    console.log('  DOM IDs: TUTTI ESISTONO (' + allIds.size + ' IDs, ' + allQuerySelectors.size + ' querySelectors)');
  } else {
    if (missingIds.length) console.log('  DOM IDs MANCANTI: ' + missingIds.join(', '));
    if (missingSelectors.length) console.log('  querySelectors MANCANTI: ' + missingSelectors.join(', '));
  }
}

console.log('\n=== VERIFICA navTo ===');
const navToMatch = js.match(/function navTo\([^)]*\)\s*\{/);
if (navToMatch) {
  const navBody = extractFunctionBody(navToMatch.index);
  for (const page of Object.keys(loadFunctions)) {
    const targetMap = {
      'loadDFIR': 'dfir',
      'loadAssets': 'assets',
      'loadHoneypot': 'honeypot',
      'loadReports': 'reports',
      'loadTopology': 'topology',
      'loadTLS': 'tls',
      'loadCampaigns': 'campaigns',
      'loadIntegrations': 'integrations',
      'loadSigma': 'sigma',
      'loadOTProtocols': 'ot-protocols',
      'loadEvidence': 'evidence',
      'loadPKI': 'pki'
    };
    const t = targetMap[page];
    const loadFn = page;
    const hasLoadCall = navBody.includes(loadFn + '()');
    if (hasLoadCall) {
      console.log('  navTo -> ' + t + ' chiama ' + loadFn + '(): OK');
    } else {
      console.log('  navTo -> ' + t + ' NON CHIAMA ' + loadFn + '(): PROBLEMA');
    }
  }
}
