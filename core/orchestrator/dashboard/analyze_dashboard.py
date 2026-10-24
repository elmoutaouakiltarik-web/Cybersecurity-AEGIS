import re, subprocess, os

with open('index.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()
    html_text = ''.join(lines)

html_ids = set(m.group(1) for m in re.finditer(r'id="([^"]+)"', html_text))

blocks = {
    'loadDFIR': (4971, 5123),
    'loadAssets': (5127, 5207),
    'loadHoneypot': (5219, 5281),
    'loadReports': (5294, 5477),
    'loadTopology': (5765, 5936),
    'loadTLS-main': (6356, 6365),
    'loadCampaigns': (6076, 6186),
    'loadIntegrations': (6194, 6219),
    'loadSigma': (6221, 6243),
    'loadOTProtocols': (6245, 6287),
    'loadEvidence': (6289, 6318),
    'loadPKI': (6320, 6354),
}

for name, (start, end) in blocks.items():
    print('=== ' + name + ' (righe ' + str(start) + '-' + str(end) + ') ===')
    block_text = ''.join(lines[start-1:end])
    
    ids = set(m.group(1) for m in re.finditer(r"getElementById\(['\"]([^'\"]+)['\"]\)", block_text))
    qs = set(m.group(1) for m in re.finditer(r"querySelector\(['\"](#[^'\"]+)['\"]\)", block_text))
    
    missing = []
    for id in ids:
        if id not in html_ids:
            missing.append("getElementById('" + id + "')")
    for sel in qs:
        if sel not in html_ids:
            missing.append("querySelector('#" + sel + "')")
    
    if missing:
        print('  MANCANTI:')
        for m in missing:
            print('    - ' + m)
    else:
        print('  TUTTI ESISTONO (' + str(len(ids)) + ' IDs, ' + str(len(qs)) + ' querySelectors)')
    
    with open('_tmp_syntax.js', 'w', encoding='utf-8') as f:
        f.write(block_text)
    try:
        result = subprocess.run(['node', '-e', "try { new Function(require('fs').readFileSync('_tmp_syntax.js','utf8')); console.log('OK'); } catch(e) { console.log('SYNTAX ERROR: ' + e.message); }"], capture_output=True, text=True, timeout=10)
        out = result.stdout.strip()
        if out == 'OK':
            print('  Sintassi JS: OK')
        else:
            print('  Sintassi JS: ' + out)
    except Exception as e:
        print('  Sintassi JS: check fallito (' + str(e) + ')')
    print()

if os.path.exists('_tmp_syntax.js'):
    os.remove('_tmp_syntax.js')
