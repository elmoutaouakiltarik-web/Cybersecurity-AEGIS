import re

with open('js/app.js', 'r', encoding='utf-8') as f:
    js_lines = f.readlines()

with open('index.html', 'r', encoding='utf-8') as f:
    html_text = f.read()

html_ids = set(m.group(1) for m in re.finditer(r'id="([^"]+)"', html_text))

load_blocks = {
    'loadDFIR': (2881, 3044),
    'loadAssets': (3048, 3149),
    'loadHoneypot': (3150, 3224),
    'loadReports': (3237, 3427),
    'loadTopology': (3715, 4027),
    'loadTLS': (4312, 4325),
    'loadCampaigns': (4028, 4139),
    'loadIntegrations': (4147, 4172),
    'loadSigma': (4174, 4196),
    'loadOTProtocols': (4198, 4243),
    'loadEvidence': (4245, 4274),
    'loadPKI': (4276, 4310),
}

for name, (start, end) in load_blocks.items():
    print('=== ' + name + ' (js righe ' + str(start) + '-' + str(end) + ') ===')
    block_text = ''.join(js_lines[start-1:end])
    
    ids = set(m.group(1) for m in re.finditer(r"getElementById\(['\"]([^'\"]+)['\"]\)", block_text))
    qs = set(m.group(1) for m in re.finditer(r"querySelector\(['\"](#[^'\"]+)['\"]\)", block_text))
    
    missing = []
    for id in ids:
        if id not in html_ids:
            missing.append("getElementById('" + id + "')")
    for sel in qs:
        # sel include il #, es. #sigmaTable tbody
        base_id = sel[1:].split()[0]  # rimuovi # e prendi la prima parola
        if base_id not in html_ids:
            missing.append("querySelector('" + sel + "')")
    
    if missing:
        print('  MANCANTI:')
        for m in missing:
            print('    - ' + m)
    else:
        print('  TUTTI ESISTONO (' + str(len(ids)) + ' IDs, ' + str(len(qs)) + ' querySelectors)')
