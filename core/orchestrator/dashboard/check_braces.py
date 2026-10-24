import sys

with open('js/app.js', 'r', encoding='utf-8') as f:
    text = f.read()

# Stato: 0=normale, 1=stringa doppia, 2=stringa singola, 3=template literal, 4=commento linea, 5=commento blocco
state = 0
stack = []
line = 1
col = 0
error_pos = None

i = 0
while i < len(text):
    ch = text[i]
    if ch == '\n':
        line += 1
        col = 0
    else:
        col += 1
    
    if state == 4:  # commento linea
        if ch == '\n':
            state = 0
        i += 1
        continue
    
    if state == 5:  # commento blocco
        if ch == '*' and i+1 < len(text) and text[i+1] == '/':
            state = 0
            i += 2
            continue
        i += 1
        continue
    
    if state == 1:  # stringa doppia
        if ch == chr(92) and i+1 < len(text):
            i += 2
            continue
        if ch == '"':
            state = 0
        i += 1
        continue
    
    if state == 2:  # stringa singola
        if ch == chr(92) and i+1 < len(text):
            i += 2
            continue
        if ch == "'":
            state = 0
        i += 1
        continue
    
    if state == 3:  # template literal
        if ch == chr(92) and i+1 < len(text):
            i += 2
            continue
        if ch == '`':
            state = 0
        # ${} dentro template literal - per semplicità ignoriamo i bilanciamenti qui
        i += 1
        continue
    
    # stato normale
    if ch == '/' and i+1 < len(text):
        if text[i+1] == '/':
            state = 4
            i += 2
            continue
        if text[i+1] == '*':
            state = 5
            i += 2
            continue
    
    if ch == '"':
        state = 1
        i += 1
        continue
    if ch == "'":
        state = 2
        i += 1
        continue
    if ch == '`':
        state = 3
        i += 1
        continue
    
    if ch in '([{':
        stack.append((ch, line, col))
    elif ch in ')]}':
        expected = {'(': ')', '[': ']', '{': '{'}[ch] if False else None
        # mappa corretta
        pairs = {'(': ')', '[': ']', '{': '}'}
        if not stack:
            error_pos = (line, col, ch, 'extra closing')
            break
        last, ll, lc = stack.pop()
        if pairs[last] != ch:
            error_pos = (line, col, ch, 'mismatch with ' + last + ' at ' + str(ll) + ':' + str(lc))
            break
    
    i += 1

if error_pos:
    print('ERRORE DI BILANCIAMENTO a riga ' + str(error_pos[0]) + ', col ' + str(error_pos[1]) + ': ' + str(error_pos[2]) + ' (' + error_pos[3] + ')')
elif stack:
    print('PARENTESI/GRAFFE NON CHIUSE:')
    for item in stack:
        print('  ' + item[0] + ' aperta a riga ' + str(item[1]) + ':' + str(item[2]))
else:
    print('TUTTE LE PARENTESI E GRAFFE SONO BILANCIATE')
