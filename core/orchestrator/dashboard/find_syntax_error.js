const fs = require('fs');
const js = fs.readFileSync('js/app.js', 'utf8');

function checkSyntax(code) {
  try {
    new Function(code);
    return true;
  } catch(e) {
    return false;
  }
}

// Binary search per trovare la riga dell'errore
let lines = js.split('\n');
let low = 0;
let high = lines.length;

while (low < high) {
  const mid = Math.floor((low + high) / 2);
  const testCode = lines.slice(0, mid + 1).join('\n');
  if (checkSyntax(testCode)) {
    low = mid + 1;
  } else {
    high = mid;
  }
}

console.log('Errore di sintassi intorno alla riga: ' + (low + 1));
const start = Math.max(0, low - 5);
const end = Math.min(lines.length, low + 5);
for (let i = start; i < end; i++) {
  console.log((i+1) + ': ' + lines[i]);
}
