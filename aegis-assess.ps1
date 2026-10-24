# Cybersecurity-AEGIS — wrapper per l'assessment di reti industriali.
#
# Esempi:
#   .\aegis-assess.ps1 preflight
#   .\aegis-assess.ps1 selftest --out reports\demo
#   .\aegis-assess.ps1 assess --site "Linea 2" --auth-ref "WO-2026-014" `
#       --target 192.168.10.0/24 --pcap C:\capture\linea2.pcapng --out reports\linea2
#
# Non invia nulla in rete in modalita' passive. Per lo scan read-only serve
# autorizzazione scritta del proprietario dell'impianto.

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleDir = Join-Path $root "modules\industrial"

if (-not (Test-Path $moduleDir)) {
    Write-Host "[XX] Directory modulo non trovata: $moduleDir" -ForegroundColor Red
    exit 1
}

Push-Location $moduleDir
try {
    & python -m site_assessment @CliArgs
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $code
