#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Avvia il modulo Endpoint Protection nativo su questo host Windows.

.DESCRIPTION
    Il modulo Endpoint Protection legge stato reale di Defender, Firewall,
    BitLocker, account, autorun, processi, porte, ecc. usando PowerShell.
    Deve girare NATIVO (non in Docker) perché richiede accesso diretto al
    sistema operativo. Si registra all'orchestrator AEGIS via /api/v1/ingest.

    Esegui questo script DOPO aver avviato lo stack Docker con aegis-docker.ps1.

.PARAMETER Port
    Porta TCP locale (default 8088).

.PARAMETER Admin
    Forza la richiesta dei privilegi di amministratore (necessari per alcuni
    check come Get-MpComputerStatus, Get-LocalUser dettagliato, processi
    di altri utenti).

.PARAMETER NoIngest
    Disabilita l'invio dei findings all'orchestrator.

.EXAMPLE
    .\aegis-endpoint.ps1                # avvia su 127.0.0.1:8088
    .\aegis-endpoint.ps1 -Admin          # elevazione UAC
    .\aegis-endpoint.ps1 -Port 9088      # porta diversa
#>
[CmdletBinding()]
param(
    [int]$Port = 8088,
    [switch]$Admin,
    [switch]$NoIngest,
    [string]$OrchestratorUrl = "http://127.0.0.1:8070"
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$ROOT      = $PSScriptRoot
$MODULE    = Join-Path $ROOT "modules\endpoint"
$LOGS_DIR  = Join-Path $ROOT "logs"
$LOG_FILE  = Join-Path $LOGS_DIR "endpoint.log"

function Step($m) { Write-Host "  >> $m" -ForegroundColor Yellow }
function OK($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!!] $m" -ForegroundColor DarkYellow }
function Err($m)  { Write-Host "  [XX] $m" -ForegroundColor Red }

Write-Host ""
Write-Host "═══ AEGIS Endpoint Protection — native launcher ═══" -ForegroundColor Cyan
Write-Host "  Module: $MODULE" -ForegroundColor DarkGray
Write-Host "  Port:   $Port" -ForegroundColor DarkGray
Write-Host ""

# ── Self-elevate when -Admin ───────────────────────────────────────────────
if ($Admin) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        Step "Elevazione UAC necessaria — riavvio come amministratore..."
        $cmd = "& '$($MyInvocation.MyCommand.Path)' -Port $Port -OrchestratorUrl '$OrchestratorUrl'"
        if ($NoIngest) { $cmd += " -NoIngest" }
        Start-Process pwsh -Verb RunAs -ArgumentList "-NoExit", "-Command", $cmd
        exit 0
    } else {
        OK "Privilegi amministratore confermati"
    }
} else {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        Warn "Non sei amministratore — alcuni check (Defender state, updates, processi altri utenti) restituiranno 'not available'"
        Warn "Per un audit completo: .\aegis-endpoint.ps1 -Admin"
    } else {
        OK "Privilegi amministratore confermati"
    }
}

# ── Python check ───────────────────────────────────────────────────────────
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $py) {
    Err "Python non trovato. Installa Python 3.10+ da https://python.org"
    exit 1
}
OK ("Python: " + (& python --version 2>&1))

# ── Install deps ───────────────────────────────────────────────────────────
Step "Verifica dipendenze Python..."
$req = Join-Path $MODULE "requirements.txt"
& python -m pip install --quiet --disable-pip-version-check -r $req 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Warn "Alcune dipendenze potrebbero non essersi installate (yara-python necessita Visual C++ Build Tools su Windows)"
    Warn "Provo a installarle singolarmente in modalità non-bloccante..."
    & python -m pip install --quiet --disable-pip-version-check flask requests pyyaml psutil 2>&1 | Out-Null
    & python -m pip install --quiet --disable-pip-version-check yara-python 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Warn "yara-python non installato — il modulo girerà senza YARA. Per abilitarlo: 'pip install yara-python' dopo aver installato Visual C++ Build Tools."
    }
}
OK "Dipendenze pronte"

# ── Logs dir ────────────────────────────────────────────────────────────────
if (-not (Test-Path $LOGS_DIR)) { New-Item -ItemType Directory -Path $LOGS_DIR -Force | Out-Null }

# ── Port already in use? ───────────────────────────────────────────────────
$conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    Err "Porta $Port già in uso da PID $($conn[0].OwningProcess). Termina il processo o usa -Port <altra>."
    exit 1
}

# ── Env ────────────────────────────────────────────────────────────────────
$env:ENDPOINT_API_PORT  = $Port
$env:ENDPOINT_BIND_HOST = "0.0.0.0"   # bound to all interfaces so containers can reach it via host-gateway
$env:ORCHESTRATOR_URL   = $OrchestratorUrl
$env:ENDPOINT_INGEST    = if ($NoIngest) { "0" } else { "1" }
$env:AEGIS_LOG_LEVEL    = "INFO"

# YARA rules dir auto-discovery
$yaraDir = Join-Path $ROOT "modules\intelligence\yara\rules"
if (Test-Path $yaraDir) {
    $env:YARA_RULES_DIR = $yaraDir
    OK "YARA rules dir: $yaraDir"
} else {
    Warn "YARA rules dir non trovato: $yaraDir"
}

Step "Avvio Endpoint Protection (porta $Port, ingest=$($env:ENDPOINT_INGEST))..."
Write-Host ""
Write-Host "  Log file:  $LOG_FILE" -ForegroundColor DarkGray
Write-Host "  Endpoints: http://127.0.0.1:$Port/health" -ForegroundColor DarkGray
Write-Host "             http://127.0.0.1:$Port/audit" -ForegroundColor DarkGray
Write-Host "             http://127.0.0.1:$Port/defender" -ForegroundColor DarkGray
Write-Host "             http://127.0.0.1:$Port/firewall" -ForegroundColor DarkGray
Write-Host "             http://127.0.0.1:$Port/processes" -ForegroundColor DarkGray
Write-Host "             ..." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Premi Ctrl+C per terminare." -ForegroundColor Yellow
Write-Host ""

# ── Run app.py ─────────────────────────────────────────────────────────────
Push-Location $MODULE
try {
    & python app.py 2>&1 | Tee-Object -FilePath $LOG_FILE -Append
} finally {
    Pop-Location
}

