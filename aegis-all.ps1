#!/usr/bin/env pwsh
<#
.SYNOPSIS
    AEGIS-OMNI — Launcher unificato (no Docker).

.DESCRIPTION
    Avvia in sequenza:
      1) Go orchestrator              (porta 8070)
      2) Python endpoint module       (porta 8088, host telemetry)
      3) Python network module        (porta 8081, LAN scan / TLS / topology / fusion)
      4) Python vuln module           (porta 8085, CVE lookup)
      5) Python threat-intel module   (porta 8084, IOC lookup)
      6) Python reports module        (porta 8086, HTML/JSON report)

    Esegue health check, apre il browser sulla dashboard, e stampa
    credenziali + tabella riepilogativa.

    Per stoppare tutto: .\aegis-all.ps1 -Stop

.PARAMETER Stop
    Ferma tutti i processi avviati da questo script.

.PARAMETER NoBrowser
    Non apre il browser.

.PARAMETER Admin
    Self-eleva per audit Defender + processes completi.

.EXAMPLE
    .\aegis-all.ps1                  # avvia tutto
    .\aegis-all.ps1 -Admin           # con privilegi admin
    .\aegis-all.ps1 -Stop            # ferma tutto
#>
[CmdletBinding()]
param(
    [switch]$Stop,
    [switch]$NoBrowser,
    [switch]$Admin,
    [switch]$SkipPythonDeps,
    [string]$AdminPassword = ""
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$ROOT      = $PSScriptRoot
$LOGS_DIR  = Join-Path $ROOT "logs"
$DASH_URL  = "http://127.0.0.1:8070/dashboard/"
$PID_FILE  = Join-Path $LOGS_DIR "aegis-all.pids.json"

function Banner {
    Write-Host ""
    Write-Host "  █████╗ ███████╗ ██████╗ ██╗███████╗" -ForegroundColor Cyan
    Write-Host " ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝" -ForegroundColor Cyan
    Write-Host " ███████║█████╗  ██║  ███╗██║███████╗" -ForegroundColor Cyan
    Write-Host " ██╔══██║██╔══╝  ██║   ██║██║╚════██║" -ForegroundColor Cyan
    Write-Host " ██║  ██║███████╗╚██████╔╝██║███████║" -ForegroundColor Cyan
    Write-Host " ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝" -ForegroundColor Cyan
    Write-Host "  OMNI — Personal Cybersecurity Suite" -ForegroundColor White
    Write-Host ""
}
function Step($m) { Write-Host "  >> $m" -ForegroundColor Yellow }
function OK($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!!] $m" -ForegroundColor DarkYellow }
function Err($m)  { Write-Host "  [XX] $m" -ForegroundColor Red }

function Ensure-PythonDeps {
    if ($SkipPythonDeps) {
        Warn "Verifica dipendenze Python saltata (-SkipPythonDeps)."
        return
    }
    Step "Verifica dipendenze Python minime..."
    $testCode = @"
import importlib.util
mods = [
    "flask","flask_cors","requests","yaml","psutil",
    "pydantic","uvicorn","numpy","pandas","sklearn","joblib"
]
missing = [m for m in mods if importlib.util.find_spec(m) is None]
print(" ".join(missing))
"@
    $missing = ""
    try {
        $missing = (& python -c $testCode 2>$null).Trim()
    } catch {
        $missing = "flask flask-cors requests pyyaml psutil pydantic uvicorn numpy pandas scikit-learn joblib"
    }
    if ([string]::IsNullOrWhiteSpace($missing)) {
        OK "Dipendenze Python OK."
        return
    }
    Warn "Dipendenze mancanti rilevate: $missing"
    Step "Installo/aggiorno dipendenze Python..."
    $pkgs = @(
        "flask>=2.3",
        "flask-cors>=4.0",
        "requests>=2.31",
        "PyYAML>=6.0",
        "psutil>=5.9",
        "pydantic>=2.4",
        "uvicorn[standard]>=0.34",
        "numpy>=1.26",
        "pandas>=2.2",
        "scikit-learn>=1.4",
        "joblib>=1.4",
        "pymodbus>=3.5",
        "waitress>=3.0"
    )
    & python -m pip install --disable-pip-version-check --upgrade $pkgs | Out-Null
    if ($LASTEXITCODE -eq 0) {
        OK "Dipendenze Python aggiornate."
    } else {
        Warn "Install dipendenze ha restituito errore; continuo comunque. Controlla logs e pip."
    }
}

function Ensure-OrchestratorBuilt {
    $coreDir = Join-Path $ROOT "core\orchestrator"
    $exePath = Join-Path $coreDir "orchestrator.exe"
    $go = Get-Command go -ErrorAction SilentlyContinue

    if (-not $go) {
        if (Test-Path $exePath) {
            Warn "Go non trovato: uso orchestrator.exe precompilato."
            return
        }
        throw "Go non trovato e orchestrator.exe assente: impossibile avviare."
    }

    $needsBuild = -not (Test-Path $exePath)
    if (-not $needsBuild) {
        $exeTime = (Get-Item $exePath).LastWriteTimeUtc
        $newerGo = Get-ChildItem -Path $coreDir -Filter *.go -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -gt $exeTime }
        $dashboardDir = Join-Path $coreDir "dashboard"
        $newerDashboard = Get-ChildItem -Path $dashboardDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTimeUtc -gt $exeTime }
        if ($newerGo -or $newerDashboard) { $needsBuild = $true }
    }

    if (-not $needsBuild) {
        OK "orchestrator.exe aggiornato."
        return
    }

    Step "Compilo orchestrator.exe (Go)..."
    Push-Location $coreDir
    try {
        & go build -ldflags="-s -w" -o orchestrator.exe . | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "go build fallito (exit $LASTEXITCODE)"
        }
        OK "orchestrator.exe compilato con successo."
    } finally {
        Pop-Location
    }
}

Banner

# ── Stop mode ────────────────────────────────────────────────────────────
if ($Stop) {
    Step "Arresto stack AEGIS..."
    $killed = 0
    if (Test-Path $PID_FILE) {
        $pids = Get-Content $PID_FILE -Raw | ConvertFrom-Json
        foreach ($p in $pids) {
            try {
                Stop-Process -Id $p.pid -Force -ErrorAction SilentlyContinue
                Write-Host "    Stopped $($p.name) (PID $($p.pid))" -ForegroundColor DarkGray
                $killed++
            } catch {}
        }
        Remove-Item $PID_FILE -Force
    }
    # Brutal fallback: kill anything on our ports
    foreach ($port in 8080,8081,8082,8083,8084,8085,8086,8087,8088,8090,8091,8092,8093,8094,8095,8096,8919) {
        $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        if ($conn) {
            try { Stop-Process -Id $conn[0].OwningProcess -Force -ErrorAction SilentlyContinue; $killed++ } catch {}
        }
    }
    OK "Stopped $killed processes."
    exit 0
}

# ── Self-elevate if requested ─────────────────────────────────────────────
if ($Admin) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        Step "Self-elevazione UAC..."
        $args = @("-NoExit", "-Command", "& '$($MyInvocation.MyCommand.Path)' -AdminPassword '$AdminPassword'")
        if ($NoBrowser) { $args[-1] += " -NoBrowser" }
        Start-Process pwsh -Verb RunAs -ArgumentList $args
        exit 0
    }
}

if (-not (Test-Path $LOGS_DIR)) { New-Item -ItemType Directory -Path $LOGS_DIR -Force | Out-Null }
Ensure-PythonDeps
Ensure-OrchestratorBuilt

# ── Stop any previous instance ────────────────────────────────────────────
Step "Stop eventuali processi precedenti..."
foreach ($port in 8080,8081,8082,8083,8084,8085,8086,8087,8088,8090,8091,8092,8093,8094,8095,8096,8919) {
    $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        try { Stop-Process -Id $conn[0].OwningProcess -Force -ErrorAction SilentlyContinue } catch {}
    }
}
Start-Sleep -Seconds 1

# ── Track PIDs ────────────────────────────────────────────────────────────
$processes = @()

function Start-Service-Quiet {
    param([string]$Name, [string]$Cmd, [string[]]$CmdArgs, [string]$WorkDir, [hashtable]$Env)
    $logFile = Join-Path $LOGS_DIR ($Name + ".log")
    Set-Content -Path $logFile -Value "[$(Get-Date -Format o)] $Name launching" -Encoding utf8 -ErrorAction SilentlyContinue

    # Use raw System.Diagnostics.ProcessStartInfo WITHOUT redirecting stdout/stderr
    # because Python 3.14 + redirect = REPL crash (WinError 123). CreateNoWindow
    # is enough to hide the console window. Services log to file via their own
    # logging config; we capture stderr only if needed for debugging.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Cmd
    # Quote arguments containing spaces
    if ($CmdArgs -and $CmdArgs.Count -gt 0) {
        $psi.Arguments = ($CmdArgs | ForEach-Object {
            if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
        }) -join ' '
    }
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $false
    $psi.RedirectStandardError  = $false
    $psi.CreateNoWindow = $true

    # Inherit + override env
    $psi.EnvironmentVariables.Clear()
    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        try { $psi.EnvironmentVariables[$e.Key] = $e.Value } catch {}
    }
    $psi.EnvironmentVariables["PYTHONUNBUFFERED"] = "1"
    $psi.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8"
    $psi.EnvironmentVariables["FLASK_ENV"] = "production"
    $psi.EnvironmentVariables["FLASK_DEBUG"] = "0"
    $psi.EnvironmentVariables["WERKZEUG_DEBUG_PIN"] = "off"
    foreach ($kv in $Env.GetEnumerator()) {
        $psi.EnvironmentVariables[$kv.Key] = [string]$kv.Value
    }

    try {
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $null = $proc.Start()
        $script:processes += [pscustomobject]@{ name=$Name; pid=$proc.Id; log=$logFile }
        OK "$Name avviato (PID $($proc.Id)) — log: logs\$Name.log"
        return $proc
    } catch {
        Err "$Name fallito: $($_.Exception.Message)"
        return $null
    }
}

# ── 1) Orchestrator Go ────────────────────────────────────────────────────
Step "Avvio Go orchestrator (porta 8070)..."
$null = Start-Service-Quiet -Name "orchestrator" `
    -Cmd (Join-Path $ROOT "core\orchestrator\orchestrator.exe") `
    -CmdArgs @() `
    -WorkDir (Join-Path $ROOT "core\orchestrator") `
    -Env @{
        AEGIS_AUTH_REQUIRED = 'true'
        AEGIS_ADMIN_PASSWORD = $AdminPassword
        AEGIS_LOG_LEVEL = 'INFO'
        AEGIS_SIGMA_DIR = (Join-Path $ROOT "data\sigma")
        AEGIS_EVIDENCE_DIR = (Join-Path $ROOT "data\evidence")
        AEGIS_PKI_DIR = (Join-Path $ROOT "data\pki")
    }
Start-Sleep -Seconds 2

# ── 2) Endpoint module ────────────────────────────────────────────────────
Step "Avvio endpoint module Python (porta 8088)..."
Remove-Item -Recurse -Force (Join-Path $ROOT "modules\endpoint\__pycache__") -ErrorAction SilentlyContinue
$null = Start-Service-Quiet -Name "endpoint" `
    -Cmd "python" -CmdArgs @("app.py") `
    -WorkDir (Join-Path $ROOT "modules\endpoint") `
    -Env @{
        ENDPOINT_API_PORT = '8088'
        ENDPOINT_BIND_HOST = '127.0.0.1'
        ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
        ENDPOINT_INGEST = '1'
        YARA_RULES_DIR = (Join-Path $ROOT "modules\intelligence\yara\rules")
        AEGIS_LOG_LEVEL = 'INFO'
    }

# ── 3) Network module (LAN scan / TLS / topology / fusion) ────────────────
$networkApp = Join-Path $ROOT "modules\network\app.py"
if (Test-Path $networkApp) {
    Step "Avvio network module Python (porta 8081)..."
    $null = Start-Service-Quiet -Name "network" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\network") `
        -Env @{
            NETWORK_API_PORT = '8081'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            SCAN_MAX_HOSTS = '256'
            SCAN_MAX_CONCURRENT = '3'
            AEGIS_LOG_LEVEL = 'INFO'
        }
} else { Warn "network module non trovato — Topology/TLS/Campaigns mostreranno empty state." }

# ── 4) Vuln module ────────────────────────────────────────────────────────
$vulnApp = Join-Path $ROOT "modules\vuln\app.py"
if (Test-Path $vulnApp) {
    Step "Avvio vuln module Python (porta 8085)..."
    $null = Start-Service-Quiet -Name "vuln" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\vuln") `
        -Env @{
            VULN_API_PORT = '8085'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 5) Threat-intel module ────────────────────────────────────────────────
$tiApp = Join-Path $ROOT "modules\threat_intel\app.py"
if (Test-Path $tiApp) {
    Step "Avvio threat-intel module Python (porta 8084)..."
    $null = Start-Service-Quiet -Name "threat-intel" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\threat_intel") `
        -Env @{
            THREAT_INTEL_API_PORT = '8084'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 6) Reports module ─────────────────────────────────────────────────────
$reportsApp = Join-Path $ROOT "modules\reports\app.py"
if (Test-Path $reportsApp) {
    Step "Avvio reports module Python (porta 8086)..."
    $null = Start-Service-Quiet -Name "reports" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\reports") `
        -Env @{
            REPORTS_API_PORT = '8086'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            REPORTS_DIR = (Join-Path $ROOT "data\reports")
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 7) SIEM Correlator ────────────────────────────────────────────────────
$siemApp = Join-Path $ROOT "modules\siem\app.py"
if (Test-Path $siemApp) {
    Step "Avvio SIEM module Python (porta 8082)..."
    $null = Start-Service-Quiet -Name "siem" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\siem") `
        -Env @{
            SIEM_API_PORT = '8082'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 8) SOAR Executor ──────────────────────────────────────────────────────
$soarApp = Join-Path $ROOT "modules\soar\app.py"
if (Test-Path $soarApp) {
    Step "Avvio SOAR module Python (porta 8083)..."
    $null = Start-Service-Quiet -Name "soar" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\soar") `
        -Env @{
            SOAR_API_PORT = '8083'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 9) OT Monitor ─────────────────────────────────────────────────────────
$otApp = Join-Path $ROOT "modules\industrial\ot_monitor\app.py"
if (Test-Path $otApp) {
    Step "Avvio OT Monitor Python (porta 8087)..."
    $null = Start-Service-Quiet -Name "ot-monitor" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\industrial\ot_monitor") `
        -Env @{
            OT_API_PORT = '8087'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
            OT_SIMULATION_MODE = 'false'
        }
}

# ── 10) DFIR Case Management ──────────────────────────────────────────────
$dfirApp = Join-Path $ROOT "modules\dfir\app.py"
if (Test-Path $dfirApp) {
    Step "Avvio DFIR module Python (porta 8093)..."
    $null = Start-Service-Quiet -Name "dfir" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\dfir") `
        -Env @{
            DFIR_PORT = '8093'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 11) Compliance (GDPR/NIS2/OT) ─────────────────────────────────────────
$compApp = Join-Path $ROOT "modules\compliance\app.py"
if (Test-Path $compApp) {
    Step "Avvio Compliance module Python (porta 8094)..."
    $null = Start-Service-Quiet -Name "compliance" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\compliance") `
        -Env @{
            COMPLIANCE_PORT = '8094'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 12) Integrations module ───────────────────────────────────────────────
$integrationsApp = Join-Path $ROOT "modules\integrations\app.py"
if (Test-Path $integrationsApp) {
    Step "Avvio Integrations module Python (porta 8090)..."
    $null = Start-Service-Quiet -Name "integrations" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\integrations") `
        -Env @{
            INTEGRATIONS_PORT = '8090'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 13) Sigma module ──────────────────────────────────────────────────────
$sigmaApp = Join-Path $ROOT "modules\sigma\app.py"
if (Test-Path $sigmaApp) {
    Step "Avvio Sigma module Python (porta 8091)..."
    $null = Start-Service-Quiet -Name "sigma" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\sigma") `
        -Env @{
            SIGMA_PORT = '8091'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 14) OT Protocols module ───────────────────────────────────────────────
$otProtocolsApp = Join-Path $ROOT "modules\ot_protocols\app.py"
if (Test-Path $otProtocolsApp) {
    Step "Avvio OT Protocols module Python (porta 8092)..."
    $null = Start-Service-Quiet -Name "ot-protocols" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\ot_protocols") `
        -Env @{
            OT_PROTOCOLS_PORT = '8092'
            OT_SAFE_MODE = '1'
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 15) Evidence module ───────────────────────────────────────────────────
$evidenceApp = Join-Path $ROOT "modules\evidence\app.py"
if (Test-Path $evidenceApp) {
    Step "Avvio Evidence module Python (porta 8095)..."
    $null = Start-Service-Quiet -Name "evidence" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\evidence") `
        -Env @{
            EVIDENCE_PORT = '8095'
            EVIDENCE_STORE_DIR = (Join-Path $ROOT "data\evidence")
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 16) PKI module ────────────────────────────────────────────────────────
$pkiApp = Join-Path $ROOT "modules\pki\app.py"
if (Test-Path $pkiApp) {
    Step "Avvio PKI module Python (porta 8096)..."
    $null = Start-Service-Quiet -Name "pki" `
        -Cmd "python" -CmdArgs @("app.py") `
        -WorkDir (Join-Path $ROOT "modules\pki") `
        -Env @{
            PKI_PORT = '8096'
            PKI_DATA_DIR = (Join-Path $ROOT "data\pki")
            ORCHESTRATOR_URL = 'http://127.0.0.1:8070'
            AEGIS_LOG_LEVEL = 'INFO'
        }
}

# ── 17) CyberShield AI (ML) — uvicorn ─────────────────────────────────────
$mlApp = Join-Path $ROOT "modules\ml\cybershield_ai\api\app.py"
if (Test-Path $mlApp) {
    Step "Avvio CyberShield AI (porta 8919)..."
    $null = Start-Service-Quiet -Name "cybershield" `
        -Cmd "python"        -CmdArgs @("-m","uvicorn","api.app:app","--host","127.0.0.1","--port","8919","--log-level","warning") `
        -WorkDir (Join-Path $ROOT "modules\ml\cybershield_ai") `
        -Env @{ AEGIS_LOG_LEVEL = 'INFO' }
}

# ── Save PIDs ─────────────────────────────────────────────────────────────
$processes | ConvertTo-Json | Set-Content -Path $PID_FILE -Encoding UTF8

# ── Health checks ─────────────────────────────────────────────────────────
Write-Host ""
Step "Attendo healthy (max 20s)..."
$probes = @(
    @{ Name='orchestrator'; Url='http://127.0.0.1:8070/health' }
    @{ Name='endpoint';     Url='http://127.0.0.1:8088/health' }
    @{ Name='network';      Url='http://127.0.0.1:8081/health' }
    @{ Name='vuln';         Url='http://127.0.0.1:8085/health' }
    @{ Name='threat-intel'; Url='http://127.0.0.1:8084/health' }
    @{ Name='reports';      Url='http://127.0.0.1:8086/health' }
    @{ Name='siem';         Url='http://127.0.0.1:8082/health' }
    @{ Name='soar';         Url='http://127.0.0.1:8083/health' }
    @{ Name='ot-monitor';   Url='http://127.0.0.1:8087/health' }
    @{ Name='dfir';         Url='http://127.0.0.1:8093/health' }
    @{ Name='compliance';   Url='http://127.0.0.1:8094/health' }
    @{ Name='integrations'; Url='http://127.0.0.1:8090/health' }
    @{ Name='sigma';        Url='http://127.0.0.1:8091/health' }
    @{ Name='ot-protocols'; Url='http://127.0.0.1:8092/health' }
    @{ Name='evidence';     Url='http://127.0.0.1:8095/health' }
    @{ Name='pki';          Url='http://127.0.0.1:8096/health' }
    @{ Name='ml';           Url='http://127.0.0.1:8919/health' }
)
$status = @{}
for ($i = 0; $i -lt 15; $i++) {
    foreach ($pr in $probes) {
        if ($status[$pr.Name]) { continue }
        try {
            $r = Invoke-WebRequest -Uri $pr.Url -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
            if ($r.StatusCode -eq 200) { $status[$pr.Name] = $true }
        } catch {}
    }
    if (($status.Values | Where-Object { $_ }).Count -eq $probes.Count) { break }
    Start-Sleep -Seconds 1
}
foreach ($pr in $probes) {
    if ($status[$pr.Name]) { OK "$($pr.Name) — UP" } else { Warn "$($pr.Name) — DOWN" }
}

# ── Summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   AEGIS-OMNI Control Room è ATTIVO" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Dashboard:   " -NoNewline -ForegroundColor White
Write-Host "$DASH_URL" -ForegroundColor Cyan
Write-Host ""
Write-Host "   Username:    " -NoNewline -ForegroundColor White
Write-Host "admin" -ForegroundColor Green
Write-Host "   Password:    " -NoNewline -ForegroundColor White
Write-Host "$AdminPassword" -ForegroundColor Green
Write-Host ""
Write-Host "   Servizi:" -ForegroundColor White
Write-Host "     Orchestrator     http://127.0.0.1:8070   (Go core + Sigma/Integrations/Evidence/PKI/OT-Protocols)" -ForegroundColor DarkGray
Write-Host "     Endpoint native  http://127.0.0.1:8088   (Defender/Firewall/YARA/Posture/Hunt)" -ForegroundColor DarkGray
Write-Host "     Network          http://127.0.0.1:8081   (LAN scan / TLS / Topology / Fusion)" -ForegroundColor DarkGray
Write-Host "     SIEM             http://127.0.0.1:8082   (Correlation rules)" -ForegroundColor DarkGray
Write-Host "     SOAR             http://127.0.0.1:8083   (Playbooks / automation)" -ForegroundColor DarkGray
Write-Host "     Threat-intel     http://127.0.0.1:8084   (IOC lookup)" -ForegroundColor DarkGray
Write-Host "     Vuln scanner     http://127.0.0.1:8085   (CVE lookup)" -ForegroundColor DarkGray
Write-Host "     Reports          http://127.0.0.1:8086   (HTML/JSON export)" -ForegroundColor DarkGray
Write-Host "     OT Monitor       http://127.0.0.1:8087   (OT asset discovery)" -ForegroundColor DarkGray
Write-Host "     DFIR             http://127.0.0.1:8093   (Case management / timeline)" -ForegroundColor DarkGray
Write-Host "     Compliance       http://127.0.0.1:8094   (GDPR / NIS2 / NIST-OT assessment)" -ForegroundColor DarkGray
Write-Host "     Integrations     http://127.0.0.1:8090   (tool discovery)" -ForegroundColor DarkGray
Write-Host "     Sigma Engine     http://127.0.0.1:8091   (detection as code)" -ForegroundColor DarkGray
Write-Host "     OT Protocols     http://127.0.0.1:8092   (Modbus / OPC UA)" -ForegroundColor DarkGray
Write-Host "     Evidence Store   http://127.0.0.1:8095   (hash + immutability)" -ForegroundColor DarkGray
Write-Host "     PKI              http://127.0.0.1:8096   (cert inventory + mTLS)" -ForegroundColor DarkGray
Write-Host "     CyberShield AI   http://127.0.0.1:8919   (ML anomaly detection)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   Comandi:" -ForegroundColor White
Write-Host "     .\aegis-all.ps1 -Stop    # ferma tutto" -ForegroundColor DarkGray
Write-Host "     logs\*.log                # output per servizio" -ForegroundColor DarkGray
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

if (-not $NoBrowser) {
    Start-Sleep -Seconds 1
    Start-Process $DASH_URL
}
