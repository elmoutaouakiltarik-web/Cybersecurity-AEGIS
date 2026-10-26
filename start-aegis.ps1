#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Cybersecurity-AEGIS — One-Click Windows Launcher
.DESCRIPTION
    Builds the Go orchestrator, starts all Python module services,
    and opens the Control Room dashboard in the browser.
    Press Ctrl+C or close this window to stop all services.
#>

[CmdletBinding()]
param(
    [switch]$NoEndpoint,
    [int]$EndpointPort = 8088,
    [string]$BindAddress = "127.0.0.1:8080",
    [string]$ModuleBindAddress = "127.0.0.1",
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# ── PATHS ──────────────────────────────────────────────────────────────────────
$ROOT       = $PSScriptRoot
$CORE_DIR   = Join-Path $ROOT "core\orchestrator"
$MODULES    = Join-Path $ROOT "modules"
$LOGS_DIR   = Join-Path $ROOT "logs"
$EXE        = Join-Path $CORE_DIR "orchestrator.exe"
$DASH_URL   = "http://localhost:8080/dashboard/"

# ── COLORS ─────────────────────────────────────────────────────────────────────
function Write-Banner {
    $banner = @"

  ___  _____ ___ ___ ____       ___  __  __ _   _ ___
 / _ \| ____/ __|_ _/ ___|     / _ \|  \/  | \ | |_ _|
| | | |  _|| |  | |\___  \    | | | | |\/| |  \| || |
| |_| | |__| |__| | ___) |   | |_| | |  | | |\  || |
 \__\_\_____|\___|___|____/    \___/|_|  |_|_| \_|___|

       Cybersecurity-AEGIS Control Room  v1.0
       Defensive-Only | Zero-Trust | IT+OT
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Msg, [string]$Color = "Yellow")
    Write-Host "  >> $Msg" -ForegroundColor $Color
}

function Write-OK   { param([string]$Msg) Write-Host "  [OK] $Msg" -ForegroundColor Green  }
function Write-Warn { param([string]$Msg) Write-Host "  [!!] $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "  [XX] $Msg" -ForegroundColor Red    }

# ── PREREQUISITES ──────────────────────────────────────────────────────────────
function Test-Prerequisites {
    Write-Step "Checking prerequisites..."

    # Python
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) {
        $py = Get-Command python3 -ErrorAction SilentlyContinue
    }
    if (-not $py) {
        Write-Err "Python not found. Install Python 3.10+ from https://python.org"
        exit 1
    }
    $pyVer = & python --version 2>&1
    Write-OK "Python: $pyVer"

    # Go (optional — only needed to rebuild)
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($go) {
        $goVer = & go version 2>&1
        Write-OK "Go: $goVer"
        return $true
    } else {
        Write-Warn "Go compiler not found — will use pre-built orchestrator.exe"
        return $false
    }
}

# ── BUILD GO ORCHESTRATOR ──────────────────────────────────────────────────────
function Build-Orchestrator {
    param([bool]$HasGo)

    if (-not $HasGo) {
        if (Test-Path $EXE) {
            Write-OK "Using pre-built orchestrator.exe"
            return
        }
        Write-Err "No Go compiler and no pre-built orchestrator.exe found."
        Write-Err "Install Go from https://go.dev/dl/ or add orchestrator.exe to core\orchestrator\"
        exit 1
    }

    # Check if rebuild needed: any .go file newer than exe
    $needsBuild = $true
    if (Test-Path $EXE) {
        $exeTime   = (Get-Item $EXE).LastWriteTime
        $newerGoFiles = Get-ChildItem $CORE_DIR -Filter "*.go" | Where-Object { $_.LastWriteTime -gt $exeTime }
        $dashboardDir = Join-Path $CORE_DIR "dashboard"
        $newerDashboardFiles = Get-ChildItem -Path $dashboardDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $exeTime }
        if (-not $newerGoFiles -and -not $newerDashboardFiles) {
            $needsBuild = $false
            Write-OK "orchestrator.exe is up to date — skipping build"
        }
    }

    if ($needsBuild) {
        Write-Step "Building Go orchestrator..." "Cyan"
        Push-Location $CORE_DIR
        try {
            & go build -ldflags="-s -w" -o orchestrator.exe . 2>&1 | ForEach-Object { Write-Host "    $_" }
            if ($LASTEXITCODE -ne 0) {
                Write-Err "go build failed (exit $LASTEXITCODE)"
                exit 1
            }
            Write-OK "orchestrator.exe built successfully"
        } finally {
            Pop-Location
        }
    }
}

# ── INSTALL PYTHON DEPS ────────────────────────────────────────────────────────
function Install-PythonDeps {
    Write-Step "Installing Python dependencies (this may take a moment on first run)..."

    # Collect all unique packages needed
    $allPkgs = @(
        "flask>=2.3",
        "flask-cors>=4.0",
        "requests>=2.31",
        "PyYAML>=6.0",
        "psutil>=5.9",
        "yara-python>=4.5",
        "pymodbus>=3.5",
        "fastapi>=0.115",
        "uvicorn[standard]>=0.34",
        "pandas>=2.2",
        "numpy>=1.26",
        "scikit-learn>=1.4",
        "joblib>=1.4",
        "pydantic>=2.4",
        "waitress>=3.0",
        "scapy>=2.5"
    )

    $pip = "pip"
    $pkgStr = $allPkgs -join " "

    Write-Host "    Installing: $($allPkgs -join ', ')" -ForegroundColor DarkGray

    # Quiet install, only show errors
    $result = & python -m pip install --quiet --upgrade $allPkgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Some packages may have failed to install. Trying individually..."
        foreach ($pkg in $allPkgs) {
            & python -m pip install --quiet $pkg 2>$null | Out-Null
        }
    }
    Write-OK "Python dependencies ready"
}

# ── PORT AVAILABILITY ──────────────────────────────────────────────────────────
function Test-PortFree {
    param([int]$Port)
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return ($null -eq $conn)
}

function Wait-PortBusy {
    param([int]$Port, [int]$TimeoutSec = 30, [string]$Name = "service")
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        if ($conn) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# ── SERVICE LAUNCHER ──────────────────────────────────────────────────────────
$script:RunningProcs = @()

function Start-PythonService {
    param(
        [string]$Name,
        [string]$WorkDir,
        [string[]]$CmdArgs,
        [hashtable]$Env = @{},
        [int]$Port,
        [string]$LogFile
    )

    if (-not (Test-PortFree $Port)) {
        Write-Warn "${Name}: port $Port already in use — skipping launch (assuming already running)"
        return
    }

    $envStr = ($Env.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", "

    # Build environment block
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "python"
    $psi.Arguments = $CmdArgs -join " "
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $false
    $psi.RedirectStandardError  = $false
    $psi.CreateNoWindow = $true

    # Inherit current environment + overrides
    $psi.EnvironmentVariables.Clear()
    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $psi.EnvironmentVariables[$e.Key] = $e.Value
    }
    $psi.EnvironmentVariables["PYTHONUNBUFFERED"] = "1"
    $psi.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8"
    $psi.EnvironmentVariables["FLASK_ENV"] = "production"
    $psi.EnvironmentVariables["FLASK_DEBUG"] = "0"
    $psi.EnvironmentVariables["WERKZEUG_DEBUG_PIN"] = "off"
    foreach ($kv in $Env.GetEnumerator()) {
        $psi.EnvironmentVariables[$kv.Key] = $kv.Value
    }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    $null = $proc.Start()
    Add-Content -Path $LogFile -Value "[$(Get-Date -Format o)] $Name started (PID $($proc.Id)); env: $envStr" -ErrorAction SilentlyContinue

    $script:RunningProcs += $proc
    Write-OK "$Name started (PID $($proc.Id)) — log: logs\$([System.IO.Path]::GetFileName($LogFile))"
    return $proc
}

function Start-UvicornService {
    param(
        [string]$Name,
        [string]$WorkDir,
        [string]$Module,
        [int]$Port,
        [string]$LogFile,
        [hashtable]$Env = @{}
    )

    if (-not (Test-PortFree $Port)) {
        Write-Warn "${Name}: port $Port already in use — skipping launch"
        return
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "python"
    $psi.Arguments = "-m uvicorn $Module --host $ModuleBindAddress --port $Port --log-level warning"
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $false
    $psi.RedirectStandardError  = $false
    $psi.CreateNoWindow = $true

    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        try { $psi.EnvironmentVariables[$e.Key] = $e.Value } catch {}
    }
    $psi.EnvironmentVariables["PYTHONUNBUFFERED"] = "1"
    $psi.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8"
    $psi.EnvironmentVariables["FLASK_ENV"] = "production"
    $psi.EnvironmentVariables["FLASK_DEBUG"] = "0"
    $psi.EnvironmentVariables["WERKZEUG_DEBUG_PIN"] = "off"
    foreach ($kv in $Env.GetEnumerator()) {
        $psi.EnvironmentVariables[$kv.Key] = $kv.Value
    }

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    $null = $proc.Start()
    Add-Content -Path $LogFile -Value "[$(Get-Date -Format o)] $Name started (PID $($proc.Id)); module: $Module" -ErrorAction SilentlyContinue

    $script:RunningProcs += $proc
    Write-OK "$Name started (PID $($proc.Id)) — log: logs\$([System.IO.Path]::GetFileName($LogFile))"
    return $proc
}

# ── HEALTH CHECK ──────────────────────────────────────────────────────────────
function Wait-Healthy {
    param([string]$Url, [string]$Name, [int]$TimeoutSec = 20)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        try {
            $r = Invoke-WebRequest -Uri $Url -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
            if ($r.StatusCode -eq 200) { return $true }
        } catch {}
        Start-Sleep -Milliseconds 600
    }
    Write-Warn "$Name health check timed out — may still be starting"
    return $false
}

# ── CLEANUP ───────────────────────────────────────────────────────────────────
function Stop-AllServices {
    Write-Host ""
    Write-Step "Stopping all AEGIS services..." "Red"
    foreach ($proc in $script:RunningProcs) {
        try {
            if (-not $proc.HasExited) {
                $proc.Kill()
                Write-Host "    Stopped PID $($proc.Id)" -ForegroundColor DarkGray
            }
        } catch {}
    }
    Write-OK "All services stopped."
}

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

Write-Banner

# Ensure logs dir
if (-not (Test-Path $LOGS_DIR)) {
    New-Item -ItemType Directory -Path $LOGS_DIR -Force | Out-Null
}

# 1. Prerequisites
$hasGo = Test-Prerequisites
Write-Host ""

# 2. Build
Build-Orchestrator -HasGo $hasGo
Write-Host ""

# 3. Python deps
Install-PythonDeps
Write-Host ""

# 4. Start Python modules
Write-Step "Starting Python module services..." "Cyan"

# ── API KEY CONFIGURATION ─────────────────────────────────────────────────────
# Set your API keys here (or as Windows environment variables before running)
# AbuseIPDB: https://www.abuseipdb.com/api  (free tier: 1000 req/day)
# OTX AlienVault: https://otx.alienvault.com/api  (free)
if (-not $env:ABUSEIPDB_KEY)  { $env:ABUSEIPDB_KEY  = "YOUR_ABUSEIPDB_KEY_HERE" }
if (-not $env:OTX_API_KEY)    { $env:OTX_API_KEY    = "YOUR_OTX_API_KEY_HERE"   }

# ── INGEST SHARED SECRET ──────────────────────────────────────────────────────
# Every module signs its event posts with AEGIS_INGEST_KEY and the orchestrator
# rejects anything without it. Generated once per run unless already set, then
# inherited by every child process started below.
if (-not $env:AEGIS_INGEST_KEY) {
    $ingestBytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($ingestBytes)
    $env:AEGIS_INGEST_KEY = -join ($ingestBytes | ForEach-Object { $_.ToString("x2") })
    Write-Host "    Ingest shared secret generated for this run" -ForegroundColor DarkGray
}

$orchUrl = "http://localhost:8080"

# Network Monitor — port 8081
Start-PythonService `
    -Name "Network Monitor" `
    -WorkDir (Join-Path $MODULES "network") `
    -CmdArgs @("app.py") `
    -Port 8081 `
    -Env @{ NETWORK_API_PORT="8081"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "network.log")

# SIEM Correlator — port 8082
Start-PythonService `
    -Name "SIEM Correlator" `
    -WorkDir (Join-Path $MODULES "siem") `
    -CmdArgs @("app.py") `
    -Port 8082 `
    -Env @{ SIEM_API_PORT="8082"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "siem.log")

# SOAR Executor — port 8083
Start-PythonService `
    -Name "SOAR Executor" `
    -WorkDir (Join-Path $MODULES "soar") `
    -CmdArgs @("app.py") `
    -Port 8083 `
    -Env @{ SOAR_API_PORT="8083"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "soar.log")

# Threat Intel — port 8084 (with optional API keys for live feeds)
Start-PythonService `
    -Name "Threat Intel" `
    -WorkDir (Join-Path $MODULES "threat_intel") `
    -CmdArgs @("app.py") `
    -Port 8084 `
    -Env @{ THREAT_INTEL_API_PORT="8084"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING";
            ABUSEIPDB_KEY=$env:ABUSEIPDB_KEY; OTX_API_KEY=$env:OTX_API_KEY } `
    -LogFile (Join-Path $LOGS_DIR "threat_intel.log")

# Vuln Scanner — port 8085
Start-PythonService `
    -Name "Vuln Scanner" `
    -WorkDir (Join-Path $MODULES "vuln") `
    -CmdArgs @("app.py") `
    -Port 8085 `
    -Env @{ VULN_API_PORT="8085"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING"; VULN_ACTIVE_SCAN="1" } `
    -LogFile (Join-Path $LOGS_DIR "vuln.log")

# Reports Generator — port 8086
Start-PythonService `
    -Name "Reports Generator" `
    -WorkDir (Join-Path $MODULES "reports") `
    -CmdArgs @("app.py") `
    -Port 8086 `
    -Env @{ REPORTS_API_PORT="8086"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "reports.log")

# Endpoint Protection (host-native) — port 8088 by default
if (-not $NoEndpoint) {
    if ($IsWindows) {
        $endpointEnv = @{
            ENDPOINT_API_PORT  = "$EndpointPort"
            ENDPOINT_BIND_HOST = "127.0.0.1"
            ORCHESTRATOR_URL   = $orchUrl
            ENDPOINT_INGEST    = "1"
            AEGIS_LOG_LEVEL    = "WARNING"
        }
        $yaraRulesDir = Join-Path $MODULES "intelligence\yara\rules"
        if (Test-Path $yaraRulesDir) {
            $endpointEnv["YARA_RULES_DIR"] = $yaraRulesDir
        }
        Start-PythonService `
            -Name "Endpoint Protection" `
            -WorkDir (Join-Path $MODULES "endpoint") `
            -CmdArgs @("app.py") `
            -Port $EndpointPort `
            -Env $endpointEnv `
            -LogFile (Join-Path $LOGS_DIR "endpoint.log")
    } else {
        Write-Warn "Endpoint module skipped: host-native endpoint checks are currently available on Windows hosts."
    }
}

# OT Monitor — port 8087
Start-PythonService `
    -Name "OT Monitor" `
    -WorkDir (Join-Path $MODULES "industrial\ot_monitor") `
    -CmdArgs @("app.py") `
    -Port 8087 `
    -Env @{ OT_API_PORT="8087"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING"; OT_SIMULATION_MODE="false" } `
    -LogFile (Join-Path $LOGS_DIR "ot.log")

# CyberShield AI — port 8919 (FastAPI/uvicorn)
Start-UvicornService `
    -Name "CyberShield AI" `
    -WorkDir (Join-Path $MODULES "ml\cybershield_ai") `
    -Module "api.app:app" `
    -Port 8919 `
    -LogFile (Join-Path $LOGS_DIR "cybershield.log")

# Integrations — port 8090 (external tool discovery)
Start-PythonService `
    -Name "Integrations" `
    -WorkDir (Join-Path $MODULES "integrations") `
    -CmdArgs @("app.py") `
    -Port 8090 `
    -Env @{ INTEGRATIONS_PORT="8090"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "integrations.log")

# Sigma Engine — port 8091 (detection-as-code)
Start-PythonService `
    -Name "Sigma Engine" `
    -WorkDir (Join-Path $MODULES "sigma") `
    -CmdArgs @("app.py") `
    -Port 8091 `
    -Env @{ SIGMA_PORT="8091"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "sigma.log")

# OT Protocols — port 8092 (Modbus, OPC UA collectors)
Start-PythonService `
    -Name "OT Protocols" `
    -WorkDir (Join-Path $MODULES "ot_protocols") `
    -CmdArgs @("app.py") `
    -Port 8092 `
    -Env @{ OT_PROTOCOLS_PORT="8092"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING"; OT_SAFE_MODE="1" } `
    -LogFile (Join-Path $LOGS_DIR "ot_protocols.log")

# DFIR — port 8093 (case management & timeline)
Start-PythonService `
    -Name "DFIR" `
    -WorkDir (Join-Path $MODULES "dfir") `
    -CmdArgs @("app.py") `
    -Port 8093 `
    -Env @{ DFIR_PORT="8093"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "dfir.log")

# Compliance — port 8094 (GDPR, NIS2, OT/NIST)
Start-PythonService `
    -Name "Compliance" `
    -WorkDir (Join-Path $MODULES "compliance") `
    -CmdArgs @("app.py") `
    -Port 8094 `
    -Env @{ COMPLIANCE_PORT="8094"; ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "compliance.log")

# Evidence Store — port 8095 (immutable artifacts)
Start-PythonService `
    -Name "Evidence Store" `
    -WorkDir (Join-Path $MODULES "evidence") `
    -CmdArgs @("app.py") `
    -Port 8095 `
    -Env @{ EVIDENCE_PORT="8095"; EVIDENCE_STORE_DIR=(Join-Path $ROOT "data\evidence"); ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "evidence.log")

# PKI — port 8096 (certificate management)
Start-PythonService `
    -Name "PKI" `
    -WorkDir (Join-Path $MODULES "pki") `
    -CmdArgs @("app.py") `
    -Port 8096 `
    -Env @{ PKI_PORT="8096"; PKI_DATA_DIR=(Join-Path $ROOT "data\pki"); ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "pki.log")

# Plant Assessment — port 8097 (assessment rete industriale, read-only)
Start-PythonService `
    -Name "Plant Assessment" `
    -WorkDir (Join-Path $MODULES "industrial") `
    -CmdArgs @("-m", "site_assessment.app") `
    -Port 8097 `
    -Env @{ ASSESS_API_PORT="8097"; ASSESS_BIND_HOST="127.0.0.1"; AEGIS_ASSESS_DATA_DIR=(Join-Path $ROOT "data\site_assessment"); ORCHESTRATOR_URL=$orchUrl; AEGIS_LOG_LEVEL="WARNING" } `
    -LogFile (Join-Path $LOGS_DIR "site_assessment.log")

Write-Host ""
Write-Step "Waiting for modules to initialize (5s)..." "DarkGray"
Start-Sleep -Seconds 5

# 5. Start Go orchestrator
Write-Step "Starting Go Orchestrator (port 8080)..." "Cyan"

if (-not (Test-PortFree 8080)) {
    Write-Warn "Port 8080 already in use — orchestrator may already be running"
} else {
    $orchPsi = New-Object System.Diagnostics.ProcessStartInfo
    $orchPsi.FileName = $EXE
    $orchPsi.WorkingDirectory = $CORE_DIR
    $orchPsi.UseShellExecute = $false
    $orchPsi.RedirectStandardOutput = $false
    $orchPsi.RedirectStandardError  = $false
    $orchPsi.CreateNoWindow = $true

    foreach ($e in [System.Environment]::GetEnvironmentVariables().GetEnumerator()) {
        try { $orchPsi.EnvironmentVariables[$e.Key] = $e.Value } catch {}
    }
    $orchPsi.EnvironmentVariables["AEGIS_BIND"] = $BindAddress
    $orchPsi.EnvironmentVariables["AEGIS_INGEST_KEY"] = $env:AEGIS_INGEST_KEY
    $orchPsi.EnvironmentVariables["AEGIS_LOG_LEVEL"] = "info"
    $orchPsi.EnvironmentVariables["AEGIS_PROXY_ENDPOINT"] = "http://localhost:$EndpointPort"

    $orchProc = New-Object System.Diagnostics.Process
    $orchProc.StartInfo = $orchPsi

    $null = $orchProc.Start()
    $orchLog = Join-Path $LOGS_DIR "orchestrator.log"
    Add-Content -Path $orchLog -Value "[$(Get-Date -Format o)] Orchestrator started (PID $($orchProc.Id)); bind: $BindAddress" -ErrorAction SilentlyContinue
    $script:RunningProcs += $orchProc

    Write-OK "Orchestrator started (PID $($orchProc.Id)) — log: logs\orchestrator.log"
}

# 6. Health checks
Write-Host ""
Write-Step "Waiting for orchestrator health check..." "Cyan"
$healthy = Wait-Healthy -Url "http://localhost:8080/health" -Name "Orchestrator" -TimeoutSec 30
if (-not $healthy) {
    Write-Warn "Orchestrator not responding — check logs\orchestrator.log"
}

# 7. Real telemetry mode. Generated event injection is not available.
Write-Host ""
Write-Step "Real telemetry mode: no generated event injection" "DarkGray"

# 8. Status summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   AEGIS Control Room is LIVE" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Dashboard:     $DASH_URL" -ForegroundColor White
Write-Host "  Health:        http://localhost:8080/health" -ForegroundColor DarkGray
Write-Host "  Metrics:       http://localhost:8080/api/v1/metrics" -ForegroundColor DarkGray
Write-Host "  Live Events:   http://localhost:8080/api/v1/events/live (SSE)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Module Ports:" -ForegroundColor DarkGray
Write-Host "    Network:     :8081   SIEM:     :8082   SOAR:     :8083" -ForegroundColor DarkGray
Write-Host "    Threat-Intel::8084   Vuln:     :8085   Reports:  :8086" -ForegroundColor DarkGray
Write-Host "    OT Monitor:  :8087   CyberShield: :8919" -ForegroundColor DarkGray
Write-Host "    Assessment:  :8097   (Plant Assessment — rete industriale)" -ForegroundColor DarkGray
if (-not $NoEndpoint) {
    Write-Host "    Endpoint:    :$EndpointPort (host-native)" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  Logs: $LOGS_DIR" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Press Ctrl+C to stop all services" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# 9. Open browser
if (-not $NoBrowser) {
    Start-Sleep -Seconds 1
    Start-Process $DASH_URL
}

# 10. Wait (keep alive + periodic status)
try {
    $tick = 0
    while ($true) {
        Start-Sleep -Seconds 30
        $tick++
        # Every 5 min, log a heartbeat
        if ($tick % 10 -eq 0) {
            $ts = Get-Date -Format "HH:mm:ss"
            try {
                $m = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/metrics" -TimeoutSec 3 -ErrorAction Stop
                Write-Host "  [$ts] AEGIS alive — events: $($m.total_events)" -ForegroundColor DarkGray
            } catch {
                Write-Host "  [$ts] AEGIS heartbeat (metrics unavailable)" -ForegroundColor DarkGray
            }
        }
    }
} finally {
    Stop-AllServices
}
