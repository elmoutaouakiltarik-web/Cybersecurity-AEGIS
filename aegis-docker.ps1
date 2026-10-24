#!/usr/bin/env pwsh
<#
.SYNOPSIS
    AEGIS-OMNI Docker launcher — one-click full stack.

.DESCRIPTION
    Builds and starts the complete Cybersecurity-AEGIS stack via Docker Compose:
      - Postgres (events store)
      - Go orchestrator (port 8070) with admin/password login
      - All Python modules: network, siem, soar, threat-intel, vuln, reports
      - Optional: --industrial adds the OT/ICS monitor (port 8087)

    On success, opens the Control Room in the default browser and prints the
    admin credentials.

.PARAMETER Industrial
    Include the OT/ICS profile (industrial control system monitor).

.PARAMETER Rebuild
    Force a full rebuild of all images.

.PARAMETER Stop
    Stop and remove all containers (volumes preserved).

.PARAMETER AdminPassword
    Override the default admin password (env AEGIS_ADMIN_PASSWORD).

.EXAMPLE
    .\aegis-docker.ps1
    .\aegis-docker.ps1 -Industrial
    .\aegis-docker.ps1 -Rebuild
    .\aegis-docker.ps1 -Stop
#>
[CmdletBinding()]
param(
    [switch]$Industrial,
    [switch]$Rebuild,
    [switch]$Stop,
    [string]$AdminPassword = ""
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# ── Paths ──────────────────────────────────────────────────────────────────
$ROOT     = $PSScriptRoot
$COMPOSE  = Join-Path $ROOT "docker-compose.full.yml"
$DASH_URL = "http://localhost:8070/dashboard/"

# ── Pretty printers ────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "  ___  _____ ___ ___ ____      ___  __  __ _   _ ___ " -ForegroundColor Cyan
    Write-Host " / _ \| ____/ __|_ _/ ___|    / _ \|  \/  | \ | |_ _|" -ForegroundColor Cyan
    Write-Host "| |_| |  _|| |  | |\___ \    | | | | |\/| |  \| || | " -ForegroundColor Cyan
    Write-Host "|  _  | |__| |__| | ___) |   | |_| | |  | | |\  || | " -ForegroundColor Cyan
    Write-Host "|_| |_|_____|\___|___|____/    \___/|_|  |_|_| \_|___|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "       AEGIS-OMNI Control Room  (Docker mode)" -ForegroundColor White
    Write-Host "       Defensive-Only | Zero-Trust | IT+OT" -ForegroundColor DarkGray
    Write-Host ""
}
function Step($m) { Write-Host "  >> $m" -ForegroundColor Yellow }
function OK($m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!!] $m" -ForegroundColor DarkYellow }
function Err($m)  { Write-Host "  [XX] $m" -ForegroundColor Red }

Write-Banner

# ── Stop mode ──────────────────────────────────────────────────────────────
if ($Stop) {
    Step "Stopping AEGIS-OMNI stack..."
    docker compose -f $COMPOSE --profile industrial down
    OK "All containers stopped (volumes preserved). Run again without -Stop to restart."
    exit 0
}

# ── Verify Docker ──────────────────────────────────────────────────────────
Step "Checking Docker..."
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Err "Docker non trovato nel PATH. Installa Docker Desktop da https://docker.com/products/docker-desktop"
    exit 1
}
try {
    $dockerInfo = docker info --format '{{.ServerVersion}}' 2>$null
    if (-not $dockerInfo) {
        Err "Docker engine non risponde. Avvia Docker Desktop e riprova."
        exit 1
    }
    OK "Docker engine: $dockerInfo"
} catch {
    Err "Docker engine non raggiungibile: $($_.Exception.Message)"
    exit 1
}

if (-not (Test-Path $COMPOSE)) {
    Err "File $COMPOSE non trovato."
    exit 1
}

# ── Compose up ─────────────────────────────────────────────────────────────
$env:AEGIS_ADMIN_USER     = "admin"
$env:AEGIS_ADMIN_PASSWORD = $AdminPassword
$env:AEGIS_BIND_HOST      = "127.0.0.1"

$profiles = @()
if ($Industrial) { $profiles += "--profile"; $profiles += "industrial" }

$buildFlag = if ($Rebuild) { "--build" } else { "--build" }  # Always build to pick up code changes

Step "Building images (first run: ~2-4 min)..."
$buildArgs = @("compose", "-f", $COMPOSE) + $profiles + @("build")
if ($Rebuild) { $buildArgs += "--no-cache" }
& docker @buildArgs
if ($LASTEXITCODE -ne 0) {
    Err "Build fallita. Controlla l'output sopra."
    exit 1
}
OK "Build completata."

Step "Avvio container in background..."
$upArgs = @("compose", "-f", $COMPOSE) + $profiles + @("up", "-d")
& docker @upArgs
if ($LASTEXITCODE -ne 0) {
    Err "docker compose up fallito."
    exit 1
}
OK "Container avviati."

# ── Wait for orchestrator health ───────────────────────────────────────────
Step "Attendo healthy orchestrator (max 60s)..."
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        $h = Invoke-WebRequest -Uri "http://127.0.0.1:8070/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($h.StatusCode -eq 200) { $ready = $true; break }
    } catch {}
    Start-Sleep -Seconds 1
}
if ($ready) { OK "Orchestrator UP a http://127.0.0.1:8070" }
else        { Warn "Orchestrator non ancora healthy — controlla: docker compose -f docker-compose.full.yml logs orchestrator" }

# ── Smoke test ─────────────────────────────────────────────────────────────
Step "Smoke test moduli..."
$modules = @(
    @{ Name="orchestrator"; Url="http://127.0.0.1:8070/health" }
    @{ Name="network";      Url="http://127.0.0.1:8081/health" }
    @{ Name="siem";         Url="http://127.0.0.1:8082/health" }
    @{ Name="soar";         Url="http://127.0.0.1:8083/health" }
    @{ Name="threat-intel"; Url="http://127.0.0.1:8084/health" }
    @{ Name="vuln";         Url="http://127.0.0.1:8085/health" }
    @{ Name="reports";      Url="http://127.0.0.1:8086/health" }
)
if ($Industrial) { $modules += @{ Name="ot-monitor"; Url="http://127.0.0.1:8087/health" } }

$results = @()
foreach ($m in $modules) {
    $up = $false
    for ($t = 0; $t -lt 30; $t++) {
        try {
            $r = Invoke-WebRequest -Uri $m.Url -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($r.StatusCode -eq 200) { $up = $true; break }
        } catch {}
        Start-Sleep -Milliseconds 800
    }
    $results += @{ Name=$m.Name; Up=$up }
    if ($up) { OK "$($m.Name) — OK" } else { Warn "$($m.Name) — DOWN ($($m.Url))" }
}

# ── Login smoke test ───────────────────────────────────────────────────────
Step "Test login admin/password..."
try {
    $body = @{ username = "admin"; password = $AdminPassword } | ConvertTo-Json
    $loginResp = Invoke-WebRequest -Uri "http://127.0.0.1:8070/api/v1/auth/login" `
        -Method POST -Body $body -ContentType "application/json" `
        -SessionVariable session -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($loginResp.StatusCode -eq 200) {
        OK "Login OK — la pagina sarà aperta nel browser"
    } else {
        Warn "Login HTTP $($loginResp.StatusCode)"
    }
} catch {
    Warn "Test login fallito: $($_.Exception.Message)"
}

# ── Final summary ──────────────────────────────────────────────────────────
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
Write-Host "   Override:    AEGIS_ADMIN_PASSWORD env var oppure -AdminPassword <pw>" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   Moduli attivi (porte locali):" -ForegroundColor White
Write-Host "     Network        http://127.0.0.1:8081" -ForegroundColor DarkGray
Write-Host "     SIEM           http://127.0.0.1:8082" -ForegroundColor DarkGray
Write-Host "     SOAR           http://127.0.0.1:8083" -ForegroundColor DarkGray
Write-Host "     Threat-Intel   http://127.0.0.1:8084" -ForegroundColor DarkGray
Write-Host "     Vuln           http://127.0.0.1:8085" -ForegroundColor DarkGray
Write-Host "     Reports        http://127.0.0.1:8086" -ForegroundColor DarkGray
if ($Industrial) {
    Write-Host "     OT/ICS         http://127.0.0.1:8087" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "   Comandi utili:" -ForegroundColor White
Write-Host "     docker compose -f docker-compose.full.yml logs -f       # follow logs" -ForegroundColor DarkGray
Write-Host "     docker compose -f docker-compose.full.yml ps            # stato container" -ForegroundColor DarkGray
Write-Host "     .\aegis-docker.ps1 -Stop                                 # arresta tutto" -ForegroundColor DarkGray
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ── Open browser ───────────────────────────────────────────────────────────
Start-Sleep -Seconds 1
Start-Process $DASH_URL

