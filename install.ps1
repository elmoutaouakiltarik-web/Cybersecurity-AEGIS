# Cybersecurity-AEGIS Windows Installer
#Requires -RunAsAdministrator

$AEGIS_VERSION = "1.0.0"
$AEGIS_DIR = $PSScriptRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Docker is required but not installed." -ForegroundColor Red
    exit 1
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "     Cybersecurity-AEGIS Installer v$AEGIS_VERSION          " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Set-Location $AEGIS_DIR

if (-not (Test-Path .env)) {
    Write-Host "[1/5] Creating .env from template..."
    Copy-Item .env.example .env
} else {
    Write-Host "[1/5] .env already exists, preserving."
}

Write-Host "[2/5] Pulling base images..."
docker compose --profile full pull 2>$null

Write-Host "[3/5] Building AEGIS services..."
docker compose --profile full build

Write-Host "[4/5] Starting core services..."
docker compose --profile core up -d

Write-Host "[5/5] Starting full defensive stack..."
docker compose --profile full up -d

Write-Host ""
Write-Host "AEGIS installation complete!" -ForegroundColor Green
Write-Host "Dashboard:  http://localhost:8080/dashboard/"
Write-Host "Health:     Invoke-RestMethod http://localhost:8080/health"
Write-Host "Metrics:    Invoke-RestMethod http://localhost:8080/api/v1/metrics"
Write-Host ""
Write-Host "To stop:    docker compose --profile full down"
Write-Host "To update:  docker compose --profile full pull; docker compose --profile full up --build -d"
