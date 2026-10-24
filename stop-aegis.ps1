#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Cybersecurity-AEGIS — Stop all services
.DESCRIPTION
    Kills orchestrator.exe and all Python module processes listening
    on AEGIS ports (8080-8088, 8919).
#>

$ports = @(8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8919)

Write-Host ""
Write-Host "  Stopping Cybersecurity-AEGIS services..." -ForegroundColor Cyan
Write-Host ""

$stopped = 0
foreach ($port in $ports) {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($conn in $conns) {
        $owningPid = $conn.OwningProcess
        try {
            $proc = Get-Process -Id $owningPid -ErrorAction Stop
            Write-Host "  Stopping $($proc.ProcessName) (PID $owningPid, port $port)" -ForegroundColor Yellow
            Stop-Process -Id $owningPid -Force
            $stopped++
        } catch {
            Write-Host "  Could not stop PID $owningPid on port $port : $_" -ForegroundColor DarkGray
        }
    }
}

if ($stopped -eq 0) {
    Write-Host "  No AEGIS services found running." -ForegroundColor DarkGray
} else {
    Write-Host ""
    Write-Host "  Stopped $stopped service(s)." -ForegroundColor Green
}
Write-Host ""
