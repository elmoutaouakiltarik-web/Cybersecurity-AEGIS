#!/usr/bin/env pwsh
# ============================================================
# AEGIS Log Rotator - Previene l'esplosione dei log a GB
# Salva in: $PSScriptRoot\
# Esegui con Task Scheduler ogni giorno alle 03:00
# ============================================================

$LogDir = "$PSScriptRoot\logs"
$MaxSizeMB = 100       # Max 100 MB per file
$MaxAgeDays = 3        # Elimina log vecchi di 3+ giorni
$RotatorLog = "$LogDir\.rotator.log"

function Write-RotatorLog($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg"
    Add-Content $RotatorLog $line -ErrorAction SilentlyContinue
    Write-Output $line
}

Write-RotatorLog "=== AEGIS Log Rotator START ==="
$totalFreed = 0

Get-ChildItem $LogDir -Filter "*.err.log" -ErrorAction SilentlyContinue | ForEach-Object {
    $fileMB = [math]::Round($_.Length / 1MB, 1)
    
    if ($_.Length -gt ($MaxSizeMB * 1MB)) {
        try {
            # Salva ultimi 1000 righe, tronca il resto
            $lastLines = Get-Content $_.FullName -Tail 1000 -ErrorAction SilentlyContinue
            $header = "# Rotated $(Get-Date -Format 'yyyy-MM-dd HH:mm') | was $fileMB MB | kept last 1000 lines`n"
            $header + ($lastLines -join "`n") | Set-Content $_.FullName -Encoding UTF8 -ErrorAction Stop
            Write-RotatorLog "ROTATED: $($_.Name) ($fileMB MB → kept 1000 lines)"
            $totalFreed += $fileMB
        } catch {
            Write-RotatorLog "SKIP (locked): $($_.Name)"
        }
    }
}

# Elimina log più vecchi di MaxAgeDays (non correnti)
Get-ChildItem $LogDir -File -ErrorAction SilentlyContinue | 
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxAgeDays) -and $_.Extension -in '.log','.err','.gz','.old' } |
    ForEach-Object {
        $mb = [math]::Round($_.Length/1MB,1)
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        Write-RotatorLog "DELETED (old): $($_.Name) ($mb MB)"
        $totalFreed += $mb
    }

Write-RotatorLog "=== DONE | Freed: $([math]::Round($totalFreed,1)) MB ==="

# Limita il log del rotatore stesso a 500 righe
if (Test-Path $RotatorLog) {
    $lines = Get-Content $RotatorLog -Tail 500
    $lines | Set-Content $RotatorLog -Encoding UTF8
}
