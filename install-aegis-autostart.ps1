#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Installa o rimuove l'avvio automatico di AEGIS all'accesso utente.

.DESCRIPTION
    Crea una Scheduled Task che avvia `aegis-all.ps1 -NoBrowser` ad ogni logon.
    Utile per avere tutti i moduli Python + orchestrator disponibili subito
    all'avvio del PC, senza lanciare manualmente lo script.
#>

[CmdletBinding()]
param(
    [switch]$Remove,
    [string]$TaskName = "AEGIS-OMNI AutoStart"
)

$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$scriptPath = Join-Path $root "aegis-all.ps1"

if (-not (Test-Path $scriptPath)) {
    throw "Script non trovato: $scriptPath"
}

if ($Remove) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[OK] Task rimossa: $TaskName" -ForegroundColor Green
    } else {
        Write-Host "[OK] Nessuna task da rimuovere: $TaskName" -ForegroundColor DarkGray
    }
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Get-ItemProperty -Path $runKey -Name $TaskName -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $runKey -Name $TaskName -ErrorAction SilentlyContinue
        Write-Host "[OK] Run key rimossa: $TaskName" -ForegroundColor Green
    }
    exit 0
}

$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $pwsh) {
    $pwsh = (Get-Command powershell -ErrorAction Stop).Source
}

$arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -NoBrowser"
$action = New-ScheduledTaskAction -Execute $pwsh -Argument $arg
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$userId = if ($env:USERDOMAIN) { "$($env:USERDOMAIN)\$($env:USERNAME)" } else { $env:USERNAME }

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    } catch {
        Write-Host "[!!] Impossibile rimuovere la task esistente ($TaskName): $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

$installedMode = $null
try {
    $principalHigh = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principalHigh -ErrorAction Stop | Out-Null
    $installedMode = "ScheduledTask (Highest)"
} catch {
    try {
        $principalLimited = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principalLimited -ErrorAction Stop | Out-Null
        $installedMode = "ScheduledTask (Limited)"
    } catch {
        # Fallback no-admin: HKCU\Run
        $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        New-Item -Path $runKey -Force | Out-Null
        $cmd = "`"$pwsh`" $arg"
        Set-ItemProperty -Path $runKey -Name $TaskName -Value $cmd -Type String
        $installedMode = "Registry Run (HKCU)"
    }
}

Write-Host "[OK] Task installata: $TaskName" -ForegroundColor Green
Write-Host "     Esegue: $scriptPath -NoBrowser" -ForegroundColor DarkGray
Write-Host "     Modalità: $installedMode" -ForegroundColor DarkGray
