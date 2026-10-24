#!/usr/bin/env pwsh
<#
.SYNOPSIS
    End-to-end smoke test for AEGIS-OMNI: login, scan, vuln, TI, remediation.

.DESCRIPTION
    Verifies the dashboard's user journey from authentication to actionable
    remediation. Designed to run after `.\aegis-docker.ps1`.
#>
[CmdletBinding()]
param(
    [string]$BaseUrl  = "http://127.0.0.1:8070",
    [string]$Username = "admin",
    [string]$Password = $env:AEGIS_ADMIN_PASSWORD,
    [switch]$RequireEndpoint
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$pass = 0; $fail = 0
function Assert-OK($name, $cond, $detail = "") {
    if ($cond) {
        Write-Host "  [PASS] $name" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  [FAIL] $name  $detail" -ForegroundColor Red
        $script:fail++
    }
}

Write-Host ""
Write-Host "═══ AEGIS-OMNI Smoke Test ═══" -ForegroundColor Cyan
Write-Host "  Base: $BaseUrl" -ForegroundColor DarkGray
Write-Host ""

# ── 1. Orchestrator health ───────────────────────────────────────────────
try {
    $h = Invoke-RestMethod -Uri "$BaseUrl/health" -TimeoutSec 5
    Assert-OK "orchestrator /health"  ($h.status -eq "healthy")
} catch {
    Assert-OK "orchestrator /health" $false $_.Exception.Message
    Write-Host ""
    Write-Host "Orchestrator non raggiungibile — abort." -ForegroundColor Red
    exit 1
}

# ── 2. Login with admin/password ─────────────────────────────────────────
$session = $null
try {
    $body = @{ username = $Username; password = $Password } | ConvertTo-Json
    $r = Invoke-WebRequest -Uri "$BaseUrl/api/v1/auth/login" -Method POST -Body $body `
        -ContentType "application/json" -SessionVariable session -UseBasicParsing -TimeoutSec 5
    $loginJson = $r.Content | ConvertFrom-Json
    Assert-OK "login admin/password"  ($r.StatusCode -eq 200 -and $loginJson.ok -eq $true)
} catch {
    Assert-OK "login admin/password" $false $_.Exception.Message
}

# ── 3. Wrong password should fail ────────────────────────────────────────
try {
    $bad = @{ username = $Username; password = "wrong-on-purpose" } | ConvertTo-Json
    $r = Invoke-WebRequest -Uri "$BaseUrl/api/v1/auth/login" -Method POST -Body $bad `
        -ContentType "application/json" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    Assert-OK "login rifiuta password sbagliata" ($r.StatusCode -ne 200)
} catch {
    # PowerShell throws on non-2xx — that's actually what we want.
    Assert-OK "login rifiuta password sbagliata" $true
}

# ── 4. /auth/me with cookie ──────────────────────────────────────────────
try {
    $me = Invoke-RestMethod -Uri "$BaseUrl/api/v1/auth/me" -WebSession $session -TimeoutSec 5
    Assert-OK "/auth/me autenticato"  ($me.authenticated -eq $true -and $me.user -eq "admin")
} catch {
    Assert-OK "/auth/me autenticato" $false $_.Exception.Message
}

# ── 5. Metrics via session ──────────────────────────────────────────────
try {
    $m = Invoke-RestMethod -Uri "$BaseUrl/api/v1/metrics" -WebSession $session -TimeoutSec 5
    Assert-OK "GET /api/v1/metrics"  ($m.total_modules -gt 0)
} catch {
    Assert-OK "GET /api/v1/metrics" $false $_.Exception.Message
}

# ── 5b. Endpoint module checks (optional) ───────────────────────────────
if ($RequireEndpoint) {
    try {
        $ep = Invoke-RestMethod -Uri "$BaseUrl/api/endpoint/health" -WebSession $session -TimeoutSec 8
        Assert-OK "endpoint /health" ($ep.status -eq "healthy")
    } catch {
        Assert-OK "endpoint /health" $false $_.Exception.Message
    }

    try {
        $inv = Invoke-RestMethod -Uri "$BaseUrl/api/endpoint/integrations" -WebSession $session -TimeoutSec 8
        Assert-OK "endpoint integrations inventory" ($inv.total_count -ge 10)
    } catch {
        Assert-OK "endpoint integrations inventory" $false $_.Exception.Message
    }
}

# ── 6. Remediation: CVE lookup ───────────────────────────────────────────
try {
    $rem = Invoke-RestMethod -Uri "$BaseUrl/api/v1/remediation?cve=CVE-2024-3400" `
        -WebSession $session -TimeoutSec 5
    Assert-OK "remediation CVE-2024-3400" ($rem.count -gt 0)
} catch {
    Assert-OK "remediation CVE-2024-3400" $false $_.Exception.Message
}

# ── 7. Remediation: service lookup ───────────────────────────────────────
try {
    $rem = Invoke-RestMethod -Uri "$BaseUrl/api/v1/remediation?service=smb&port=445" `
        -WebSession $session -TimeoutSec 5
    Assert-OK "remediation service=smb"   ($rem.count -gt 0)
} catch {
    Assert-OK "remediation service=smb" $false $_.Exception.Message
}

# ── 8. Remediation: OT modbus ────────────────────────────────────────────
try {
    $rem = Invoke-RestMethod -Uri "$BaseUrl/api/v1/remediation?service=modbus" `
        -WebSession $session -TimeoutSec 5
    Assert-OK "remediation OT modbus"     ($rem.count -gt 0)
} catch {
    Assert-OK "remediation OT modbus" $false $_.Exception.Message
}

# ── 9. SIEM rules loaded ─────────────────────────────────────────────────
try {
    $rules = Invoke-RestMethod -Uri "$BaseUrl/api/v1/siem/rules" -WebSession $session -TimeoutSec 5
    Assert-OK "SIEM rules caricati"       ($rules.count -ge 5)
} catch {
    Assert-OK "SIEM rules caricati" $false $_.Exception.Message
}

# ── 10. CVE search (static fallback if NVD offline) ──────────────────────
try {
    $cveR = Invoke-RestMethod -Uri "$BaseUrl/api/v1/vuln/cve-search?q=CVE-2024" -WebSession $session -TimeoutSec 8
    Assert-OK "CVE search"                (($cveR.results | Measure-Object).Count -gt 0)
} catch {
    Assert-OK "CVE search" $false $_.Exception.Message
}

# ── 11. Verify ingest endpoint accepts a real event (no demo seed) ───────
try {
    $payload = @{
        source = "smoke-test"
        category = "test"
        severity = "info"
        title = "Smoke test ingest"
        description = "End-to-end test event from aegis-smoke-test.ps1"
        timestamp = (Get-Date -Format "o")
    } | ConvertTo-Json
    $r = Invoke-WebRequest -Uri "$BaseUrl/api/v1/ingest/generic" -Method POST -Body $payload `
        -ContentType "application/json" -UseBasicParsing -TimeoutSec 5
    Assert-OK "ingest accepts real event" ($r.StatusCode -ge 200 -and $r.StatusCode -lt 300)
} catch {
    Assert-OK "ingest accepts real event" $false $_.Exception.Message
}

# ── 12. Network module discover ──────────────────────────────────────────
try {
    $disc = Invoke-RestMethod -Uri "$BaseUrl/api/scan/discover" -WebSession $session -TimeoutSec 10
    Assert-OK "network /discover"         ($disc -ne $null)
} catch {
    Assert-OK "network /discover" $false $_.Exception.Message
}

# ── 13. Threat intel lookup (will be 'not matched' for 8.8.8.8) ──────────
try {
    $ti = Invoke-RestMethod -Uri "$BaseUrl/api/ti/lookup?ip=8.8.8.8" -WebSession $session -TimeoutSec 8
    Assert-OK "threat-intel lookup 8.8.8.8" ($ti -ne $null)
} catch {
    Assert-OK "threat-intel lookup 8.8.8.8" $false $_.Exception.Message
}

# ── 14. Logout clears session ────────────────────────────────────────────
try {
    Invoke-RestMethod -Uri "$BaseUrl/api/v1/auth/logout" -Method POST -WebSession $session -TimeoutSec 5 | Out-Null
    $me2 = Invoke-RestMethod -Uri "$BaseUrl/api/v1/auth/me" -WebSession $session -TimeoutSec 5
    Assert-OK "logout invalida sessione" ($me2.authenticated -eq $false)
} catch {
    Assert-OK "logout invalida sessione" $false $_.Exception.Message
}

# ── Summary ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "─────────────────────────────────────────────" -ForegroundColor DarkGray
$total = $pass + $fail
$color = if ($fail -eq 0) { "Green" } else { "Red" }
Write-Host ("  Risultato: {0} / {1} pass" -f $pass, $total) -ForegroundColor $color
Write-Host ""

if ($fail -gt 0) { exit 1 }
exit 0
