# Pre-demo check. Run this after .\run.ps1, before presenting.
#
#   1. the offline guard proves itself (python -m engine.offline)
#   2. every beat of the 7-minute demo works against the running API
#      (scripts/rehearse.py), with the numbers to say on stage
#
# Exit code 0 only if both pass. Takes about 15 seconds on the demo laptop.

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot

Write-Host "`nVERA pre-flight`n" -ForegroundColor Cyan

try {
    $health = Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 5
    Write-Host "  API is up ($($health.version))" -ForegroundColor Green
} catch {
    Write-Host '  API is not reachable. Start it with .\run.ps1' -ForegroundColor Red
    exit 1
}

Write-Host "`nOffline guard" -ForegroundColor Cyan
Push-Location (Join-Path $root 'backend')
python -m engine.offline
$offline = $LASTEXITCODE
Pop-Location

Write-Host "`nDemo beats" -ForegroundColor Cyan
python (Join-Path $root 'scripts\rehearse.py')
$beats = $LASTEXITCODE

if ($offline -eq 0 -and $beats -eq 0) {
    Write-Host "`nREADY" -ForegroundColor Green
    exit 0
}
Write-Host "`nNOT READY: fix the FAIL lines above" -ForegroundColor Red
exit 1
