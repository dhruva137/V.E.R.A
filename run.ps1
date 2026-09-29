# Starts VERA for a demo: API (NTRO mode) and dashboard, then warms the local model.
#
#   .\run.ps1                 start both, wait until each answers, warm qwen3:1.7b
#   .\run.ps1 -Rehearse       also run the demo rehearsal checks (scripts/rehearse.py)
#   .\run.ps1 -Demo           also offer "Explore the demo" on the sign-in screen (a
#                             passwordless analyst account, this machine only)
#
# Two processes, so the dashboard can be restarted without losing the scan state
# the API holds. `python main.py` fills the NTRO defaults for anything unset:
# read-only agent, local qwen3:1.7b, VERA_OFFLINE=1. Nothing here needs the
# internet; the only network use is Ollama on this machine.

param([switch]$Rehearse, [switch]$Demo)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$started = Get-Date
Write-Host 'VERA: starting API and dashboard' -ForegroundColor Cyan

function Test-LocalPort {
    param([int]$Port)
    # Connect rather than parse netstat: the same check a browser makes.
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(400)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Wait-Until {
    param([scriptblock]$Ready, [int]$Seconds, [string]$What)
    foreach ($i in 1..$Seconds) {
        if (& $Ready) { return $true }
        Start-Sleep -Seconds 1
    }
    Write-Host "  $What did not come up in $Seconds s" -ForegroundColor Red
    return $false
}

# Clear orphaned uvicorn reloader workers still holding port 8000. They survive
# when a supervisor is killed without its worker; the next start then fails to
# bind and the OLD worker keeps serving stale code.
$orphans = @(Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like '*multiprocessing-fork*' })
foreach ($o in $orphans) {
    Write-Host "  clearing orphaned worker $($o.ProcessId)" -ForegroundColor DarkYellow
    Stop-Process -Id $o.ProcessId -Force -ErrorAction SilentlyContinue
}

if (Test-LocalPort -Port 8000) {
    Write-Host '  port 8000 is already in use: another API is running. Stop it first.' -ForegroundColor Red
    exit 1
}

if (-not (Test-Path (Join-Path $root 'frontend\node_modules'))) {
    Write-Host '  installing frontend dependencies (first run only)...' -ForegroundColor Yellow
    Push-Location (Join-Path $root 'frontend')
    cmd /c "npm install"
    Pop-Location
}

$demoEnv = if ($Demo) { "`$env:VERA_DEMO_LOGIN='1'; " } else { '' }
Start-Process powershell -ArgumentList @(
    '-NoExit', '-Command',
    "Set-Location '$root\backend'; ${demoEnv}Write-Host 'VERA API -> http://localhost:8000/docs' -ForegroundColor Green; python main.py"
)

# Vite through cmd /c: a PowerShell host can stall on npm's own shell shim.
if (-not (Test-LocalPort -Port 5173)) {
    Start-Process cmd -ArgumentList @('/k', "cd /d `"$root\frontend`" && npm run dev")
}

$apiUp = Wait-Until -Seconds 60 -What 'API' -Ready {
    try { (Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 2).status -eq 'ok' } catch { $false }
}
$uiUp = Wait-Until -Seconds 60 -What 'Dashboard' -Ready { Test-LocalPort -Port 5173 }

# The first model call loads it (about 27 s on the demo laptop); pay that now,
# not in front of the judges. Ollama is on this machine, so this stays offline.
$modelWarm = $false
if (Test-LocalPort -Port 11434) {
    Write-Host '  warming qwen3:1.7b...' -ForegroundColor Yellow
    try {
        $body = @{ model = 'qwen3:1.7b'; prompt = 'ready'; stream = $false; keep_alive = '2h'; think = $false } |
            ConvertTo-Json
        Invoke-RestMethod 'http://127.0.0.1:11434/api/generate' -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 120 | Out-Null
        $modelWarm = $true
    } catch {
        Write-Host "  model warm-up failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
} else {
    Write-Host '  Ollama is not running: the agent will say so; everything else works.' -ForegroundColor DarkYellow
}

$elapsed = [int]((Get-Date) - $started).TotalSeconds
Write-Host ''
Write-Host ("  API        {0}  http://localhost:8000/docs" -f $(if ($apiUp) { 'up  ' } else { 'DOWN' })) -ForegroundColor $(if ($apiUp) { 'Green' } else { 'Red' })
Write-Host ("  Dashboard  {0}  http://localhost:5173" -f $(if ($uiUp) { 'up  ' } else { 'DOWN' })) -ForegroundColor $(if ($uiUp) { 'Green' } else { 'Red' })
Write-Host ("  Model      {0}" -f $(if ($modelWarm) { 'warm (qwen3:1.7b, local)' } else { 'not warmed' })) -ForegroundColor $(if ($modelWarm) { 'Green' } else { 'DarkYellow' })
Write-Host "  Ready in $elapsed s" -ForegroundColor Cyan

if ($Rehearse -and $apiUp) {
    Write-Host ''
    python (Join-Path $root 'scripts\rehearse.py')
}
