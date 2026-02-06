# Comprehensive PID lookup test
# Tests PID lookups with various system processes

Write-Host "Running comprehensive PID lookup test..." -ForegroundColor Yellow

# Get some actual PIDs from running processes
$systemPIDs = @(4)  # System process always exists

# Try to get explorer.exe PID (usually running)
$explorerProc = Get-Process -Name "explorer" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($explorerProc) {
    $systemPIDs += $explorerProc.Id
}

# Try to get a svchost.exe PID (always running)
$svchostProc = Get-Process -Name "svchost" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($svchostProc) {
    $systemPIDs += $svchostProc.Id
}

foreach ($pid in $systemPIDs) {
    Write-Host "  Testing PID $pid..." -ForegroundColor Cyan
    & win-witr --pid $pid | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to lookup PID $pid"
        exit 1
    }
}

Write-Host "All PID lookups successful" -ForegroundColor Green
exit 0
