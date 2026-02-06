# Performance test for PID lookup - 100 iterations
# Measures time taken for each execution to look up a process by PID

Write-Host "Testing PID lookup performance over 100 iterations..." -ForegroundColor Yellow

# Get current PowerShell PID
$currentPid = $PID

# Verify win-witr works before starting measurements
& win-witr --pid $currentPid | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "win-witr --pid command failed"
    exit 1
}

# Run 100 iterations and measure each
Write-Host "Running 100 iterations of win-witr --pid $currentPid..." -ForegroundColor Cyan
1..100 | ForEach-Object { 
    Measure-Command { 
        & win-witr --pid $currentPid | Out-Null
    } | Select-Object TotalMilliseconds 
}

Write-Host "Performance test completed successfully!" -ForegroundColor Green
exit 0
