# Performance test for process lookup - 100 iterations
# Measures time taken for each execution to look up a process by name

Write-Host "Testing process lookup performance over 100 iterations..." -ForegroundColor Yellow

# Verify win-witr works before starting measurements
& win-witr win-witr.exe | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "win-witr process lookup failed"
    exit 1
}

# Run 100 iterations and measure each
Write-Host "Running 100 iterations of win-witr win-witr.exe..." -ForegroundColor Cyan
1..100 | ForEach-Object { 
    Measure-Command { 
        & win-witr win-witr.exe | Out-Null
    } | Select-Object TotalMilliseconds 
}

Write-Host "Performance test completed successfully!" -ForegroundColor Green
exit 0
