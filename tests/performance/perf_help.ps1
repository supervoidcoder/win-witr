# Performance test for help command
# Measures time taken to display help information

Write-Host "Testing help command performance..." -ForegroundColor Yellow

# Warm-up run
& win-witr --help | Out-Null

# Measure performance
$result = Measure-Command {
    & win-witr --help | Out-Null
}

Write-Host "Performance: Help command took $($result.TotalMilliseconds)ms" -ForegroundColor Cyan

# Verify it worked
if ($LASTEXITCODE -ne 0) {
    Write-Error "Help command failed"
    exit 1
}

exit 0
