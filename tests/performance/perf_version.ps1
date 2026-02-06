# Performance test for version command
# Measures time taken to display version information

Write-Host "Testing version command performance..." -ForegroundColor Yellow

# Warm-up run
& win-witr --version | Out-Null

# Measure performance
$result = Measure-Command {
    & win-witr --version | Out-Null
}

Write-Host "Performance: Version command took $($result.TotalMilliseconds)ms" -ForegroundColor Cyan

# Verify it worked
if ($LASTEXITCODE -ne 0) {
    Write-Error "Version command failed"
    exit 1
}

exit 0
