# Performance test for port lookup
# Measures time taken to lookup a process by port number

Write-Host "Testing port lookup performance..." -ForegroundColor Yellow

# Warm-up run - Port 135 is a common Windows service port
& win-witr --port 135 | Out-Null

# Measure performance
$result = Measure-Command {
    & win-witr --port 135 | Out-Null
}

Write-Host "Performance: Port lookup took $($result.TotalMilliseconds)ms" -ForegroundColor Cyan

# Verify it worked (exit code should be 0 regardless of whether port was found)
if ($LASTEXITCODE -ne 0) {
    Write-Error "Port lookup command failed"
    exit 1
}

exit 0
