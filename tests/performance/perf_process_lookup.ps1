# Performance test for process name lookup
# Measures time taken to lookup a process by name

Write-Host "Testing process lookup performance..." -ForegroundColor Yellow

# Warm-up run - explorer.exe is always running on Windows
& win-witr explorer.exe | Out-Null

# Measure performance
$result = Measure-Command {
    & win-witr explorer.exe | Out-Null
}

Write-Host "Performance: Process lookup took $($result.TotalMilliseconds)ms" -ForegroundColor Cyan

# Verify it worked
if ($LASTEXITCODE -ne 0) {
    Write-Error "Process lookup command failed"
    exit 1
}

exit 0
