# Performance test for process lookup
# Measures time taken to look up the win-witr process itself

Write-Host "Testing process lookup performance..." -ForegroundColor Yellow

# Warm-up run
& win-witr win-witr.exe | Out-Null

# Measure performance - average of 5 runs
$measurements = @()
for ($i = 1; $i -le 5; $i++) {
    $result = Measure-Command {
        & win-witr win-witr.exe | Out-Null
    }
    $measurements += $result.TotalMilliseconds
}

$average = ($measurements | Measure-Object -Average).Average
$min = ($measurements | Measure-Object -Minimum).Minimum
$max = ($measurements | Measure-Object -Maximum).Maximum

Write-Host "Performance: Process lookup took avg=$([Math]::Round($average, 2))ms, min=$([Math]::Round($min, 2))ms, max=$([Math]::Round($max, 2))ms" -ForegroundColor Cyan

# Verify it worked
if ($LASTEXITCODE -ne 0) {
    Write-Error "Process lookup failed"
    exit 1
}

exit 0
