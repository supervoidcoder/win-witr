# Performance test for PID lookup
# Measures time taken to look up a process by PID

Write-Host "Testing PID lookup performance..." -ForegroundColor Yellow

# Get current PowerShell PID
$currentPid = $PID

# Warm-up run
& win-witr --pid $currentPid | Out-Null

# Measure performance - average of 5 runs
$measurements = @()
for ($i = 1; $i -le 5; $i++) {
    $result = Measure-Command {
        & win-witr --pid $currentPid | Out-Null
    }
    $measurements += $result.TotalMilliseconds
}

$average = ($measurements | Measure-Object -Average).Average
$min = ($measurements | Measure-Object -Minimum).Minimum
$max = ($measurements | Measure-Object -Maximum).Maximum

Write-Host "Performance: PID lookup took avg=$([Math]::Round($average, 2))ms, min=$([Math]::Round($min, 2))ms, max=$([Math]::Round($max, 2))ms" -ForegroundColor Cyan

# Verify it worked
if ($LASTEXITCODE -ne 0) {
    Write-Error "PID lookup failed"
    exit 1
}

exit 0
