# Stress test: Rapid sequential process lookups
# Tests if the tool can handle many rapid calls without crashing

Write-Host "Running rapid sequential lookup stress test..." -ForegroundColor Yellow

$iterations = 50
$processes = @("explorer.exe", "svchost.exe", "csrss.exe")

for ($i = 0; $i -lt $iterations; $i++) {
    $proc = $processes[$i % $processes.Length]
    & win-witr $proc | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed on iteration $i with process $proc"
        exit 1
    }
}

Write-Host "Successfully completed $iterations rapid lookups" -ForegroundColor Green
exit 0
