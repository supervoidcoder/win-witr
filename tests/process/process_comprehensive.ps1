# Comprehensive process name test
# Tests process name lookups with various Windows system processes

Write-Host "Running comprehensive process name lookup test..." -ForegroundColor Yellow

# Common Windows system processes that should exist
$processes = @(
    "explorer.exe",
    "svchost.exe", 
    "csrss.exe",
    "winlogon.exe",
    "lsass.exe",
    "System"
)

foreach ($proc in $processes) {
    Write-Host "  Testing process $proc..." -ForegroundColor Cyan
    & win-witr $proc | Out-Null
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to lookup process $proc"
        exit 1
    }
}

Write-Host "All process lookups successful" -ForegroundColor Green
exit 0
