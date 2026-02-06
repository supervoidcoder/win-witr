# Test case sensitivity in process names
# Windows process names are case-insensitive

Write-Host "Testing case sensitivity in process names..." -ForegroundColor Yellow

# Test with different cases
& win-witr explorer.exe | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed: explorer.exe"
    exit 1
}

& win-witr EXPLORER.EXE | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed: EXPLORER.EXE"
    exit 1
}

& win-witr Explorer.exe | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed: Explorer.exe"
    exit 1
}

& win-witr ExPlOrEr.ExE | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed: ExPlOrEr.ExE"
    exit 1
}

Write-Host "Case sensitivity test passed" -ForegroundColor Green
exit 0
