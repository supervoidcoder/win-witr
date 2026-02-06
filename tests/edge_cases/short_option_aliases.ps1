# Test short option aliases
# Verify that short options work the same as long options

Write-Host "Testing short option aliases..." -ForegroundColor Yellow

# Test -h vs --help
$helpShort = & win-witr -h 2>&1 | Out-String
$helpLong = & win-witr --help 2>&1 | Out-String

if ($helpShort -ne $helpLong) {
    Write-Warning "Short and long help options produce different output"
}

# Test -v vs --version  
$versionShort = & win-witr -v 2>&1 | Out-String
$versionLong = & win-witr --version 2>&1 | Out-String

if ($versionShort -ne $versionLong) {
    Write-Warning "Short and long version options produce different output"
}

Write-Host "Short option aliases test completed" -ForegroundColor Green
exit 0
