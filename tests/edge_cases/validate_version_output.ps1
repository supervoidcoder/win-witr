# Output validation test for --version
# Verifies that version output contains expected information

Write-Host "Testing version output format..." -ForegroundColor Yellow

$output = & win-witr --version 2>&1 | Out-String

# Check if output contains version-related keywords
$hasVersion = $output -match "version|v\d+\.\d+|win-witr"

if (-not $hasVersion) {
    Write-Error "Version output doesn't contain expected information"
    exit 1
}

Write-Host "Version output format is valid" -ForegroundColor Green
exit 0
