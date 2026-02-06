# Output validation test for --help
# Verifies that help output contains expected sections

Write-Host "Testing help output format..." -ForegroundColor Yellow

$output = & win-witr --help 2>&1 | Out-String

# Check if output contains the exact expected help sections from main.cpp
$hasUsage = $output -match "Usage:"
$hasOptions = $output -match "Options:"
$hasHelp = $output -match "--help"

if (-not $hasUsage -or -not $hasOptions -or -not $hasHelp) {
    Write-Error "Help output doesn't contain expected sections (Usage:, Options:, --help)"
    exit 1
}

Write-Host "Help output format is valid" -ForegroundColor Green
exit 0
