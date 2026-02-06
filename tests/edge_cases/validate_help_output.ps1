# Output validation test for --help
# Verifies that help output contains expected sections

Write-Host "Testing help output format..." -ForegroundColor Yellow

$output = & win-witr --help 2>&1 | Out-String

# Check if output contains expected help sections
$hasUsage = $output -match "usage|Usage|USAGE"
$hasOptions = $output -match "options|Options|help|--help|-h"

if (-not $hasUsage -and -not $hasOptions) {
    Write-Error "Help output doesn't contain expected sections"
    exit 1
}

Write-Host "Help output format is valid" -ForegroundColor Green
exit 0
