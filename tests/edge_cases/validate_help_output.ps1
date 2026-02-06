# Output validation test for --help
# Verifies that help output contains expected sections

Write-Host "Testing help output format..." -ForegroundColor Yellow

$output = & win-witr --help 2>&1 | Out-String

# Check if output contains the exact expected help sections from main.cpp
$hasUsage = $output -match "Usage:"
$hasOptions = $output -match "Options:"

if (-not $hasUsage -or -not $hasOptions) {
    Write-Error "Help output doesn't contain expected sections (Usage: and Options:)"
    exit 1
}

Write-Host "Help output format is valid" -ForegroundColor Green
exit 0
