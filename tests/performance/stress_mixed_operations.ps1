# Stress test: Mixed operation types
# Tests switching between different lookup modes rapidly

Write-Host "Running mixed operation stress test..." -ForegroundColor Yellow

$iterations = 30

for ($i = 0; $i -lt $iterations; $i++) {
    # Alternate between different lookup modes
    switch ($i % 4) {
        0 {
            & win-witr --pid 4 | Out-Null
        }
        1 {
            & win-witr --port 135 | Out-Null
        }
        2 {
            & win-witr explorer.exe | Out-Null
        }
        3 {
            & win-witr --help | Out-Null
        }
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed on iteration $i"
        exit 1
    }
}

Write-Host "Successfully completed $iterations mixed operations" -ForegroundColor Green
exit 0
