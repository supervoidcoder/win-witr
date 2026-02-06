param(
    [int]$MaxDepth = 50,
    [int]$CurrentDepth = 0,
    [string]$CurrentShell = "powershell"
)

# Find the script directory and navigate to repository root
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent (Split-Path -Parent $scriptDir)
Set-Location $repoRoot

if ($CurrentDepth -ge $MaxDepth) {
    # We've reached max depth - run the actual test
    Write-Host "Reached depth $CurrentDepth - Running stress test..." -ForegroundColor Green
    
    # Run the measurement
    $result = Measure-Command { 
        & win-witr win-witr.exe | Out-Null
    }
    
    Write-Host "Performance: Nested shell lookup at depth $CurrentDepth took $($result.TotalMilliseconds)ms" -ForegroundColor Cyan
    
    # Verify it actually worked
    if ($LASTEXITCODE -ne 0) {
        Write-Error "win-witr failed at depth $CurrentDepth"
        exit 1
    }
    
    exit 0
}

# Determine next shell
$nextShell = if ($CurrentShell -eq "powershell") { "cmd" } else { "powershell" }
$nextDepth = $CurrentDepth + 1

Write-Host "Layer $CurrentDepth ($CurrentShell) -> spawning $nextShell..." -ForegroundColor Gray

if ($nextShell -eq "cmd") {
    # Spawn CMD which will spawn PowerShell next
    $scriptPath = $MyInvocation.MyCommand.Path
    $cmdCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -MaxDepth $MaxDepth -CurrentDepth $nextDepth -CurrentShell cmd"
    
    cmd.exe /c $cmdCommand
    exit $LASTEXITCODE
} else {
    # Spawn PowerShell
    $scriptPath = $MyInvocation.MyCommand.Path
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -MaxDepth $MaxDepth -CurrentDepth $nextDepth -CurrentShell "powershell"
    exit $LASTEXITCODE
}