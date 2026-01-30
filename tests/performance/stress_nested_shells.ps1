param(
    [int]$MaxDepth = 50,
    [int]$CurrentDepth = 0,
    [string]$CurrentShell = "powershell"
)

# Ensure win-witr.exe is in PATH or current directory
$exePath = if (Test-Path ".\win-witr.exe") { ".\win-witr.exe" } else { "win-witr.exe" }

if ($CurrentDepth -ge $MaxDepth) {
    # We've reached max depth - run the actual test
    Write-Host "✓ Reached depth $CurrentDepth - Running stress test..." -ForegroundColor Green
    
    # Run the measurement
    $result = Measure-Command { 
        & $exePath $exePath 
    }
    
    Write-Host "⏱ Time taken at depth ${CurrentDepth}: $($result.TotalMilliseconds)ms" -ForegroundColor Cyan
    
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

Write-Host "Layer $CurrentDepth ($CurrentShell) → spawning $nextShell..." -ForegroundColor Gray

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