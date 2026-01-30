@echo off
echo Running nested shell stress test...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0stress_nested_shells.ps1" -MaxDepth 100
if %ERRORLEVEL% neq 0 (
    echo Stress test failed!
    exit /b 1
)
echo Stress test passed!
exit /b 0