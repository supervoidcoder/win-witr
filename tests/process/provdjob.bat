@echo off
REM Get the full process name using tasklist
for /f "tokens=1" %%i in ('tasklist ^| findstr /B "provjobd.exe"') do (
    echo Found: %%i
    win-witr %%i
    goto :done
)
echo Could not find provjobd.exe*
:done