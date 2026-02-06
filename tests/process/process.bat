REM Test system processes that should always be running
win-witr winlogon.exe
win-witr lsass.exe
win-witr win-witr.exe
win-witr wininit.exe 
win-witr explorer.exe
win-witr Registry
win-witr csrss.exe
win-witr fontdrvhost.exe
win-witr svchost.exe
win-witr smss.exe
win-witr services.exe
win-witr powershell.exe
win-witr Runner.Listener.exe
win-witr cmd.exe
win-witr pwsh.exe
win-witr Runner.Worker.exe
win-witr hosted-compute-agent
win-witr conhost.exe
win-witr dwm.exe
win-witr RuntimeBroker.exe
win-witr SearchIndexer.exe
win-witr spoolsv.exe
win-witr taskhostw.exe
win-witr dllhost.exe

REM Start notepad and test it, then close
start /B notepad.exe
timeout /t 1 /nobreak >nul
win-witr notepad.exe
taskkill /F /IM notepad.exe >nul 2>&1

REM Start calc and test it, then close
start /B calc.exe
timeout /t 1 /nobreak >nul
win-witr calc.exe
taskkill /F /IM calc.exe >nul 2>&1

REM Start mspaint and test it, then close
start /B mspaint.exe
timeout /t 1 /nobreak >nul
win-witr mspaint.exe
taskkill /F /IM mspaint.exe >nul 2>&1

REM Start another cmd instance and test it, then close
start /B cmd.exe
timeout /t 1 /nobreak >nul
win-witr cmd.exe
taskkill /F /IM cmd.exe /FI "PID ne %CMDPID%" >nul 2>&1

REM Start PowerShell and test it
start /B powershell.exe -NoProfile -Command "Start-Sleep -Seconds 5"
timeout /t 1 /nobreak >nul
win-witr powershell.exe
REM PowerShell will exit on its own

REM Start another instance of win-witr to test self-lookup
start /B win-witr.exe --help
timeout /t 1 /nobreak >nul
win-witr win-witr.exe

