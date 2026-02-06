REM Test multiple processes in sequence
REM Verifies the tool can handle sequential lookups

win-witr explorer.exe
win-witr svchost.exe
win-witr csrss.exe
win-witr lsass.exe
win-witr winlogon.exe
