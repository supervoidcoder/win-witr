$time = Measure-Command { win-witr winlogon.exe | Out-Default }
"winlogon.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr lsass.exe | Out-Default }
"lsass.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr win-witr.exe | Out-Default }
"win-witr.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr wininit.exe | Out-Default }
"wininit.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr explorer.exe | Out-Default }
"explorer.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr Registry | Out-Default }
"Registry check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr csrss.exe | Out-Default }
"csrss.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr fontdrvhost.exe | Out-Default }
"fontdrvhost.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr svchost.exe | Out-Default }
"svchost.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr smss.exe | Out-Default }
"smss.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr services.exe | Out-Default }
"services.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr powershell.exe | Out-Default }
"powershell.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr Runner.Listener.exe | Out-Default }
"Runner.Listener.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr cmd.exe | Out-Default }
"cmd.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr pwsh.exe | Out-Default }
"pwsh.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr Runner.Worker.exe | Out-Default }
"Runner.Worker.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr hosted-compute-agent | Out-Default }
"hosted-compute-agent check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr conhost.exe | Out-Default }
"conhost.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr dwm.exe | Out-Default }
"dwm.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr RuntimeBroker.exe | Out-Default }
"RuntimeBroker.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr SearchIndexer.exe | Out-Default }
"SearchIndexer.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr spoolsv.exe | Out-Default }
"spoolsv.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr taskhostw.exe | Out-Default }
"taskhostw.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr dllhost.exe | Out-Default }
"dllhost.exe check took {0} ms" -f $time.TotalMilliseconds

REM Start notepad and test it, then close
start /B notepad.exe
timeout /t 1 /nobreak >nul
$time = Measure-Command { win-witr notepad.exe | Out-Default }
"notepad.exe check took {0} ms" -f $time.TotalMilliseconds
taskkill /F /IM notepad.exe >nul 2>&1

REM Start calc and test it, then close
start /B calc.exe
timeout /t 1 /nobreak >nul
$time = Measure-Command { win-witr calc.exe | Out-Default }
"calc.exe check took {0} ms" -f $time.TotalMilliseconds
taskkill /F /IM calc.exe >nul 2>&1

REM Start mspaint and test it, then close
start /B mspaint.exe
timeout /t 1 /nobreak >nul
$time = Measure-Command { win-witr mspaint.exe | Out-Default }
"mspaint.exe check took {0} ms" -f $time.TotalMilliseconds
taskkill /F /IM mspaint.exe >nul 2>&1

$time = Measure-Command { win-witr powershell.exe | Out-Default }
"powershell.exe (final check) took {0} ms" -f $time.TotalMilliseconds
