$time = Measure-Command { win-witr winlogon | Out-Default }
"winlogon.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr lsass | Out-Default }
"lsass.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr win-witr | Out-Default }
"win-witr.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr wininit | Out-Default }
"wininit.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr explorer | Out-Default }
"explorer.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr Registry | Out-Default }
"Registry check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr csrss | Out-Default }
"csrss.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr fontdrvhost | Out-Default }
"fontdrvhost.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr svchost | Out-Default }
"svchost.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr smss | Out-Default }
"smss.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr services | Out-Default }
"services.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr powershell | Out-Default }
"powershell.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr Runner.Listener.exe | Out-Default }
"Runner.Listener.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr cmd | Out-Default }
"cmd.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr pwsh | Out-Default }
"pwsh.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr Runner.Worker | Out-Default }
"Runner.Worker.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr hosted-compute-agent | Out-Default }
"hosted-compute-agent check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr conhost | Out-Default }
"conhost.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr dwm | Out-Default }
"dwm.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr RuntimeBroker | Out-Default }
"RuntimeBroker.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr SearchIndexer | Out-Default }
"SearchIndexer.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr spoolsv | Out-Default }
"spoolsv.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr taskhostw | Out-Default }
"taskhostw.exe check took {0} ms" -f $time.TotalMilliseconds

$time = Measure-Command { win-witr dllhost | Out-Default }
"dllhost.exe check took {0} ms" -f $time.TotalMilliseconds

