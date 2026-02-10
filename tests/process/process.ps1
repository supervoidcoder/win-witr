
Measure-Command { win-witr winlogon.exe | Out-Default}
Measure-Command { win-witr lsass.exe | Out-Default}
Measure-Command { win-witr win-witr.exe | Out-Default} 
Measure-Command { win-witr wininit.exe | Out-Default} 
Measure-Command { win-witr explorer.exe | Out-Default} 
Measure-Command { win-witr Registry| Out-Default}
Measure-Command { win-witr csrss.exe| Out-Default}
Measure-Command { win-witr fontdrvhost.exe | Out-Default}
Measure-Command { win-witr svchost.exe | Out-Default}
Measure-Command { win-witr smss.exe | Out-Default}
Measure-Command { win-witr services.exe | Out-Default} 
Measure-Command { win-witr powershell.exe | Out-Default }
Measure-Command { win-witr Runner.Listener.exe | Out-Default} 
Measure-Command { win-witr cmd.exe | Out-Default}
Measure-Command { win-witr pwsh.exe | Out-Default}
Measure-Command { win-witr Runner.Worker.exe | Out-Default}
Measure-Command { win-witr hosted-compute-agent | Out-Default}
Measure-Command { win-witr conhost.exe | Out-Default}
Measure-Command { win-witr dwm.exe | Out-Default}
Measure-Command { win-witr RuntimeBroker.exe | Out-Default}
Measure-Command { win-witr SearchIndexer.exe | Out-Default}
Measure-Command { win-witr spoolsv.exe | Out-Default}
Measure-Command { win-witr taskhostw.exe | Out-Default}
Measure-Command { win-witr dllhost.exe | Out-Default}

Measure-Command { win-witr powershell.exe | Out-Default}



