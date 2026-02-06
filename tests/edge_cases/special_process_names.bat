REM Test edge cases with process names

REM Process name with space (should handle gracefully)
win-witr "Windows Defender.exe"

REM Process name without .exe extension (should still work based on repo memory)
win-witr explorer

REM System process (PID 0 or 4)
win-witr System

REM Idle process
win-witr Idle
