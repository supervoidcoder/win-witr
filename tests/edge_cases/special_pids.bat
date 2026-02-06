REM Test with special PID values

REM PID 0 - System Idle Process
win-witr --pid 0

REM PID 4 - System process
win-witr --pid 4

REM PID 1 (usually doesn't exist on Windows)
win-witr --pid 1
