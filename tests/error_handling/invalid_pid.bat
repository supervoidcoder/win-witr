REM Test error handling with invalid PID arguments
REM These should handle gracefully and not crash

REM Invalid PID (negative number)
win-witr --pid -1

REM Invalid PID (not a number)
win-witr --pid notanumber

REM Invalid PID (too large)
win-witr --pid 999999999

REM Missing PID argument
win-witr --pid
