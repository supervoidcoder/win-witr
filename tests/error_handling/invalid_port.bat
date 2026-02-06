REM Test error handling with invalid port arguments

REM Invalid port (negative number)
win-witr --port -1

REM Invalid port (not a number)
win-witr --port notanumber

REM Invalid port (too large, max is 65535)
win-witr --port 999999

REM Missing port argument
win-witr --port
