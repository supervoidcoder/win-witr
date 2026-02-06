REM Test with unknown/invalid command-line options

REM Unknown long option
win-witr --unknown-option

REM Unknown short option  
win-witr -x

REM Invalid combination
win-witr --pid --port
