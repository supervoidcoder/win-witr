REM Test with non-existent process names
REM These should not crash the program

win-witr ThisProcessDoesNotExist123456.exe
win-witr NonExistentProcess.exe
win-witr FakeProcess999.exe
