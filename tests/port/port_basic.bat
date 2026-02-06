REM Test basic --port functionality with common Windows ports
REM Windows should have some services listening on these ports

REM Port 135 - RPC Endpoint Mapper (Windows service)
win-witr --port 135

REM Port 445 - SMB (Windows file sharing)
win-witr --port 445
