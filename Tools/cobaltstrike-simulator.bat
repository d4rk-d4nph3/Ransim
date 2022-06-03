@ECHO OFF

ECHO ===========================================================================
ECHO Simulate CobaltStrike Beacon Activity
ping -n 3 127.0.0.1 > NUL

ECHO.
ECHO --- Create some default Named Pipes ...
ping -n 2 127.0.0.1 > NUL

ECHO Creating Named Pipe number 1: MSSE-1337-server
start "" "%TEMP%\CreateNamedPipe.exe" MSSE-1337-server
timeout /t 5
ECHO Killing named pipe creator for pipe 1
taskkill /IM CreateNamedPipe.exe /F

ECHO Creating Named Pipe number 2 (P2P communication): msagent_fedac123
start "" "%TEMP%\CreateNamedPipe.exe" msagent_fedac123
timeout /t 5
ECHO Killing named pipe creator for pipe 2
taskkill /IM CreateNamedPipe.exe /F

ECHO Creating Named Pipe number 3 (Post Exploitation): postex_ssh_fedac123
start "" "%TEMP%\CreateNamedPipe.exe" postex_ssh_fedac123
timeout /t 5
ECHO Killing named pipe creator for pipe 3
taskkill /IM CreateNamedPipe.exe /F

del %TEMP%\CreateNamedPipe.exe