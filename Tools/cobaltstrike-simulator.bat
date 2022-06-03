:: Taken from: https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/cobaltstrike/cobaltstrike-simulation.bat
:: Latest commit 64d8acb 

ECHO ===========================================================================
ECHO Simulate CobaltStrike Beacon Activity

ECHO.
ECHO --- Create some default Named Pipes ...

ECHO Creating Named Pipe number 1: MSSE-1337-server
start "" "%TEMP%\CreateNamedPipe.exe" MSSE-1337-server
timeout /t 1
ECHO Killing named pipe creator for pipe 1
taskkill /IM CreateNamedPipe.exe /F

ECHO Creating Named Pipe number 2 (P2P communication): msagent_fedac123
start "" "%TEMP%\CreateNamedPipe.exe" msagent_fedac123
timeout /t 1
ECHO Killing named pipe creator for pipe 2
taskkill /IM CreateNamedPipe.exe /F

ECHO Creating Named Pipe number 3 (Post Exploitation): postex_ssh_fedac123
start "" "%TEMP%\CreateNamedPipe.exe" postex_ssh_fedac123
timeout /t 1
ECHO Killing named pipe creator for pipe 3
taskkill /IM CreateNamedPipe.exe /F

del %TEMP%\CreateNamedPipe.exe
del %TEMP%\cs-simulator.bat