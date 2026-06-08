@echo off
setlocal ENABLEEXTENSIONS

REM === CONFIG ===
set PROCMON_PATH=C:\Temp\Procmon64.exe
set OUTPUT_DIR=C:\Temp\ProcmonCaptures

set TS=%DATE:~-4%%DATE:~4,2%%DATE:~7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%
set TS=%TS: =0%
set TS=%TS::=%

set CAPTURE=%OUTPUT_DIR%\Procmon_%COMPUTERNAME%_%TS%.pml

REM === PREP ===
if not exist "%PROCMON_PATH%" exit /b 1
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM === START CAPTURE ===
"%PROCMON_PATH%" /AcceptEula /Quiet /Minimized /BackingFile "%CAPTURE%"

REM === WAIT 30s ===
timeout /t 30 /nobreak >nul

REM === HARD STOP (RELIABLE) ===
taskkill /F /T /IM Procmon64.exe >nul 2>&1

echo Procmon capture saved to:
echo %CAPTURE%
exit /b 0