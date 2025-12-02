@echo off
REM Wrapper script to run Optimus from Windows CMD
REM This avoids Git Bash environment issues

echo ============================================================
echo Starting Optimus from Windows CMD
echo ============================================================

REM Change to the project directory
cd /d D:\Work\Ai Engineering\Git\Optimus

REM Run the main start script
call start.bat

echo.
echo Press any key to exit...
pause >nul