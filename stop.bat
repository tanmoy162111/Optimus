@echo off
echo ============================================================
echo Stopping Project Optimus
echo ============================================================

REM Stop Backend (Python)
echo.
echo [1/3] Stopping Backend Server...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
    echo Backend stopped.
)

REM Stop Frontend (Node)
echo.
echo [2/3] Stopping Frontend Dev Server...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5173 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
    echo Frontend stopped.
)

REM Optionally stop Kali VM (commented out by default)
REM Uncomment the lines below if you want to stop Kali VM automatically
REM echo.
REM echo [3/3] Stopping Kali VM...
REM VBoxManage controlvm "Kali" poweroff
REM echo Kali VM stopped.

echo.
echo ============================================================
echo Project Optimus Stopped Successfully!
echo ============================================================
echo.
echo Note: Kali VM is still running (stop manually if needed)
echo To stop Kali VM: VBoxManage controlvm "Kali" poweroff
echo.
pause
