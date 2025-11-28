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

REM Stop Kali VM
set VBOX_PATH=D:\Virtualbox\VBoxManage.exe
echo.
echo [3/3] Stopping Kali VM...
"%VBOX_PATH%" controlvm "kali" poweroff
if %errorlevel%==0 (
    echo Kali VM powered off.
) else (
    echo Warning: Failed to power off Kali VM. Please ensure VBoxManage path and VM name are correct.
)

echo.
echo ============================================================
echo Project Optimus Stopped Successfully!
echo ============================================================
echo.
pause