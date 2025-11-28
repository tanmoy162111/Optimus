@echo off
echo ============================================================
echo Starting Optimus
echo ============================================================

REM Set VirtualBox path
set VBOX_PATH=D:\Virtualbox\VBoxManage.exe

REM Start Kali VM if not running
echo.
echo [1/3] Checking Kali VM status...
"%VBOX_PATH%" list runningvms | findstr "kali" >nul
if errorlevel 1 (
    echo Kali VM not running. Starting Kali VM...
    "%VBOX_PATH%" startvm "kali" --type headless
    echo Waiting 60 seconds for Kali VM to boot and SSH service to start...
    timeout /t 60 /nobreak >nul
    echo Kali VM started successfully!
) else (
    echo Kali VM already running.
)

REM Start Backend
echo.
echo [2/3] Starting Backend Server (Port 5000)...
IF EXIST "%~dp0backend\venv\Scripts\python.exe" (
    start "Optimus Backend" /D "%~dp0backend" "%~dp0backend\venv\Scripts\python.exe" "app.py"
) ELSE (
    echo Virtualenv Python not found, using system Python
    start "Optimus Backend" /D "%~dp0backend" python "app.py"
)

REM Start Frontend
echo.
echo [3/3] Starting Frontend Dev Server (Port 5173)...
start "Optimus Frontend" /D "%~dp0frontend" cmd /k "npm run dev"

echo.
echo ============================================================
echo Optimus Started Successfully!
echo ============================================================
echo.
echo Backend:  http://localhost:5000
echo Frontend: http://localhost:5173
echo Kali VM:  127.0.0.1:2222 (SSH port forwarding)
echo.
echo Press any key to exit this window...
pause >nul