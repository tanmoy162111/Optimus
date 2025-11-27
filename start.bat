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
    echo Waiting 60 seconds for Kali VM to boot...
    timeout /t 60 /nobreak >nul
    echo Kali VM started successfully!
) else (
    echo Kali VM already running.
)

REM Start Backend
echo.
echo [2/3] Starting Backend Server (Port 5000)...
IF EXIST "%~dp0backend\venv\Scripts\python.exe" (
    start "Optimus Backend" "%~dp0backend\venv\Scripts\python.exe" "%~dp0backend\app.py"
) ELSE (
    echo Virtualenv Python not found, using system Python
    start "Optimus Backend" python "%~dp0backend\app.py"
)
timeout /t 3 /nobreak >nul

REM Start Frontend
echo.
echo [3/3] Starting Frontend Dev Server (Port 5173)...
start "Optimus Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ============================================================
echo Optimus Started Successfully!
echo ============================================================
echo.
echo Backend:  http://localhost:5000
echo Frontend: http://localhost:5173
echo Kali VM:  10.0.2.15 (headless mode)
echo.
echo Press any key to exit this window...
pause >nul
