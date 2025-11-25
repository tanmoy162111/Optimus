@echo off
echo ============================================================
echo Starting Project Optimus
echo ============================================================

REM Start Kali VM if not running
echo.
echo [1/3] Checking Kali VM status...
VBoxManage list runningvms | findstr "Kali" >nul
if errorlevel 1 (
    echo Kali VM not running. Starting Kali VM...
    VBoxManage startvm "Kali" --type headless
    echo Waiting 30 seconds for Kali VM to boot...
    timeout /t 30 /nobreak >nul
    echo Kali VM started successfully!
) else (
    echo Kali VM already running.
)

REM Start Backend
echo.
echo [2/3] Starting Backend Server (Port 5000)...
start "Optimus Backend" cmd /k "cd /d "%~dp0backend" && venv\Scripts\python.exe app.py"
timeout /t 3 /nobreak >nul

REM Start Frontend
echo.
echo [3/3] Starting Frontend Dev Server (Port 5173)...
start "Optimus Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

echo.
echo ============================================================
echo Project Optimus Started Successfully!
echo ============================================================
echo.
echo Backend:  http://localhost:5000
echo Frontend: http://localhost:5173
echo Kali VM:  10.0.2.15 (headless mode)
echo.
echo Press any key to exit this window...
pause >nul
