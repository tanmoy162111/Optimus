@echo off
echo ============================================================
echo Starting Optimus
echo ============================================================

REM Set VirtualBox path
set VBOX_PATH=D:\Virtualbox\VBoxManage.exe

REM Check if VirtualBox exists at the specified path
if not exist "%VBOX_PATH%" (
    echo ERROR: VirtualBox not found at %VBOX_PATH%
    echo Please check your VirtualBox installation path.
    echo.
    pause
    exit /b 1
)

REM Start Kali VM if not running
echo.
echo [1/3] Checking Kali VM status...
"%VBOX_PATH%" list runningvms | findstr "kali" >nul
if errorlevel 1 (
    echo Kali VM not running. Starting Kali VM...
    "%VBOX_PATH%" startvm "kali" --type headless
    if errorlevel 1 (
        echo ERROR: Failed to start Kali VM. Please check if the VM exists and is properly configured.
        echo You can run setup-vm.bat to find your VM name.
        echo.
        pause
        exit /b 1
    )
    echo Waiting for Kali VM to boot and SSH service to start...
    REM Use ping instead of timeout to avoid input redirection errors
    ping -n 61 127.0.0.1 > nul
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

REM Wait for backend to start
echo Waiting for backend to initialize...
ping -n 6 127.0.0.1 > nul

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