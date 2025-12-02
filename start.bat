@echo off
:: Optimus Start Script for Windows
:: Starts both backend and frontend servers and Kali VM

setlocal enabledelayedexpansion

echo 🚀 Starting Optimus Platform...

:: Set project paths
set PROJECT_ROOT=%~dp0
set BACKEND_DIR=%PROJECT_ROOT%backend
set FRONTEND_DIR=%PROJECT_ROOT%frontend
set LOGS_DIR=%PROJECT_ROOT%logs
set VBOX_PATH=D:\Virtualbox\VBoxManage.exe

:: Create logs directory
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"

:: Check if VirtualBox exists
if not exist "%VBOX_PATH%" (
    echo ERROR: VirtualBox not found at %VBOX_PATH%
    echo Please check your VirtualBox installation path.
    echo.
    pause
    exit /b 1
)

:: Start Kali VM if not running
echo.
echo [1/3] Checking Kali VM status...
"%VBOX_PATH%" list runningvms | findstr "kali" >nul
if errorlevel 1 (
    echo Kali VM not running. Starting Kali VM...
    "%VBOX_PATH%" startvm "kali" --type headless
    if errorlevel 1 (
        echo ERROR: Failed to start Kali VM.
        echo Please check if the VM exists and is properly configured.
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

:: Start Backend
echo.
echo [2/3] Starting Backend Server (Port 5000)...
REM Try multiple Python paths (prioritizing Python 313)
IF EXIST "C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python313\python.exe" (
    echo Using system Python 313
    start "Optimus Backend" /D "%~dp0backend" "C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python313\python.exe" "app.py"
) ELSE IF EXIST "C:\Program Files\Python313\python.exe" (
    echo Using system Python 313
    start "Optimus Backend" /D "%~dp0backend" "C:\Program Files\Python313\python.exe" "app.py"
) ELSE IF EXIST "%~dp0backend\venv\Scripts\python.exe" (
    echo Using virtual environment Python
    start "Optimus Backend" /D "%~dp0backend" "%~dp0backend\venv\Scripts\python.exe" "app.py"
) ELSE IF EXIST "C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python314\python.exe" (
    echo Using system Python 314 (AppData)
    start "Optimus Backend" /D "%~dp0backend" "C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python314\python.exe" "app.py"
) ELSE IF EXIST "C:\Program Files\Python314\python.exe" (
    echo Using system Python 314
    start "Optimus Backend" /D "%~dp0backend" "C:\Program Files\Python314\python.exe" "app.py"
) ELSE (
    echo Trying system Python command...
    start "Optimus Backend" /D "%~dp0backend" python "app.py"
)

:: Wait for backend to start
echo Waiting for backend to initialize...
ping -n 6 127.0.0.1 > nul

:: Start Frontend
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