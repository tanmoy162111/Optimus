@echo off
REM ========================================
REM Optimus - Automated Startup Script
REM Starts Backend + Frontend + Kali VM
REM ========================================

echo.
echo ================================================
echo    OPTIMUS - AI Penetration Testing Platform
echo ================================================
echo.

REM Check if VBoxManage exists
where VBoxManage >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] VirtualBox not found in PATH
    echo [INFO] VirtualBox will not be managed automatically
    set SKIP_VBOX=1
) else (
    set SKIP_VBOX=0
)

REM Step 1: Start Kali Linux VM
if %SKIP_VBOX%==0 (
    echo [STEP 1/3] Starting Kali Linux VM...
    VBoxManage list vms | findstr "Kali" >nul
    if %ERRORLEVEL% EQU 0 (
        for /f "tokens=1 delims= " %%a in ('VBoxManage list vms ^| findstr "Kali"') do (
            set KALI_VM=%%a
            set KALI_VM=!KALI_VM:"=!
        )
        VBoxManage showvminfo "!KALI_VM!" | findstr "running" >nul
        if %ERRORLEVEL% NEQ 0 (
            echo [INFO] Starting VM: !KALI_VM!
            VBoxManage startvm "!KALI_VM!" --type headless
            echo [INFO] Waiting 30 seconds for Kali to boot...
            timeout /t 30 /nobreak >nul
            echo [OK] Kali VM started
        ) else (
            echo [INFO] Kali VM already running
        )
    ) else (
        echo [WARNING] No Kali VM found
    )
) else (
    echo [STEP 1/3] Skipping Kali VM (VirtualBox not available)
)

REM Step 2: Start Backend
echo.
echo [STEP 2/3] Starting Optimus Backend...
cd /d "%~dp0"
set "PYTHON_PATH=C:\Users\Tanmoy Saha\AppData\Local\Programs\Python\Python313\python.exe"
if not exist "backend\venv" (
    echo [INFO] Creating Python virtual environment...
    "%PYTHON_PATH%" -m venv backend\venv
)
echo [INFO] Activating virtual environment and starting backend...
start "Optimus Backend" cmd /k "cd /d %~dp0backend && venv\Scripts\activate && python app.py"
timeout /t 3 /nobreak >nul
echo [OK] Backend started

REM Step 3: Start Frontend
echo.
echo [STEP 3/3] Starting Optimus Frontend...
if not exist "frontend\node_modules" (
    echo [INFO] Installing frontend dependencies...
    cd frontend
    call npm install
    cd ..
)
echo [INFO] Starting development server...
start "Optimus Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"
timeout /t 3 /nobreak >nul
echo [OK] Frontend started

REM Done
echo.
echo ================================================
echo    OPTIMUS STARTED SUCCESSFULLY!
echo ================================================
echo.
echo Backend:  http://localhost:5000
echo Frontend: http://localhost:5173
echo.
echo To stop Optimus, run: STOP_OPTIMUS.bat
echo.
pause
