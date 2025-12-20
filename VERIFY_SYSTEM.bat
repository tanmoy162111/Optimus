@echo off
REM ========================================
REM Optimus System Verification Script
REM Checks all dependencies and configuration
REM ========================================

setlocal enabledelayedexpansion
set ERRORS=0

echo.
echo ================================================
echo    OPTIMUS - System Verification
echo ================================================
echo.

REM Check Python
echo [CHECK 1/8] Python installation...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Python not found in PATH
    set /a ERRORS+=1
) else (
    for /f "tokens=2" %%a in ('python --version 2^>^&1') do set PY_VER=%%a
    echo [OK] Python !PY_VER! found
)

REM Check Node.js
echo.
echo [CHECK 2/8] Node.js installation...
node --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] Node.js not found in PATH
    set /a ERRORS+=1
) else (
    for /f %%a in ('node --version') do set NODE_VER=%%a
    echo [OK] Node.js !NODE_VER! found
)

REM Check npm
echo.
echo [CHECK 3/8] npm installation...
npm --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] npm not found
    set /a ERRORS+=1
) else (
    for /f %%a in ('npm --version') do set NPM_VER=%%a
    echo [OK] npm !NPM_VER! found
)

REM Check VirtualBox
echo.
echo [CHECK 4/8] VirtualBox installation...
where VBoxManage >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] VirtualBox not found (optional)
) else (
    for /f "tokens=6" %%a in ('VBoxManage --version 2^>^&1') do set VBOX_VER=%%a
    echo [OK] VirtualBox found
    
    REM Check for Kali VM
    VBoxManage list vms | findstr "Kali" >nul
    if %ERRORLEVEL% EQU 0 (
        echo [OK] Kali VM found
    ) else (
        echo [WARN] Kali VM not found
    )
)

REM Check backend .env file
echo.
echo [CHECK 5/8] Backend configuration...
if exist "backend\.env" (
    echo [OK] .env file exists
    findstr "KALI_HOST" backend\.env >nul
    if %ERRORLEVEL% EQU 0 (
        echo [OK] KALI_HOST configured
    ) else (
        echo [WARN] KALI_HOST not set in .env
    )
) else (
    echo [FAIL] .env file missing in backend/
    echo [INFO] Copy .env.example to .env and configure
    set /a ERRORS+=1
)

REM Check backend dependencies
echo.
echo [CHECK 6/8] Backend dependencies...
if exist "backend\venv\Scripts\python.exe" (
    echo [OK] Virtual environment exists
) else (
    echo [WARN] Virtual environment not created
    echo [INFO] Run: cd backend ^&^& python -m venv venv
)

REM Check frontend dependencies
echo.
echo [CHECK 7/8] Frontend dependencies...
if exist "frontend\node_modules" (
    echo [OK] node_modules exists
) else (
    echo [WARN] Frontend dependencies not installed
    echo [INFO] Run: cd frontend ^&^& npm install
)

REM Check required ports
echo.
echo [CHECK 8/8] Port availability...
netstat -an | findstr ":5000" | findstr "LISTENING" >nul
if %ERRORLEVEL% EQU 0 (
    echo [WARN] Port 5000 already in use
) else (
    echo [OK] Port 5000 available (Backend)
)

netstat -an | findstr ":5173" | findstr "LISTENING" >nul
if %ERRORLEVEL% EQU 0 (
    echo [WARN] Port 5173 already in use
) else (
    echo [OK] Port 5173 available (Frontend)
)

REM Summary
echo.
echo ================================================
if %ERRORS% EQU 0 (
    echo    STATUS: READY TO START
    echo ================================================
    echo.
    echo All critical checks passed!
    echo Run START_OPTIMUS.bat to launch
) else (
    echo    STATUS: ISSUES DETECTED
    echo ================================================
    echo.
    echo Found %ERRORS% critical error(s^)
    echo Please fix the issues above before starting
)
echo.
pause
