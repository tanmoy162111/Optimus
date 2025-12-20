@echo off
REM ========================================
REM Optimus - Automated Shutdown Script
REM Stops Backend + Frontend + Kali VM
REM ========================================

echo.
echo ================================================
echo    OPTIMUS - Shutdown Sequence
echo ================================================
echo.

REM Step 1: Kill Backend process
echo [STEP 1/3] Stopping Backend...
tasklist | findstr "python.exe" >nul
if %ERRORLEVEL% EQU 0 (
    for /f "tokens=2" %%a in ('tasklist ^| findstr "python.exe"') do (
        taskkill /PID %%a /F 2>nul
    )
    echo [OK] Backend stopped
) else (
    echo [INFO] Backend not running
)

REM Step 2: Kill Frontend process
echo.
echo [STEP 2/3] Stopping Frontend...
tasklist | findstr "node.exe" >nul
if %ERRORLEVEL% EQU 0 (
    for /f "tokens=2" %%a in ('tasklist ^| findstr "node.exe"') do (
        taskkill /PID %%a /F 2>nul
    )
    echo [OK] Frontend stopped
) else (
    echo [INFO] Frontend not running
)

REM Step 3: Stop Kali VM (optional)
echo.
echo [STEP 3/3] Managing Kali VM...
where VBoxManage >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    choice /C YN /M "Stop Kali VM"
    if ERRORLEVEL 2 goto skip_vm
    if ERRORLEVEL 1 goto stop_vm
    
    :stop_vm
    VBoxManage list runningvms | findstr "Kali" >nul
    if %ERRORLEVEL% EQU 0 (
        for /f "tokens=1 delims= " %%a in ('VBoxManage list runningvms ^| findstr "Kali"') do (
            set KALI_VM=%%a
            set KALI_VM=!KALI_VM:"=!
        )
        echo [INFO] Stopping VM: !KALI_VM!
        VBoxManage controlvm "!KALI_VM!" acpipowerbutton
        echo [OK] Kali VM shutdown initiated
    ) else (
        echo [INFO] Kali VM not running
    )
    goto done
    
    :skip_vm
    echo [INFO] Kali VM left running
) else (
    echo [INFO] VirtualBox not found, skipping VM management
)

:done
echo.
echo ================================================
echo    OPTIMUS STOPPED SUCCESSFULLY!
echo ================================================
echo.
pause
