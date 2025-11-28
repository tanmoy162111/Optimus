@echo off
echo ============================================================
echo VirtualBox VM Setup Helper
echo ============================================================
echo.
echo This script will help you find your Kali VM name.
echo.

REM Try common VirtualBox installation paths
set VBOX_PATH=
if exist "D:\Virtualbox\VBoxManage.exe" set VBOX_PATH=D:\Virtualbox\VBoxManage.exe
if exist "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" set VBOX_PATH=C:\Program Files\Oracle\VirtualBox\VBoxManage.exe
if exist "C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe" set VBOX_PATH=C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe

if "%VBOX_PATH%"=="" (
    echo ERROR: VirtualBox not found in standard locations.
    echo Please install VirtualBox or add VBoxManage to PATH.
    echo.
    pause
    exit /b 1
)

echo VirtualBox found at: %VBOX_PATH%
echo.
echo Your VMs:
echo ----------------------------------------
"%VBOX_PATH%" list vms
echo ----------------------------------------
echo.
echo Copy the VM name (in quotes) and update start.bat
echo Replace "kali" with your actual VM name on line 15
echo.
echo Example: If your VM is "kali-linux-2025", change line 15 to:
echo "%VBOX_PATH%" startvm "kali-linux-2025" --type headless
echo.
pause