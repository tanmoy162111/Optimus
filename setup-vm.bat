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
    echo Common installation paths:
    echo   D:\Virtualbox\
    echo   C:\Program Files\Oracle\VirtualBox\
    echo   C:\Program Files (x86)\Oracle\VirtualBox\
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
echo Instructions:
echo 1. Note the name of your Kali VM (in quotes)
echo 2. Edit start.bat and replace "kali" with your actual VM name
echo.
echo Example: If your VM is named "kali-linux-2025", change line 15 in start.bat to:
echo start /B "%%VBOX_PATH%%" startvm "kali-linux-2025" --type headless
echo.
echo Also make sure your VM has SSH enabled and port forwarding configured:
echo   Host IP: 127.0.0.1, Host Port: 2222
echo   Guest IP: (leave blank), Guest Port: 22
echo.
pause