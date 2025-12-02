@echo off
:: Optimus Stop Script for Windows
:: Stops both backend and frontend servers

echo 🛑 Stopping Optimus Platform...

:: Kill Python processes (backend)
echo 🔧 Stopping Backend Server...
taskkill /f /im python.exe /fi "WINDOWTITLE eq Optimus Backend*" 2>nul

:: Kill Node.js processes (frontend)
echo 🎨 Stopping Frontend Server...
taskkill /f /im node.exe /fi "WINDOWTITLE eq Optimus Frontend*" 2>nul

:: Alternative method using port numbers
echo 🧹 Cleaning up any remaining processes...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000') do taskkill /f /pid %%a 2>nul
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5173') do taskkill /f /pid %%a 2>nul

echo ✅ Optimus Platform Stopped!

pause