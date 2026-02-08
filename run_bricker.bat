@echo off
:: MSI Mystic Light Bricker Launcher
:: Runs the Python script with administrator privileges

:: Check if running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Change to script directory
cd /d "%~dp0"

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

:: Check if hidapi is installed
python -c "import hid" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing required dependency: hidapi
    pip install hidapi
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install hidapi
        pause
        exit /b 1
    )
)

:: Run the script
python msi_mystic_light_bricker.py %*

:: Keep window open
echo.
pause
