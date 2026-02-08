# MSI Mystic Light Bricker Launcher
# PowerShell script to run the bricker with admin privileges

param(
    [switch]$List,
    [switch]$Help
)

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
    $scriptPath = $MyInvocation.MyCommand.Path
    $args = @()
    if ($List) { $args += "-List" }
    if ($Help) { $args += "-Help" }
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" $args"
    exit
}

# Change to script directory
Set-Location $PSScriptRoot

Write-Host "MSI Mystic Light Bricker" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[OK] $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Python from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "Make sure to check 'Add Python to PATH' during installation" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if hidapi is installed
$hidCheck = python -c "import hid" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "[*] Installing required dependency: hidapi" -ForegroundColor Yellow
    pip install hidapi
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to install hidapi" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "[OK] hidapi installed" -ForegroundColor Green
}

Write-Host ""

# Build arguments
$pyArgs = @()
if ($List) { $pyArgs += "--list" }
if ($Help) { $pyArgs += "--help" }

# Run the script
if ($pyArgs.Count -gt 0) {
    python msi_mystic_light_bricker.py @pyArgs
} else {
    python msi_mystic_light_bricker.py
}

# Keep window open
Write-Host ""
Read-Host "Press Enter to exit"
