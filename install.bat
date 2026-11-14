@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title BLACKVEIL Installer

echo ============================================================
echo   BLACKVEIL // ADVANCED CYBER OPERATIONS - INSTALLER
echo ============================================================
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo         Please install Python 3.12+ from https://www.python.org/
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [*] Detected Python %PYVER%

if not exist ".venv" (
    echo [*] Creating isolated virtual environment in .venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo [*] Upgrading pip and installing BLACKVEIL dependencies...
call ".venv\Scripts\python.exe" -m pip install --upgrade pip
call ".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed.
    pause
    exit /b 1
)

echo [*] Registering 'blackveil' CLI entry point inside .venv...
call ".venv\Scripts\python.exe" -m pip install --no-build-isolation -e . >nul 2>&1
if errorlevel 1 (
    call ".venv\Scripts\python.exe" -m pip install -e .
)

echo.
echo [+] Installation complete!
echo [*] Launch interactive terminal : run.bat
echo [*] Direct CLI usage (this dir) : blackveil intel --system
echo [*] Optional global CLI         : Add "%CD%\.venv\Scripts" to your Windows PATH.
echo.
pause
