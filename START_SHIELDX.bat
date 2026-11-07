@echo off
title SHIELDX - Web Security Header Analyzer
cd /d "%~dp0"

echo ==========================================
echo          SHIELDX SECURITY ANALYZER
echo ==========================================
echo.

where py >nul 2>nul
if %errorlevel%==0 (
    set "PY=py"
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        set "PY=python"
    ) else (
        echo Python was not found.
        echo Install Python 3.9 or newer from https://www.python.org/downloads/
        echo IMPORTANT: Enable "Add Python to PATH" during installation.
        pause
        exit /b 1
    )
)

echo Checking required package...
%PY% -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo.
    echo Could not install dependencies. Check your internet connection.
    pause
    exit /b 1
)

echo.
echo Launching SHIELDX...
%PY% main.py
if %errorlevel% neq 0 (
    echo.
    echo SHIELDX closed with an error. Read the message above.
    pause
)
