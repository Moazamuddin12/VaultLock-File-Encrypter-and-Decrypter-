@echo off
setlocal
title VaultLock
cd /d "%~dp0"

rem ---------------------------------------------------------------------------
rem  VaultLock launcher for Windows.  Double-click it, or run it from any shell.
rem  First run: finds Python 3.11+, builds .venv, installs VaultLock (about a minute).
rem  Every later run: just starts the app.   Uses a .bat on purpose: no PowerShell
rem  execution-policy problems, no activation step.
rem ---------------------------------------------------------------------------

set "VPY=%~dp0.venv\Scripts\python.exe"

if exist "%VPY%" goto install_check

rem A .venv folder without Scripts\python.exe is broken or was made by a non-Windows
rem Python (MSYS2 / Cygwin / Git Bash make bin\ and lib\).  Remove it and start clean.
if exist "%~dp0.venv" echo Removing an incomplete or incompatible .venv folder...
if exist "%~dp0.venv" rmdir /s /q "%~dp0.venv"

set "PYCMD="
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if not errorlevel 1 set "PYCMD=py -3"
if defined PYCMD goto make_venv
python -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if not errorlevel 1 set "PYCMD=python"
if defined PYCMD goto make_venv

echo.
echo  Could not find Python 3.11 or newer.
echo.
echo  1. Download the Windows installer from https://www.python.org/downloads/
echo  2. On the first screen tick "Add python.exe to PATH", then install.
echo  3. Close this window and double-click start_vaultlock.bat again.
echo.
pause
exit /b 1

:make_venv
echo Creating the virtual environment with: %PYCMD%
%PYCMD% -m venv "%~dp0.venv"
if exist "%VPY%" goto install_check

echo.
echo  The virtual environment could not be created in the standard Windows layout.
echo  The Python on your PATH is probably not the official Windows build
echo  (for example the one that ships with MSYS2, Cygwin or Git Bash).
echo  Install Python from https://www.python.org/downloads/ (tick "Add to PATH"),
echo  then run this file again.
echo.
pause
exit /b 1

:install_check
"%VPY%" -c "import cryptography, flask, argon2" >nul 2>nul
if not errorlevel 1 goto launch

echo Installing VaultLock and its dependencies (first run only)...
"%VPY%" -m pip install --disable-pip-version-check -e .
if errorlevel 1 goto install_failed
goto launch

:install_failed
echo.
echo  Installation failed. Check your internet connection and read the message above.
echo  If it mentions "Microsoft Visual C++", install the "Build Tools" or use Python 3.11-3.13.
echo.
pause
exit /b 1

:launch
echo.
echo  Starting VaultLock. Your browser will open in a moment.
echo  Keep this window open while you use it. To quit: close it, or press Ctrl+C.
echo.
"%VPY%" -m vaultlock gui --browser
if errorlevel 1 goto crashed
exit /b 0

:crashed
echo.
echo  VaultLock stopped with an error (see above).
pause
exit /b 1
