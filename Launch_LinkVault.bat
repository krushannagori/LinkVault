@echo off
rem Resolve the Python launcher from System32/PATH only (never from this folder),
rem so a stray pythonw.exe lying next to this script can't hijack the launch.
set "SCRIPT=%~dp0link_vault.py"
set "PYEXE="
pushd "%SystemRoot%\System32"
for /f "delims=" %%i in ('where pyw 2^>nul') do if not defined PYEXE set "PYEXE=%%i"
if not defined PYEXE for /f "delims=" %%i in ('where pythonw 2^>nul') do if not defined PYEXE set "PYEXE=%%i"
popd
if not defined PYEXE (
    echo Python not found. Install it from python.org and tick "Add Python to PATH".
    pause
    exit /b 1
)
start "" "%PYEXE%" "%SCRIPT%"
