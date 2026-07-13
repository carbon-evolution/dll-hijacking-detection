@echo off
REM ============================================================
REM  DLL Hijacking Detection - one-click runner for Windows
REM  Double-click this file. It installs dependencies (once)
REM  and runs the scan. Right-click > "Run as administrator"
REM  for the most complete results.
REM ============================================================

cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    set PY=py
) else (
    set PY=python
)

echo Installing dependencies (first run only)...
%PY% -m pip install -r requirements.txt

echo.
echo Starting DLL hijacking scan...
%PY% find_suspicious_dlls.py

echo.
echo Done. Reports were saved in the "reports" folder.
pause
