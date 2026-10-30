@echo off
cd /d "%~dp0"
echo ============================================
echo  CDN Accelerator - Uninstall / Restore
echo ============================================
echo.
set "PWSH=C:\Program Files\PowerShell\7\pwsh.exe"
if exist "%PWSH%" (
  "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
)
echo.
if %errorlevel%==0 (echo Done: DNS restored, tasks removed.) else (echo FAILED: see messages above.)
pause
