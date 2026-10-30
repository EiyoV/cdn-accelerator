@echo off
cd /d "%~dp0"
echo ============================================
echo  CDN Accelerator - Installer (with LAN share)
echo ============================================
echo.
set "PWSH=C:\Program Files\PowerShell\7\pwsh.exe"
if exist "%PWSH%" (
  "%PWSH%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Lan
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Lan
)
echo.
if %errorlevel%==0 (echo Done: DNS taken over, tasks registered.) else (echo FAILED: see messages above.)
pause
