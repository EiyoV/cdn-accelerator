@echo off
cd /d "%~dp0"
echo ============================================
echo  CDN Accelerator - Uninstall / Restore
echo  右键本文件 - "以管理员身份运行"
echo  （恢复原 DNS、删除开机自启、停止加速器）
echo ============================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
echo.
if %errorlevel%==0 (
  echo 已卸载：原 DNS 已恢复，开机自启已删除。
  echo 如果之前改过 hosts，本程序不会动 hosts。
) else (
  echo 执行出错，请按上面提示处理。
)
echo.
pause
