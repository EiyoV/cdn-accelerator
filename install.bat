@echo off
cd /d "%~dp0"
echo ============================================
echo  CDN Accelerator - Installer
echo  右键本文件 - "以管理员身份运行"
echo ============================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
echo.
if %errorlevel%==0 (
  echo 安装完成：DNS 已接管，开机自启已注册。
) else (
  echo 安装出错了，请按上面提示处理（多半是没装 Python）。
)
echo.
pause
