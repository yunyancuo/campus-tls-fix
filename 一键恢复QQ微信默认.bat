@echo off
chcp 65001 >nul 2>&1
title 卸载 QQ/微信 HTTPDNS 修复规则并恢复默认配置

rem ============ 管理员权限检查（带防重复提权保护，避免无限弹窗） ============
fltmc >nul 2>&1
if %errorlevel% equ 0 goto Run
if /i "%~1"=="--elevated" goto NoAdmin

echo [*] 正在请求管理员权限以恢复 QQ/微信默认配置...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '--elevated' -Verb RunAs"
if errorlevel 1 goto ElevateFailed
exit /b

:ElevateFailed
echo [X] 已取消管理员权限请求，恢复未执行。
pause
exit /b 1

:NoAdmin
echo [X] 未能获得管理员权限，恢复未执行。
echo     请右键本文件，选择“以管理员身份运行”。
pause
exit /b 1

:Run
echo [*] 正在执行 QQ/微信恢复脚本，请稍候...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0unfix-qq-wechat.ps1"
echo.
pause
exit /b 0
