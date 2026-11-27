@echo off
setlocal
chcp 65001 >nul 2>&1
title 校园网 QQ/微信图片加载缓慢 (HTTPDNS阻断) 一键修复工具

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell"

rem ============ 管理员权限检查（带防重复提权保护，避免无限弹窗） ============
fltmc >nul 2>&1
if %errorlevel% equ 0 goto Run
if /i "%~1"=="--elevated" goto NoAdmin

echo [*] 正在请求管理员权限以完成 QQ/微信图片加载修复...
set "SCRIPT_PATH=%~f0"
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:SCRIPT_PATH -ArgumentList '--elevated' -Verb RunAs"
if errorlevel 1 goto ElevateFailed
exit /b 0

:ElevateFailed
echo [X] 已取消管理员权限请求，修复未执行。
pause
exit /b 1

:NoAdmin
echo [X] 未能获得管理员权限，修复未执行。
echo     请右键本文件，选择“以管理员身份运行”。
pause
exit /b 1

:Run
set "TARGET_PS1=%~dp0fix-qq-wechat.ps1"
if not exist "%TARGET_PS1%" (
    echo [X] 未找到同目录下的脚本文件: "%TARGET_PS1%"
    echo     请先完整解压整个压缩包后再运行本工具，切勿单独复制 .bat 文件。
    pause
    exit /b 1
)
pushd "%~dp0" >nul 2>&1
echo [*] 正在执行 QQ/微信图片加载缓慢修复脚本，请稍候...
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%TARGET_PS1%"
set "EXIT_CODE=%errorlevel%"
popd >nul 2>&1
if not "%EXIT_CODE%"=="0" (
    echo.
    echo [X] 修复过程中出现错误 ^(退出码: %EXIT_CODE%^)，请查看上方日志输出。
)
echo.
pause
exit /b %EXIT_CODE%
