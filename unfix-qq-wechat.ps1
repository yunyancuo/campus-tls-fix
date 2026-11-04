#Requires -Version 5.1
<#
.SYNOPSIS
    校园网 QQ / 微信图片加载缓慢修复工具 — 独立卸载与恢复默认脚本
.DESCRIPTION
    仅移除 QQ/微信 HTTPDNS 相关的 hosts 规则与模式配置，不影响 UU 远程修复状态。
#>

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Write-Ok([string]$msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }

$isAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$installDir   = Join-Path $env:LOCALAPPDATA "UURemoteTlsFix"
$modeFile     = Join-Path $installDir "qq_wechat_mode.txt"
$runKey       = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$uuDataDir    = Join-Path $env:ProgramData "Netease\GameViewer"
$proxyIniPath = Join-Path $uuDataDir "proxy_config.ini"
$hostsPath    = Join-Path $env:WINDIR "System32\drivers\etc\hosts"
$utf8NoBom    = New-Object System.Text.UTF8Encoding($false)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "         正在卸载 QQ / 微信 HTTPDNS 修复规则并恢复默认设置            " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if (Test-Path $modeFile) {
    [System.IO.File]::WriteAllText($modeFile, "off", $utf8NoBom)
    Write-Ok "已关闭局域网 DNS 中的腾讯 HTTPDNS 拦截/分片规则"
}

if ($isAdmin -and (Test-Path $hostsPath)) {
    $hLines = @(Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object {
        $_ -notmatch 'QQ_WECHAT_HTTPDNS_FIX' -and
        $_ -notmatch '(^|\s)(dns\.qq\.com|dns\.weixin\.qq\.com|dns\.weixin\.qq\.com\.cn|httpdns\.kg\.qq\.com|dns\.wechat\.com)(\s|$)'
    })
    [System.IO.File]::WriteAllLines($hostsPath, $hLines, $utf8NoBom)
    & ipconfig.exe /flushdns | Out-Null
    Write-Ok "已清理系统 hosts 中的腾讯 HTTPDNS 映射条目并刷新 DNS 缓存"
} else {
    Write-Warn "当前非管理员权限，如需清理系统 hosts 请以管理员身份运行本脚本。"
}

# 检查 UU 远程修复是否仍在使用守护进程；若未使用，则一并停止并清理守护进程
$uuActive = $false
if (Test-Path $proxyIniPath) {
    $iniText = Get-Content $proxyIniPath -Raw -ErrorAction SilentlyContinue
    if ($iniText -match '17899') { $uuActive = $true }
}
if (-not $uuActive) {
    Stop-Process -Name "UUTlsFragmenter" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runKey -Name "UURemoteTLSFragmenter" -ErrorAction SilentlyContinue
    Write-Ok "检测到 UU 远程分片未启用，已同步停止后台守护进程并移除自启项"
} else {
    Write-Ok "检测到 UU 远程修复正在使用中，已保留后台守护进程供 UU 远程继续运行"
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " 恢复完成！QQ / 微信已恢复默认 DNS 行为。" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
