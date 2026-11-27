#Requires -Version 5.1
<#
.SYNOPSIS
    校园网 QQ / 微信图片加载缓慢修复工具 — 独立卸载与恢复默认脚本
.DESCRIPTION
    仅移除 QQ/微信 HTTPDNS 相关的 hosts 规则与模式配置，不影响 UU 远程修复状态；
    若检测到 UU 远程修复也未启用，则同步停止守护进程、移除自启项、清理防火墙规则与安装目录。
#>

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { Write-Verbose $_.Exception.Message }

function Write-Ok([string]$msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  [!] $msg" -ForegroundColor Yellow }

function Backup-FileBeforeModify([string]$sourcePath, [string]$backupDir, [string]$prefix) {
    if (-not (Test-Path $sourcePath)) { return }
    try {
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }
        $lastBackup = Join-Path $backupDir "$prefix.last.bak"
        Copy-Item -Path $sourcePath -Destination $lastBackup -Force -ErrorAction SilentlyContinue
    } catch { Write-Verbose $_.Exception.Message }
}

function Write-LinesSafely([string]$path, [string[]]$lines, [System.Text.Encoding]$encoding) {
    $wasReadOnly = $false
    try {
        if (Test-Path $path) {
            $item = Get-Item -Path $path -Force
            if ($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                $wasReadOnly = $true
                $item.Attributes = $item.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
            }
        }
        [System.IO.File]::WriteAllLines($path, [string[]]$lines, $encoding)
    } finally {
        if ($wasReadOnly -and (Test-Path $path)) {
            try {
                $item = Get-Item -Path $path -Force
                $item.Attributes = $item.Attributes -bor [System.IO.FileAttributes]::ReadOnly
            } catch { Write-Verbose $_.Exception.Message }
        }
    }
}

function Stop-FragmenterProcess {
    Stop-Process -Name "UUTlsFragmenter" -Force -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 15; $i++) {
        if (-not (Get-Process -Name "UUTlsFragmenter" -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 200
    }
}

$isAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$installDir   = Join-Path $env:LOCALAPPDATA "UURemoteTlsFix"
$backupDir    = Join-Path $installDir "backups"
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

$uuHostsActive = $false
if (Test-Path $hostsPath) {
    $allLines = @(Get-Content -Path $hostsPath -Encoding UTF8 -ErrorAction SilentlyContinue)
    foreach ($l in $allLines) {
        if ($l -match 'UU_REMOTE_TLS_FIX') { $uuHostsActive = $true }
    }

    if ($isAdmin) {
        Backup-FileBeforeModify -sourcePath $hostsPath -backupDir $backupDir -prefix "hosts"
        $hLines = [string[]]@($allLines | Where-Object {
            $_ -notmatch 'QQ_WECHAT_HTTPDNS_FIX' -and
            $_ -notmatch '^\s*(?:127\.0\.0\.1|0\.0\.0\.0|::1?)\s+(?:dns\.qq\.com|dns\.weixin\.qq\.com|dns\.weixin\.qq\.com\.cn|httpdns\.kg\.qq\.com|dns\.wechat\.com)(?:\s|$)'
        })
        try {
            Write-LinesSafely -path $hostsPath -lines $hLines -encoding $utf8NoBom
            & ipconfig.exe /flushdns | Out-Null
            Write-Ok "已清理系统 hosts 中的腾讯 HTTPDNS 映射条目并刷新 DNS 缓存"
        } catch {
            Write-Warn "写入 hosts 失败（请检查安全软件是否锁定 hosts 文件）: $($_.Exception.Message)"
        }
    } else {
        Write-Warn "当前非管理员权限，如需清理系统 hosts 与防火墙规则，请以管理员身份运行本脚本。"
    }
}

# 检查 UU 远程修复是否仍在使用守护进程；若未使用，则一并停止守护进程并清理自启、防火墙与安装目录
$uuActive = $uuHostsActive
if (-not $uuActive -and (Test-Path $proxyIniPath)) {
    $iniText = Get-Content -Path $proxyIniPath -Raw -ErrorAction SilentlyContinue
    if ($iniText -match '17899') { $uuActive = $true }
}

if (-not $uuActive) {
    Stop-FragmenterProcess
    Remove-ItemProperty -Path $runKey -Name "UURemoteTLSFragmenter" -ErrorAction SilentlyContinue
    if ($isAdmin) {
        Remove-NetFirewallRule -DisplayName "UURemoteTlsFix-LAN-TCP","UURemoteTlsFix-LAN-UDP" -ErrorAction SilentlyContinue
        Write-Ok "已移除 Windows 防火墙局域网放行规则 (UURemoteTlsFix-LAN-TCP / UDP)"
    }
    if (Test-Path $installDir) {
        Remove-Item -Path $installDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "检测到 UU 远程分片未启用，已同步停止后台守护进程并移除自启项与安装目录"
} else {
    Write-Ok "检测到 UU 远程修复正在使用中，已保留后台守护进程与防火墙规则供 UU 远程继续运行"
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " 恢复完成！QQ / 微信已恢复默认 DNS 行为。" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
