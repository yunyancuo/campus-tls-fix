#Requires -Version 5.1
<#
.SYNOPSIS
    网易 UU 远程 (GameViewer) 校园网 TLS 握手阻断修复工具 — 一键卸载与恢复默认脚本
.DESCRIPTION
    支持一行 PowerShell 命令在线卸载或本地运行：
      irm https://gh-proxy.com/https://raw.githubusercontent.com/yunyancuo/campus-tls-fix/main/uninstall.ps1 | iex
    安全清理 UU 远程代理配置与 hosts 映射；若 QQ/微信分片模式未启用，同步停止守护进程并清理自启项与防火墙规则。
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

function Stop-FragmenterProcesses {
    Stop-Process -Name "UUTlsFragmenter" -Force -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'python' -and $_.CommandLine -match 'uu_tls_fragmenter'
    } | ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
    for ($i = 0; $i -lt 15; $i++) {
        if (-not (Get-Process -Name "UUTlsFragmenter" -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 200
    }
}

$isAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$installDir   = Join-Path $env:LOCALAPPDATA "UURemoteTlsFix"
$backupDir    = Join-Path $installDir "backups"
$runKey       = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$uuDataDir    = Join-Path $env:ProgramData "Netease\GameViewer"
$proxyIniPath = Join-Path $uuDataDir "proxy_config.ini"
$hostsPath    = Join-Path $env:WINDIR "System32\drivers\etc\hosts"
$utf8NoBom    = New-Object System.Text.UTF8Encoding($false)

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "         正在卸载 UU 远程校园网 TLS 破阻断服务并恢复默认配置          " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. 恢复 UU 远程原生 proxy_config.ini 为无代理状态
if (Test-Path $proxyIniPath) {
    try {
        $resetIni = "[Proxy]`r`nsettingType=0`r`ntype=0`r`nhost=`r`nport=0`r`nusername=`r`nbypass=`r`npassword=`r`n"
        [System.IO.File]::WriteAllText($proxyIniPath, $resetIni, $utf8NoBom)
        Write-Ok "已将 UU 远程 proxy_config.ini 恢复为默认无代理状态 (settingType=0)"
    } catch {
        Write-Warn "恢复 proxy_config.ini 失败（可能需要管理员权限）: $($_.Exception.Message)"
    }
}

# 2. 清理系统 hosts 中的 UU 远程条目（保留可能存在的 QQ/微信条目）
$qqHostsActive = $false
if (Test-Path $hostsPath) {
    $allLines = @(Get-Content -Path $hostsPath -Encoding UTF8 -ErrorAction SilentlyContinue)
    foreach ($l in $allLines) {
        if ($l -match 'QQ_WECHAT_HTTPDNS_FIX' -and $l -match '^\s*127\.0\.0\.1\s+') {
            $qqHostsActive = $true
        }
    }

    if ($isAdmin) {
        Backup-FileBeforeModify -sourcePath $hostsPath -backupDir $backupDir -prefix "hosts"
        $hLines = [string[]]@($allLines | Where-Object {
            $_ -notmatch 'UU_REMOTE_TLS_FIX' -and
            $_ -notmatch '^\s*(?:127\.0\.0\.1|0\.0\.0\.0|::1?)\s+\S*nrd\.nie\.163\.com(?:\s|$)'
        })
        try {
            Write-LinesSafely -path $hostsPath -lines $hLines -encoding $utf8NoBom
            & ipconfig.exe /flushdns | Out-Null
            Write-Ok "已清理系统 hosts 中的 UU 远程映射条目并刷新 DNS 缓存"
        } catch {
            Write-Warn "写入 hosts 失败（请检查安全软件是否锁定 hosts 文件）: $($_.Exception.Message)"
        }
    } else {
        $hasUuHosts = @($allLines | Where-Object { $_ -match 'UU_REMOTE_TLS_FIX' }).Count -gt 0
        if ($hasUuHosts) {
            Write-Warn "当前非管理员权限，未能清理系统 hosts 中的 UU 远程映射条目！请右键「一键卸载恢复.bat」以管理员身份重新运行。"
        } else {
            Write-Warn "当前非管理员权限，跳过系统 hosts 与防火墙规则清理。"
        }
    }
}

# 3. 停止后台进程、移除自启与防火墙规则（若 QQ/微信分片模式仍在使用，则保留守护进程与规则）
if (-not $qqHostsActive) {
    Stop-FragmenterProcesses
    Remove-ItemProperty -Path $runKey -Name "UURemoteTLSFragmenter" -ErrorAction SilentlyContinue
    if ($isAdmin) {
        Remove-NetFirewallRule -DisplayName "UURemoteTlsFix-LAN-TCP","UURemoteTlsFix-LAN-UDP" -ErrorAction SilentlyContinue
        Write-Ok "已移除 Windows 防火墙局域网放行规则 (UURemoteTlsFix-LAN-TCP / UDP)"
    }
    if (Test-Path $installDir) {
        Remove-Item -Path $installDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "已停止后台分片服务并移除开机自启项与安装目录"
} else {
    Write-Ok "检测到 QQ/微信 TLS 分片仍在启用中，已保留后台守护服务与防火墙规则"
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " 卸载完成！UU 远程已恢复出厂默认网络设置。" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
