#Requires -Version 5.1
<#
.SYNOPSIS
    Campus TLS Fix 自动化测试套件一键入口
.DESCRIPTION
    依次执行：
      1. 静态语法 (AST)、编码行尾、源码同步校验与原生 csc.exe 零警告编译测试
      2. C# 核心单元测试与 127.0.0.1 隔离环回全链路集成测试
      3. 可选 PSScriptAnalyzer 静态代码质量检查（若已安装）
    全程不修改宿主机任何网络、DNS、hosts 或防火墙配置。
#>

param(
    [switch]$RequireScriptAnalyzer
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { Write-Verbose $_.Exception.Message }

$repoRoot = Split-Path -Parent $PSScriptRoot
$totalSw = [System.Diagnostics.Stopwatch]::StartNew()
$overallFailed = $false

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "          Campus TLS Fix 全量自动化测试与编译验证套件                 " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# Suite 1: 静态规范与编译验证
& (Join-Path $PSScriptRoot "Test-StaticAndBuild.ps1") -RepoRoot $repoRoot
if ($LASTEXITCODE -ne 0) { $overallFailed = $true }

# Suite 2 & 3: 核心单测与环回集成测试
& (Join-Path $PSScriptRoot "Test-CoreUnitAndLoopback.ps1") -RepoRoot $repoRoot
if ($LASTEXITCODE -ne 0) { $overallFailed = $true }

# Suite 4: PSScriptAnalyzer（若本机已安装或显式要求）
$psa = Get-Module -ListAvailable -Name PSScriptAnalyzer -ErrorAction SilentlyContinue
if ($psa) {
    Write-Host "`n=== [Suite 4] PSScriptAnalyzer PowerShell 静态分析 ===" -ForegroundColor Cyan
    Import-Module PSScriptAnalyzer -ErrorAction Stop
    $excludeRules = @(
        "PSAvoidUsingWriteHost",
        "PSUseShouldProcessForStateChangingFunctions"
    )
    $psFiles = @(Get-ChildItem -Path $repoRoot -Filter "*.ps1" -Recurse | Where-Object { $_.FullName -notmatch '\\\.git\\' })
    $issues = @()
    foreach ($f in $psFiles) {
        $res = Invoke-ScriptAnalyzer -Path $f.FullName -Severity @("Error", "Warning") -ExcludeRule $excludeRules
        if ($res) { $issues += $res }
    }
    if ($issues.Count -gt 0) {
        $issues | Format-Table ScriptName, Line, Severity, RuleName, Message -AutoSize | Out-String | Write-Host -ForegroundColor Red
        $overallFailed = $true
    } else {
        Write-Host ("  [PASS] 全部 {0} 个 .ps1 文件通过 PSScriptAnalyzer 静态检查（0 Error, 0 Warning）" -f $psFiles.Count) -ForegroundColor Green
    }
} elseif ($RequireScriptAnalyzer) {
    Write-Host "`n  [FAIL] 已启用 -RequireScriptAnalyzer，但本机未安装 PSScriptAnalyzer 模块。" -ForegroundColor Red
    $overallFailed = $true
} else {
    Write-Host "`n  [INFO] 本机未安装 PSScriptAnalyzer，已跳过 Suite 4（CI 流水线将自动安装并强制校验）。" -ForegroundColor Yellow
}

$totalSw.Stop()
Write-Host "`n======================================================================" -ForegroundColor Cyan
if (-not $overallFailed) {
    Write-Host (" 全部测试套件 100% 通过！总耗时: {0:F2} 秒" -f $totalSw.Elapsed.TotalSeconds) -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host (" 测试套件存在失败项，请检查上方详细输出。总耗时: {0:F2} 秒" -f $totalSw.Elapsed.TotalSeconds) -ForegroundColor Red
    Write-Host "======================================================================" -ForegroundColor Cyan
    exit 1
}
