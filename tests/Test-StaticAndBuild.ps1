#Requires -Version 5.1
<#
.SYNOPSIS
    静态规范、编码行尾、三处源码一致性与原生 C# 零警告编译验证测试
.DESCRIPTION
    纯只读校验与沙盒临时目录测试，绝不修改宿主机任何系统配置。
#>

param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { Write-Verbose $_.Exception.Message }
$RepoRoot = (Resolve-Path -Path $RepoRoot).Path

$script:Passed = 0
$script:Failed = 0

function Invoke-TestCase([string]$Name, [scriptblock]$Body) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Body
        $sw.Stop()
        $script:Passed++
        Write-Host ("  [PASS] {0} ({1} ms)" -f $Name, $sw.ElapsedMilliseconds) -ForegroundColor Green
    } catch {
        $sw.Stop()
        $script:Failed++
        Write-Host ("  [FAIL] {0} ({1} ms): {2}" -f $Name, $sw.ElapsedMilliseconds, $_.Exception.Message) -ForegroundColor Red
    }
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

Write-Host "`n=== [Suite 1] 静态规范、编码行尾、源码同步与 C# 编译测试 ===" -ForegroundColor Cyan

# 1. PowerShell AST 语法解析测试（覆盖仓库与 tests 全部 .ps1）
Invoke-TestCase "全部 .ps1 文件 PowerShell Parser AST 零语法错误校验" {
    $psFiles = @(Get-ChildItem -Path $RepoRoot -Filter "*.ps1" -Recurse | Where-Object { $_.FullName -notmatch '\\\.git\\' })
    Assert-True ($psFiles.Count -ge 4) "未找到预期的 .ps1 脚本文件"
    foreach ($f in $psFiles) {
        $tokens = $null
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
        Assert-True ($errors.Count -eq 0) "$($f.Name) 存在 $($errors.Count) 个语法错误: $($errors[0].Message)"
    }
}

# 2. PowerShell 编码与行尾校验（UTF-8 with BOM + CRLF，确保 Windows PowerShell 5.1 中文不乱码）
Invoke-TestCase "全部 .ps1 文件 UTF-8 BOM 与 CRLF 行尾合规校验" {
    $psFiles = @(Get-ChildItem -Path $RepoRoot -Filter "*.ps1" -Recurse | Where-Object { $_.FullName -notmatch '\\\.git\\' })
    foreach ($f in $psFiles) {
        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
        Assert-True $hasBom "$($f.Name) 缺少 UTF-8 BOM，可能导致 Windows PowerShell 5.1 中文乱码或语法异常"
        $txt = [System.Text.Encoding]::UTF8.GetString($bytes)
        $lfOnly = ([regex]::Matches($txt, "(?<!`r)`n")).Count
        Assert-True ($lfOnly -eq 0) "$($f.Name) 包含 $lfOnly 个非 CRLF 的裸 LF 换行符"
    }
}

# 3. BAT 文件严格 CRLF、无 UTF-8 BOM、防 UAC 死循环与防路径注入校验
Invoke-TestCase "全部 .bat 文件 CRLF、无 BOM、防 UAC 死循环与防注入安全校验" {
    $batFiles = @(Get-ChildItem -Path $RepoRoot -Filter "*.bat")
    Assert-True ($batFiles.Count -eq 4) "预期 4 个 .bat 文件，实际找到 $($batFiles.Count) 个"
    foreach ($f in $batFiles) {
        $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
        $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
        Assert-True (-not $hasBom) "$($f.Name) 包含 UTF-8 BOM，会导致 cmd.exe 首行 @echo off 报错"

        $utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
        $txt = $utf8Strict.GetString($bytes)
        $crlf = ([regex]::Matches($txt, "`r`n")).Count
        $lfOnly = ([regex]::Matches($txt, "(?<!`r)`n")).Count
        Assert-True ($crlf -gt 0 -and $lfOnly -eq 0) "$($f.Name) 行尾非严格 CRLF (CRLF=$crlf, LFOnly=$lfOnly)"
        Assert-True ($txt -match '(?m)^fltmc\s+>nul') "$($f.Name) 缺少 fltmc 管理员检测"
        Assert-True ($txt -match '--elevated') "$($f.Name) 缺少 --elevated 防 UAC 无限循环哨兵"
        Assert-True ($txt -match 'SCRIPT_PATH=%~f0' -and $txt -match '\$env:SCRIPT_PATH') "$($f.Name) 未使用环境变量安全传递提权路径"
        Assert-True ($txt -match 'EXIT_CODE=%errorlevel%') "$($f.Name) 未透传 PowerShell 真实退出码"
    }
}

# 4. BAT 极端特殊字符路径真实 cmd.exe 解析安全验证
Invoke-TestCase "BAT 环境变量路径传递在空格/单引号/&/中文/括号路径下安全运行" {
    $tmpDir = Join-Path $env:TEMP ("campus_tls_bat_O'Brien & 中文 (Test)_" + [guid]::NewGuid().ToString("N").Substring(0, 6))
    try {
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $testBat = Join-Path $tmpDir "测试 'quote' & 1.bat"
        $batBody = @(
            '@echo off',
            'setlocal',
            'chcp 65001 >nul 2>&1',
            'set "SCRIPT_PATH=%~f0"',
            '"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Write-Output (''PATH='' + $env:SCRIPT_PATH)"'
        ) -join "`r`n"
        [System.IO.File]::WriteAllText($testBat, $batBody + "`r`n", (New-Object System.Text.UTF8Encoding($false)))

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "cmd.exe"
        $psi.Arguments = "/c `"`"$testBat`"`""
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEnd().Trim()
        $stderr = $proc.StandardError.ReadToEnd().Trim()
        $proc.WaitForExit()
        Assert-True ($proc.ExitCode -eq 0) "cmd.exe 执行失败 ExitCode=$($proc.ExitCode), stderr=$stderr"
        Assert-True ($stdout -eq ("PATH=" + $testBat)) "路径传递失真: 期望 PATH=$testBat，实际 $stdout"
    } finally {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 5. 三处 C# 源码一致性（Drift Check）
Invoke-TestCase "src\UUTlsFragmenter.cs 与 install.ps1 / fix-qq-wechat.ps1 内嵌源码零漂移校验" {
    $csPath = Join-Path $RepoRoot "src\UUTlsFragmenter.cs"
    $csRaw = ([System.IO.File]::ReadAllText($csPath, [System.Text.Encoding]::UTF8) -replace "`r?`n", "`r`n").TrimEnd("`r", "`n")
    foreach ($scriptName in @("install.ps1", "fix-qq-wechat.ps1")) {
        $p = Join-Path $RepoRoot $scriptName
        $txt = [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)
        $m = [regex]::Match($txt, "(?ms)\`$csSource\s*=\s*@'\r\n(.*?)\r\n'@")
        Assert-True $m.Success "$scriptName 中未找到内嵌 `$csSource here-string"
        Assert-True ($m.Groups[1].Value -eq $csRaw) "$scriptName 内嵌源码与 src\UUTlsFragmenter.cs 存在漂移！请运行 tests\Sync-EmbeddedSource.ps1 同步。"
    }
}

# 6. 原生 .NET Framework 4.x csc.exe /warn:4 /warnaserror+ 零警告零错误编译校验
Invoke-TestCase "Windows 原生 .NET 4.x csc.exe (/warn:4 /warnaserror+ /target:winexe) 零警告编译" {
    $csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
    if (-not (Test-Path $csc)) {
        $csc = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"
    }
    Assert-True (Test-Path $csc) "未找到系统内置 csc.exe"

    $csPath = Join-Path $RepoRoot "src\UUTlsFragmenter.cs"
    $outExe = Join-Path $env:TEMP ("UUTlsFragmenter_CI_" + [guid]::NewGuid().ToString("N").Substring(0, 8) + ".exe")
    try {
        $out = & $csc /nologo /optimize+ /warn:4 /warnaserror+ /target:winexe /out:"$outExe" "$csPath" 2>&1
        Assert-True ($LASTEXITCODE -eq 0) "csc.exe 编译失败或存在警告 (ExitCode=$LASTEXITCODE): $($out | Out-String)"
        Assert-True (Test-Path $outExe) "未生成目标 EXE 文件"
        $fi = Get-Item $outExe
        Assert-True ($fi.Length -gt 8192) "编译产物大小异常: $($fi.Length) bytes"
    } finally {
        Remove-Item -Path $outExe -Force -ErrorAction SilentlyContinue
    }
}

# 7. 沙盒目录离线测试 hosts 只读写入、单行/空行防崩与注释保护
Invoke-TestCase "沙盒模拟只读 hosts 写入、空数组防崩溃与用户注释精准保护" {
    $tmpDir = Join-Path $env:TEMP ("campus_tls_hosts_sandbox_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    try {
        New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
        $fakeHosts = Join-Path $tmpDir "hosts"
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $seed = @(
            "# 用户笔记：关于 nrd.nie.163.com 和 dns.qq.com 的说明",
            "127.0.0.1 api.nrd.nie.163.com # UU_REMOTE_TLS_FIX",
            "127.0.0.1 dns.qq.com # QQ_WECHAT_HTTPDNS_FIX",
            "10.0.0.1 intranet.school.edu.cn"
        )
        [System.IO.File]::WriteAllLines($fakeHosts, $seed, $utf8NoBom)
        # 设为只读属性模拟安全软件锁定
        $fi = Get-Item $fakeHosts
        $fi.Attributes = $fi.Attributes -bor [System.IO.FileAttributes]::ReadOnly

        # 模拟 uninstall 清理 UU 映射并安全恢复只读属性
        $all = @(Get-Content -Path $fakeHosts -Encoding UTF8)
        $filtered = [string[]]@($all | Where-Object {
            $_ -notmatch 'UU_REMOTE_TLS_FIX' -and
            $_ -notmatch '^\s*(?:127\.0\.0\.1|0\.0\.0\.0|::1?)\s+\S*nrd\.nie\.163\.com(?:\s|$)'
        })
        $wasRo = ($fi.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0
        if ($wasRo) { $fi.Attributes = $fi.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly) }
        [System.IO.File]::WriteAllLines($fakeHosts, $filtered, $utf8NoBom)
        if ($wasRo) { $fi.Attributes = $fi.Attributes -bor [System.IO.FileAttributes]::ReadOnly }

        $after = @(Get-Content -Path $fakeHosts -Encoding UTF8)
        Assert-True ($after.Count -eq 3) "清理 UU 条目后预期 3 行，实际 $($after.Count) 行"
        Assert-True ($after[0] -match '用户笔记：关于 nrd\.nie\.163\.com') "误删了用户的注释行！"
        Assert-True ($after[1] -match 'QQ_WECHAT_HTTPDNS_FIX') "误删了 QQ/微信条目！"
        Assert-True ($after[2] -eq '10.0.0.1 intranet.school.edu.cn') "误删了校园内网条目！"
        Assert-True (((Get-Item $fakeHosts).Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) "未还原只读属性"

        # 额外验证单行和零行 [string[]] 传给 WriteAllLines 不报错
        $fi = Get-Item $fakeHosts
        $fi.Attributes = $fi.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
        [System.IO.File]::WriteAllLines($fakeHosts, [string[]]@(), $utf8NoBom)
        [System.IO.File]::WriteAllLines($fakeHosts, [string[]]@("127.0.0.1 localhost"), $utf8NoBom)
        Assert-True ((Get-Content $fakeHosts).Count -eq 1) "单行写入校验失败"
    } finally {
        if (Test-Path $tmpDir) {
            Get-ChildItem -Path $tmpDir -Force | ForEach-Object {
                $_.Attributes = $_.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
            }
            Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host ("`n[Suite 1 汇总] 通过: {0}, 失败: {1}" -f $script:Passed, $script:Failed) -ForegroundColor $(if ($script:Failed -eq 0) { "Green" } else { "Red" })
if ($script:Failed -gt 0) { exit 1 }
exit 0
