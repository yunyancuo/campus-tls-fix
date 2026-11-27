#Requires -Version 5.1
<#
.SYNOPSIS
    将 src\UUTlsFragmenter.cs 同步嵌入 install.ps1 与 fix-qq-wechat.ps1
.DESCRIPTION
    修改 src\UUTlsFragmenter.cs 后执行本脚本，自动保持单文件在线脚本 (irm ... | iex) 内嵌源码与
    src\UUTlsFragmenter.cs 字节级完全同步，并保持 UTF-8 BOM + CRLF 编码规范。
#>

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { Write-Verbose $_.Exception.Message }

$repoRoot = Split-Path -Parent $PSScriptRoot
$csPath = Join-Path $repoRoot "src\UUTlsFragmenter.cs"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$utf8WithBom = New-Object System.Text.UTF8Encoding($true)

$csText = ([System.IO.File]::ReadAllText($csPath, [System.Text.Encoding]::UTF8) -replace "`r?`n", "`r`n").TrimEnd("`r", "`n")
[System.IO.File]::WriteAllText($csPath, $csText + "`r`n", $utf8NoBom)

foreach ($scriptName in @("install.ps1", "fix-qq-wechat.ps1")) {
    $path = Join-Path $repoRoot $scriptName
    $content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8) -replace "`r?`n", "`r`n"
    $pattern = "(?ms)(\`$csSource\s*=\s*@'\r\n)(.*?)(\r\n'@)"
    $m = [regex]::Match($content, $pattern)
    if (-not $m.Success) {
        throw "未在 $scriptName 中定位到 `$csSource here-string 区块"
    }
    $updated = $content.Substring(0, $m.Groups[2].Index) + $csText + $content.Substring($m.Groups[2].Index + $m.Groups[2].Length)
    [System.IO.File]::WriteAllText($path, $updated, $utf8WithBom)
    Write-Host "  [OK] 已同步 $scriptName 内嵌 C# 源码 ($($csText.Length) chars)" -ForegroundColor Green
}
