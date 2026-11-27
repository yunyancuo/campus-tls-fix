#Requires -Version 5.1
<#
.SYNOPSIS
    UUTlsFragmenter 核心单元测试与全链路环回集成测试（100% 隔离在 127.0.0.1 随机空闲端口）
.DESCRIPTION
    通过 Add-Type 加载 src\UUTlsFragmenter.cs，在不触碰宿主机任何 DNS/hosts/防火墙/网卡的前提下，
    验证 TLS ClientHello SNI 精确解析、双帧切分、DNS 畸形包防护、SOCKS5/HTTP CONNECT/透明 TLS 分片、
    TCP 拆包聚合、TCP 半关闭转发、LAN DNS 三模式热切换、上游转发与超时 SERVFAIL 及优雅停机。
#>

param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { Write-Verbose $_.Exception.Message }

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

function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -ne $Expected) {
        throw "$Message (期望: '$Expected', 实际: '$Actual')"
    }
}

# 构造标准 RFC 5246/6066 TLS ClientHello 报文（支持在 ClientRandom 中注入诱饵 ASCII 串以测试防误判）
function New-TestTlsClientHello {
    param(
        [string]$SniHost = "",
        [byte[]]$ExtraTrailingBytes = $null,
        [string]$DecoyInRandom = "",
        [switch]$IncludeGreaseExtension
    )
    $ms = New-Object System.IO.MemoryStream
    # ClientVersion TLS 1.2
    $ms.Write([byte[]]@(0x03, 0x03), 0, 2)
    # 32 字节 ClientRandom
    $rand = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) { $rand[$i] = [byte](($i * 7 + 13) -band 0xFF) }
    if (-not [string]::IsNullOrEmpty($DecoyInRandom)) {
        $decoyBytes = [System.Text.Encoding]::ASCII.GetBytes($DecoyInRandom)
        $copyLen = [Math]::Min(32, $decoyBytes.Length)
        [Array]::Copy($decoyBytes, 0, $rand, 0, $copyLen)
    }
    $ms.Write($rand, 0, 32)
    # SessionID (4 字节)
    $ms.Write([byte[]]@(0x04, 0xAA, 0xBB, 0xCC, 0xDD), 0, 5)
    # CipherSuites (2 个套件 = 4 字节)
    $ms.Write([byte[]]@(0x00, 0x04, 0x13, 0x01, 0xC0, 0x2F), 0, 6)
    # CompressionMethods (1 个 null)
    $ms.Write([byte[]]@(0x01, 0x00), 0, 2)

    # Extensions
    $extMs = New-Object System.IO.MemoryStream
    if ($IncludeGreaseExtension) {
        # GREASE extension 0x2A2A + 2 字节载荷
        $extMs.Write([byte[]]@(0x2A, 0x2A, 0x00, 0x02, 0x00, 0x00), 0, 6)
    }
    if (-not [string]::IsNullOrEmpty($SniHost)) {
        $hostBytes = [System.Text.Encoding]::ASCII.GetBytes($SniHost)
        $nameLen = $hostBytes.Length
        $listLen = 1 + 2 + $nameLen
        $extLen = 2 + $listLen
        $extMs.Write([byte[]]@(
            0x00, 0x00,
            [byte](($extLen -shr 8) -band 0xFF), [byte]($extLen -band 0xFF),
            [byte](($listLen -shr 8) -band 0xFF), [byte]($listLen -band 0xFF),
            0x00,
            [byte](($nameLen -shr 8) -band 0xFF), [byte]($nameLen -band 0xFF)
        ), 0, 9)
        $extMs.Write($hostBytes, 0, $nameLen)
    }
    # supported_versions (TLS 1.3)
    $extMs.Write([byte[]]@(0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04), 0, 7)

    $extBytes = $extMs.ToArray()
    $ms.Write([byte[]]@([byte](($extBytes.Length -shr 8) -band 0xFF), [byte]($extBytes.Length -band 0xFF)), 0, 2)
    $ms.Write($extBytes, 0, $extBytes.Length)

    $body = $ms.ToArray()
    # Handshake Header: 0x01 + 3 字节长度
    $hsLen = $body.Length
    $recLen = 4 + $hsLen
    $outMs = New-Object System.IO.MemoryStream
    $outMs.Write([byte[]]@(
        0x16, 0x03, 0x01,
        [byte](($recLen -shr 8) -band 0xFF), [byte]($recLen -band 0xFF),
        0x01,
        [byte](($hsLen -shr 16) -band 0xFF), [byte](($hsLen -shr 8) -band 0xFF), [byte]($hsLen -band 0xFF)
    ), 0, 9)
    $outMs.Write($body, 0, $body.Length)
    if ($null -ne $ExtraTrailingBytes -and $ExtraTrailingBytes.Length -gt 0) {
        $outMs.Write($ExtraTrailingBytes, 0, $ExtraTrailingBytes.Length)
    }
    return $outMs.ToArray()
}

# 构造标准 DNS 查询包
function New-TestDnsQuery {
    param(
        [uint16]$TxId = 0x1234,
        [string]$Domain = "api.nrd.nie.163.com",
        [uint16]$QType = 1,
        [byte]$FlagsHi = 0x01
    )
    $ms = New-Object System.IO.MemoryStream
    $ms.Write([byte[]]@(
        [byte](($TxId -shr 8) -band 0xFF), [byte]($TxId -band 0xFF),
        $FlagsHi, 0x00,
        0x00, 0x01, # QDCOUNT=1
        0x00, 0x00, # ANCOUNT=0
        0x00, 0x00, # NSCOUNT=0
        0x00, 0x00  # ARCOUNT=0
    ), 0, 12)
    foreach ($label in $Domain.Split('.')) {
        $lb = [System.Text.Encoding]::ASCII.GetBytes($label)
        $ms.WriteByte([byte]$lb.Length)
        $ms.Write($lb, 0, $lb.Length)
    }
    $ms.WriteByte(0x00)
    $ms.Write([byte[]]@(
        [byte](($QType -shr 8) -band 0xFF), [byte]($QType -band 0xFF),
        0x00, 0x01 # Class IN
    ), 0, 4)
    return $ms.ToArray()
}

function Get-FreeTcpPort {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $l.Start()
    $port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port
    $l.Stop()
    return $port
}

function Get-FreeUdpPort {
    $s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
    $s.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, 0)))
    $port = ([System.Net.IPEndPoint]$s.LocalEndPoint).Port
    $s.Close()
    return $port
}

# 加载 C# 核心源码
$csPath = Join-Path $RepoRoot "src\UUTlsFragmenter.cs"
if (-not ([System.Management.Automation.PSTypeName]'UURemoteTlsFix.TlsFragmenter').Type) {
    $csCode = [System.IO.File]::ReadAllText($csPath, [System.Text.Encoding]::UTF8)
    Add-Type -TypeDefinition $csCode -Language CSharp -ErrorAction Stop
}

# 辅助 C# Mock 工具（仅存在于测试进程内存，用于稳定可靠地运行环回 Mock TCP/UDP 服务端）
if (-not ([System.Management.Automation.PSTypeName]'CampusTlsTestHarness.LoopbackMocks').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace CampusTlsTestHarness
{
    public sealed class MockTcpCaptureServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        public int Port { get; private set; }
        public byte[] LastReceivedPayload { get; private set; }
        public int ResponseDelayMs { get; set; }
        public byte[] ResponsePayload { get; set; }

        public MockTcpCaptureServer()
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            ResponsePayload = System.Text.Encoding.ASCII.GetBytes("MOCK-SERVER-OK");
            Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    TcpClient c = await _listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    Task t = HandleAsync(c, ct);
                    GC.KeepAlive(t);
                }
                catch { break; }
            }
        }

        private async Task HandleAsync(TcpClient client, CancellationToken ct)
        {
            try
            {
                using (client)
                using (NetworkStream ns = client.GetStream())
                using (MemoryStream ms = new MemoryStream())
                {
                    byte[] buf = new byte[4096];
                    // 持续读取直到客户端关闭写端 (EOF) 或读取超短空闲间隔
                    while (!ct.IsCancellationRequested)
                    {
                        Task<int> rTask = ns.ReadAsync(buf, 0, buf.Length, ct);
                        Task dTask = Task.Delay(120, ct);
                        Task done = await Task.WhenAny(rTask, dTask).ConfigureAwait(false);
                        if (done != rTask) break;
                        int n = await rTask.ConfigureAwait(false);
                        if (n <= 0) break;
                        ms.Write(buf, 0, n);
                    }
                    LastReceivedPayload = ms.ToArray();
                    if (ResponseDelayMs > 0)
                        await Task.Delay(ResponseDelayMs, ct).ConfigureAwait(false);
                    if (ResponsePayload != null && ResponsePayload.Length > 0)
                    {
                        await ns.WriteAsync(ResponsePayload, 0, ResponsePayload.Length, ct).ConfigureAwait(false);
                        await ns.FlushAsync(ct).ConfigureAwait(false);
                    }
                }
            }
            catch { }
        }

        public void Dispose()
        {
            try { _cts.Cancel(); } catch { }
            try { _listener.Stop(); } catch { }
            try { _cts.Dispose(); } catch { }
        }
    }

    public sealed class MockUpstreamDnsServer : IDisposable
    {
        private readonly Socket _udp;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        public int Port { get; private set; }
        public IPAddress AnswerIp { get; set; }
        public int QueryCount { get; private set; }

        public MockUpstreamDnsServer(string answerIp)
        {
            AnswerIp = IPAddress.Parse(answerIp);
            _udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            Port = ((IPEndPoint)_udp.LocalEndPoint).Port;
            Task.Run(() => Loop());
        }

        private void Loop()
        {
            byte[] buf = new byte[4096];
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                    int n = _udp.ReceiveFrom(buf, ref ep);
                    if (n < 17 || (buf[2] & 0x80) != 0) continue;
                    int pos = 12;
                    while (pos < n && buf[pos] != 0)
                    {
                        pos += buf[pos] + 1;
                    }
                    if (pos + 5 > n) continue;
                    int qEnd = pos + 5;
                    QueryCount++;
                    byte[] resp = new byte[qEnd + 16];
                    Buffer.BlockCopy(buf, 0, resp, 0, qEnd);
                    resp[2] = (byte)(0x80 | (buf[2] & 0x01));
                    resp[3] = 0x80;
                    resp[4] = 0x00; resp[5] = 0x01;
                    resp[6] = 0x00; resp[7] = 0x01;
                    resp[8] = 0x00; resp[9] = 0x00;
                    resp[10] = 0x00; resp[11] = 0x00;
                    resp[qEnd] = 0xC0; resp[qEnd + 1] = 0x0C;
                    resp[qEnd + 2] = 0x00; resp[qEnd + 3] = 0x01;
                    resp[qEnd + 4] = 0x00; resp[qEnd + 5] = 0x01;
                    resp[qEnd + 6] = 0x00; resp[qEnd + 7] = 0x00; resp[qEnd + 8] = 0x00; resp[qEnd + 9] = 0x78;
                    resp[qEnd + 10] = 0x00; resp[qEnd + 11] = 0x04;
                    Buffer.BlockCopy(AnswerIp.GetAddressBytes(), 0, resp, qEnd + 12, 4);
                    _udp.SendTo(resp, ep);
                }
                catch { break; }
            }
        }

        public void Dispose()
        {
            try { _cts.Cancel(); } catch { }
            try { _udp.Close(); } catch { }
            try { _cts.Dispose(); } catch { }
        }
    }

    public static class ResolverFactory
    {
        public static Func<string, int, IPEndPoint> CreateFixedLoopback(int port)
        {
            return delegate(string host, int reqPort)
            {
                return new IPEndPoint(IPAddress.Loopback, port);
            };
        }
    }
}
'@ -ErrorAction Stop
}

Write-Host "`n=== [Suite 2] C# 核心逻辑单元测试 ===" -ForegroundColor Cyan

Invoke-TestCase "TLS ClientHello RFC 6066 精确 SNI 提取（含 GREASE 扩展与 Random 诱饵防御）" {
    $ch1 = New-TestTlsClientHello -SniHost "sig-3303-d.nrd.nie.163.com" -DecoyInRandom "fake.api.nrd.nie.163.com" -IncludeGreaseExtension
    $sni1 = [UURemoteTlsFix.TlsFragmenter]::ExtractSniFromClientHello($ch1, $ch1.Length)
    Assert-Equal $sni1 "sig-3303-d.nrd.nie.163.com" "应忽略 Random 中的诱饵域名并精确提取 SNI"

    $ch2 = New-TestTlsClientHello -SniHost "dns.weixin.qq.com.cn" -IncludeGreaseExtension
    $sni2 = [UURemoteTlsFix.TlsFragmenter]::ExtractSniFromClientHello($ch2, $ch2.Length)
    Assert-Equal $sni2 "dns.weixin.qq.com.cn" "腾讯域名 SNI 提取失败"

    $ch3 = New-TestTlsClientHello -SniHost "www.example.com"
    $sni3 = [UURemoteTlsFix.TlsFragmenter]::ExtractSniFromClientHello($ch3, $ch3.Length)
    Assert-Equal $sni3 "www.example.com" "普通第三方域名 SNI 提取失败"
}

Invoke-TestCase "TLS ClientHello 边界与畸形报文防越界测试" {
    Assert-True ($null -eq [UURemoteTlsFix.TlsFragmenter]::ExtractSniFromClientHello($null, 0)) "null 输入应返回 null"
    Assert-True ($null -eq [UURemoteTlsFix.TlsFragmenter]::ExtractSniFromClientHello([byte[]]@(), 0)) "空数组应返回 null"
    Assert-True ($null -eq [UURemoteTlsFix.TlsFragmenter]::ExtractSniFromClientHello([byte[]]@(0x16, 0x03, 0x01, 0x00, 0x01, 0x01), 6)) "超短包应返回 null"
    # ServerHello (0x02) 而非 ClientHello (0x01)
    $badHs = New-TestTlsClientHello -SniHost "api.nrd.nie.163.com"
    $badHs[5] = 0x02
    Assert-True ($null -eq [UURemoteTlsFix.TlsFragmenter]::ExtractSniFromClientHello($badHs, $badHs.Length)) "ServerHello 应返回 null"
    # 截断包
    $ch = New-TestTlsClientHello -SniHost "api.nrd.nie.163.com"
    Assert-True ($null -eq [UURemoteTlsFix.TlsFragmenter]::ExtractSniFromClientHello($ch, 50)) "截断包应安全返回 null"
}

Invoke-TestCase "TLS Record 双帧切分验证：UU 长子域与全部 5 个腾讯域名均撕碎特征后缀且重组无损" {
    $targets = @(
        @{ Host = "relay-mg-3303-d.nrd.nie.163.com"; Marker = "nrd.nie.163.com" },
        @{ Host = "api.nrd.nie.163.com";             Marker = "nrd.nie.163.com" },
        @{ Host = "dns.qq.com";                      Marker = "dns.qq.com" },
        @{ Host = "dns.weixin.qq.com";               Marker = "dns.weixin.qq.com" },
        @{ Host = "dns.weixin.qq.com.cn";            Marker = "dns.weixin.qq.com.cn" },
        @{ Host = "httpdns.kg.qq.com";               Marker = "httpdns.kg.qq.com" },
        @{ Host = "dns.wechat.com";                  Marker = "dns.wechat.com" }
    )
    foreach ($t in $targets) {
        $ch = New-TestTlsClientHello -SniHost $t.Host -IncludeGreaseExtension
        $origRecLen = ([int]$ch[3] -shl 8) -bor $ch[4]
        $frag = [UURemoteTlsFix.TlsFragmenter]::FragmentTlsClientHello($ch, $ch.Length)

        Assert-Equal $frag.Length ($ch.Length + 5) "$($t.Host) 切分后应恰好增加 5 字节 Record 头"
        Assert-Equal $frag[0] ([byte]0x16) "$($t.Host) 第 1 帧类型必须为 0x16"
        $len1 = ([int]$frag[3] -shl 8) -bor $frag[4]
        $off2 = 5 + $len1
        Assert-Equal $frag[$off2] ([byte]0x16) "$($t.Host) 第 2 帧类型必须为 0x16"
        $len2 = ([int]$frag[$off2 + 3] -shl 8) -bor $frag[$off2 + 4]
        Assert-True ($len1 -gt 0 -and $len2 -gt 0) "$($t.Host) 不允许出现空帧"
        Assert-Equal ($len1 + $len2) $origRecLen "$($t.Host) 两帧载荷长度之和必须等于原 Record 长度"

        # 校验单帧都不再包含完整特征标记（真正穿透 SNI DPI！）
        $f1Ascii = [System.Text.Encoding]::ASCII.GetString($frag, 5, $len1)
        $f2Ascii = [System.Text.Encoding]::ASCII.GetString($frag, $off2 + 5, $len2)
        Assert-True ($f1Ascii.IndexOf($t.Marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) "$($t.Host) 第 1 帧仍含完整特征 $($t.Marker)"
        Assert-True ($f2Ascii.IndexOf($t.Marker, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) "$($t.Host) 第 2 帧仍含完整特征 $($t.Marker)"

        # 校验两帧重组后与原载荷逐字节 100% 一致
        $reassembled = New-Object byte[] $origRecLen
        [Array]::Copy($frag, 5, $reassembled, 0, $len1)
        [Array]::Copy($frag, $off2 + 5, $reassembled, $len1, $len2)
        for ($i = 0; $i -lt $origRecLen; $i++) {
            if ($reassembled[$i] -ne $ch[5 + $i]) {
                throw "$($t.Host) 重组载荷在第 $i 字节不一致"
            }
        }
    }
}

Invoke-TestCase "TLS 粘包保留、非目标域名透传及超短包/非 TLS 流量零异常透传" {
    # 1. 粘包尾部保留
    $tail = [byte[]]@(0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0xDE, 0xAD, 0xBE, 0xEF)
    $chWithTail = New-TestTlsClientHello -SniHost "api.nrd.nie.163.com" -ExtraTrailingBytes $tail
    $fragTail = [UURemoteTlsFix.TlsFragmenter]::FragmentTlsClientHello($chWithTail, $chWithTail.Length)
    Assert-Equal $fragTail.Length ($chWithTail.Length + 5) "粘包切分后长度异常"
    for ($i = 0; $i -lt $tail.Length; $i++) {
        Assert-Equal $fragTail[$fragTail.Length - $tail.Length + $i] $tail[$i] "尾部粘包第 $i 字节丢失或篡改"
    }

    # 2. 非目标域名透传
    $other = New-TestTlsClientHello -SniHost "www.github.com"
    $otherOut = [UURemoteTlsFix.TlsFragmenter]::FragmentTlsClientHello($other, $other.Length)
    Assert-Equal $otherOut.Length $other.Length "非目标域名不应被切分"

    # 3. 明文 HTTP 与超短包安全透传
    $httpPlain = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: example.com`r`n`r`n")
    $httpOut = [UURemoteTlsFix.TlsFragmenter]::FragmentTlsClientHello($httpPlain, $httpPlain.Length)
    Assert-Equal $httpOut.Length $httpPlain.Length "明文 HTTP 应原样透传"

    $tiny1 = [byte[]]@(0x16, 0x03, 0x01, 0x00, 0x01, 0x01)
    $tiny1Out = [UURemoteTlsFix.TlsFragmenter]::FragmentTlsClientHello($tiny1, $tiny1.Length)
    Assert-Equal $tiny1Out.Length $tiny1.Length "recLen=1 的极短 TLS 记录不应切分出空帧"

    Assert-Equal ([UURemoteTlsFix.TlsFragmenter]::FragmentTlsClientHello($null, 0)).Length 0 "null 应返回空数组"
}

Invoke-TestCase "FragmentedFirstWriteStream 同步 Write 与异步 WriteAsync 首次分片/二次透传校验" {
    $ch = New-TestTlsClientHello -SniHost "api.nrd.nie.163.com"
    $secondMsg = [System.Text.Encoding]::ASCII.GetBytes("SECOND-FRAME")

    # 同步 Write 路径
    $sink1 = New-Object System.IO.MemoryStream
    $fs1 = New-Object UURemoteTlsFix.FragmentedFirstWriteStream($sink1, $true)
    $fs1.Write($ch, 0, $ch.Length)
    $fs1.Write($secondMsg, 0, $secondMsg.Length)
    $fs1.Dispose()
    Assert-Equal $sink1.Length ($ch.Length + 5 + $secondMsg.Length) "同步 Write 首次应分片、二次应透传"

    # 异步 WriteAsync 路径
    $sink2 = New-Object System.IO.MemoryStream
    $fs2 = New-Object UURemoteTlsFix.FragmentedFirstWriteStream($sink2, $true)
    $fs2.WriteAsync($ch, 0, $ch.Length).GetAwaiter().GetResult()
    $fs2.WriteAsync($secondMsg, 0, $secondMsg.Length).GetAwaiter().GetResult()
    $fs2.Dispose()
    Assert-Equal $sink2.Length ($ch.Length + 5 + $secondMsg.Length) "异步 WriteAsync 首次应分片、二次应透传"
}

Invoke-TestCase "HTTP 降级 Host 改写无损保留二进制 POST Body 测试" {
    $hdr = [System.Text.Encoding]::ASCII.GetBytes("POST /upload HTTP/1.1`r`nHost: 123.58.184.232:80`r`nContent-Length: 5`r`n`r`n")
    $binBody = [byte[]]@(0xFF, 0xFE, 0x00, 0x80, 0xC3)
    $req = New-Object byte[] ($hdr.Length + $binBody.Length)
    [Array]::Copy($hdr, 0, $req, 0, $hdr.Length)
    [Array]::Copy($binBody, 0, $req, $hdr.Length, $binBody.Length)

    $rewritten = [UURemoteTlsFix.TlsFragmenter]::RewriteFallbackHttpHost($req)
    $rewrittenStr = [System.Text.Encoding]::GetEncoding("ISO-8859-1").GetString($rewritten)
    Assert-True ($rewrittenStr.Contains("Host: api.nrd.nie.163.com`r`n")) "Host 头未正确改写"
    for ($i = 0; $i -lt $binBody.Length; $i++) {
        Assert-Equal $rewritten[$rewritten.Length - $binBody.Length + $i] $binBody[$i] "二进制 Body 第 $i 字节被破坏"
    }
}

Invoke-TestCase "DNS 报文解析、构包、压缩指针防环与畸形包防护单元测试" {
    # 1. 正常查询
    $q = New-TestDnsQuery -TxId 0xBEEF -Domain "Api.NRD.nie.163.com" -QType 1
    $qname = $null; $qtype = 0; $qclass = 0; $qEnd = 0
    $ok = [UURemoteTlsFix.DnsPacketHelper]::TryParseQuery($q, $q.Length, [ref]$qname, [ref]$qtype, [ref]$qclass, [ref]$qEnd)
    Assert-True $ok "标准查询解析失败"
    Assert-Equal $qname "api.nrd.nie.163.com" "域名小写规范化失败"
    Assert-Equal $qtype 1 "QTYPE 应为 1"

    # 2. A 记录构造
    $respA = [UURemoteTlsFix.DnsPacketHelper]::BuildAResponse($q, $qEnd, [System.Net.IPAddress]::Parse("192.168.10.88"), 60)
    Assert-Equal $respA[0] ([byte]0xBE) "TxId 高字节不匹配"
    Assert-Equal $respA[1] ([byte]0xEF) "TxId 低字节不匹配"
    Assert-True (($respA[2] -band 0x80) -ne 0) "QR 应为 1"
    Assert-Equal $respA[7] ([byte]0x01) "ANCOUNT 应为 1"
    Assert-Equal $respA[$respA.Length - 4] ([byte]192) "A 记录 IPv4 第 1 段错误"
    Assert-Equal $respA[$respA.Length - 1] ([byte]88) "A 记录 IPv4 第 4 段错误"
    Assert-True ([UURemoteTlsFix.DnsPacketHelper]::IsValidUpstreamResponse($q, $respA, $respA.Length)) "合法响应校验失败"

    # 3. 篡改 TxId 校验拒绝
    $tampered = [byte[]]$respA.Clone()
    $tampered[0] = 0x00
    Assert-True (-not [UURemoteTlsFix.DnsPacketHelper]::IsValidUpstreamResponse($q, $tampered, $tampered.Length)) "篡改 TxId 应被拒绝"

    # 4. 畸形包全部安全拒绝
    $qrResp = New-TestDnsQuery -TxId 0x1111 -Domain "dns.qq.com" -FlagsHi 0x81 # QR=1 响应包
    Assert-True (-not [UURemoteTlsFix.DnsPacketHelper]::TryParseQuery($qrResp, $qrResp.Length, [ref]$qname, [ref]$qtype, [ref]$qclass, [ref]$qEnd)) "QR=1 响应包应拒绝处理"

    $zeroQd = [byte[]]@(0x12, 0x34, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01)
    Assert-True (-not [UURemoteTlsFix.DnsPacketHelper]::TryParseQuery($zeroQd, $zeroQd.Length, [ref]$qname, [ref]$qtype, [ref]$qclass, [ref]$qEnd)) "QDCOUNT=0 应拒绝"

    # 压缩指针自环：偏移 12 指向自身 0xC0 0x0C
    $loopPtr = [byte[]]@(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01)
    Assert-True (-not [UURemoteTlsFix.DnsPacketHelper]::TryParseQuery($loopPtr, $loopPtr.Length, [ref]$qname, [ref]$qtype, [ref]$qclass, [ref]$qEnd)) "循环压缩指针应被安全拦截"

    # 非法保留高位标签 0x41
    $badLabel = [byte[]]@(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x41, 0x61, 0x00, 0x00, 0x01, 0x00, 0x01)
    Assert-True (-not [UURemoteTlsFix.DnsPacketHelper]::TryParseQuery($badLabel, $badLabel.Length, [ref]$qname, [ref]$qtype, [ref]$qclass, [ref]$qEnd)) "非法保留标签位应拒绝"
}

Invoke-TestCase "目标 IP 策略映射与未知不可解析域名绝不误导流测试" {
    $cfg = New-Object UURemoteTlsFix.FragmenterConfig
    $cfg.EnableFileLogging = $false
    $srv = New-Object UURemoteTlsFix.FragmenterServer($cfg)
    try {
        $ip1 = $srv.ResolveOptimalTargetIpAsync("123.58.163.37", [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        Assert-Equal $ip1 "112.13.123.98" "受限 IP 应重定向至优质官方 IP"
        $ip2 = $srv.ResolveOptimalTargetIpAsync("223.252.194.149", [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        Assert-Equal $ip2 "34.95.122.33" "受限信令 IP 应重定向"
        $ip3 = $srv.ResolveOptimalTargetIpAsync("dns.wechat.com", [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        Assert-Equal $ip3 "43.152.112.101" "dns.wechat.com 应返回优选 IP"
        $ipNull = $srv.ResolveOptimalTargetIpAsync("nonexistent-unit-test-host-xyz.invalid", [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        Assert-True ($ipNull -ne "112.13.123.98") "未知不可解析域名绝不能错误导流到网易服务器 IP！"
    } finally {
        $srv.Dispose()
    }
}

Write-Host "`n=== [Suite 3] 全链路环回集成测试（127.0.0.1 随机端口，零宿主机影响） ===" -ForegroundColor Cyan

$tmpBaseDir = Join-Path $env:TEMP ("campus_tls_int_test_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $tmpBaseDir -Force | Out-Null

$mockTcp = New-Object CampusTlsTestHarness.MockTcpCaptureServer
$mockDns = New-Object CampusTlsTestHarness.MockUpstreamDnsServer("10.10.20.30")
$mainPort = Get-FreeTcpPort
$tlsPort  = Get-FreeTcpPort
$dnsPort  = Get-FreeUdpPort

$cfg = New-Object UURemoteTlsFix.FragmenterConfig
$cfg.TcpBindAddress = [System.Net.IPAddress]::Loopback
$cfg.MainPort = $mainPort
$cfg.TransparentTlsPort = $tlsPort
$cfg.EnableLanDns = $true
$cfg.DnsBindAddress = [System.Net.IPAddress]::Loopback
$cfg.DnsPort = $dnsPort
$cfg.LanDnsAnswerIp = [System.Net.IPAddress]::Parse("192.168.55.66")
$cfg.BindOutboundToPhysicalNic = $false
$cfg.BaseDir = $tmpBaseDir
$cfg.EnableFileLogging = $false
$cfg.HandshakeReadTimeoutMs = 3000
$cfg.DnsUpstreamTimeoutMs = 400
$cfg.HalfCloseGraceTimeoutMs = 2000

$upstreamList = New-Object 'System.Collections.Generic.List[System.Net.IPEndPoint]'
$upstreamList.Add((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, $mockDns.Port)))
$cfg.UpstreamDnsOverride = $upstreamList

# 仅在环回集成测试中将解析结果重定向到本地 Mock TCP 捕获服务器，绝不访问外网
# 使用纯 C# 委托避免 PowerShell ScriptBlock 在后台线程池中缺少 Runspace 的问题
$cfg.TargetResolverOverride = [CampusTlsTestHarness.ResolverFactory]::CreateFixedLoopback($mockTcp.Port)

$cts = New-Object System.Threading.CancellationTokenSource
$server = New-Object UURemoteTlsFix.FragmenterServer($cfg)
$serverTask = $server.RunAsync($cts.Token)

# 等待所有监听就绪
Start-Sleep -Milliseconds 300

try {
    Invoke-TestCase "集成 1: SOCKS5 代理 + TLS ClientHello 3 段 TCP 拆包聚合与双帧精准切分" {
        $mockTcp.ResponseDelayMs = 0
        $mockTcp.ResponsePayload = [System.Text.Encoding]::ASCII.GetBytes("SOCKS5-PONG")
        $ch = New-TestTlsClientHello -SniHost "api.nrd.nie.163.com" -IncludeGreaseExtension

        $tc = New-Object System.Net.Sockets.TcpClient
        try {
            $tc.Connect("127.0.0.1", $mainPort)
            $ns = $tc.GetStream()
            $ns.ReadTimeout = 3000

            # SOCKS5 greeting
            $ns.Write([byte[]]@(0x05, 0x01, 0x00), 0, 3)
            $gResp = New-Object byte[] 2
            Assert-Equal ($ns.Read($gResp, 0, 2)) 2 "SOCKS5 握手响应不完整"
            Assert-Equal $gResp[1] ([byte]0x00) "SOCKS5 未选择无认证"

            # SOCKS5 CONNECT api.nrd.nie.163.com:443
            $hostBytes = [System.Text.Encoding]::ASCII.GetBytes("api.nrd.nie.163.com")
            $req = New-Object System.IO.MemoryStream
            $req.Write([byte[]]@(0x05, 0x01, 0x00, 0x03, [byte]$hostBytes.Length), 0, 5)
            $req.Write($hostBytes, 0, $hostBytes.Length)
            $req.Write([byte[]]@(0x01, 0xBB), 0, 2) # 443
            $reqBytes = $req.ToArray()
            $ns.Write($reqBytes, 0, $reqBytes.Length)

            $cResp = New-Object byte[] 10
            Assert-Equal ($ns.Read($cResp, 0, 10)) 10 "SOCKS5 CONNECT 响应不完整"
            Assert-Equal $cResp[1] ([byte]0x00) "SOCKS5 CONNECT 未返回成功"

            # 故意拆包发送 TLS ClientHello：先发 3 字节，再发 10 字节，再发剩余字节
            $ns.Write($ch, 0, 3); $ns.Flush(); Start-Sleep -Milliseconds 25
            $ns.Write($ch, 3, 10); $ns.Flush(); Start-Sleep -Milliseconds 25
            $ns.Write($ch, 13, $ch.Length - 13); $ns.Flush()
            $tc.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)

            $respBuf = New-Object byte[] 64
            $rn = $ns.Read($respBuf, 0, $respBuf.Length)
            $respStr = [System.Text.Encoding]::ASCII.GetString($respBuf, 0, $rn)
            Assert-Equal $respStr "SOCKS5-PONG" "未收到 Mock 服务端回包"

            $captured = $mockTcp.LastReceivedPayload
            Assert-Equal $captured.Length ($ch.Length + 5) "拆包聚合后的 ClientHello 应被准确切分为 2 个 TLS Record（长度 +5）"
            $len1 = ([int]$captured[3] -shl 8) -bor $captured[4]
            Assert-Equal $captured[5 + $len1] ([byte]0x16) "第 2 个 TLS Record 起始标志缺失"
        } finally {
            $tc.Dispose()
        }
    }

    Invoke-TestCase "集成 2: HTTP CONNECT + TLS 分片 + TCP 半关闭 (Half-Close) 完整接收延迟响应" {
        $bigPayload = New-Object byte[] 4096
        for ($i = 0; $i -lt $bigPayload.Length; $i++) { $bigPayload[$i] = [byte]($i -band 0xFF) }
        $mockTcp.ResponseDelayMs = 100
        $mockTcp.ResponsePayload = $bigPayload

        $ch = New-TestTlsClientHello -SniHost "dns.qq.com"
        $tc = New-Object System.Net.Sockets.TcpClient
        try {
            $tc.Connect("127.0.0.1", $mainPort)
            $ns = $tc.GetStream()
            $ns.ReadTimeout = 3000

            $connectReq = [System.Text.Encoding]::ASCII.GetBytes("CONNECT dns.qq.com:443 HTTP/1.1`r`nHost: dns.qq.com:443`r`n`r`n")
            $ns.Write($connectReq, 0, $connectReq.Length)

            $hdrBuf = New-Object byte[] 256
            $hn = $ns.Read($hdrBuf, 0, $hdrBuf.Length)
            $hdrText = [System.Text.Encoding]::ASCII.GetString($hdrBuf, 0, $hn)
            Assert-True ($hdrText.StartsWith("HTTP/1.1 200")) "HTTP CONNECT 未返回 200: $hdrText"

            # 发送 ClientHello 后立刻半关闭写方向，考验代理是否保留服务端回流数据
            $ns.Write($ch, 0, $ch.Length); $ns.Flush()
            $tc.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)

            $recvMs = New-Object System.IO.MemoryStream
            $rBuf = New-Object byte[] 1024
            while ($true) {
                $r = $ns.Read($rBuf, 0, $rBuf.Length)
                if ($r -le 0) { break }
                $recvMs.Write($rBuf, 0, $r)
            }
            $got = $recvMs.ToArray()
            Assert-Equal $got.Length 4096 "TCP 半关闭后服务端延迟回传的 4096 字节被提前截断！"
            Assert-Equal $mockTcp.LastReceivedPayload.Length ($ch.Length + 5) "HTTP CONNECT 下未触发 TLS 分片"
        } finally {
            $tc.Dispose()
        }
    }

    Invoke-TestCase "集成 3: HTTP 非法方法 (405) 与越界端口 (400) 及超长 Header 熔断防护" {
        # 3a. 非 CONNECT 方法返回 405
        $tc1 = New-Object System.Net.Sockets.TcpClient
        try {
            $tc1.Connect("127.0.0.1", $mainPort)
            $ns1 = $tc1.GetStream(); $ns1.ReadTimeout = 2000
            $req1 = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: example.com`r`n`r`n")
            $ns1.Write($req1, 0, $req1.Length)
            $b1 = New-Object byte[] 256
            $n1 = $ns1.Read($b1, 0, $b1.Length)
            $t1 = [System.Text.Encoding]::ASCII.GetString($b1, 0, $n1)
            Assert-True ($t1.StartsWith("HTTP/1.1 405")) "GET 请求应返回 405，实际: $t1"
        } finally { $tc1.Dispose() }

        # 3b. 非法端口返回 400
        $tc2 = New-Object System.Net.Sockets.TcpClient
        try {
            $tc2.Connect("127.0.0.1", $mainPort)
            $ns2 = $tc2.GetStream(); $ns2.ReadTimeout = 2000
            $req2 = [System.Text.Encoding]::ASCII.GetBytes("CONNECT example.com:99999 HTTP/1.1`r`n`r`n")
            $ns2.Write($req2, 0, $req2.Length)
            $b2 = New-Object byte[] 256
            $n2 = $ns2.Read($b2, 0, $b2.Length)
            $t2 = [System.Text.Encoding]::ASCII.GetString($b2, 0, $n2)
            Assert-True ($t2.StartsWith("HTTP/1.1 400")) "越界端口应返回 400，实际: $t2"
        } finally { $tc2.Dispose() }

        # 3c. 超长无换行 HTTP 垃圾流快速熔断断开
        $tc3 = New-Object System.Net.Sockets.TcpClient
        try {
            $tc3.Connect("127.0.0.1", $mainPort)
            $ns3 = $tc3.GetStream(); $ns3.ReadTimeout = 2000
            $junk = New-Object byte[] 10000
            for ($i = 0; $i -lt $junk.Length; $i++) { $junk[$i] = [byte]0x41 }
            try { $ns3.Write($junk, 0, $junk.Length) } catch { $null = $_ }
            $b3 = New-Object byte[] 16
            $closed = $false
            try { $closed = ($ns3.Read($b3, 0, $b3.Length) -eq 0) } catch { $closed = $true }
            Assert-True $closed "超长无换行 Header 未被服务端熔断断开"
        } finally { $tc3.Dispose() }
    }

    Invoke-TestCase "集成 4: 透明 TLS 监听端口直连分片与双向转发验证" {
        $mockTcp.ResponseDelayMs = 0
        $mockTcp.ResponsePayload = [System.Text.Encoding]::ASCII.GetBytes("TRANSPARENT-OK")
        $ch = New-TestTlsClientHello -SniHost "dns.weixin.qq.com.cn"
        $tc = New-Object System.Net.Sockets.TcpClient
        try {
            $tc.Connect("127.0.0.1", $tlsPort)
            $ns = $tc.GetStream(); $ns.ReadTimeout = 3000
            $ns.Write($ch, 0, $ch.Length); $ns.Flush()
            $tc.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
            $rb = New-Object byte[] 64
            $rn = $ns.Read($rb, 0, $rb.Length)
            Assert-Equal ([System.Text.Encoding]::ASCII.GetString($rb, 0, $rn)) "TRANSPARENT-OK" "透明 TLS 转发回包异常"
            Assert-Equal $mockTcp.LastReceivedPayload.Length ($ch.Length + 5) "透明 TLS 端口未触发双帧分片"
        } finally { $tc.Dispose() }
    }

    Invoke-TestCase "集成 5: UDP LAN DNS 拦截、QQ 三模式热切换、上游内网转发、畸形包抗压与 SERVFAIL" {
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Client.ReceiveTimeout = 2000
        $dnsEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, $dnsPort)
        $modeFile = Join-Path $tmpBaseDir "qq_wechat_mode.txt"
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

        try {
            # 5a. UU 域名 A 记录 -> 192.168.55.66; AAAA -> NOERROR 空应答
            $qUuA = New-TestDnsQuery -TxId 0x2001 -Domain "api.nrd.nie.163.com" -QType 1
            [void]$udpClient.Send($qUuA, $qUuA.Length, $dnsEp)
            $from = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $rUuA = $udpClient.Receive([ref]$from)
            Assert-Equal $rUuA[7] ([byte]1) "UU 域名 A 记录应返回 1 条 Answer"
            $ipAns = New-Object System.Net.IPAddress(, $rUuA[($rUuA.Length - 4)..($rUuA.Length - 1)])
            Assert-Equal $ipAns.ToString() "192.168.55.66" "UU 域名 LAN DNS 返回 IP 错误"

            $qUuAAAA = New-TestDnsQuery -TxId 0x2002 -Domain "api.nrd.nie.163.com" -QType 28
            [void]$udpClient.Send($qUuAAAA, $qUuAAAA.Length, $dnsEp)
            $rUuAAAA = $udpClient.Receive([ref]$from)
            Assert-Equal ($rUuAAAA[3] -band 0x0F) 0 "UU AAAA 应返回 NOERROR"
            Assert-Equal $rUuAAAA[7] ([byte]0) "UU AAAA Answer 数应为 0"

            # 5b. QQ 域名默认 fragment 模式 -> 192.168.55.66
            $qQq = New-TestDnsQuery -TxId 0x2003 -Domain "dns.qq.com" -QType 1
            [void]$udpClient.Send($qQq, $qQq.Length, $dnsEp)
            $rQqFrag = $udpClient.Receive([ref]$from)
            Assert-Equal $rQqFrag[7] ([byte]1) "fragment 模式下 dns.qq.com 应返回 LAN IP"

            # 5c. 热切换模式为 fastfail -> NXDOMAIN (RCODE=3)
            [System.IO.File]::WriteAllText($modeFile, "fastfail", $utf8NoBom)
            Start-Sleep -Milliseconds 1150 # 等待 1s 模式缓存过期
            $qQq2 = New-TestDnsQuery -TxId 0x2004 -Domain "dns.qq.com" -QType 1
            [void]$udpClient.Send($qQq2, $qQq2.Length, $dnsEp)
            $rQqFf = $udpClient.Receive([ref]$from)
            Assert-Equal ($rQqFf[3] -band 0x0F) 3 "fastfail 模式下 dns.qq.com 应返回 NXDOMAIN (RCODE=3)"

            # 5d. 普通校园内网域名 -> 转发至 Mock 上游并返回 10.10.20.30
            $qCampus = New-TestDnsQuery -TxId 0x2005 -Domain "portal.campus.edu.cn" -QType 1
            [void]$udpClient.Send($qCampus, $qCampus.Length, $dnsEp)
            $rCampus = $udpClient.Receive([ref]$from)
            $campusIp = New-Object System.Net.IPAddress(, $rCampus[($rCampus.Length - 4)..($rCampus.Length - 1)])
            Assert-Equal $campusIp.ToString() "10.10.20.30" "校园内网域名未正确转发上游 DNS"

            # 5e. 热切换模式为 off -> dns.qq.com 放行转发给上游
            [System.IO.File]::WriteAllText($modeFile, "off", $utf8NoBom)
            Start-Sleep -Milliseconds 1150
            $qQq3 = New-TestDnsQuery -TxId 0x2006 -Domain "dns.qq.com" -QType 1
            [void]$udpClient.Send($qQq3, $qQq3.Length, $dnsEp)
            $rQqOff = $udpClient.Receive([ref]$from)
            $qqOffIp = New-Object System.Net.IPAddress(, $rQqOff[($rQqOff.Length - 4)..($rQqOff.Length - 1)])
            Assert-Equal $qqOffIp.ToString() "10.10.20.30" "off 模式下 dns.qq.com 应直接转发上游"

            # 5f. 连续发送畸形 DNS 包（超短包、QR=1、循环压缩指针），服务不得崩溃
            $malformedList = @(
                [byte[]]@(0x01, 0x02),
                (New-TestDnsQuery -TxId 0x9999 -Domain "dns.qq.com" -FlagsHi 0x81),
                [byte[]]@(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01)
            )
            foreach ($mal in $malformedList) {
                [void]$udpClient.Send($mal, $mal.Length, $dnsEp)
            }
            Start-Sleep -Milliseconds 100
            $qAfter = New-TestDnsQuery -TxId 0x2007 -Domain "api.nrd.nie.163.com" -QType 1
            [void]$udpClient.Send($qAfter, $qAfter.Length, $dnsEp)
            $rAfter = $udpClient.Receive([ref]$from)
            Assert-Equal $rAfter[7] ([byte]1) "遭受畸形 DNS 包后服务应保持完全健康"

            # 5g. 关闭上游 Mock DNS，验证超时后优雅返回 SERVFAIL (RCODE=2)
            $mockDns.Dispose()
            $qFail = New-TestDnsQuery -TxId 0x2008 -Domain "unreachable.campus.edu.cn" -QType 1
            [void]$udpClient.Send($qFail, $qFail.Length, $dnsEp)
            $rFail = $udpClient.Receive([ref]$from)
            Assert-Equal ($rFail[3] -band 0x0F) 2 "所有上游不可达时应返回 SERVFAIL (RCODE=2)"
        } finally {
            $udpClient.Dispose()
        }
    }

    Invoke-TestCase "集成 6: CancellationToken 优雅停机与 TCP/UDP 端口即时释放验证" {
        $cts.Cancel()
        $finished = $serverTask.Wait(3000)
        Assert-True $finished "服务端未在 3 秒内响应 CancellationToken 优雅退出"

        # 验证端口已全部释放可立即重新绑定
        $rebindTcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $mainPort)
        $rebindTcp.Start()
        $rebindTcp.Stop()

        $rebindUdp = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
        $rebindUdp.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, $dnsPort)))
        $rebindUdp.Close()
    }
} finally {
    try { $cts.Cancel() } catch { $null = $_ }
    try { $null = $serverTask.Wait(2000) } catch { $null = $_ }
    $server.Dispose()
    $cts.Dispose()
    $mockTcp.Dispose()
    $mockDns.Dispose()
    Remove-Item -Path $tmpBaseDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ("`n[Suite 2+3 汇总] 通过: {0}, 失败: {1}" -f $script:Passed, $script:Failed) -ForegroundColor $(if ($script:Failed -eq 0) { "Green" } else { "Red" })
if ($script:Failed -gt 0) { exit 1 }
exit 0
