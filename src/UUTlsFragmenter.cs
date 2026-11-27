using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace UURemoteTlsFix
{
    /// <summary>
    /// 包装底层流并在首次写入 TLS ClientHello 报文时自动执行双帧 Record 切分的装饰流。
    /// 同时重写同步 Write、APM BeginWrite/EndWrite 与异步 WriteAsync，确保任意 I/O 路径均可稳定生效。
    /// </summary>
    public sealed class FragmentedFirstWriteStream : Stream
    {
        private readonly Stream _inner;
        private readonly bool _leaveInnerStreamOpen;
        private int _firstWritePending = 1;

        public FragmentedFirstWriteStream(Stream inner)
            : this(inner, true)
        {
        }

        public FragmentedFirstWriteStream(Stream inner, bool leaveInnerStreamOpen)
        {
            if (inner == null) throw new ArgumentNullException("inner");
            _inner = inner;
            _leaveInnerStreamOpen = leaveInnerStreamOpen;
        }

        public override bool CanRead { get { return _inner.CanRead; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return _inner.CanWrite; } }
        public override bool CanTimeout { get { return _inner.CanTimeout; } }
        public override int ReadTimeout { get { return _inner.ReadTimeout; } set { _inner.ReadTimeout = value; } }
        public override int WriteTimeout { get { return _inner.WriteTimeout; } set { _inner.WriteTimeout = value; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

        public override void Flush()
        {
            _inner.Flush();
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return _inner.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _inner.Read(buffer, offset, count);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return _inner.ReadAsync(buffer, offset, count, cancellationToken);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        private byte[] PrepareWriteBuffer(byte[] buffer, int offset, int count, out int outOffset, out int outCount)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            if (offset < 0 || count < 0 || offset + count > buffer.Length)
                throw new ArgumentOutOfRangeException("count");

            if (count > 0 && Interlocked.CompareExchange(ref _firstWritePending, 0, 1) == 1)
            {
                byte[] slice = new byte[count];
                Buffer.BlockCopy(buffer, offset, slice, 0, count);
                byte[] fragmented = TlsFragmenter.FragmentTlsClientHello(slice, count);
                outOffset = 0;
                outCount = fragmented.Length;
                return fragmented;
            }

            outOffset = offset;
            outCount = count;
            return buffer;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            int outOffset;
            int outCount;
            byte[] payload = PrepareWriteBuffer(buffer, offset, count, out outOffset, out outCount);
            _inner.Write(payload, outOffset, outCount);
        }

        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            int outOffset;
            int outCount;
            byte[] payload = PrepareWriteBuffer(buffer, offset, count, out outOffset, out outCount);
            return _inner.BeginWrite(payload, outOffset, outCount, callback, state);
        }

        public override void EndWrite(IAsyncResult asyncResult)
        {
            _inner.EndWrite(asyncResult);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int outOffset;
            int outCount;
            byte[] payload = PrepareWriteBuffer(buffer, offset, count, out outOffset, out outCount);
            return _inner.WriteAsync(payload, outOffset, outCount, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_leaveInnerStreamOpen)
            {
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// TLS ClientHello 精确解析、SNI 提取、Record 双帧切分及 HTTP 降级头改写工具类。
    /// 严格遵循 RFC 5246 / RFC 6066 / RFC 8446 边界检查，杜绝越界与非标误判。
    /// </summary>
    public static class TlsFragmenter
    {
        public const int MaxTlsRecordPayload = 16384;

        private static readonly string[] TargetMarkers = new string[]
        {
            "nrd.nie.163.com",
            "dns.weixin.qq.com.cn",
            "dns.weixin.qq.com",
            "httpdns.kg.qq.com",
            "dns.wechat.com",
            "dns.qq.com"
        };

        private static readonly HashSet<string> TencentHttpDnsHosts =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "dns.qq.com",
                "dns.weixin.qq.com",
                "dns.weixin.qq.com.cn",
                "httpdns.kg.qq.com",
                "dns.wechat.com"
            };

        private static readonly Regex FallbackHostHeaderRegex =
            new Regex(@"(?im)^Host:\s*(123\.58\.184\.232|42\.186\.225\.155)(:\d+)?\r\n", RegexOptions.Compiled);

        /// <summary>
        /// 判断域名是否属于网易 UU 远程受阻断域名（nrd.nie.163.com 及其子域）。
        /// </summary>
        public static bool IsUuTargetHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            string normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
            return normalized == "nrd.nie.163.com" || normalized.EndsWith(".nrd.nie.163.com", StringComparison.Ordinal);
        }

        /// <summary>
        /// 判断域名是否属于腾讯/微信 HTTPDNS 目标域名。
        /// </summary>
        public static bool IsTencentHttpDnsHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            string normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
            return TencentHttpDnsHosts.Contains(normalized);
        }

        /// <summary>
        /// 判断域名是否需要执行 TLS ClientHello SNI 双帧分片。
        /// </summary>
        public static bool IsTargetFragmentHost(string host)
        {
            return IsUuTargetHost(host) || IsTencentHttpDnsHost(host);
        }

        /// <summary>
        /// 校验 5 字节 TLS Record 头部是否为合法的 Handshake (0x16) 记录。
        /// </summary>
        public static bool TryReadTlsHandshakeRecordLength(byte[] data, int len, out int recordLength)
        {
            recordLength = 0;
            if (data == null || len < 5 || len > data.Length) return false;
            if (data[0] != 0x16 || data[1] != 0x03 || data[2] > 0x04) return false;
            int rlen = (data[3] << 8) | data[4];
            if (rlen <= 0 || rlen > MaxTlsRecordPayload) return false;
            recordLength = rlen;
            return true;
        }

        /// <summary>
        /// 按 RFC 6066 严格解析 TLS ClientHello 中的 server_name (SNI) 扩展，
        /// 同时输出主机名以及主机名在首条 TLS Record 载荷中的精确偏移与长度。
        /// </summary>
        public static bool TryParseClientHelloSni(
            byte[] data,
            int len,
            out string sni,
            out int sniPayloadOffset,
            out int sniPayloadLength)
        {
            sni = null;
            sniPayloadOffset = -1;
            sniPayloadLength = 0;

            int recLen;
            if (!TryReadTlsHandshakeRecordLength(data, len, out recLen)) return false;

            int recEnd = Math.Min(len, 5 + recLen);
            // Record Header(5) + Handshake Header(4) + ClientVersion(2) + Random(32) = 43 字节
            if (recEnd < 43) return false;
            if (data[5] != 0x01) return false; // 必须为 ClientHello

            int handshakeLen = (data[6] << 16) | (data[7] << 8) | data[8];
            int hsEnd = Math.Min(recEnd, 9 + handshakeLen);
            if (hsEnd < 43) return false;

            int pos = 43; // 跳过 ClientVersion(2) + Random(32)

            // 1. Session ID
            if (pos + 1 > hsEnd) return false;
            int sessionIdLen = data[pos++];
            if (pos + sessionIdLen > hsEnd) return false;
            pos += sessionIdLen;

            // 2. Cipher Suites
            if (pos + 2 > hsEnd) return false;
            int cipherSuitesLen = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (cipherSuitesLen < 2 || (cipherSuitesLen & 1) != 0 || pos + cipherSuitesLen > hsEnd) return false;
            pos += cipherSuitesLen;

            // 3. Compression Methods
            if (pos + 1 > hsEnd) return false;
            int compressionLen = data[pos++];
            if (compressionLen < 1 || pos + compressionLen > hsEnd) return false;
            pos += compressionLen;

            // 4. Extensions
            if (pos + 2 > hsEnd) return false;
            int extensionsLen = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            int extEnd = Math.Min(hsEnd, pos + extensionsLen);

            while (pos + 4 <= extEnd)
            {
                int extType = (data[pos] << 8) | data[pos + 1];
                int extLen = (data[pos + 2] << 8) | data[pos + 3];
                pos += 4;
                if (pos + extLen > extEnd) return false;

                if (extType == 0x0000) // server_name 扩展
                {
                    int sniPos = pos;
                    int sniLimit = pos + extLen;
                    if (sniPos + 2 > sniLimit) return false;
                    int listLen = (data[sniPos] << 8) | data[sniPos + 1];
                    sniPos += 2;
                    int listEnd = Math.Min(sniLimit, sniPos + listLen);

                    while (sniPos + 3 <= listEnd)
                    {
                        byte nameType = data[sniPos++];
                        int nameLen = (data[sniPos] << 8) | data[sniPos + 1];
                        sniPos += 2;
                        if (sniPos + nameLen > listEnd) return false;

                        if (nameType == 0x00 && nameLen > 0 && nameLen <= 255)
                        {
                            if (!IsValidHostNameBytes(data, sniPos, nameLen)) return false;
                            sni = Encoding.ASCII.GetString(data, sniPos, nameLen).ToLowerInvariant();
                            sniPayloadOffset = sniPos - 5; // 相对于 Record Payload (data[5]) 的偏移
                            sniPayloadLength = nameLen;
                            return true;
                        }
                        sniPos += nameLen;
                    }
                    return false;
                }

                pos += extLen;
            }

            return false;
        }

        /// <summary>
        /// 从 TLS ClientHello 报文中提取 SNI 主机名；非 TLS 报文或畸形报文安全返回 null。
        /// </summary>
        public static string ExtractSniFromClientHello(byte[] buf, int len)
        {
            string sni;
            int offset;
            int length;
            if (TryParseClientHelloSni(buf, len, out sni, out offset, out length))
                return sni;
            return null;
        }

        /// <summary>
        /// 若首个 TLS Record 为命中目标域名的 ClientHello，将其在关键域名标识中间切分为 2 个标准 TLS Record 帧；
        /// 其余流量（非 TLS、非目标域名、短包、截断包）保持原样安全拷贝透传。
        /// </summary>
        public static byte[] FragmentTlsClientHello(byte[] data, int len)
        {
            if (data == null || len <= 0) return new byte[0];
            if (len > data.Length) len = data.Length;

            int recLen;
            if (!TryReadTlsHandshakeRecordLength(data, len, out recLen))
                return CopySlice(data, len);

            int totalFirstRec = 5 + recLen;
            // 至少需要 2 字节载荷才能切分成两个非空 TLS Record
            if (len < totalFirstRec || recLen < 2 || data[5] != 0x01)
                return CopySlice(data, len);

            int splitPos = -1;

            // 主路径：严格按 RFC 6066 定位 SNI 扩展偏移，并优先在核心被封锁后缀中间切分
            string sni;
            int sniPayloadOffset;
            int sniPayloadLength;
            if (TryParseClientHelloSni(data, totalFirstRec, out sni, out sniPayloadOffset, out sniPayloadLength))
            {
                if (!IsTargetFragmentHost(sni))
                    return CopySlice(data, len);

                int markerIdx = -1;
                int markerLen = 0;
                for (int i = 0; i < TargetMarkers.Length; i++)
                {
                    int idx = sni.IndexOf(TargetMarkers[i], StringComparison.OrdinalIgnoreCase);
                    if (idx >= 0)
                    {
                        markerIdx = idx;
                        markerLen = TargetMarkers[i].Length;
                        break;
                    }
                }

                if (markerIdx >= 0 && markerLen >= 2)
                    splitPos = sniPayloadOffset + markerIdx + (markerLen / 2);
                else
                    splitPos = sniPayloadOffset + Math.Max(1, sniPayloadLength / 2);
            }
            else
            {
                // 兜底路径：针对极少数非标准 ClientHello，在首个 Record 载荷字节内安全扫描 ASCII 目标标记
                for (int i = 0; i < TargetMarkers.Length; i++)
                {
                    int relIdx = IndexOfAsciiIgnoreCase(data, 5, recLen, TargetMarkers[i]);
                    if (relIdx >= 0)
                    {
                        splitPos = relIdx + (TargetMarkers[i].Length / 2);
                        break;
                    }
                }
            }

            if (splitPos < 0)
                return CopySlice(data, len);

            if (splitPos <= 0 || splitPos >= recLen)
                splitPos = recLen / 2;

            byte verMajor = data[1];
            byte verMinor = data[2];
            int len1 = splitPos;
            int len2 = recLen - splitPos;
            int remLen = len - totalFirstRec;

            byte[] outBuf = new byte[5 + len1 + 5 + len2 + remLen];

            // 第 1 个 TLS Record 帧
            outBuf[0] = 0x16;
            outBuf[1] = verMajor;
            outBuf[2] = verMinor;
            outBuf[3] = (byte)((len1 >> 8) & 0xFF);
            outBuf[4] = (byte)(len1 & 0xFF);
            Buffer.BlockCopy(data, 5, outBuf, 5, len1);

            // 第 2 个 TLS Record 帧
            int off2 = 5 + len1;
            outBuf[off2] = 0x16;
            outBuf[off2 + 1] = verMajor;
            outBuf[off2 + 2] = verMinor;
            outBuf[off2 + 3] = (byte)((len2 >> 8) & 0xFF);
            outBuf[off2 + 4] = (byte)(len2 & 0xFF);
            Buffer.BlockCopy(data, 5 + len1, outBuf, off2 + 5, len2);

            // 完整保留首条 Record 之后可能粘包的后续数据
            if (remLen > 0)
                Buffer.BlockCopy(data, totalFirstRec, outBuf, off2 + 5 + len2, remLen);

            return outBuf;
        }

        /// <summary>
        /// 仅改写 HTTP 头部区域中的降级 IP Host 头为 api.nrd.nie.163.com，
        /// 完整无损保留 \r\n\r\n 之后的二进制请求体，避免 UTF-8 编解码损坏非文本 Body。
        /// </summary>
        public static byte[] RewriteFallbackHttpHost(byte[] rawRequest)
        {
            if (rawRequest == null || rawRequest.Length == 0) return new byte[0];

            int headerEnd = FindHeaderTerminator(rawRequest, rawRequest.Length);
            int headerLen = headerEnd >= 0 ? headerEnd : rawRequest.Length;
            int bodyLen = rawRequest.Length - headerLen;

            string headerText = Encoding.GetEncoding("ISO-8859-1").GetString(rawRequest, 0, headerLen);
            string rewrittenHeader = FallbackHostHeaderRegex.Replace(headerText, "Host: api.nrd.nie.163.com\r\n");
            byte[] headerBytes = Encoding.GetEncoding("ISO-8859-1").GetBytes(rewrittenHeader);

            if (bodyLen <= 0) return headerBytes;

            byte[] result = new byte[headerBytes.Length + bodyLen];
            Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
            Buffer.BlockCopy(rawRequest, headerLen, result, headerBytes.Length, bodyLen);
            return result;
        }

        private static int FindHeaderTerminator(byte[] data, int len)
        {
            for (int i = 3; i < len; i++)
            {
                if (data[i - 3] == (byte)'\r' &&
                    data[i - 2] == (byte)'\n' &&
                    data[i - 1] == (byte)'\r' &&
                    data[i] == (byte)'\n')
                {
                    return i + 1;
                }
            }
            return -1;
        }

        private static bool IsValidHostNameBytes(byte[] data, int offset, int length)
        {
            for (int i = 0; i < length; i++)
            {
                byte b = data[offset + i];
                bool valid = (b >= (byte)'a' && b <= (byte)'z') ||
                             (b >= (byte)'A' && b <= (byte)'Z') ||
                             (b >= (byte)'0' && b <= (byte)'9') ||
                             b == (byte)'-' || b == (byte)'.' || b == (byte)'_';
                if (!valid) return false;
            }
            return true;
        }

        private static int IndexOfAsciiIgnoreCase(byte[] haystack, int start, int count, string needle)
        {
            int nLen = needle.Length;
            if (nLen == 0 || nLen > count) return -1;
            int limit = start + count - nLen;
            for (int i = start; i <= limit; i++)
            {
                bool matched = true;
                for (int j = 0; j < nLen; j++)
                {
                    byte hb = haystack[i + j];
                    if (hb >= (byte)'A' && hb <= (byte)'Z') hb = (byte)(hb + 32);
                    char nc = needle[j];
                    if (nc >= 'A' && nc <= 'Z') nc = (char)(nc + 32);
                    if (hb != (byte)nc)
                    {
                        matched = false;
                        break;
                    }
                }
                if (matched) return i - start;
            }
            return -1;
        }

        private static byte[] CopySlice(byte[] data, int len)
        {
            byte[] copy = new byte[len];
            Buffer.BlockCopy(data, 0, copy, 0, len);
            return copy;
        }
    }

    /// <summary>
    /// RFC 1035 DNS 报文安全解析与响应构造工具类。
    /// 包含畸形包防护、QR 标志校验、压缩指针防死循环与 Transaction ID 一致性校验。
    /// </summary>
    public static class DnsPacketHelper
    {
        public const int MaxDnsUdpPacketSize = 4096;
        private const int MaxDomainLength = 255;
        private const int MaxCompressionJumps = 16;

        /// <summary>
        /// 安全解析 DNS 查询报文。
        /// 拒绝响应包 (QR=1)、空问题段 (QDCOUNT=0)、非法标签长度 (>63)、越界或循环压缩指针。
        /// </summary>
        public static bool TryParseQuery(
            byte[] req,
            int length,
            out string qname,
            out int qtype,
            out int qclass,
            out int questionEnd)
        {
            qname = null;
            qtype = 0;
            qclass = 0;
            questionEnd = 0;

            if (req == null || length < 12 || length > req.Length) return false;

            // 仅处理标准查询请求 (QR 位必须为 0)，防止 DNS 反射/放大循环
            if ((req[2] & 0x80) != 0) return false;

            int qdCount = (req[4] << 8) | req[5];
            if (qdCount < 1) return false;

            int pos = 12;
            int afterQnamePos = -1;
            int jumps = 0;
            StringBuilder sb = new StringBuilder();

            while (true)
            {
                if (pos >= length) return false;
                byte labLen = req[pos];

                if (labLen == 0)
                {
                    if (afterQnamePos < 0) afterQnamePos = pos + 1;
                    break;
                }

                if ((labLen & 0xC0) == 0xC0)
                {
                    if (pos + 1 >= length) return false;
                    if (++jumps > MaxCompressionJumps) return false;
                    int ptr = ((labLen & 0x3F) << 8) | req[pos + 1];
                    if (ptr < 12 || ptr >= length) return false;
                    if (afterQnamePos < 0) afterQnamePos = pos + 2;
                    pos = ptr;
                    continue;
                }

                // RFC 1035 规定普通标签高两位必须为 00（长度 1..63）
                if ((labLen & 0xC0) != 0) return false;

                pos++;
                if (pos + labLen > length) return false;

                if (sb.Length > 0) sb.Append('.');
                if (sb.Length + labLen > MaxDomainLength) return false;

                for (int i = 0; i < labLen; i++)
                {
                    byte b = req[pos + i];
                    if (b < 0x20 || b > 0x7E) return false;
                    sb.Append((char)b);
                }
                pos += labLen;
            }

            if (afterQnamePos < 0 || afterQnamePos + 4 > length) return false;

            qtype = (req[afterQnamePos] << 8) | req[afterQnamePos + 1];
            qclass = (req[afterQnamePos + 2] << 8) | req[afterQnamePos + 3];
            questionEnd = afterQnamePos + 4;
            qname = sb.ToString().ToLowerInvariant();
            return true;
        }

        /// <summary>
        /// 构造标准 IPv4 A 记录应答报文（规范化 QDCOUNT=1, ANCOUNT=1, 清空 NS/AR, 继承 RD 标志）。
        /// </summary>
        public static byte[] BuildAResponse(byte[] req, int qEnd, IPAddress ipv4, uint ttlSeconds)
        {
            if (req == null || qEnd < 12 || qEnd > req.Length)
                throw new ArgumentOutOfRangeException("qEnd");
            if (ipv4 == null || ipv4.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("IPv4 address is required.", "ipv4");

            byte[] resp = new byte[qEnd + 16];
            Buffer.BlockCopy(req, 0, resp, 0, qEnd);

            resp[2] = (byte)(0x80 | (req[2] & 0x01)); // QR=1, Opcode=0, AA=0, TC=0, 继承 RD
            resp[3] = 0x80;                           // RA=1, RCODE=0 (NOERROR)
            resp[4] = 0x00; resp[5] = 0x01;           // QDCOUNT=1
            resp[6] = 0x00; resp[7] = 0x01;           // ANCOUNT=1
            resp[8] = 0x00; resp[9] = 0x00;           // NSCOUNT=0
            resp[10] = 0x00; resp[11] = 0x00;         // ARCOUNT=0

            int aOff = qEnd;
            resp[aOff] = 0xC0; resp[aOff + 1] = 0x0C;     // Name pointer -> offset 12
            resp[aOff + 2] = 0x00; resp[aOff + 3] = 0x01; // Type A
            resp[aOff + 4] = 0x00; resp[aOff + 5] = 0x01; // Class IN
            resp[aOff + 6] = (byte)((ttlSeconds >> 24) & 0xFF);
            resp[aOff + 7] = (byte)((ttlSeconds >> 16) & 0xFF);
            resp[aOff + 8] = (byte)((ttlSeconds >> 8) & 0xFF);
            resp[aOff + 9] = (byte)(ttlSeconds & 0xFF);
            resp[aOff + 10] = 0x00; resp[aOff + 11] = 0x04; // RDLENGTH=4

            byte[] ipBytes = ipv4.GetAddressBytes();
            Buffer.BlockCopy(ipBytes, 0, resp, aOff + 12, 4);
            return resp;
        }

        /// <summary>
        /// 构造无 Answer 段的 DNS 状态响应（如 NOERROR=0、SERVFAIL=2、NXDOMAIN=3）。
        /// </summary>
        public static byte[] BuildStatusResponse(byte[] req, int qEnd, byte rcode)
        {
            if (req == null || qEnd < 12 || qEnd > req.Length)
                throw new ArgumentOutOfRangeException("qEnd");

            byte[] resp = new byte[qEnd];
            Buffer.BlockCopy(req, 0, resp, 0, qEnd);

            resp[2] = (byte)(0x80 | (req[2] & 0x01)); // QR=1, 继承 RD
            resp[3] = (byte)(0x80 | (rcode & 0x0F));  // RA=1, RCODE
            resp[4] = 0x00; resp[5] = 0x01;           // QDCOUNT=1
            resp[6] = 0x00; resp[7] = 0x00;           // ANCOUNT=0
            resp[8] = 0x00; resp[9] = 0x00;           // NSCOUNT=0
            resp[10] = 0x00; resp[11] = 0x00;         // ARCOUNT=0
            return resp;
        }

        /// <summary>
        /// 校验上游 DNS 响应包长度、QR 标志以及 Transaction ID 与原请求是否一致。
        /// </summary>
        public static bool IsValidUpstreamResponse(byte[] req, byte[] resp, int respLen)
        {
            if (req == null || resp == null || req.Length < 12 || respLen < 12 || respLen > resp.Length)
                return false;
            if ((resp[2] & 0x80) == 0) return false;
            return resp[0] == req[0] && resp[1] == req[1];
        }
    }

    /// <summary>
    /// 服务端运行参数配置（默认参数与原有零参数启动行为 100% 一致，同时支持测试与定制化部署）。
    /// </summary>
    public sealed class FragmenterConfig
    {
        public IPAddress TcpBindAddress { get; set; }
        public int MainPort { get; set; }
        public int TransparentTlsPort { get; set; }
        public bool EnableLanDns { get; set; }
        public IPAddress DnsBindAddress { get; set; }
        public int DnsPort { get; set; }
        public IPAddress LanDnsAnswerIp { get; set; }
        public IList<IPEndPoint> UpstreamDnsOverride { get; set; }
        public Func<string, int, IPEndPoint> TargetResolverOverride { get; set; }
        public bool BindOutboundToPhysicalNic { get; set; }
        public string BaseDir { get; set; }
        public bool EnableFileLogging { get; set; }
        public int HandshakeReadTimeoutMs { get; set; }
        public int ConnectTimeoutMs { get; set; }
        public int HalfCloseGraceTimeoutMs { get; set; }
        public int DnsUpstreamTimeoutMs { get; set; }

        public FragmenterConfig()
        {
            TcpBindAddress = IPAddress.Any;
            MainPort = 17899;
            TransparentTlsPort = 443;
            EnableLanDns = true;
            DnsBindAddress = null;
            DnsPort = 53;
            LanDnsAnswerIp = null;
            UpstreamDnsOverride = null;
            TargetResolverOverride = null;
            BindOutboundToPhysicalNic = true;
            BaseDir = AppDomain.CurrentDomain.BaseDirectory;
            EnableFileLogging = true;
            HandshakeReadTimeoutMs = 10000;
            ConnectTimeoutMs = 5000;
            HalfCloseGraceTimeoutMs = 3000;
            DnsUpstreamTimeoutMs = 1500;
        }
    }

    /// <summary>
    /// 本机无窗口 TLS 分片代理与局域网 DNS 守护引擎。
    /// 支持 SOCKS5 / HTTP CONNECT / 透明 TLS / HTTP 降级自愈升级 / 局域网 DNS 动态继承与优雅关停。
    /// </summary>
    public sealed class FragmenterServer : IDisposable
    {
        private const int MaxHttpHeaderBytes = 8192;
        private const int MaxDnsCacheEntries = 1024;
        private const int MaxDohResponseBytes = 65536;
        private const int PumpBufferSize = 16384;
        private const int NetworkSnapshotTtlSeconds = 30;
        private const int SioUdpConnReset = -1744830452;

        private sealed class NetworkSnapshot
        {
            public readonly IPAddress PhysicalIp;
            public readonly IList<IPAddress> PhysicalDnsServers;
            public readonly DateTime CapturedAtUtc;

            public NetworkSnapshot(IPAddress physicalIp, IList<IPAddress> dnsServers, DateTime capturedAtUtc)
            {
                PhysicalIp = physicalIp;
                PhysicalDnsServers = dnsServers;
                CapturedAtUtc = capturedAtUtc;
            }
        }

        private static readonly string[] VirtualAdapterKeywords = new string[]
        {
            "wintun", "tun", "tap", "vethernet", "wsl", "hyper-v",
            "vmware", "virtual", "vbox", "docker", "wireguard", "tailscale",
            "zerotier", "clash", "mihomo", "sing-box", "hamachi", "radmin", "npcap"
        };

        private static readonly string[] DohServers = new string[]
        {
            "223.5.5.5",
            "223.6.6.6"
        };

        private static readonly Regex DohDataIpRegex =
            new Regex("\"data\"\\s*:\\s*\"((?:\\d{1,3}\\.){3}\\d{1,3})\"", RegexOptions.Compiled);

        private static readonly Dictionary<string, string> FallbackHostIps =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "api.nrd.nie.163.com", "112.13.123.98" },
                { "api-ipv4.nrd.nie.163.com", "112.13.123.98" },
                { "api-dcdn.nrd.nie.163.com", "117.148.172.102" },
                { "api-event.nrd.nie.163.com", "117.147.201.23" },
                { "sig-3303-d.nrd.nie.163.com", "34.95.122.33" },
                { "relay-mg-3303-d.nrd.nie.163.com", "117.147.201.40" },
                { "uuyc.163.com", "59.111.44.89" },
                { "uuyc.webapp.163.com", "117.148.172.102" },
                { "nrd-ugc.fp.ps.netease.com", "111.3.79.64" },
                { "fp.ps.netease.com", "111.3.79.64" },
                { "dns.qq.com", "119.29.29.229" },
                { "dns.weixin.qq.com", "120.204.0.63" },
                { "dns.weixin.qq.com.cn", "120.204.0.63" },
                { "httpdns.kg.qq.com", "117.135.175.48" },
                { "dns.wechat.com", "43.152.112.101" }
            };

        private readonly FragmenterConfig _config;
        private readonly string _logPath;
        private readonly string _logOldPath;
        private readonly string _modeFilePath;
        private readonly object _logLock = new object();
        private readonly object _modeCacheLock = new object();
        private readonly ConcurrentDictionary<string, Tuple<string, DateTime>> _dnsCache =
            new ConcurrentDictionary<string, Tuple<string, DateTime>>(StringComparer.OrdinalIgnoreCase);

        private volatile NetworkSnapshot _netSnapshot;
        private string _cachedTencentMode = "fragment";
        private DateTime _cachedTencentModeCheckUtc = DateTime.MinValue;
        private DateTime _cachedTencentModeWriteUtc = DateTime.MinValue;
        private int _disposed;
        private readonly object _dnsSocketLock = new object();
        private Socket _activeAutoLanDnsSocket;
        private IPAddress _activeAutoLanDnsIp;

        private NetworkAddressChangedEventHandler _addrChangedHandler;
        private NetworkAvailabilityChangedEventHandler _availChangedHandler;

        public FragmenterServer(FragmenterConfig config)
        {
            if (config == null) throw new ArgumentNullException("config");
            _config = config;
            string baseDir = string.IsNullOrEmpty(config.BaseDir)
                ? AppDomain.CurrentDomain.BaseDirectory
                : config.BaseDir;
            _logPath = Path.Combine(baseDir, "uu_tls_fragmenter.log");
            _logOldPath = Path.Combine(baseDir, "uu_tls_fragmenter.log.old");
            _modeFilePath = Path.Combine(baseDir, "qq_wechat_mode.txt");

            _addrChangedHandler = delegate(object s, EventArgs e) { OnNetworkChanged(); };
            _availChangedHandler = delegate(object s, NetworkAvailabilityEventArgs e) { OnNetworkChanged(); };
            NetworkChange.NetworkAddressChanged += _addrChangedHandler;
            NetworkChange.NetworkAvailabilityChanged += _availChangedHandler;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                try { NetworkChange.NetworkAddressChanged -= _addrChangedHandler; } catch { }
                try { NetworkChange.NetworkAvailabilityChanged -= _availChangedHandler; } catch { }
            }
        }

        public void InvalidateNetworkCache()
        {
            _netSnapshot = null;
        }

        private void OnNetworkChanged()
        {
            InvalidateNetworkCache();
            if (_config.DnsBindAddress != null) return;

            Socket socketToRestart = null;
            lock (_dnsSocketLock)
            {
                if (_activeAutoLanDnsSocket != null && _activeAutoLanDnsIp != null)
                {
                    IPAddress currentPhys = GetPhysicalNetworkSnapshot().PhysicalIp;
                    if (currentPhys != null && !currentPhys.Equals(_activeAutoLanDnsIp))
                    {
                        socketToRestart = _activeAutoLanDnsSocket;
                    }
                }
            }
            if (socketToRestart != null)
            {
                Log("Network change detected; triggering immediate LAN DNS rebind.");
                try { socketToRestart.Close(); } catch { }
            }
        }

        /// <summary>
        /// 启动所有已配置的 TCP 代理监听与局域网 UDP DNS 服务，直至 CancellationToken 取消。
        /// </summary>
        public Task RunAsync(CancellationToken ct)
        {
            List<Task> tasks = new List<Task>();
            Log(string.Format(
                "Starting UUTlsFragmenter Service (TCP {0}:{1}, TransparentTLS :{2}, LAN DNS :{3})",
                _config.TcpBindAddress,
                _config.MainPort,
                _config.TransparentTlsPort,
                _config.EnableLanDns ? _config.DnsPort : 0));

            if (_config.MainPort > 0)
                tasks.Add(StartTcpListenerAsync(_config.TcpBindAddress, _config.MainPort, ct));
            if (_config.TransparentTlsPort > 0)
                tasks.Add(StartTcpListenerAsync(_config.TcpBindAddress, _config.TransparentTlsPort, ct));
            if (_config.EnableLanDns && _config.DnsPort > 0)
                tasks.Add(StartLanDnsServerAsync(ct));

            return Task.WhenAll(tasks.ToArray());
        }

        private void Log(string msg)
        {
            if (!_config.EnableFileLogging) return;
            try
            {
                string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + " [INFO] " + msg + Environment.NewLine;
                lock (_logLock)
                {
                    FileInfo fi = new FileInfo(_logPath);
                    if (fi.Exists && fi.Length > 2 * 1024 * 1024)
                    {
                        try
                        {
                            if (File.Exists(_logOldPath)) File.Delete(_logOldPath);
                            File.Move(_logPath, _logOldPath);
                        }
                        catch { }
                        File.WriteAllText(_logPath, line, Encoding.UTF8);
                    }
                    else
                    {
                        File.AppendAllText(_logPath, line, Encoding.UTF8);
                    }
                }
            }
            catch { }
        }

        private void ObserveTask(Task task, string context)
        {
            if (task == null) return;
            task.ContinueWith(
                t =>
                {
                    if (t.IsFaulted && t.Exception != null)
                    {
                        Exception inner = t.Exception.GetBaseException();
                        Log("[WARN] Background task fault (" + context + "): " + inner.Message);
                    }
                },
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        }

        /// <summary>
        /// 读取 qq_wechat_mode.txt 运行模式（带 1 秒缓存与修改时间检测，支持热切换且降低磁盘 I/O）。
        /// </summary>
        public string GetTencentDnsLanMode()
        {
            DateTime now = DateTime.UtcNow;
            lock (_modeCacheLock)
            {
                if ((now - _cachedTencentModeCheckUtc).TotalMilliseconds < 1000)
                    return _cachedTencentMode;
                _cachedTencentModeCheckUtc = now;

                try
                {
                    if (!File.Exists(_modeFilePath))
                    {
                        _cachedTencentMode = "fragment";
                        _cachedTencentModeWriteUtc = DateTime.MinValue;
                        return _cachedTencentMode;
                    }

                    DateTime writeUtc = File.GetLastWriteTimeUtc(_modeFilePath);
                    if (writeUtc != _cachedTencentModeWriteUtc)
                    {
                        string m = File.ReadAllText(_modeFilePath, Encoding.UTF8).Trim().ToLowerInvariant();
                        if (m == "fastfail" || m == "nxdomain" || m == "off")
                            _cachedTencentMode = m;
                        else
                            _cachedTencentMode = "fragment";
                        _cachedTencentModeWriteUtc = writeUtc;
                    }
                }
                catch
                {
                    _cachedTencentMode = "fragment";
                }
                return _cachedTencentMode;
            }
        }

        private async Task StartTcpListenerAsync(IPAddress bindAddr, int port, CancellationToken ct)
        {
            TcpListener listener = null;
            CancellationTokenRegistration cancelReg = default(CancellationTokenRegistration);
            try
            {
                listener = new TcpListener(bindAddr, port);
                listener.Start(128);
                TcpListener localListener = listener;
                cancelReg = ct.Register(delegate
                {
                    try { localListener.Stop(); } catch { }
                });

                Log("Listening TCP on " + bindAddr + ":" + port);
                while (!ct.IsCancellationRequested)
                {
                    TcpClient client = null;
                    bool acceptTransientError = false;
                    try
                    {
                        client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (SocketException)
                    {
                        if (ct.IsCancellationRequested) break;
                        acceptTransientError = true;
                    }

                    if (acceptTransientError)
                    {
                        try { await Task.Delay(50, ct).ConfigureAwait(false); }
                        catch (OperationCanceledException) { break; }
                        continue;
                    }

                    if (client != null)
                        ObserveTask(HandleClientAsync(client, ct), "HandleClient:" + port);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                    Log("Listener on port " + port + " skipped/stopped: " + ex.Message);
            }
            finally
            {
                cancelReg.Dispose();
                if (listener != null) { try { listener.Stop(); } catch { } }
            }
        }

        private async Task StartLanDnsServerAsync(CancellationToken ct)
        {
            await Task.Yield();
            while (!ct.IsCancellationRequested)
            {
                IPAddress bindIp = _config.DnsBindAddress ?? GetPhysicalNetworkSnapshot().PhysicalIp;
                if (bindIp == null)
                {
                    try { await Task.Delay(3000, ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    continue;
                }

                IPAddress answerIp = _config.LanDnsAnswerIp ?? bindIp;
                Socket udp = null;
                CancellationTokenRegistration cancelReg = default(CancellationTokenRegistration);
                bool retryDelayNeeded = false;
                try
                {
                    udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                    udp.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    try { udp.IOControl(SioUdpConnReset, new byte[] { 0, 0, 0, 0 }, null); } catch { }
                    udp.Bind(new IPEndPoint(bindIp, _config.DnsPort));

                    if (_config.DnsBindAddress == null)
                    {
                        lock (_dnsSocketLock)
                        {
                            _activeAutoLanDnsSocket = udp;
                            _activeAutoLanDnsIp = bindIp;
                        }
                    }

                    Socket localUdp = udp;
                    cancelReg = ct.Register(delegate
                    {
                        try { localUdp.Close(); } catch { }
                    });

                    Log("Listening LAN DNS on " + bindIp + ":" + _config.DnsPort + " (for Router / Wi-Fi devices)");

                    byte[] buf = new byte[DnsPacketHelper.MaxDnsUdpPacketSize];
                    DateTime lastIpVerifyUtc = DateTime.UtcNow;

                    while (!ct.IsCancellationRequested)
                    {
                        // 仅在自动网卡模式下周期校验物理 IP 是否已因 Wi-Fi/以太网切换而变更
                        if (_config.DnsBindAddress == null && (DateTime.UtcNow - lastIpVerifyUtc).TotalSeconds >= 10)
                        {
                            lastIpVerifyUtc = DateTime.UtcNow;
                            IPAddress currentPhys = GetPhysicalNetworkSnapshot().PhysicalIp;
                            if (currentPhys != null && !currentPhys.Equals(bindIp))
                            {
                                Log("Physical IP changed from " + bindIp + " to " + currentPhys + ", rebinding LAN DNS");
                                break;
                            }
                        }

                        EndPoint remoteEp = new IPEndPoint(IPAddress.Any, 0);
                        int n;
                        try
                        {
                            n = await ReceiveFromAsync(udp, buf, remoteEp, ct).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }
                        catch (ObjectDisposedException)
                        {
                            break;
                        }
                        catch (SocketException sex)
                        {
                            if (ct.IsCancellationRequested) break;
                            if (sex.SocketErrorCode == SocketError.ConnectionReset ||
                                sex.SocketErrorCode == SocketError.MessageSize)
                            {
                                continue;
                            }
                            Log("LAN DNS socket receive error (" + sex.SocketErrorCode + "), restarting listener");
                            break;
                        }

                        if (n < 12) continue;

                        byte[] reqCopy = new byte[n];
                        Buffer.BlockCopy(buf, 0, reqCopy, 0, n);
                        IPEndPoint clientEp = remoteEp as IPEndPoint;
                        if (clientEp == null) continue;

                        Socket udpRef = udp;
                        IPAddress ansIpRef = answerIp;
                        IPAddress bindIpRef = bindIp;
                        ObserveTask(
                            HandleDnsQueryAsync(udpRef, clientEp, reqCopy, bindIpRef, ansIpRef, ct),
                            "HandleDnsQuery");
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    if (!ct.IsCancellationRequested)
                    {
                        Log("LAN DNS listener skipped/retrying: " + ex.Message);
                        retryDelayNeeded = true;
                    }
                }
                finally
                {
                    cancelReg.Dispose();
                    if (_config.DnsBindAddress == null)
                    {
                        lock (_dnsSocketLock)
                        {
                            if (_activeAutoLanDnsSocket == udp)
                            {
                                _activeAutoLanDnsSocket = null;
                                _activeAutoLanDnsIp = null;
                            }
                        }
                    }
                    if (udp != null) { try { udp.Close(); } catch { } }
                }

                if (retryDelayNeeded && !ct.IsCancellationRequested)
                {
                    try { await Task.Delay(5000, ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                }
            }
        }

        private static Task<int> ReceiveFromAsync(Socket udp, byte[] buffer, EndPoint remoteEp, CancellationToken ct)
        {
            TaskCompletionSource<int> tcs = new TaskCompletionSource<int>();
            try
            {
                EndPoint ep = remoteEp;
                udp.BeginReceiveFrom(
                    buffer,
                    0,
                    buffer.Length,
                    SocketFlags.None,
                    ref ep,
                    delegate(IAsyncResult ar)
                    {
                        try
                        {
                            EndPoint actualEp = ep;
                            int received = udp.EndReceiveFrom(ar, ref actualEp);
                            // 回写对端地址信息
                            IPEndPoint target = remoteEp as IPEndPoint;
                            IPEndPoint actual = actualEp as IPEndPoint;
                            if (target != null && actual != null)
                            {
                                target.Address = actual.Address;
                                target.Port = actual.Port;
                            }
                            tcs.TrySetResult(received);
                        }
                        catch (Exception ex)
                        {
                            if (ct.IsCancellationRequested) tcs.TrySetCanceled();
                            else tcs.TrySetException(ex);
                        }
                    },
                    null);
            }
            catch (Exception ex)
            {
                if (ct.IsCancellationRequested) tcs.TrySetCanceled();
                else tcs.TrySetException(ex);
            }
            return tcs.Task;
        }

        private static void SafeUdpSend(Socket udp, byte[] payload, IPEndPoint target)
        {
            try
            {
                udp.SendTo(payload, target);
            }
            catch { }
        }

        private async Task HandleDnsQueryAsync(
            Socket udp,
            IPEndPoint clientEp,
            byte[] req,
            IPAddress bindIp,
            IPAddress answerIp,
            CancellationToken ct)
        {
            try
            {
                string qname;
                int qtype;
                int qclass;
                int qEnd;
                if (!DnsPacketHelper.TryParseQuery(req, req.Length, out qname, out qtype, out qclass, out qEnd))
                    return;

                if (TlsFragmenter.IsUuTargetHost(qname))
                {
                    if (qtype == 1)
                    {
                        byte[] resp = DnsPacketHelper.BuildAResponse(req, qEnd, answerIp, 60);
                        SafeUdpSend(udp, resp, clientEp);
                        Log("[LAN-DNS-UU] " + qname + " -> " + answerIp + " (for " + clientEp.Address + ")");
                        return;
                    }
                    if (qtype == 28)
                    {
                        byte[] resp = DnsPacketHelper.BuildStatusResponse(req, qEnd, 0);
                        SafeUdpSend(udp, resp, clientEp);
                        return;
                    }
                }

                if (TlsFragmenter.IsTencentHttpDnsHost(qname))
                {
                    string mode = GetTencentDnsLanMode();
                    if (mode == "fastfail" || mode == "nxdomain")
                    {
                        byte[] resp = DnsPacketHelper.BuildStatusResponse(req, qEnd, 3); // NXDOMAIN
                        SafeUdpSend(udp, resp, clientEp);
                        Log("[LAN-DNS-QQ-FASTFAIL] " + qname + " -> NXDOMAIN (for " + clientEp.Address + ")");
                        return;
                    }
                    if (mode != "off")
                    {
                        if (qtype == 1)
                        {
                            byte[] resp = DnsPacketHelper.BuildAResponse(req, qEnd, answerIp, 60);
                            SafeUdpSend(udp, resp, clientEp);
                            Log("[LAN-DNS-QQ-FRAG] " + qname + " -> " + answerIp + " (for " + clientEp.Address + ")");
                            return;
                        }
                        if (qtype == 28)
                        {
                            byte[] resp = DnsPacketHelper.BuildStatusResponse(req, qEnd, 0);
                            SafeUdpSend(udp, resp, clientEp);
                            return;
                        }
                    }
                }

                // 转发其余域名至上游 DNS（优先物理网卡配置的校园网内网 DNS，失败回退至阿里公共 DNS）
                IList<IPEndPoint> upstreams = GetUpstreamDnsEndpoints();
                for (int i = 0; i < upstreams.Count; i++)
                {
                    if (ct.IsCancellationRequested) return;
                    byte[] upstreamResp = await ForwardUdpDnsAsync(req, bindIp, upstreams[i], ct).ConfigureAwait(false);
                    if (upstreamResp != null)
                    {
                        SafeUdpSend(udp, upstreamResp, clientEp);
                        return;
                    }
                }

                // 全部上游失败时显式返回 SERVFAIL，促使客户端快速切换至备选 DNS
                byte[] servFail = DnsPacketHelper.BuildStatusResponse(req, qEnd, 2);
                SafeUdpSend(udp, servFail, clientEp);
            }
            catch { }
        }

        private async Task<byte[]> ForwardUdpDnsAsync(byte[] req, IPAddress bindIp, IPEndPoint upstream, CancellationToken ct)
        {
            Socket fSock = null;
            try
            {
                fSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                try { fSock.IOControl(SioUdpConnReset, new byte[] { 0, 0, 0, 0 }, null); } catch { }

                // 仅当目标上游与本机绑定地址均为非回环物理地址时才绑定物理 IP，避免环回测试或本地转发失败
                if (_config.BindOutboundToPhysicalNic &&
                    bindIp != null &&
                    !IPAddress.IsLoopback(bindIp) &&
                    !IPAddress.IsLoopback(upstream.Address))
                {
                    try { fSock.Bind(new IPEndPoint(bindIp, 0)); } catch { }
                }

                // Connect 锁定对端地址与端口，由内核过滤离路径伪造 UDP 报文
                fSock.Connect(upstream);
                fSock.Send(req);

                byte[] rBuf = new byte[DnsPacketHelper.MaxDnsUdpPacketSize];
                int rn = await ReceiveAsyncWithTimeout(fSock, rBuf, _config.DnsUpstreamTimeoutMs, ct).ConfigureAwait(false);
                if (DnsPacketHelper.IsValidUpstreamResponse(req, rBuf, rn))
                {
                    byte[] outB = new byte[rn];
                    Buffer.BlockCopy(rBuf, 0, outB, 0, rn);
                    return outB;
                }
            }
            catch { }
            finally
            {
                if (fSock != null) { try { fSock.Close(); } catch { } }
            }
            return null;
        }

        private static void SwallowFaultedTask(Task task)
        {
            if (task == null) return;
            task.ContinueWith(
                t =>
                {
                    if (t.Exception != null) GC.KeepAlive(t.Exception);
                },
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        }

        private static async Task<int> ReceiveAsyncWithTimeout(Socket sock, byte[] buf, int timeoutMs, CancellationToken ct)
        {
            TaskCompletionSource<int> tcs = new TaskCompletionSource<int>();
            try
            {
                sock.BeginReceive(
                    buf,
                    0,
                    buf.Length,
                    SocketFlags.None,
                    delegate(IAsyncResult ar)
                    {
                        try
                        {
                            int n = sock.EndReceive(ar);
                            tcs.TrySetResult(n);
                        }
                        catch (Exception ex)
                        {
                            tcs.TrySetException(ex);
                        }
                    },
                    null);
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }

            using (CancellationTokenSource delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                Task delayTask = Task.Delay(timeoutMs, delayCts.Token);
                Task completed = await Task.WhenAny(tcs.Task, delayTask).ConfigureAwait(false);
                if (completed != tcs.Task)
                {
                    SwallowFaultedTask(tcs.Task);
                    try { sock.Close(); } catch { }
                    throw new TimeoutException("UDP DNS upstream receive timeout.");
                }
                delayCts.Cancel();
                return await tcs.Task.ConfigureAwait(false);
            }
        }

        private IList<IPEndPoint> GetUpstreamDnsEndpoints()
        {
            if (_config.UpstreamDnsOverride != null && _config.UpstreamDnsOverride.Count > 0)
                return _config.UpstreamDnsOverride;

            NetworkSnapshot snap = GetPhysicalNetworkSnapshot();
            List<IPEndPoint> result = new List<IPEndPoint>();
            if (snap != null && snap.PhysicalDnsServers != null)
            {
                for (int i = 0; i < snap.PhysicalDnsServers.Count; i++)
                    result.Add(new IPEndPoint(snap.PhysicalDnsServers[i], 53));
            }
            IPAddress fallback1 = IPAddress.Parse("223.5.5.5");
            IPAddress fallback2 = IPAddress.Parse("223.6.6.6");
            AddUniqueDnsEndpoint(result, fallback1, 53);
            AddUniqueDnsEndpoint(result, fallback2, 53);
            return result;
        }

        private static void AddUniqueDnsEndpoint(List<IPEndPoint> list, IPAddress ip, int port)
        {
            for (int i = 0; i < list.Count; i++)
            {
                if (list[i].Address.Equals(ip) && list[i].Port == port) return;
            }
            list.Add(new IPEndPoint(ip, port));
        }

        /// <summary>
        /// 获取当前物理网卡 IP 与对应的上游 IPv4 DNS 列表（通过不可变快照原子缓存 30 秒，网卡变更即时失效）。
        /// </summary>
        private NetworkSnapshot GetPhysicalNetworkSnapshot()
        {
            NetworkSnapshot current = _netSnapshot;
            if (current != null && (DateTime.UtcNow - current.CapturedAtUtc).TotalSeconds < NetworkSnapshotTtlSeconds)
                return current;

            IPAddress bestIp = null;
            List<IPAddress> bestDns = new List<IPAddress>();
            int bestScore = -1;

            try
            {
                NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
                for (int i = 0; i < interfaces.Length; i++)
                {
                    NetworkInterface ni = interfaces[i];
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;

                    string desc = (ni.Name + " " + ni.Description).ToLowerInvariant();
                    if (IsVirtualAdapterDescription(desc)) continue;

                    IPInterfaceProperties props = ni.GetIPProperties();
                    if (props.GatewayAddresses == null || props.GatewayAddresses.Count == 0) continue;

                    bool hasIpv4Gw = false;
                    foreach (GatewayIPAddressInformation gw in props.GatewayAddresses)
                    {
                        if (gw.Address != null &&
                            gw.Address.AddressFamily == AddressFamily.InterNetwork &&
                            !gw.Address.Equals(IPAddress.Any))
                        {
                            hasIpv4Gw = true;
                            break;
                        }
                    }
                    if (!hasIpv4Gw) continue;

                    IPAddress candidateIp = null;
                    foreach (UnicastIPAddressInformation uni in props.UnicastAddresses)
                    {
                        if (uni.Address != null && uni.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            if (IsUsablePhysicalIpv4(uni.Address))
                            {
                                candidateIp = uni.Address;
                                break;
                            }
                        }
                    }
                    if (candidateIp == null) continue;

                    List<IPAddress> candidateDns = new List<IPAddress>();
                    foreach (IPAddress dns in props.DnsAddresses)
                    {
                        if (dns != null &&
                            dns.AddressFamily == AddressFamily.InterNetwork &&
                            !dns.Equals(candidateIp) &&
                            IsUsableUpstreamDnsIpv4(dns) &&
                            !candidateDns.Contains(dns))
                        {
                            candidateDns.Add(dns);
                        }
                    }

                    int score = 10;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet)
                        score += 20;
                    else if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                        score += 15;
                    if (candidateDns.Count > 0) score += 5;

                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestIp = candidateIp;
                        bestDns = candidateDns;
                    }
                }
            }
            catch { }

            NetworkSnapshot refreshed = new NetworkSnapshot(bestIp, bestDns, DateTime.UtcNow);
            _netSnapshot = refreshed;
            return refreshed;
        }

        private static bool IsVirtualAdapterDescription(string lowerDesc)
        {
            for (int i = 0; i < VirtualAdapterKeywords.Length; i++)
            {
                if (lowerDesc.IndexOf(VirtualAdapterKeywords[i], StringComparison.Ordinal) >= 0)
                    return true;
            }
            return false;
        }

        private static bool IsUsablePhysicalIpv4(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            if (b.Length != 4) return false;
            if (b[0] == 127 || b[0] == 0) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 198 && b[1] == 18) return false; // 代理软件常见 FakeIP 网段
            return true;
        }

        private static bool IsUsableUpstreamDnsIpv4(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            if (b.Length != 4) return false;
            if (b[0] == 127 || b[0] == 0) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 198 && b[1] == 18) return false;
            return true;
        }

        private async Task<Socket> CreateBoundSocketAsync(IPAddress targetIp, int targetPort, CancellationToken ct)
        {
            if (targetIp == null) throw new ArgumentNullException("targetIp");

            bool shouldBindPhys = _config.BindOutboundToPhysicalNic && !IPAddress.IsLoopback(targetIp);
            int maxAttempts = shouldBindPhys ? 2 : 1;

            for (int attempt = 0; attempt < maxAttempts; attempt++)
            {
                Socket sock = new Socket(targetIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                sock.NoDelay = true;
                sock.ReceiveTimeout = 8000;
                sock.SendTimeout = 8000;

                if (shouldBindPhys)
                {
                    IPAddress physIp = GetPhysicalNetworkSnapshot().PhysicalIp;
                    if (physIp != null && physIp.AddressFamily == targetIp.AddressFamily)
                    {
                        try { sock.Bind(new IPEndPoint(physIp, 0)); }
                        catch { InvalidateNetworkCache(); }
                    }
                }

                try
                {
                    await ConnectSocketWithTimeoutAsync(sock, new IPEndPoint(targetIp, targetPort), _config.ConnectTimeoutMs, ct)
                        .ConfigureAwait(false);
                    return sock;
                }
                catch
                {
                    try { sock.Close(); } catch { }
                    if (shouldBindPhys) InvalidateNetworkCache();
                    if (attempt == maxAttempts - 1) throw;
                }
            }

            throw new TimeoutException("Connect failed to " + targetIp + ":" + targetPort);
        }

        private static async Task ConnectSocketWithTimeoutAsync(Socket sock, IPEndPoint ep, int timeoutMs, CancellationToken ct)
        {
            TaskCompletionSource<bool> tcs = new TaskCompletionSource<bool>();
            try
            {
                sock.BeginConnect(
                    ep,
                    delegate(IAsyncResult ar)
                    {
                        try
                        {
                            sock.EndConnect(ar);
                            tcs.TrySetResult(true);
                        }
                        catch (Exception ex)
                        {
                            tcs.TrySetException(ex);
                        }
                    },
                    null);
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }

            using (CancellationTokenSource delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                Task delayTask = Task.Delay(timeoutMs, delayCts.Token);
                Task completed = await Task.WhenAny(tcs.Task, delayTask).ConfigureAwait(false);
                if (completed != tcs.Task)
                {
                    SwallowFaultedTask(tcs.Task);
                    try { sock.Close(); } catch { }
                    ct.ThrowIfCancellationRequested();
                    throw new TimeoutException("Connect timeout to " + ep);
                }
                delayCts.Cancel();
                await tcs.Task.ConfigureAwait(false);
            }
        }

        private async Task<string> QueryDohAliDnsAsync(string domain, string ecs, CancellationToken ct)
        {
            string key = domain + "|" + (ecs ?? "");
            Tuple<string, DateTime> cached;
            if (_dnsCache.TryGetValue(key, out cached) && DateTime.UtcNow < cached.Item2)
                return cached.Item1;

            string path = "/resolve?name=" + Uri.EscapeDataString(domain) + "&type=A";
            if (!string.IsNullOrEmpty(ecs))
                path += "&edns_client_subnet=" + Uri.EscapeDataString(ecs);

            for (int i = 0; i < DohServers.Length; i++)
            {
                string dohIp = DohServers[i];
                try
                {
                    using (Socket sock = await CreateBoundSocketAsync(IPAddress.Parse(dohIp), 443, ct).ConfigureAwait(false))
                    using (NetworkStream ns = new NetworkStream(sock, false))
                    // 注：部分老旧校园网 Windows 10 环境缺少根证书链更新，IP 直连阿里公共 DoH 时宽容校验证书以保障可用性
                    using (SslStream ssl = new SslStream(ns, false, (s, c, ch, e) => c != null))
                    {
                        await Task.Run(delegate
                        {
                            ssl.AuthenticateAsClient(dohIp, null, SslProtocols.Tls12, false);
                        }, ct).ConfigureAwait(false);

                        string req = "GET " + path + " HTTP/1.1\r\nHost: " + dohIp +
                                     "\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
                        byte[] reqBytes = Encoding.ASCII.GetBytes(req);
                        await ssl.WriteAsync(reqBytes, 0, reqBytes.Length, ct).ConfigureAwait(false);
                        await ssl.FlushAsync(ct).ConfigureAwait(false);

                        string resp = await ReadHttpTextLimitedAsync(ssl, MaxDohResponseBytes, _config.HandshakeReadTimeoutMs, ct)
                            .ConfigureAwait(false);
                        if (string.IsNullOrEmpty(resp)) continue;

                        int firstLineEnd = resp.IndexOf("\r\n", StringComparison.Ordinal);
                        string statusLine = firstLineEnd > 0 ? resp.Substring(0, firstLineEnd) : resp;
                        if (statusLine.IndexOf(" 200 ", StringComparison.Ordinal) < 0) continue;

                        int bodyIdx = resp.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                        string body = bodyIdx >= 0 ? resp.Substring(bodyIdx + 4) : resp;
                        MatchCollection matches = DohDataIpRegex.Matches(body);
                        foreach (Match m in matches)
                        {
                            string ipStr = m.Groups[1].Value;
                            IPAddress candidate;
                            if (IPAddress.TryParse(ipStr, out candidate) &&
                                candidate.AddressFamily == AddressFamily.InterNetwork &&
                                IsUsablePhysicalIpv4(candidate))
                            {
                                CacheDnsResult(key, candidate.ToString());
                                return candidate.ToString();
                            }
                        }
                    }
                }
                catch { }
            }

            return null;
        }

        private void CacheDnsResult(string key, string ip)
        {
            if (_dnsCache.Count >= MaxDnsCacheEntries)
            {
                DateTime now = DateTime.UtcNow;
                foreach (KeyValuePair<string, Tuple<string, DateTime>> kv in _dnsCache)
                {
                    if (kv.Value.Item2 <= now)
                    {
                        Tuple<string, DateTime> removed;
                        _dnsCache.TryRemove(kv.Key, out removed);
                    }
                }
                if (_dnsCache.Count >= MaxDnsCacheEntries)
                    _dnsCache.Clear();
            }
            _dnsCache[key] = Tuple.Create(ip, DateTime.UtcNow.AddMinutes(5));
        }

        /// <summary>
        /// 为已知受阻断 IP 或域名解析最优直连目标 IPv4；无法解析的未知域名安全返回 null（绝不错误导流）。
        /// </summary>
        public async Task<string> ResolveOptimalTargetIpAsync(string host, CancellationToken ct)
        {
            string h = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            if (string.IsNullOrEmpty(h)) return null;

            // 将已知不支持 TLS 多帧重组或易被限速的官方节点映射至实测稳定的官方节点
            if (h == "123.58.163.37" || h == "123.58.184.232" || h == "42.186.225.155") return "112.13.123.98";
            if (h == "223.252.194.149") return "34.95.122.33";

            IPAddress parsed;
            if (IPAddress.TryParse(h, out parsed)) return parsed.ToString();

            if (h == "dns.wechat.com")
                return "43.152.112.101";

            if (h == "api.nrd.nie.163.com" || h == "api-ipv4.nrd.nie.163.com")
            {
                string ip = await QueryDohAliDnsAsync("api.nrd.nie.163.com", null, ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(ip) && ip != "123.58.163.37") return ip;
                return "112.13.123.98";
            }

            if (h.StartsWith("sig-", StringComparison.Ordinal) && h.EndsWith(".nrd.nie.163.com", StringComparison.Ordinal))
            {
                string ip = await QueryDohAliDnsAsync(h, "8.8.8.0/24", ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(ip) && ip != "223.252.194.149") return ip;
                return "34.95.122.33";
            }

            string dohIp = await QueryDohAliDnsAsync(h, null, ct).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(dohIp)) return dohIp;

            string fb;
            if (FallbackHostIps.TryGetValue(h, out fb)) return fb;

            try
            {
                IPAddress[] addrs = await Dns.GetHostAddressesAsync(h).ConfigureAwait(false);
                for (int i = 0; i < addrs.Length; i++)
                {
                    IPAddress a = addrs[i];
                    if (a.AddressFamily == AddressFamily.InterNetwork && IsUsablePhysicalIpv4(a))
                        return a.ToString();
                }
            }
            catch { }

            return null;
        }

        private static async Task<int> ReadWithTimeoutAsync(
            Stream stream,
            byte[] buffer,
            int offset,
            int count,
            int timeoutMs,
            CancellationToken ct)
        {
            using (CancellationTokenSource delayCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                Task<int> readTask = stream.ReadAsync(buffer, offset, count, ct);
                Task delayTask = Task.Delay(timeoutMs, delayCts.Token);
                Task completed = await Task.WhenAny(readTask, delayTask).ConfigureAwait(false);
                if (completed != readTask)
                {
                    SwallowFaultedTask(readTask);
                    ct.ThrowIfCancellationRequested();
                    throw new TimeoutException("Stream read timeout.");
                }
                delayCts.Cancel();
                return await readTask.ConfigureAwait(false);
            }
        }

        private static async Task ReadExactWithTimeoutAsync(
            Stream stream,
            byte[] buf,
            int offset,
            int count,
            int timeoutMs,
            CancellationToken ct)
        {
            int read = 0;
            while (read < count)
            {
                int n = await ReadWithTimeoutAsync(stream, buf, offset + read, count - read, timeoutMs, ct)
                    .ConfigureAwait(false);
                if (n <= 0) throw new EndOfStreamException();
                read += n;
            }
        }

        private static async Task<string> ReadHttpTextLimitedAsync(Stream stream, int maxBytes, int timeoutMs, CancellationToken ct)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] buf = new byte[4096];
                while (ms.Length < maxBytes)
                {
                    int toRead = (int)Math.Min(buf.Length, maxBytes - ms.Length);
                    int n = await ReadWithTimeoutAsync(stream, buf, 0, toRead, timeoutMs, ct).ConfigureAwait(false);
                    if (n <= 0) break;
                    ms.Write(buf, 0, n);
                }
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        private async Task<byte[]> ReadHttpRequestHeadersAsync(Stream stream, byte firstByte, CancellationToken ct)
        {
            byte[] headerBuf = new byte[MaxHttpHeaderBytes];
            int len = 0;
            headerBuf[len++] = firstByte;
            byte[] one = new byte[1];

            while (len < MaxHttpHeaderBytes)
            {
                int r = await ReadWithTimeoutAsync(stream, one, 0, 1, _config.HandshakeReadTimeoutMs, ct)
                    .ConfigureAwait(false);
                if (r <= 0) return null;

                headerBuf[len++] = one[0];
                if (len >= 4 &&
                    headerBuf[len - 4] == (byte)'\r' &&
                    headerBuf[len - 3] == (byte)'\n' &&
                    headerBuf[len - 2] == (byte)'\r' &&
                    headerBuf[len - 1] == (byte)'\n')
                {
                    byte[] result = new byte[len];
                    Buffer.BlockCopy(headerBuf, 0, result, 0, len);
                    return result;
                }
            }

            // HTTP 请求头超出安全上限（防 Slowloris / OOM 攻击）
            return null;
        }

        /// <summary>
        /// 读取客户端首个应用层报文；若检测到 TLS Handshake 记录被 TCP 拆包，
        /// 自动带超时补齐完整的首个 TLS Record，确保 SNI 分片不会因拆包而静默失效。
        /// </summary>
        private async Task<byte[]> ReadInitialPayloadWithTlsCoalesceAsync(Stream cStream, CancellationToken ct)
        {
            byte[] buf = new byte[16384];
            int n = await ReadWithTimeoutAsync(cStream, buf, 0, buf.Length, _config.HandshakeReadTimeoutMs, ct)
                .ConfigureAwait(false);
            if (n <= 0) return null;

            // 若首字节为 0x16 (TLS Handshake)，确保拿到完整 Record Header 与 Record Body
            if (buf[0] == 0x16)
            {
                if (n < 5)
                {
                    await ReadExactWithTimeoutAsync(cStream, buf, n, 5 - n, _config.HandshakeReadTimeoutMs, ct)
                        .ConfigureAwait(false);
                    n = 5;
                }

                int recLen;
                if (TlsFragmenter.TryReadTlsHandshakeRecordLength(buf, n, out recLen))
                {
                    int totalNeeded = 5 + recLen;
                    if (n < totalNeeded)
                    {
                        byte[] fullRec = new byte[totalNeeded];
                        Buffer.BlockCopy(buf, 0, fullRec, 0, n);
                        await ReadExactWithTimeoutAsync(
                            cStream,
                            fullRec,
                            n,
                            totalNeeded - n,
                            _config.HandshakeReadTimeoutMs,
                            ct).ConfigureAwait(false);
                        return fullRec;
                    }
                }
            }

            byte[] initial = new byte[n];
            Buffer.BlockCopy(buf, 0, initial, 0, n);
            return initial;
        }

        private static bool TryParseHostPort(string authority, out string host, out int port)
        {
            host = null;
            port = 0;
            if (string.IsNullOrEmpty(authority)) return false;

            string trimmed = authority.Trim();
            if (trimmed.StartsWith("[", StringComparison.Ordinal))
            {
                int closeIdx = trimmed.IndexOf(']');
                if (closeIdx <= 1) return false;
                host = trimmed.Substring(1, closeIdx - 1);
                if (closeIdx + 1 < trimmed.Length && trimmed[closeIdx + 1] == ':')
                {
                    int parsedPort;
                    if (!int.TryParse(trimmed.Substring(closeIdx + 2), out parsedPort)) return false;
                    if (parsedPort < 1 || parsedPort > 65535) return false;
                    port = parsedPort;
                    return true;
                }
                port = 443;
                return true;
            }

            int colon = trimmed.LastIndexOf(':');
            if (colon > 0)
            {
                host = trimmed.Substring(0, colon);
                int parsedPort;
                if (!int.TryParse(trimmed.Substring(colon + 1), out parsedPort)) return false;
                if (parsedPort < 1 || parsedPort > 65535) return false;
                port = parsedPort;
                return !string.IsNullOrEmpty(host);
            }

            host = trimmed;
            port = 443;
            return !string.IsNullOrEmpty(host);
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            Socket remoteSock = null;
            try
            {
                using (client)
                {
                    client.NoDelay = true;
                    using (NetworkStream cStream = client.GetStream())
                    {
                        byte[] firstBuf = new byte[1];
                        int n0 = await ReadWithTimeoutAsync(cStream, firstBuf, 0, 1, _config.HandshakeReadTimeoutMs, ct)
                            .ConfigureAwait(false);
                        if (n0 <= 0) return;

                        byte b0 = firstBuf[0];
                        string targetHost = "";
                        int targetPort = 443;
                        byte[] initialClientData = null;

                        if (b0 == 0x05)
                        {
                            // ---------------- SOCKS5 协议握手 ----------------
                            byte[] nm = new byte[1];
                            await ReadExactWithTimeoutAsync(cStream, nm, 0, 1, _config.HandshakeReadTimeoutMs, ct)
                                .ConfigureAwait(false);
                            if (nm[0] == 0) return;

                            byte[] methods = new byte[nm[0]];
                            await ReadExactWithTimeoutAsync(cStream, methods, 0, nm[0], _config.HandshakeReadTimeoutMs, ct)
                                .ConfigureAwait(false);

                            bool supportsNoAuth = false;
                            for (int i = 0; i < methods.Length; i++)
                            {
                                if (methods[i] == 0x00) { supportsNoAuth = true; break; }
                            }
                            if (!supportsNoAuth)
                            {
                                await cStream.WriteAsync(new byte[] { 0x05, 0xFF }, 0, 2, ct).ConfigureAwait(false);
                                return;
                            }
                            await cStream.WriteAsync(new byte[] { 0x05, 0x00 }, 0, 2, ct).ConfigureAwait(false);

                            byte[] hdr = new byte[4];
                            await ReadExactWithTimeoutAsync(cStream, hdr, 0, 4, _config.HandshakeReadTimeoutMs, ct)
                                .ConfigureAwait(false);
                            if (hdr[0] != 0x05) return;
                            if (hdr[1] != 0x01) // 仅支持 CONNECT 命令
                            {
                                byte[] cmdErr = new byte[] { 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
                                await cStream.WriteAsync(cmdErr, 0, cmdErr.Length, ct).ConfigureAwait(false);
                                return;
                            }

                            byte atyp = hdr[3];
                            if (atyp == 0x01)
                            {
                                byte[] ipb = new byte[4];
                                await ReadExactWithTimeoutAsync(cStream, ipb, 0, 4, _config.HandshakeReadTimeoutMs, ct)
                                    .ConfigureAwait(false);
                                targetHost = new IPAddress(ipb).ToString();
                            }
                            else if (atyp == 0x03)
                            {
                                byte[] dlen = new byte[1];
                                await ReadExactWithTimeoutAsync(cStream, dlen, 0, 1, _config.HandshakeReadTimeoutMs, ct)
                                    .ConfigureAwait(false);
                                if (dlen[0] == 0) return;
                                byte[] db = new byte[dlen[0]];
                                await ReadExactWithTimeoutAsync(cStream, db, 0, dlen[0], _config.HandshakeReadTimeoutMs, ct)
                                    .ConfigureAwait(false);
                                targetHost = Encoding.ASCII.GetString(db);
                            }
                            else
                            {
                                byte[] atypErr = new byte[] { 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
                                await cStream.WriteAsync(atypErr, 0, atypErr.Length, ct).ConfigureAwait(false);
                                return;
                            }

                            byte[] pb = new byte[2];
                            await ReadExactWithTimeoutAsync(cStream, pb, 0, 2, _config.HandshakeReadTimeoutMs, ct)
                                .ConfigureAwait(false);
                            targetPort = (pb[0] << 8) | pb[1];
                            if (targetPort < 1 || targetPort > 65535) return;

                            // 提前回应成功以便读取客户端 TLS ClientHello 提取精确 SNI 后再优选目标节点
                            byte[] reply = new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
                            await cStream.WriteAsync(reply, 0, reply.Length, ct).ConfigureAwait(false);
                        }
                        else if (b0 == 0x16)
                        {
                            // ---------------- 透明 TLS (:443) 协议 ----------------
                            byte[] hdr4 = new byte[4];
                            await ReadExactWithTimeoutAsync(cStream, hdr4, 0, 4, _config.HandshakeReadTimeoutMs, ct)
                                .ConfigureAwait(false);

                            byte[] hdr5 = new byte[] { b0, hdr4[0], hdr4[1], hdr4[2], hdr4[3] };
                            int recLen;
                            if (!TlsFragmenter.TryReadTlsHandshakeRecordLength(hdr5, 5, out recLen))
                                return;

                            initialClientData = new byte[5 + recLen];
                            Buffer.BlockCopy(hdr5, 0, initialClientData, 0, 5);
                            await ReadExactWithTimeoutAsync(cStream, initialClientData, 5, recLen, _config.HandshakeReadTimeoutMs, ct)
                                .ConfigureAwait(false);

                            string sni = TlsFragmenter.ExtractSniFromClientHello(initialClientData, initialClientData.Length);
                            targetHost = !string.IsNullOrEmpty(sni) ? sni : "api.nrd.nie.163.com";
                            targetPort = 443;
                        }
                        else
                        {
                            // ---------------- HTTP CONNECT 代理协议 ----------------
                            byte[] headerBytes = await ReadHttpRequestHeadersAsync(cStream, b0, ct).ConfigureAwait(false);
                            if (headerBytes == null) return;

                            string reqStr = Encoding.ASCII.GetString(headerBytes);
                            int lineEnd = reqStr.IndexOf("\r\n", StringComparison.Ordinal);
                            string firstLine = lineEnd >= 0 ? reqStr.Substring(0, lineEnd) : reqStr;
                            string[] parts = firstLine.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length < 2)
                            {
                                byte[] badReq = Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                                await cStream.WriteAsync(badReq, 0, badReq.Length, ct).ConfigureAwait(false);
                                return;
                            }

                            if (!string.Equals(parts[0], "CONNECT", StringComparison.OrdinalIgnoreCase))
                            {
                                byte[] notAllowed = Encoding.ASCII.GetBytes("HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n");
                                await cStream.WriteAsync(notAllowed, 0, notAllowed.Length, ct).ConfigureAwait(false);
                                return;
                            }

                            if (!TryParseHostPort(parts[1], out targetHost, out targetPort))
                            {
                                byte[] badReq = Encoding.ASCII.GetBytes("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                                await cStream.WriteAsync(badReq, 0, badReq.Length, ct).ConfigureAwait(false);
                                return;
                            }

                            byte[] okResp = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                            await cStream.WriteAsync(okResp, 0, okResp.Length, ct).ConfigureAwait(false);
                        }

                        if (initialClientData == null)
                        {
                            initialClientData = await ReadInitialPayloadWithTlsCoalesceAsync(cStream, ct).ConfigureAwait(false);
                            if (initialClientData == null || initialClientData.Length == 0) return;

                            string sni = TlsFragmenter.ExtractSniFromClientHello(initialClientData, initialClientData.Length);
                            IPAddress dummyIp;
                            if (!string.IsNullOrEmpty(sni) &&
                                IPAddress.TryParse(targetHost, out dummyIp) &&
                                !IPAddress.IsLoopback(dummyIp))
                            {
                                targetHost = sni;
                            }
                        }

                        bool isFallbackHttp = (targetPort == 80) &&
                            (string.Equals(targetHost, "123.58.184.232", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(targetHost, "42.186.225.155", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(targetHost, "api.nrd.nie.163.com", StringComparison.OrdinalIgnoreCase));
                        int connectPort = isFallbackHttp ? 443 : targetPort;

                        IPEndPoint remoteEp = null;
                        if (_config.TargetResolverOverride != null)
                        {
                            remoteEp = _config.TargetResolverOverride(targetHost, connectPort);
                        }

                        if (remoteEp == null)
                        {
                            string targetIpStr = await ResolveOptimalTargetIpAsync(targetHost, ct).ConfigureAwait(false);
                            IPAddress targetIp;
                            if (string.IsNullOrEmpty(targetIpStr) || !IPAddress.TryParse(targetIpStr, out targetIp))
                            {
                                Log("[WARN] Failed to resolve target host: " + targetHost);
                                return;
                            }
                            remoteEp = new IPEndPoint(targetIp, connectPort);
                        }

                        remoteSock = await CreateBoundSocketAsync(remoteEp.Address, remoteEp.Port, ct).ConfigureAwait(false);
                        using (NetworkStream rStream = new NetworkStream(remoteSock, false))
                        {
                            Log(string.Format(
                                "[DIRECT+TLS-FRAG] {0}:{1} -> {2}:{3}",
                                targetHost,
                                targetPort,
                                remoteEp.Address,
                                remoteEp.Port));

                            if (isFallbackHttp)
                            {
                                using (FragmentedFirstWriteStream fragStream = new FragmentedFirstWriteStream(rStream, true))
                                using (SslStream ssl = new SslStream(fragStream, false, (s, c, ch, e) => c != null))
                                {
                                    await Task.Run(delegate
                                    {
                                        ssl.AuthenticateAsClient("api.nrd.nie.163.com", null, SslProtocols.Tls12, false);
                                    }, ct).ConfigureAwait(false);

                                    byte[] rewritten = TlsFragmenter.RewriteFallbackHttpHost(initialClientData);
                                    await ssl.WriteAsync(rewritten, 0, rewritten.Length, ct).ConfigureAwait(false);
                                    await ssl.FlushAsync(ct).ConfigureAwait(false);

                                    await RelayBidirectionalAsync(cStream, client.Client, ssl, remoteSock, ct)
                                        .ConfigureAwait(false);
                                }
                                return;
                            }

                            byte[] firstOut = TlsFragmenter.FragmentTlsClientHello(initialClientData, initialClientData.Length);
                            await rStream.WriteAsync(firstOut, 0, firstOut.Length, ct).ConfigureAwait(false);
                            await rStream.FlushAsync(ct).ConfigureAwait(false);

                            await RelayBidirectionalAsync(cStream, client.Client, rStream, remoteSock, ct)
                                .ConfigureAwait(false);
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (IOException) { }
            catch (SocketException) { }
            catch (TimeoutException) { }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                Log("[WARN] Unexpected client handler error: " + ex.Message);
            }
            finally
            {
                if (remoteSock != null) { try { remoteSock.Close(); } catch { } }
            }
        }

        /// <summary>
        /// 支持标准 TCP 半关闭（Half-Close）的双向数据转发：
        /// 当一侧正常读到 EOF 时仅关闭对端写方向，等待另一侧在宽限期内将剩余响应完整送达，避免响应被提前腰斩；
        /// 若发生连接异常则立即联动终止双向转发。
        /// </summary>
        private async Task RelayBidirectionalAsync(
            Stream clientStream,
            Socket clientSock,
            Stream remoteStream,
            Socket remoteSock,
            CancellationToken ct)
        {
            using (CancellationTokenSource linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                Task<bool> upTask = PumpOneWayAsync(clientStream, remoteStream, remoteSock, linkedCts);
                Task<bool> downTask = PumpOneWayAsync(remoteStream, clientStream, clientSock, linkedCts);

                Task<bool> first = await Task.WhenAny(upTask, downTask).ConfigureAwait(false);
                Task<bool> second = (first == upTask) ? downTask : upTask;

                bool cleanEof = false;
                try { cleanEof = await first.ConfigureAwait(false); }
                catch { cleanEof = false; }

                if (!cleanEof)
                {
                    linkedCts.Cancel();
                    SafeAbortSocket(clientSock);
                    SafeAbortSocket(remoteSock);
                    return;
                }

                // 正常半关闭场景：等待另一方向把尾部响应数据完全写完，但设定宽限上限防止对端僵尸挂起
                using (CancellationTokenSource graceCts = CancellationTokenSource.CreateLinkedTokenSource(linkedCts.Token))
                {
                    Task graceDelay = Task.Delay(_config.HalfCloseGraceTimeoutMs, graceCts.Token);
                    Task completedSecond = await Task.WhenAny(second, graceDelay).ConfigureAwait(false);
                    if (completedSecond != second)
                    {
                        linkedCts.Cancel();
                        SafeAbortSocket(clientSock);
                        SafeAbortSocket(remoteSock);
                    }
                    else
                    {
                        graceCts.Cancel();
                        try { await second.ConfigureAwait(false); } catch { }
                    }
                }
            }
        }

        private static async Task<bool> PumpOneWayAsync(
            Stream input,
            Stream output,
            Socket outputSocket,
            CancellationTokenSource cts)
        {
            byte[] buf = new byte[PumpBufferSize];
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    int n = await input.ReadAsync(buf, 0, buf.Length, cts.Token).ConfigureAwait(false);
                    if (n <= 0)
                    {
                        try { await output.FlushAsync(cts.Token).ConfigureAwait(false); } catch { }
                        SafeShutdownSend(outputSocket);
                        return true;
                    }
                    await output.WriteAsync(buf, 0, n, cts.Token).ConfigureAwait(false);
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        private static void SafeShutdownSend(Socket sock)
        {
            if (sock == null) return;
            try
            {
                if (sock.Connected)
                    sock.Shutdown(SocketShutdown.Send);
            }
            catch { }
        }

        private static void SafeAbortSocket(Socket sock)
        {
            if (sock == null) return;
            try { sock.Shutdown(SocketShutdown.Both); } catch { }
            try { sock.Close(); } catch { }
        }
    }

    internal static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            bool createdNew;
            using (Mutex mutex = new Mutex(true, @"Local\UURemoteTlsFragmenterNativeMutex", out createdNew))
            {
                if (!createdNew) return;

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | (SecurityProtocolType)3072;

                using (CancellationTokenSource cts = new CancellationTokenSource())
                using (FragmenterServer server = new FragmenterServer(new FragmenterConfig()))
                {
                    AppDomain.CurrentDomain.ProcessExit += delegate { try { cts.Cancel(); } catch { } };
                    try
                    {
                        Console.CancelKeyPress += delegate(object s, ConsoleCancelEventArgs e)
                        {
                            e.Cancel = true;
                            try { cts.Cancel(); } catch { }
                        };
                    }
                    catch { }

                    try
                    {
                        server.RunAsync(cts.Token).GetAwaiter().GetResult();
                    }
                    catch (OperationCanceledException)
                    {
                    }
                }
            }
        }
    }
}
