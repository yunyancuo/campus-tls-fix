# UU Remote & Tencent HTTPDNS TLS Fix

<p align="left">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011-0078D6?logo=windows" alt="Windows 10/11" />
  <img src="https://img.shields.io/badge/Dependencies-Zero%20(Built--in%20.NET)-2EA44F" alt="Zero Dependencies" />
  <img src="https://img.shields.io/badge/Mode-100%25%20Local%20Direct-008080" alt="Local Direct" />
  <img src="https://img.shields.io/badge/License-MIT-blue" alt="MIT License" />
</p>

针对部分校园网或局域网出口防火墙对特定域名进行明文 SNI 阻断丢包的问题，提供两套独立运行、免安装 Python、双击即用的本地修复工具：

1. **网易 UU 远程 (`GameViewer`) TLS 握手阻断修复**：解决 `*.nrd.nie.163.com` 控制与信令域名 TLS `ClientHello` 超时导致无法登录、无法刷新设备列表或无法建立远控的问题。
2. **QQ / 微信图片加载缓慢 (腾讯 HTTPDNS / DoH 阻断) 修复**：解决 `dns.qq.com`、`dns.weixin.qq.com` 等 5 个腾讯自建 HTTPDNS 域名被 SNI 阻断丢包，导致客户端每次加载聊天图片都卡在 TCP/TLS 状态机等待超时后才回退系统 DNS 的问题（支持 **TLS 分片直连放通** 与 **0.0.0.0 快速回退系统 DNS** 双模式）。

两个模块分开提供独立的一键修复与恢复入口，互不干扰，可单独使用也可同时开启。

---

## 模块一：修复 UU 远程 TLS 握手阻断

### 方式一：PowerShell 一行命令在线修复

打开 **终端** 或 **Windows PowerShell**，执行以下任意一行命令即可完成本地编译、启动、开机自启与 6 项握手测速：

- **国内镜像加速通道**：
  ```powershell
  irm https://gh-proxy.com/https://raw.githubusercontent.com/yunyancuo/uu-remote-tls-fix/main/install.ps1 | iex
  ```
- **GitHub 官方通道**：
  ```powershell
  irm https://raw.githubusercontent.com/yunyancuo/uu-remote-tls-fix/main/install.ps1 | iex
  ```

### 方式二：下载压缩包双击修复

1. 点击仓库右上角 `Code` -> `Download ZIP` 并解压；
2. 双击运行 **`一键修复UU远程.bat`**。

### 卸载并恢复 UU 远程默认配置

- **在线卸载**：
  ```powershell
  irm https://gh-proxy.com/https://raw.githubusercontent.com/yunyancuo/uu-remote-tls-fix/main/uninstall.ps1 | iex
  ```
- **本地双击卸载**：双击运行 **`一键卸载恢复.bat`**。

---

## 模块二：修复 QQ / 微信图片加载缓慢 (腾讯 HTTPDNS 阻断)

### 问题现象与根因

在部分校园网环境下，QQ 与微信聊天窗口加载图片经常需要转圈等待数秒才显示。原因是客户端会优先向腾讯自建的 5 个 HTTPDNS / DoH 域名发起查询：
- `dns.qq.com`
- `dns.weixin.qq.com`
- `dns.weixin.qq.com.cn`
- `httpdns.kg.qq.com`
- `dns.wechat.com`

当校园网出口对这 5 个域名进行 SNI 阻断丢包（不返回 RST，直接丢弃报文）时，客户端会卡在 TCP/TLS 握手状态机直到超时（约 3~5 秒），随后才回落到系统 DNS 加载图片。

### 双模修复机制

- **模式 A：TLS 分片直连放通（`Fragment`，默认）**
  通过系统 `hosts` 将上述 5 个域名指向 `127.0.0.1`，由本地守护程序 `UUTlsFragmenter.exe`（监听 `443` 端口）将发往腾讯 HTTPDNS 的首个 TLS `ClientHello` 报文在 SNI 字段中间切分为 2 个标准 TLS Record 帧后直连发出，使腾讯 HTTPDNS 查询在 `100~160 ms` 内正常完成握手。
- **模式 B：快速失败秒回退系统 DNS（`FastFail`）**
  将上述 5 个域名在 `hosts` 中指向 `0.0.0.0`（及 IPv6 `::`），并在局域网 DNS 服务中直接返回 `NXDOMAIN`。客户端发起 HTTPDNS 请求时在 `0~1 ms` 内立即收到失败通知并瞬间回退到系统 DNS，彻底消除状态机超时等待。

### 一键使用方法

- **本地双击修复（推荐）**：解压后直接双击运行 **`一键修复QQ微信图片缓慢.bat`**（会自动请求管理员权限完成配置并打印 5 个域名的实测耗时）。
- **PowerShell 在线一键修复（默认 TLS 分片直连模式）**：
  ```powershell
  irm https://gh-proxy.com/https://raw.githubusercontent.com/yunyancuo/uu-remote-tls-fix/main/fix-qq-wechat.ps1 | iex
  ```
- **切换为 FastFail（0.0.0.0 秒回退）模式**：
  ```powershell
  .\fix-qq-wechat.ps1 -Mode FastFail
  ```
- **独立卸载并恢复 QQ / 微信默认配置**：
  双击运行 **`一键恢复QQ微信默认.bat`**，或在管理员 PowerShell 中运行：
  ```powershell
  irm https://gh-proxy.com/https://raw.githubusercontent.com/yunyancuo/uu-remote-tls-fix/main/unfix-qq-wechat.ps1 | iex
  ```

---

## 工作原理架构

```text
┌───────────────────────────────────────────────────────────────────────────┐
│  1. UU 远程客户端 (GameViewer.exe)  -->  读取 proxy_config.ini (127.0.0.1:17899) │
│  2. QQ / 微信客户端 或 局域网手机端  -->  系统 hosts / 局域网 DNS 指向本机:443   │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  本机无窗口守护进程: UUTlsFragmenter.exe (0.0.0.0:17899 / :443 / DNS :53)  │
│  - 双帧标准 TLS Record 切分: 对 *.nrd.nie.163.com 及 5 个腾讯 HTTPDNS 域名 │
│    的首包 TLS ClientHello 在 SNI 字段中间切分为 2 个符合 RFC 规范的帧     │
│  - 网关智能优选: 通过公共 DoH (223.5.5.5) 解析支持多帧重组的官方低延迟节点 │
│  - 降级自愈: 自动将已降级的 80 端口明文请求透明升级为 443 加密 TLS 通道   │
│  - 物理网卡直连: 出站 Socket 直接绑定本机物理网卡 (以太网/WLAN) 发出      │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  网易 UU 远程官方服务器 & 腾讯 HTTPDNS / DoH 官方服务器                   │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 项目结构

```text
uu-remote-tls-fix/
├── install.ps1                  # UU 远程一键修复主脚本（支持 irm ... | iex 在线执行）
├── uninstall.ps1                # UU 远程一键卸载与恢复脚本
├── 一键修复UU远程.bat            # Windows 双击修复 UU 远程启动器
├── 一键卸载恢复.bat              # Windows 双击卸载 UU 远程启动器
├── fix-qq-wechat.ps1            # QQ/微信图片加载缓慢独立修复脚本（支持 Fragment/FastFail 双模）
├── unfix-qq-wechat.ps1          # QQ/微信图片加载缓慢独立恢复脚本
├── 一键修复QQ微信图片缓慢.bat    # Windows 双击修复 QQ/微信图片加载缓慢启动器
├── 一键恢复QQ微信默认.bat        # Windows 双击恢复 QQ/微信默认设置启动器
├── src/
│   └── UUTlsFragmenter.cs       # 零依赖原生 C#/.NET 本地 TLS Record 分片与局域网 DNS 源码
├── .gitattributes               # Git 行尾配置（强制 .bat/.ps1/.cs 使用 CRLF 换行）
├── .gitignore                   # Git 忽略规则配置
├── LICENSE                      # MIT 开源许可证
└── README.md                    # 项目说明文档
```

---

## 覆盖端点与实测表现

| 所属服务 | 域名端点 | 作用 | 修复前状态 | 修复后状态（本机分片直连） |
| :--- | :--- | :--- | :---: | :---: |
| **UU 远程** | `api.nrd.nie.163.com` | 核心控制与房间 API | TLS 握手超时 | 握手成功 (`~60-110 ms`) |
| **UU 远程** | `api-dcdn.nrd.nie.163.com` | DCDN 灾备控制 API | TLS 握手超时 | 握手成功 (`~90-120 ms`) |
| **UU 远程** | `api-event.nrd.nie.163.com` | 客户端事件上报 API | TLS 握手超时 | 握手成功 (`~60-85 ms`) |
| **UU 远程** | `api-ipv4.nrd.nie.163.com` | IPv4 远程唤醒与初始化 | TLS 握手超时 | 握手成功 (`~60-80 ms`) |
| **UU 远程** | `sig-3303-d.nrd.nie.163.com` | WebSocket 远程控制信令 | TLS 握手超时 | 握手成功 (`~300-550 ms`) |
| **UU 远程** | `relay-mg-3303-d.nrd.nie.163.com` | TURN/TLS 桌面画面流中继 | TLS 握手超时 | 握手成功 (`~40-90 ms`) |
| **QQ / 微信** | `dns.qq.com` | 腾讯公共/客户端 DoH & HTTPDNS | TLS 握手超时 (`>3000 ms`) | 握手成功 (`~60-130 ms`) / 秒回退 (`<1 ms`) |
| **QQ / 微信** | `dns.weixin.qq.com` | 微信客户端主 HTTPDNS | TLS 握手超时 (`>3000 ms`) | 握手成功 (`~110-160 ms`) / 秒回退 (`<1 ms`) |
| **QQ / 微信** | `dns.weixin.qq.com.cn` | 微信国内节点 HTTPDNS | TLS 握手超时 (`>3000 ms`) | 握手成功 (`~60-130 ms`) / 秒回退 (`<1 ms`) |
| **QQ / 微信** | `httpdns.kg.qq.com` | 腾讯多媒体/图片 HTTPDNS | TLS 握手超时 (`>3000 ms`) | 握手成功 (`~65-140 ms`) / 秒回退 (`<1 ms`) |
| **QQ / 微信** | `dns.wechat.com` | WeChat 国际/通用 HTTPDNS | TLS 握手超时 (`>3000 ms`) | 握手成功 (`~350-1300 ms`) / 秒回退 (`<1 ms`) |

---

## License

本项目基于 [MIT License](./LICENSE) 开源。
