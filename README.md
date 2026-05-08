# Wisp

Wisp 是一个基于 `Tauri 2 + Rust + Vue 3` 的 Windows 桌面抓包分析工具。它的目标不是立即复刻 Wireshark 的全部协议覆盖和分析深度，而是沿着 Wireshark 的核心技术路线，把高频真实流量逐步解释清楚，并保留更适合研发排障的桌面工作台体验。

## 项目目标

- 做一个面向 Windows 的轻量桌面抓包分析器
- 优先解释高频真实流量，而不是先堆砌协议数量
- 优先服务研发排障、接口联调、环境定位这类真实工作流
- 后端解析逻辑尽量手写，保持结构清晰和可控
- 前端保持高密度、克制、偏工作台式的分析界面
- 解析路线遵循：
  `conversation state -> reassembly -> TLS 解密 -> 应用层解释`

## 当前能力

### 抓包与回放

- Windows `Npcap/pcap` 实时抓包
- 网卡选择、开始/停止、历史会话回放
- 抓包会话统计与基础回放加载

### 已支持协议

- Ethernet II
- ARP
- IPv4
- IPv6
- TCP
- UDP
- HTTP/1.x 明文识别
- HTTP/2 基础 frame 识别
- TLS 记录层识别
- HTTPS 会话归类
- DNS
- ICMP
- ICMPv6
- QUIC 入口识别

### 已支持的分析能力

- TCP conversation / reassembly 基础框架
- TCP keep-alive 场景下的 HTTP/1.x 重组
- TLS 会话级 `SNI / ALPN / cipher suite / client_random / server_random` 提取
- `SSLKEYLOGFILE` 驱动的 `TLS 1.3` record 级解密
- 解密后的 `HTTP/1.1 / HTTP/2` 二次分发与基础解析
- `layers / fields / artifacts` 结构化详情模型
- 会话级解释产物：
  `Conversation Summary`
  `TLS Readiness`
  `Application Hint`
  `HTTP Summary`
- 实时数据包列表
- 协议占比和带宽时间线
- 数据包逐层详情查看
- 详情区直接展示“为什么没解密”

## 当前边界

- TLS 解密当前只覆盖 `TLS 1.3 + SSLKEYLOGFILE`
- 只支持当前已接入的 TLS 1.3 cipher：
  `TLS_AES_128_GCM_SHA256`
  `TLS_AES_256_GCM_SHA384`
  `TLS_CHACHA20_POLY1305_SHA256`
- HTTP/2 目前只做基础 frame 级解析，不做完整 HPACK / 语义恢复
- QUIC 目前只做入口识别和基础连接归并，不是完整 HTTP/3 解析
- 还没有完整 display filter 语法
- 还不是 Wireshark 那种完整 dissector / 全协议字段体系

这意味着：

- 明文 `http://` 流量会显示成 `HTTP`
- `https://` 流量默认仍会主要显示成 `HTTPS / TLS`
- 如果提供 `SSLKEYLOGFILE`，符合条件的 `TLS 1.3` 流量可以继续显示解密后的 `HTTP/1.1 / HTTP/2`
- 如果没有解密成功，详情区会直接提示是 `未配置 keylog`、`缺少 secret`、`cipher 暂不支持` 还是 `record 不完整`

## 与 Wireshark 的定位差异

- Wireshark 更像“协议百科 + 专家工具”
- Wisp 更像“研发排障分析台 + 高频流量解释器”
- Wireshark 的强项是协议覆盖、字段深度、显示过滤器和成熟 dissector 体系
- Wisp 当前更强调：
  更快看到真实业务请求
  更直接理解 TLS 是否就绪
  更快判断当前会话为什么没解开
  更适合围绕 Windows 桌面抓包和业务联调来组织体验

## 文档索引

- [协议差距路线图](docs/roadmap-wireshark-gap.zh-CN.md)
- [解析架构说明](docs/parser-architecture.zh-CN.md)
- [协议支持矩阵](docs/protocol-matrix.zh-CN.md)

## 技术栈

### 后端

- Rust
- Tauri 2
- `pcap`
- `ring`
- `serde / serde_json`

### 前端

- Vue 3
- TypeScript
- Vite
- `shadcn-vue` 风格组件组织
- `reka-ui`
- `vue-sonner`

## 目录结构

```text
Wisp/
├─ docs/                  协议路线、架构、支持矩阵
├─ src/                   Vue 前端
│  ├─ components/         页面组件与协议详情组件
│  ├─ stores/             抓包状态与前端事件同步
│  ├─ types/              前后端共享的数据模型映射
│  └─ utils/              协议展示、颜色、格式化工具
└─ src-tauri/             Rust 后端
   ├─ src/app/            Tauri command / state / event
   ├─ src/capture/        网卡抓包与 worker
   ├─ src/model/          会话、数据包、过滤、统计模型
   ├─ src/parser/         协议解析主链与会话状态
   ├─ src/stats/          统计聚合
   └─ src/store/          抓包会话与回放存储
```

## 本地开发

### 前置条件

- Windows 10 / 11
- Rust toolchain
- Node.js / npm
- Npcap
- Npcap SDK

### Npcap 说明

运行抓包依赖：

- `Npcap`

本地编译 `pcap` 依赖：

- `Npcap SDK`

如果本机缺少 `wpcap.lib`，请确认 `Npcap SDK` 已安装，并且项目的 `build.rs` 能探测到 SDK 路径。

### 开发启动

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location 'D:\Issue\MicrosoftVSCode\tauri\Wisp'
npm run tauri -- dev
```

### 前端构建

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location 'D:\Issue\MicrosoftVSCode\tauri\Wisp'
npm run build
```

### Rust 编译检查

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location 'D:\Issue\MicrosoftVSCode\tauri\Wisp\src-tauri'
cargo check
```

### Rust 测试

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location 'D:\Issue\MicrosoftVSCode\tauri\Wisp\src-tauri'
cargo test
```

### 前端类型检查

```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Set-Location 'D:\Issue\MicrosoftVSCode\tauri\Wisp'
npx vue-tsc --noEmit
```

## 常用 npm 脚本

- `npm run dev`：只启动 Vite 前端
- `npm run build`：前端类型检查 + Vite build
- `npm run tauri -- dev`：启动完整桌面开发环境
- `npm run tauri:build`：构建当前平台桌面包
- `npm run tauri:win:build`：构建 Windows 目标

## 抓包使用提示

- 抓普通外网流量时，请选择实际的 Wi-Fi / 以太网接口
- 抓 `localhost`、`Vite dev server` 或 Tauri 前端调试流量时，请选择本地回环接口
- 刷新 Wisp 自己的开发页面时，如果抓的不是回环接口，通常看不到对应 HTTP 流量
- 访问 `http://` 站点更容易验证 HTTP 解析链路

## TLS 解密使用方式

### 当前支持范围

- `TLS 1.3`
- `SSLKEYLOGFILE`
- 解密后继续识别 `HTTP/1.1` 和 `HTTP/2`

### 使用步骤

1. 让浏览器或客户端把 TLS secrets 写入 `SSLKEYLOGFILE`
2. 启动 Wisp
3. 点击顶部的 `解密`
4. 勾选 `启用 TLS 解密`
5. 填入 keylog 文件路径
6. 开始抓包并查看 `HTTPS / TLS` 数据包详情

### 你会看到什么

- 解密成功时：
  详情区会出现 `解密后的 HTTP/1.x` 或 `解密后的 HTTP/2`
- 解密未成功时：
  `解密状态` 和 `TLS Readiness` 会告诉你当前卡在哪一步
- 解密相关的中间结果会进入 `分析产物`，包括：
  `Decrypted TLS Payload`
  `Conversation Summary`
  `Application Hint`
  `HTTP Summary`

## 下一步重点

- 补齐 `TLS 1.2` 解密路线或明确继续只做 `TLS 1.3`
- 补强 HTTP/2 细节展示和更稳定的 stream 级摘要
- 继续推进 QUIC state，为后续 `HTTP/3` 预留入口
- 逐步把过滤体验从“关键词搜索”推进到“字段驱动过滤”
- 继续强化“为什么没解出来”的解释能力

## 开发约束

- Rust 后端协议解析以手写为主
- 尽量不用大而全协议解析框架
- 只在高复杂度协议或 TLS 解密阶段考虑少量必要依赖
- 优先保证“真实流量解释得出来”，再补更复杂 UI 和高级过滤器
- 不以短期复刻 Wireshark 为目标，优先把研发最常见的问题看清楚
