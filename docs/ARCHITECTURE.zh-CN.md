# Wisp 架构设计

## 1. 目标与边界

Wisp 是一个基于 `Tauri 2 + Rust + Vue 3` 的 Windows 桌面抓包分析工具。

第一阶段目标：

- 选择网卡并开始/停止抓包
- 实时显示数据包列表
- 展示以太网、IP、TCP/UDP、HTTP 详细字段
- 支持协议/IP/端口过滤
- 支持关键字搜索
- 支持保存捕获结果并重新加载回放
- 支持实时带宽和协议占比统计

第一阶段建议明确的协议边界：

- 必做：`Ethernet II`、`IPv4`、`TCP`、`UDP`、`HTTP/1.x`
- 建议支持但可降级：`ARP`、`ICMP`、`IPv6`
- 未识别协议统一保留 `raw bytes + summary`，前端显示为 `Unknown`

这样可以保证核心链路先闭环，不会因为“全协议支持”把实现拖散。

## 2. 仓库结构

### Rust 后端

建议将 `src-tauri/src` 调整为：

```text
src-tauri/src/
  main.rs
  lib.rs
  app/
    mod.rs
    state.rs
    commands.rs
    events.rs
  capture/
    mod.rs
    device.rs
    session.rs
    worker.rs
    source.rs
  parser/
    mod.rs
    cursor.rs
    ethernet.rs
    ipv4.rs
    ipv6.rs
    arp.rs
    tcp.rs
    udp.rs
    http.rs
    checksum.rs
  filter/
    mod.rs
    expr.rs
    compiler.rs
    matcher.rs
  store/
    mod.rs
    sqlite.rs
    schema.rs
    replay.rs
  stats/
    mod.rs
    bandwidth.rs
    protocol.rs
  model/
    mod.rs
    packet.rs
    session.rs
    filter.rs
    stats.rs
    error.rs
```

### Vue 前端

建议将 `src` 调整为：

```text
src/
  main.ts
  App.vue
  app/
    router.ts
    events.ts
  pages/
    CapturePage.vue
    ReplayPage.vue
  components/
    layout/
      AppShell.vue
      TopBar.vue
      SideStats.vue
    capture/
      InterfaceSelector.vue
      CaptureControls.vue
      FilterBar.vue
      SearchBox.vue
      PacketTable.vue
      PacketRow.vue
      PacketDetailPanel.vue
      ProtocolTree.vue
      HexViewer.vue
      TimelineChart.vue
      ProtocolDonut.vue
    replay/
      SessionList.vue
      ReplayToolbar.vue
  stores/
    capture.ts
    replay.ts
    filters.ts
    stats.ts
  types/
    packet.ts
    session.ts
    filter.ts
    stats.ts
  utils/
    format.ts
    protocol.ts
    color.ts
```

## 3. 后端模块职责

### `app`

- Tauri 启动入口
- 注册 commands
- 挂载全局 `AppState`
- 对外发送事件给前端

### `capture`

- 枚举网络接口
- 启动/停止抓包线程
- 管理单次抓包会话生命周期
- 把原始数据包送入解析、存储、统计流水线

### `parser`

- 纯字节解析，不依赖第三方协议解析库
- 每层只负责自己的头部与 payload 切片
- 返回结构化字段与剩余字节范围

### `filter`

- 解析用户过滤表达式
- 编译为可执行匹配器
- 对实时包和回放包执行同一套过滤逻辑

### `store`

- 用 SQLite 保存捕获会话和包内容
- 负责载入历史会话、分页查询、回放读取
- 建表、迁移、索引维护

### `stats`

- 实时带宽统计
- 协议计数与占比
- 滑动时间窗口聚合

### `model`

- 统一定义前后端交互的数据结构
- 区分“列表摘要”“详细包体”“统计数据”“过滤条件”

## 4. 抓包与解析流水线

推荐采用单向流水线，避免 UI、抓包、存储彼此耦合。

```text
Npcap device
  -> capture worker
  -> raw packet
  -> parser
  -> packet summary/detail
  -> filter matcher
  -> stats aggregator
  -> sqlite writer
  -> tauri event -> Vue UI
```

### 建议流程

1. 前端调用 `list_interfaces`
2. 用户选择网卡，调用 `start_capture(interface, filter, output_path?)`
3. Rust 创建 `CaptureSession`
4. 启动后台抓包线程，持续从 pcap 读取原始字节
5. 每个包进入 `parser`
6. 生成：
   - `PacketSummary`：表格展示需要的轻量字段
   - `PacketDetail`：详细面板需要的完整结构
   - `PacketRecord`：落库结构
7. 过滤器先作用在内存对象上，决定是否发给前端
8. 统计器更新带宽和协议占比
9. 写入 SQLite
10. 通过 Tauri event 推送：
   - `capture:packet`
   - `capture:stats`
   - `capture:state`
11. 用户点击停止后，线程退出并关闭 session

### 并发建议

- 1 个抓包线程：只做读取和基础时间戳封装
- 1 个处理线程：解析、过滤、统计、写库、事件投递
- 前端只接收摘要数据，不直接接收完整原始流

这样可以减少锁竞争，也更容易定位性能瓶颈。

## 5. 协议解析实现思路

核心原则：手写小而清晰的解析器，不做“万能解码器”。

### 通用做法

- 实现一个 `ByteCursor<'a>`，提供：
  - `read_u8`
  - `read_be_u16`
  - `read_be_u32`
  - `read_slice(len)`
  - `remaining()`
- 每层解析函数签名保持统一：

```rust
fn parse_xxx(input: &[u8]) -> Result<ParsedXxx, ParseError>
```

- 返回值同时带：
  - 结构化字段
  - 头部长度
  - payload 切片范围

### 以太网层

输入至少 14 字节：

- `dst_mac: [u8; 6]`
- `src_mac: [u8; 6]`
- `ether_type: u16`

根据 `ether_type` 分发：

- `0x0800` -> IPv4
- `0x86DD` -> IPv6
- `0x0806` -> ARP
- 其他 -> `Unknown`

### IPv4 层

重点字段：

- `version`
- `ihl`
- `dscp_ecn`
- `total_length`
- `identification`
- `flags_fragment_offset`
- `ttl`
- `protocol`
- `header_checksum`
- `src_ip`
- `dst_ip`

实现要点：

- 先校验最小头长 20 字节
- `ihl * 4` 计算真实头长度
- 若 `total_length < ihl_bytes` 直接判为 malformed
- 暂不做 IP 分片重组，遇到分片时标记 `is_fragment = true`

### TCP 层

重点字段：

- `src_port`
- `dst_port`
- `seq`
- `ack`
- `data_offset`
- `flags`
- `window_size`
- `checksum`
- `urgent_pointer`

实现要点：

- 校验最小头长 20 字节
- `data_offset * 4` 作为头长
- 把 flags 展开成布尔位，方便前端显示
- 不做 TCP 流重组，HTTP 仅解析单包内可见内容

### UDP 层

重点字段：

- `src_port`
- `dst_port`
- `length`
- `checksum`

实现很简单，适合作为第一批完成模块。

### HTTP 应用层

建议只做“轻解析”，不做完整 RFC 实现。

识别条件：

- TCP payload 以常见方法开头：
  - `GET`
  - `POST`
  - `PUT`
  - `DELETE`
  - `HEAD`
  - `OPTIONS`
- 或以 `HTTP/1.` 开头

解析输出：

- `is_request`
- `start_line`
- `headers: Vec<(String, String)>`
- `body_preview: Vec<u8>`
- `raw_text_lossy: String`

限制建议：

- 只尝试解析 UTF-8/ASCII 可读部分
- body 只保留前 N KB 预览，避免 UI 和数据库膨胀
- 明确标注“未做 TCP 重组，HTTP 可能不完整”

## 6. 核心数据结构

建议把“列表摘要”和“详细包体”分开，避免前端表格承载过重对象。

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub id: i64,
    pub session_id: String,
    pub ts_unix_ms: i64,
    pub frame_no: u64,
    pub src: String,
    pub dst: String,
    pub protocol: PacketProtocol,
    pub length: u32,
    pub info: String,
    pub matched: bool,
}
```

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketDetail {
    pub id: i64,
    pub summary: PacketSummary,
    pub ethernet: Option<EthernetFrame>,
    pub ipv4: Option<Ipv4Packet>,
    pub ipv6: Option<Ipv6Packet>,
    pub arp: Option<ArpPacket>,
    pub transport: Option<TransportPacket>,
    pub application: Option<ApplicationPacket>,
    pub raw: RawPacketData,
}
```

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportPacket {
    Tcp(TcpSegment),
    Udp(UdpDatagram),
}
```

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApplicationPacket {
    Http(HttpMessage),
    Unknown(UnknownPayload),
}
```

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacketData {
    pub captured_len: u32,
    pub original_len: u32,
    pub bytes_hex: String,
    pub ascii_preview: String,
}
```

### 状态对象

```rust
pub struct AppState {
    pub capture: Mutex<CaptureManager>,
    pub store: Mutex<StoreManager>,
}
```

`CaptureManager` 维护：

- 当前 session
- 后台线程句柄
- 停止信号
- 当前过滤器

## 7. 过滤器设计

过滤器建议分两层：

### 第一层：结构化字段过滤

适合高频实时过滤，字段明确，性能稳定：

- 协议：`tcp`, `udp`, `http`, `arp`
- IP：`src_ip`, `dst_ip`, `ip`
- 端口：`src_port`, `dst_port`, `port`

前端可视化条件模型：

```ts
type FilterState = {
  protocols: string[]
  ip?: string
  srcIp?: string
  dstIp?: string
  port?: number
  srcPort?: number
  dstPort?: number
  onlyMalformed?: boolean
}
```

### 第二层：文本搜索

对以下字段做关键字匹配：

- `info`
- HTTP start line
- HTTP headers
- ASCII payload preview

建议不要对整包十六进制全文搜索，否则实时性能会明显下降。

### 表达式方案

为了兼顾易用性和扩展性，推荐支持一个简化表达式：

```text
tcp and ip=192.168.1.10 and port=443
http and contains("host:")
udp and dst_port=53
```

实现分三步：

1. 前端输入字符串
2. Rust `filter::expr` 解析为 AST
3. `filter::compiler` 编译成 matcher 闭包或结构化判定器

第一版可以只支持：

- `and`
- `protocol=value`
- `ip=value`
- `port=value`
- `contains("text")`

不建议第一版就做复杂括号和 `or/not`，会拖慢交付。

## 8. SQLite 设计

建议把 SQLite 同时作为：

- 内部历史存储
- 导出的捕获文件格式

这样“保存”和“重新加载回放”天然统一，不需要额外定义一套文件格式。

### 表：`capture_sessions`

```sql
CREATE TABLE capture_sessions (
  id TEXT PRIMARY KEY,
  name TEXT,
  interface_name TEXT NOT NULL,
  interface_desc TEXT,
  started_at_ms INTEGER NOT NULL,
  ended_at_ms INTEGER,
  packet_count INTEGER NOT NULL DEFAULT 0,
  bytes_captured INTEGER NOT NULL DEFAULT 0,
  file_path TEXT,
  app_version TEXT,
  notes TEXT
);
```

### 表：`packets`

```sql
CREATE TABLE packets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  frame_no INTEGER NOT NULL,
  ts_unix_ms INTEGER NOT NULL,
  ts_subsec_us INTEGER NOT NULL DEFAULT 0,
  captured_len INTEGER NOT NULL,
  original_len INTEGER NOT NULL,
  src_mac TEXT,
  dst_mac TEXT,
  ether_type INTEGER,
  ip_version INTEGER,
  src_ip TEXT,
  dst_ip TEXT,
  ip_protocol INTEGER,
  ttl INTEGER,
  ip_checksum INTEGER,
  src_port INTEGER,
  dst_port INTEGER,
  tcp_seq INTEGER,
  tcp_ack INTEGER,
  tcp_flags INTEGER,
  tcp_window INTEGER,
  transport_checksum INTEGER,
  app_protocol TEXT,
  summary_protocol TEXT NOT NULL,
  summary_info TEXT NOT NULL,
  search_text TEXT,
  raw_bytes BLOB NOT NULL,
  http_start_line TEXT,
  http_headers TEXT,
  http_body_preview BLOB,
  is_malformed INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (session_id) REFERENCES capture_sessions(id)
);
```

### 索引

```sql
CREATE INDEX idx_packets_session_frame ON packets(session_id, frame_no);
CREATE INDEX idx_packets_session_time ON packets(session_id, ts_unix_ms);
CREATE INDEX idx_packets_session_protocol ON packets(session_id, summary_protocol);
CREATE INDEX idx_packets_session_src_ip ON packets(session_id, src_ip);
CREATE INDEX idx_packets_session_dst_ip ON packets(session_id, dst_ip);
CREATE INDEX idx_packets_session_src_port ON packets(session_id, src_port);
CREATE INDEX idx_packets_session_dst_port ON packets(session_id, dst_port);
```

### 表：`stats_snapshots`

如果需要保存回放统计曲线，可以增加：

```sql
CREATE TABLE stats_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  bucket_start_ms INTEGER NOT NULL,
  bytes_total INTEGER NOT NULL,
  packets_total INTEGER NOT NULL,
  tcp_count INTEGER NOT NULL DEFAULT 0,
  udp_count INTEGER NOT NULL DEFAULT 0,
  http_count INTEGER NOT NULL DEFAULT 0,
  arp_count INTEGER NOT NULL DEFAULT 0,
  other_count INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (session_id) REFERENCES capture_sessions(id)
);
```

如果第一版想保持精简，也可以不落这张表，回放时由 `packets` 再聚合。

## 9. Tauri 命令与事件

### Commands

建议暴露：

- `list_interfaces() -> Vec<NetworkInterface>`
- `start_capture(req: StartCaptureRequest) -> CaptureSessionMeta`
- `stop_capture() -> CaptureSessionMeta`
- `get_packet_detail(session_id: String, packet_id: i64) -> PacketDetail`
- `list_sessions() -> Vec<CaptureSessionMeta>`
- `load_session(session_id: String) -> CaptureSessionMeta`
- `query_packets(req: PacketQuery) -> PacketPage`
- `delete_session(session_id: String) -> ()`

### Events

- `capture:state`
- `capture:packet`
- `capture:stats`
- `capture:error`

建议只把实时新增数据通过事件推送，大批量历史数据统一走分页命令查询。

## 10. 前端页面结构

## 主界面布局

推荐三栏布局：

- 顶部：接口选择、开始/停止、保存状态
- 左中主区：数据包列表
- 右侧详情：协议树 + 原始内容
- 底部或右上：流量图表与协议占比

```text
+--------------------------------------------------------------+
| TopBar: interface / start-stop / filter / search            |
+-----------------------------------+--------------------------+
| PacketTable                       | PacketDetailPanel        |
|                                   | ProtocolTree            |
|                                   | HexViewer / HTTP raw    |
+-----------------------------------+--------------------------+
| TimelineChart                     | ProtocolDonut / stats   |
+--------------------------------------------------------------+
```

### 页面

#### `CapturePage.vue`

实时抓包主页面，负责：

- 绑定实时事件
- 维护当前选中包
- 同步过滤、搜索、统计

#### `ReplayPage.vue`

历史回放页面，负责：

- 会话列表
- 加载 SQLite 会话
- 分页查询历史数据包

### 组件职责

#### `InterfaceSelector`

- 加载接口列表
- 展示名称、描述、地址信息

#### `CaptureControls`

- 开始/停止按钮
- 当前状态
- 当前 session 信息

#### `FilterBar`

- 协议快捷筛选
- IP/端口条件
- 高级表达式输入框

#### `PacketTable`

- 虚拟滚动或增量渲染
- 列：时间、源、目标、协议、长度、信息
- 支持排序和高亮匹配

#### `PacketDetailPanel`

- 左侧协议层树
- 右侧字段表
- 底部原始十六进制/ASCII

#### `TimelineChart`

- 展示最近 N 秒带宽变化
- 用 Canvas 绘制，避免大量 DOM

#### `ProtocolDonut`

- 用 SVG 绘制协议占比，结构简单、风格克制

## 11. 前端状态管理建议

不必一开始就上复杂状态库，简单方案足够：

- `capture.ts`：实时抓包状态
- `filters.ts`：过滤与搜索状态
- `stats.ts`：图表统计状态
- `replay.ts`：历史会话与回放分页

关键状态：

```ts
type CaptureStore = {
  session: CaptureSessionMeta | null
  interfaces: NetworkInterface[]
  packets: PacketSummary[]
  selectedPacketId: number | null
  running: boolean
}
```

注意点：

- 表格只保存 `PacketSummary`
- 点击行时再调用后端获取 `PacketDetail`
- 历史列表必须分页，避免一次性把整场抓包塞进内存

## 12. UI 风格建议

结合你要的 Linear/Vercel 风格，建议：

- 浅色背景为主，深灰文本，低饱和边框
- 强调信息密度，不做大面积插画
- 以 1px 分隔线、细网格、紧凑表格为主
- 状态色克制：
  - TCP：蓝
  - UDP：绿
  - HTTP：橙
  - Error/Malformed：红
- 图表不做炫光或厚重阴影
- 字体优先无衬线窄节奏组合，避免默认模板感

## 13. 开发顺序建议

### 阶段 1：基础骨架

- 清理默认 Tauri/Vue 模板
- 搭建 `app / model / capture / parser` 目录
- 定义 Tauri commands 和 event 名称
- 前端搭出主界面空壳

### 阶段 2：抓包闭环

- 接入 pcap 枚举网卡
- 实现开始/停止抓包
- 实现 `PacketSummary` 实时推送
- 前端表格展示实时列表

### 阶段 3：基础解析

- 先实现 Ethernet、IPv4、TCP、UDP
- 点击数据包查看详细字段
- 原始 hex/ascii 查看器上线

### 阶段 4：HTTP 与搜索

- 增加 HTTP 轻解析
- 增加关键字搜索
- 优化 `info` 文本生成

### 阶段 5：过滤器

- 先做协议/IP/端口结构化过滤
- 再做简化表达式
- 统一实时过滤与回放过滤逻辑

### 阶段 6：存储与回放

- SQLite 建表
- session 保存
- 历史查询和回放分页

### 阶段 7：统计面板

- 实时带宽曲线
- 协议占比图
- 回放统计复用同一套模型

### 阶段 8：稳定性

- malformed 包容错
- 大流量场景下的内存控制
- UI 虚拟列表
- 停止抓包、关闭应用时的资源释放

## 14. 第一版实现建议

如果目标是尽快做出能用的 MVP，建议第一版只承诺：

- 实时抓包
- Ethernet/IPv4/TCP/UDP/HTTP
- 协议/IP/端口过滤
- 关键字搜索
- SQLite 保存与回放
- 带宽折线 + 协议占比图

先不做：

- TCP 重组
- TLS 解密
- DNS 专项解析
- IP 分片重组
- pcapng 导出
- 复杂过滤语法

## 15. 推荐实现原则

- `parser` 只做解析，不访问数据库
- `store` 只做持久化，不关心 UI
- `stats` 只接收解析后的统一数据结构
- `PacketSummary` 与 `PacketDetail` 分离
- 历史查询必须分页
- 所有未知协议都保留原始 bytes，保证以后能补解析器

这套拆分的优点是：

- 模块职责清晰
- 抓包、解析、存储、UI 可以并行推进
- 第一版代码量可控
- 后续扩协议不会推翻主结构
