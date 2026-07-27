# Pure QUIC — 纯 Go QUIC 协议实现（无加密）

从 [quic-go](https://github.com/quic-go/quic-go) 移植核心逻辑，**剥离了 TLS 加密和 HTTP/3**，保留纯 QUIC 传输层，零外部依赖。

## 特性

| 特性 | 状态 | 说明 |
|------|------|------|
| ✅ QUIC 长/短包头 | 完成 | RFC 9000 兼容格式 |
| ✅ 流多路复用 | 完成 | Stream ID 管理，双向/单向流 |
| ✅ SACK (多Range ACK) | 完成 | QUIC ACK 帧原生支持多段不连续确认 |
| ✅ CUBIC 拥塞控制 | 完成 | 三次函数窗口增长 (RFC 8312)，默认算法 |
| ✅ BBR 拥塞控制 | 完成 | 基于模型的拥塞控制，弱网友好 |
| ✅ NewReno 拥塞控制 | 完成 | 备选算法，TCP 友好 |
| ✅ RTT 估算 | 完成 | 平滑 RTT + RTTVAR (RFC 6298) |
| ✅ 快速重传 | 完成 | 基于时间的丢包检测 (RFC 9002) |
| ✅ 流量控制 | 完成 | MAX_DATA / MAX_STREAM_DATA |
| ✅ 连接迁移 | 完成 | Connection ID 路由 + PATH_CHALLENGE/RESPONSE |
| ✅ Happy Eyeballs | 完成 | 双栈并发，300ms 偏移 (RFC 8305) |
| ✅ 多地址监听 | 完成 | 同时监听 IPv4 + IPv6 |
| ❌ TLS 加密 | 移除 | 纯明文传输 |
| ❌ HTTP/3 | 移除 | QUIC 传输层独立使用 |

## 项目结构

```
quic-test/
├── go.mod                 # 零外部依赖
├── README.md
├── cmd/
│   ├── server/main.go     # 回显服务端
│   └── client/main.go     # 测试客户端
└── quic/                  # 纯 QUIC 核心库
    ├── conn.go            # 连接管理、帧处理、ACK/重传
    ├── listener.go        # 监听器 + Dial + Happy Eyeballs
    ├── stream.go          # 流实现 (Read/Write/Close)
    ├── protocol/
    │   └── types.go       # 核心类型 (ConnectionID, PacketNumber, StreamID)
    ├── quicvarint/
    │   └── varint.go      # QUIC 变长整数编码 (RFC 9000)
    ├── utils/
    │   ├── rtt.go         # RTT 估算器 (RFC 6298)
    │   ├── congctl.go     # 拥塞控制接口
    │   ├── congestion.go  # NewReno 拥塞控制
    │   └── bbr.go         # BBR 拥塞控制
    └── wire/
        ├── header.go      # 长/短包头解析与序列化
        ├── frame.go       # 帧解析调度器
        ├── stream_frame.go
        ├── ack_frame.go
        ├── connection_close_frame.go
        ├── max_data_frame.go, max_stream_data_frame.go, max_streams_frame.go
        ├── reset_stream_frame.go, stop_sending_frame.go
        └── ... (其他帧类型)
```

## 快速开始

```bash
# 启动服务端（监听 IPv6 双栈 :4242）
go run ./cmd/server

# 启动客户端（Happy Eyeballs: 优先 IPv6）
go run ./cmd/client
```

### 预期输出

服务端：
```
监听: [::]:4242
接受新连接: [::]:4242 -> [::1]:59849
接受新流: 0
收到消息: Hello, Pure QUIC!, 17 字节
```

客户端：
```
Happy Eyeballs: 尝试 [[::1]:4242 127.0.0.1:4242]
Happy Eyeballs: 选用 #0 [::1]:4242 (0s)
连接成功: [::]:59849 -> [::1]:4242
流已打开, ID: 0
发送: Hello, Pure QUIC!
收到回显: Hello, Pure QUIC!, 17 字节
测试完成!
```

## API 参考

### 服务端

```go
// 选择拥塞控制算法
cfg := &quic.Config{
    CongestionControl: quic.CongestionCUBIC,
}

// 单地址监听
listener, err := quic.ListenAddr(":4242", cfg)

// 多地址监听
listener := quic.ListenAddrs([]*net.UDPConn{conn1, conn2}, cfg)

// 接受连接
conn, err := listener.Accept(ctx)
```

### 客户端

```go
// 单地址连接
conn, err := quic.Dial(ctx, "127.0.0.1:4242", cfg)

// Happy Eyeballs 多路径并发
conn, err := quic.DialHappy(ctx, []string{"[::1]:4242", "127.0.0.1:4242"}, cfg)
```

### 流操作

```go
// 接收流
stream, err := conn.AcceptStream(ctx)

// 打开流
stream, err := conn.OpenStream()

// 读写
n, err := stream.Read(buf)
n, err := stream.Write(data)

// 关闭
stream.Close()
```

## 拥塞控制

通过 `Config` 初始化时选择算法，客户端和服务端共用同一套逻辑：

```go
cfg := &quic.Config{CongestionControl: quic.CongestionCUBIC} // 默认
// 或: quic.CongestionBBR
// 或: quic.CongestionNewReno

// 服务端
listener := quic.ListenAddr(":4242", cfg)

// 客户端
conn, err := quic.Dial(ctx, "127.0.0.1:4242", cfg)
```

### CUBIC（默认，RFC 8312）

三次函数窗口增长，Linux 内核默认算法：

```
W_cubic(t) = C × (t - K)³ + W_max      C = 0.4
K = ³√(W_max × β / C)                   β = 0.3
```

| 阶段 | 行为 |
|------|------|
| **慢启动** | 指数增长到 ssthresh |
| **拥塞避免** | CUBIC 模式：S 形三次曲线增长 |
| **TCP 模式** | 当 W_cubic ≤ W_tcp 时，保持 TCP 友好 |
| **丢包恢复** | cwnd ×= 0.7，记录 W_max，重新计算 K |

### BBR

基于模型的拥塞控制，弱网友好：

```
Startup → Drain → ProbeBW ↔ ProbeRTT
```

| 阶段 | 行为 |
|------|------|
| **Startup** | 增益 2.0，指数探测带宽上限 |
| **Drain** | 增益 1/2.77，排空 Startup 积累的队列 |
| **ProbeBW** | 8 相位增益循环 [1.25, 0.75, 1.0×6] |
| **ProbeRTT** | 降 cwnd 到 4×MSS，刷新 minRTT |

### NewReno

经典基于丢包的拥塞控制，TCP 友好。

## 连接迁移

客户端 IP 变化时自动迁移：

```
新地址发来短包头包
 → 按 DestConnectionID 查 connIDMap 找到连接
 → 更新地址映射（迁移: oldAddr -> newAddr）
 → 发送 PATH_CHALLENGE 验证新路径
 → 对端回复 PATH_RESPONSE
 → 确认迁移完成
```

## 算法对比

| 场景 | CUBIC (默认) | BBR | NewReno |
|------|-------------|-----|---------|
| 高带宽长延迟 | ✅ 好 | ✅ 优 | ❌ 差 |
| 高丢包(>1%) | ❌ 降 30% | ✅ 几乎不受影响 | ❌ 降 50%+ |
| Bufferbloat | ⚠️ 中等 | ✅ 轻微 | ❌ 严重 |
| 高延迟(>200ms) | ✅ 时间驱动 | ✅ 主动探测 | ❌ RTT 依赖 |
| 无线网络 | ❌ 丢包敏感 | ✅ 好 | ❌ 差 |
| TCP 友好 | ✅ 设计目标 | ⚠️ 略差 | ✅ 友好 |
| 实现复杂度 | ⚠️ 中等 | ❌ 复杂 | ✅ 简单 |

## 测试

```bash
# 编译
go build ./...

# 运行服务端
go run ./cmd/server

# 运行客户端
go run ./cmd/client
```

## 依赖

**零外部依赖** — 仅使用 Go 标准库。

## 许可

MIT