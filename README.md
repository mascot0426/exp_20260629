# 网络数据包捕获与协议解析工具

> 基于 libpcap 的轻量级网络抓包与协议分析工具，类似简化版 Wireshark。

## 功能特性

- **抓包引擎**：基于 libpcap，支持网卡混杂模式，内核缓冲区可配置（8MB）
- **协议解析**：Ethernet II / IPv4 / IPv6 / TCP / UDP / ICMP / ARP / DNS / HTTP
- **HTTP 增强**：完整提取请求方法/URL/Host/响应状态码，支持请求/响应配对
- **BPF 过滤器**：支持 `pcap_compile` 过滤表达式
- **流量统计**：按协议类型 / IP地址 / 时间三维统计，支持每秒实时刷新显示
- **PCAP 读写**：写入 .pcap 文件 + 离线回放读取
- **性能模式**：静默模式（`-q`）关闭实时打印，优化高吞吐量场景丢包率

## 项目结构

```
packet_analyzer/
├── include/
│   ├── packet.h     # 共用数据包结构体
│   ├── capture.h    # 抓包引擎接口
│   ├── parser.h     # 协议解析接口
│   ├── filter.h     # BPF过滤接口
│   ├── stats.h      # 统计模块接口
│   └── pcap_io.h    # PCAP读写接口
├── src/
│   ├── main.c       # 主程序入口
│   ├── capture.c    # libpcap抓包实现
│   ├── parser.c     # 协议解析实现
│   ├── filter.c     # BPF过滤实现
│   ├── stats.c      # 流量统计实现
│   └── pcap_io.c    # PCAP文件读写
├── tests/
│   └── test_parser.c # 单元测试
├── scripts/
│   ├── gen_test_pcap.py       # 测试PCAP生成脚本
│   ├── gen_http_test_pcap.py  # HTTP配对测试生成脚本
│   ├── accept_all.sh          # 一键验收脚本
│   └── perf_test.sh           # 性能测试脚本
├── Makefile
├── README.md
├── 新手操作指南.md           # 零基础操作文档（含验收步骤）
└── 验收标准完成记录.md       # 验收结果记录
```

## 编译

```bash
make
```

## 使用方法

### 列出可用网卡
```bash
./packet_analyzer -l
```

### 实时抓包（需要 root 权限）
```bash
sudo ./packet_analyzer -i eth0 -c 10
```

### 带过滤器抓包
```bash
sudo ./packet_analyzer -i eth0 -f "tcp port 80" -c 50 -s
```

### 抓包并保存到文件
```bash
sudo ./packet_analyzer -i eth0 -w capture.pcap -c 100
```

### 从 PCAP 文件回放
```bash
./packet_analyzer -r capture.pcap -s
```

### 命令行选项
| 选项 | 说明 |
|------|------|
| `-i <interface>` | 网卡接口名 |
| `-f <filter>` | BPF 过滤表达式 |
| `-r <file>` | 从 PCAP 文件回放 |
| `-w <file>` | 保存到 PCAP 文件 |
| `-c <count>` | 抓包数量（-1 为无限） |
| `-l` | 列出可用网卡 |
| `-s` | 显示统计报告 |
| `-q` | 静默模式（性能测试，不打印每个包） |
| `-h` | 显示帮助 |

## 测试

```bash
# 单元测试
make test

# 内存检测
make valgrind

# 性能测试（静默模式）
make perf-test

# HTTP 请求响应配对演示
make demo-http

# 生成测试PCAP文件
python3 scripts/gen_test_pcap.py
```

## 项目验收

### 一键验收

```bash
bash scripts/accept_all.sh
```

### 验收结果

| 验收项 | 要求 | 实测结果 | 判定 |
|--------|------|---------|------|
| 标准1-丢包率 | 1Gbps 下 < 1% | 0.00% (0/100002) | ✅ 通过 |
| 标准1-解析正确率 | 100% | 15包全协议正确解析 | ✅ 通过 |
| 标准2-HTTP配对 | ≥ 5 对 | 6 对 | ✅ 通过 |

详细验收步骤见 [新手操作指南.md](新手操作指南.md) 第七阶段。

## 环境要求

- Linux (WSL2 Ubuntu 推荐)
- libpcap-dev
- gcc / make
- valgrind (内存检测，可选)
