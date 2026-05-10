# eBPF Security Monitor

基于 eBPF 的主机/容器安全事件实时采集与监控系统。

## 架构总览

```
┌────────────────────────────────────────────────┐
│                Linux Kernel                     │
│  ┌────────────┐ ┌──────────┐ ┌──────────────┐  │
│  │ Process BPF│ │ Network  │ │ File System  │  │
│  │ .bpf.o     │ │ BPF .o   │ │ BPF .o       │  │
│  └─────┬──────┘ └────┬─────┘ └──────┬───────┘  │
│        └──────────────┼──────────────┘          │
│                       ▼                         │
│              Perf Event Array                   │
└───────────────────────┬────────────────────────┘
                        │
┌───────────────────────▼────────────────────────┐
│          C++ Agent (libbpf + epoll)             │
│  采集 → 容器识别 → JSON序列化 → HTTP上报        │
└───────────────────────┬────────────────────────┘
                        │ HTTP POST (batched)
┌───────────────────────▼────────────────────────┐
│          Go Web Server (Gin + WebSocket)         │
│  事件存储 → WebSocket广播 → REST API            │
└───────────────────────┬────────────────────────┘
                        │
┌───────────────────────▼────────────────────────┐
│          Vue 3 Dashboard (实时显示)              │
│  事件表格 → 过滤器 → 统计面板 → 权限告警        │
└────────────────────────────────────────────────┘
```

## 采集事件类型

| 类别 | 事件 | 说明 |
|------|------|------|
| 进程 | `process_create` | 进程创建（fork/exec） |
| 进程 | `process_exit` | 进程退出 |
| 进程 | `privilege_escalation` | 权限提升（setuid等） |
| 网络 | `tcp_connect` | TCP出站连接 |
| 网络 | `tcp_accept` | TCP入站连接 |
| 网络 | `tcp_close` | TCP连接关闭 |
| 网络 | `udp_send` | UDP发送 |
| 网络 | `udp_recv` | UDP接收 |
| 文件 | `file_create` | 文件创建 |
| 文件 | `file_modify` | 文件修改 |
| 文件 | `file_delete` | 文件删除 |
| 文件 | `file_rename` | 文件重命名/移动 |
| 文件 | `file_chmod` | 权限修改 |
| 文件 | `file_chown` | 所有者修改 |

---

## 快速开始

### 环境要求

- Linux 内核 5.x+ (推荐 5.10+)
- clang/llvm (编译BPF程序)
- libbpf-dev
- libcurl-dev
- Go 1.21+
- Node.js 20+

### 1. 编译 Agent (C++)

```bash
cd agent
chmod +x build.sh
./build.sh
```

### 2. 编译前端

```bash
cd frontend
npm install
npm run build
```

### 3. 编译 Web Server (Go)

```bash
cd server
go mod tidy
go build -o ebpf-monitor-server .
```

### 4. 启动

```bash
# 启动 Web Server
./server/ebpf-monitor-server --port 8000

# 启动 Agent (需要root权限)
sudo ./agent/build/ebpf-monitor-agent -s http://localhost:8000
```

### 5. 访问

打开浏览器访问 http://localhost:8000

---

## Agent 命令行参数

```
Usage: ebpf-monitor-agent [OPTIONS]

Options:
  -s, --server URL       Web服务器地址 (默认: http://localhost:8000)
  -e, --events TYPES     事件类型: process,network,file (默认: 全部)
  -b, --batch-size N     每批事件数 (默认: 100)
  -f, --flush-ms MS      刷新间隔毫秒 (默认: 100)
  -l, --log-file PATH    日志文件路径 (默认: 仅控制台)
  -L, --log-level LEVEL  日志级别: trace/debug/info/warn/error (默认: info)
  -v, --verbose          快捷方式，等同于 --log-level debug
  -h, --help             帮助信息
```

### 日志系统

日志级别: `TRACE` < `DEBUG` < `INFO` < `WARN` < `ERROR` < `FATAL`

- 控制台输出带颜色高亮 (WARN=黄色, ERROR=红色, 权限提升=红色)
- 文件输出支持自动轮转 (默认 50MB/文件, 保留 5 个备份)
- 格式: `[2024-01-15 14:30:22.123] [INFO ] [main:143] Message here`
- `DEBUG` 级别会输出每个采集事件的详细信息

```bash
# 仅控制台，INFO级别
sudo ./ebpf-monitor-agent -s http://localhost:8000

# DEBUG级别，同时写入日志文件
sudo ./ebpf-monitor-agent -s http://localhost:8000 -L debug -l /var/log/ebpf-agent.log

# 仅记录WARN及以上级别到文件
sudo ./ebpf-monitor-agent -s http://localhost:8000 -L warn -l /var/log/ebpf-agent.log
```

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/events` | 接收事件（Agent上报） |
| GET | `/api/events?category=X&type=Y&pid=Z` | 查询事件 |
| GET | `/api/stats` | 获取统计信息 |
| WS | `/ws` | WebSocket实时事件流 |

## Docker 部署

```bash
# 仅Web Server可容器化部署
docker build -f Dockerfile.server -t ebpf-monitor-server .
docker run -p 8000:8000 ebpf-monitor-server

# Agent必须在宿主机上运行
sudo ./ebpf-monitor-agent -s http://<server-ip>:8000
```

---

## 项目结构

```
ebpf-monitor/
├── agent/                         # C++ eBPF采集端
│   ├── bpf/                       # eBPF内核程序 (C语言)
│   │   ├── vmlinux.h              # 内核类型定义 (bpftool生成)
│   │   ├── process_monitor.bpf.c  # 进程事件采集
│   │   ├── network_monitor.bpf.c  # 网络事件采集
│   │   └── file_monitor.bpf.c     # 文件事件采集
│   ├── src/                       # 用户态程序 (C++17)
│   │   ├── main.cpp               # 入口、CLI解析、信号处理
│   │   ├── ebpf_loader.h/.cpp     # BPF程序加载与附加
│   │   ├── event_reader.h/.cpp    # 事件读取与分发
│   │   ├── event_sender.h/.cpp    # 事件序列化与HTTP上报
│   │   ├── event_types.h          # 事件结构体与枚举定义
│   │   ├── container_utils.h/.cpp # 容器环境检测
│   │   └── logger.h/.cpp          # 日志系统
│   ├── CMakeLists.txt             # CMake构建配置
│   └── build.sh                   # 一键编译脚本
├── server/                        # Go Web服务器
│   ├── main.go                    # 入口、路由、中间件
│   ├── handler/
│   │   ├── events.go              # 事件API处理器
│   │   └── websocket.go           # WebSocket连接管理
│   ├── model/
│   │   └── event.go               # 事件模型与存储
│   └── go.mod                     # Go模块定义
├── frontend/                      # Vue 3 前端
│   ├── src/
│   │   ├── App.vue                # 根组件、布局
│   │   ├── main.ts                # Vue应用入口
│   │   ├── env.d.ts               # TypeScript声明
│   │   ├── types/
│   │   │   └── event.ts           # 事件类型定义、颜色、标签
│   │   ├── composables/
│   │   │   └── useWebSocket.ts    # WebSocket连接管理
│   │   └── components/
│   │       ├── StatsBar.vue       # 统计面板
│   │       ├── EventFilter.vue    # 事件过滤器
│   │       └── EventTable.vue     # 事件表格
│   ├── index.html                 # HTML入口
│   ├── package.json               # npm依赖
│   ├── vite.config.ts             # Vite构建配置
│   ├── tsconfig.json              # TypeScript配置
│   └── tsconfig.node.json         # Node端TS配置
├── docker-compose.yml             # Docker编排
├── Dockerfile.server              # 服务器镜像
├── Dockerfile.agent               # Agent镜像(参考)
└── README.md                      # 本文件
```

---

## 文件与函数详细说明

### 一、eBPF 内核程序 (`agent/bpf/`)

#### `vmlinux.h`

内核类型定义头文件。在生产环境中由 `bpftool btf dump file /sys/kernel/btf/vmlinux format c` 自动生成。提供 eBPF 程序所需的内核数据结构定义（`task_struct`、`sock`、`dentry`、`inode` 等）以及 `pt_regs` 寄存器访问宏。

#### `process_monitor.bpf.c` — 进程事件采集

| 挂载点 | 类型 | 说明 |
|--------|------|------|
| `tracepoint/sched/sched_process_fork` | tracepoint | 进程创建，捕获 pid、ppid、uid、comm |
| `tracepoint/sched/sched_process_exec` | tracepoint | 进程执行，捕获可执行文件路径；检测 uid 变化触发权限提升事件 |
| `tracepoint/sched/sched_process_exit` | tracepoint | 进程退出，捕获退出码 |

关键函数:
- `tracepoint__sched__sched_process_fork()` — 新进程创建时填充 `ProcessEventRaw`，记录 uid 到 `exec_uid_map` 供后续比对
- `tracepoint__sched__sched_process_exec()` — 进程 exec 时读取文件名，比对 `exec_uid_map` 中的旧 uid，若变化则发送 `PRIV_ESC` 事件
- `tracepoint__sched__sched_process_exit()` — 仅主线程退出时上报，读取 `task->exit_code`，清理 uid 追踪

BPF Maps:
- `process_events` — `PERF_EVENT_ARRAY`，向用户态发送事件
- `process_event_heap` — `PERCPU_ARRAY`，临时事件存储（避免栈溢出）
- `exec_uid_map` — `HASH`，追踪进程 uid 用于提权检测

#### `network_monitor.bpf.c` — 网络事件采集

| 挂载点 | 类型 | 说明 |
|--------|------|------|
| `kprobe/tcp_v4_connect` | kprobe | TCP连接发起，记录源地址 |
| `kretprobe/tcp_v4_connect` | kretprobe | TCP连接结果 |
| `kprobe/tcp_set_state` | kprobe | TCP状态变为ESTABLISHED时记录完整四元组 |
| `kretprobe/inet_csk_accept` | kretprobe | TCP入站连接接受 |
| `kprobe/tcp_close` | kprobe | TCP连接关闭 |
| `kprobe/udp_sendmsg` | kprobe | UDP发送 |
| `kretprobe/udp_recvmsg` | kretprobe | UDP接收 |

关键函数:
- `fill_network_event()` — 通用填充函数，从 `bpf_get_current_pid_tgid()` 获取 pid，从 `sock->__sk_common` 读取 IP/端口
- `kprobe__tcp_set_state()` — 仅在 `TCP_ESTABLISHED` 状态转换时触发，获取完整源/目地址四元组
- `kprobe__tcp_close()` — 跳过无实际连接（saddr/daddr 均为 0）的情况

BPF Maps:
- `network_events` — `PERF_EVENT_ARRAY`
- `network_event_heap` — `PERCPU_ARRAY`
- `sock_info_map` — `HASH`，kprobe/kretprobe 配对时传递 socket 信息

#### `file_monitor.bpf.c` — 文件事件采集

| 挂载点 | 类型 | 说明 |
|--------|------|------|
| `tracepoint/syscalls/sys_enter_openat` | tracepoint | 文件打开，仅捕获带 `O_CREAT` 标志的（文件创建） |
| `tracepoint/syscalls/sys_enter_unlinkat` | tracepoint | 文件删除 |
| `kprobe/vfs_rename` | kprobe | 文件重命名/移动，构建旧/新路径 |
| `kprobe/security_inode_setattr` | kprobe | 权限/所有者变更，检查 `ATTR_MODE`/`ATTR_UID`/`ATTR_GID` |
| `kprobe/vfs_write` | kprobe | 文件写入，跳过 <16 字节写入和非常规文件 |

关键函数:
- `fill_file_event()` — 通用填充，设置时间戳、pid、uid、cgroup_id
- `get_dentry_name()` — 从 dentry 读取文件名字符串
- `kprobe__vfs_rename()` — 从 old_dentry/new_dentry 构建完整路径（父目录名 + "/" + 文件名）
- `kprobe__security_inode_setattr()` — 通过 `attr->ia_valid` 判断是 chmod 还是 chown
- `kprobe__vfs_write()` — 通过 `S_ISREG(mode)` 过滤非常规文件，写入字节数存入 `flags` 字段

---

### 二、C++ 用户态 Agent (`agent/src/`)

#### `event_types.h` — 事件类型定义

定义整个系统的核心数据结构，是 BPF 程序与用户态之间的桥梁。

枚举:
- `EventCategory` — 事件大类：PROCESS(1)、NETWORK(2)、FILE(3)
- `ProcessEventType` — 进程事件子类型：CREATE(1)、EXIT(2)、PRIV_ESC(3)
- `NetworkEventType` — 网络事件子类型：TCP_CONNECT(10)、TCP_ACCEPT(11)、TCP_CLOSE(12)、UDP_SEND(20)、UDP_RECV(21)
- `FileEventType` — 文件事件子类型：CREATE(30)~CHOWN(35)

原始结构体（与 BPF 程序一一对应）:
- `ProcessEventRaw` — 832 字节，含 timestamp、pid、ppid、uid、gid、comm[16]、filename[256]、args[512]
- `NetworkEventRaw` — 48 字节，含 IP 地址（网络字节序）、端口、协议号
- `FileEventRaw` — 548 字节，含新旧文件名、mode、flags

富化结构体:
- `Event` — 用户态使用的事件，含 std::string 字段、容器信息、网络地址（已转换为点分十进制）

转换函数:
- `from_raw(ProcessEventRaw)` — 原始进程事件 → Event
- `from_raw(NetworkEventRaw)` — 原始网络事件 → Event，inet_ntop 转换 IP
- `from_raw(FileEventRaw)` — 原始文件事件 → Event

工具函数:
- `event_type_name(cat, type)` — 返回事件类型的字符串名称（如 "tcp_connect"）
- `category_name(cat)` — 返回类别名称（"process"/"network"/"file"）

#### `logger.h` / `logger.cpp` — 日志系统

单例模式的线程安全日志系统，支持控制台彩色输出和文件轮转。

类 `Logger`:

| 方法 | 说明 |
|------|------|
| `instance()` | 获取全局单例 |
| `set_level(LogLevel)` | 设置最低日志级别 |
| `set_console(bool)` | 启用/禁用控制台输出 |
| `set_file(path, max_size, max_files)` | 设置日志文件路径、轮转大小（默认50MB）、备份数（默认5） |
| `set_module(name)` | 设置当前模块名（显示在日志中） |
| `log(level, file, line, fmt, ...)` | 通用日志方法 |
| `trace/debug/info/warn/error/fatal()` | 各级别便捷方法 |
| `should_log(level)` | 检查是否应输出该级别（避免无用的字符串构造） |
| `level_name(level)` | 级别枚举 → 字符串 |
| `parse_level(string)` | 字符串 → 级别枚举 |

内部方法:
- `write()` — 实际写入，控制台带 ANSI 颜色（TRACE=灰、DEBUG=青、INFO=绿、WARN=黄、ERROR=红、FATAL=品红）
- `rotate_if_needed()` — 文件超过 max_size 时轮转：`.1` → `.2` → ... → `.5`（删除最旧）
- `format_time()` — 格式化为 `YYYY-MM-DD HH:MM:SS.mmm`
- `extract_filename()` — 从完整路径提取文件名

便捷宏:
- `LOG_TRACE/DEBUG/INFO/WARN/ERROR/FATAL(fmt, ...)` — 自动填充 `__FILE__` 和 `__LINE__`
- `LOG_MODULE(name)` — 设置模块名
- `LOG_SHOULD(level)` — 级别检查（用于避免昂贵的日志消息构造）

#### `ebpf_loader.h` / `ebpf_loader.cpp` — BPF 程序加载器

封装 libbpf 的 BPF 对象加载和程序附加逻辑。

结构体 `BpfProgramInfo`:
- `name` — BPF 程序名称
- `prog_fd` — 文件描述符
- `link` — 附加链接指针

类 `EbpfLoader`:

| 方法 | 说明 |
|------|------|
| `load_object(path)` | 加载 .bpf.o 文件：`bpf_object__open()` → `bpf_object__load()` → 枚举所有程序 |
| `attach_all()` | 自动附加所有程序：根据 section 名判断类型，tracepoint 用 `bpf_program__attach_tracepoint()`，kprobe 用 `bpf_program__attach_kprobe()` |
| `get_perf_buffer_fd(map_name)` | 获取 perf event array 的 fd |
| `cleanup()` | 销毁所有 link 和 object |
| `has_btf()` | 静态方法，检查 `/sys/kernel/btf/vmlinux` 是否存在 |

内部函数:
- `libbpf_print_fn()` — libbpf 日志回调，将 libbpf 输出接入 Logger（WARN/INFO/DEBUG 分级）

#### `event_reader.h` / `event_reader.cpp` — 事件读取器

从 BPF perf buffer 读取事件，富化后分发给回调函数。

类 `EventReader`:

| 方法 | 说明 |
|------|------|
| `add_perf_buffer(loader, map_name, category)` | 注册一个 perf buffer，记录 map_fd 和事件类别 |
| `start(callback)` | 创建 perf_buffer 实例，启动轮询线程 |
| `stop()` | 停止线程，释放 perf_buffer |
| `get_events_read()` | 返回已读取事件计数 |
| `get_events_lost()` | 返回丢失事件计数 |

私有方法:
- `reader_thread()` — epoll 轮询循环，每个 perf buffer poll 100ms 超时
- `handle_process_event()` — 解析 ProcessEventRaw → Event，调用容器识别，DEBUG 级别格式化日志
- `handle_network_event()` — 解析 NetworkEventRaw → Event，日志格式含 `TCP src:port → dst:port`
- `handle_file_event()` — 解析 FileEventRaw → Event，rename 事件显示 `old → new`，chmod 显示八进制 mode

回调函数（静态）:
- `process_event_cb()` / `network_event_cb()` / `file_event_cb()` — perf_buffer 回调，转发到对应 handle 方法
- `lost_events_cb()` — 丢失事件回调，WARN 级别日志

#### `event_sender.h` / `event_sender.cpp` — 事件上报器

将事件批量序列化为 JSON，通过 HTTP POST 发送到 Web 服务器。

类 `EventSender`:

| 方法 | 说明 |
|------|------|
| `enqueue(event)` | 将事件加入发送缓冲区，达到 batch_size 时唤醒发送线程 |
| `start()` | 启动发送线程 |
| `stop()` | 停止线程，刷新剩余事件 |
| `get_events_sent()` | 返回已发送事件计数 |
| `get_send_errors()` | 返回发送错误计数 |

私有方法:
- `sender_thread()` — 等待缓冲区满或 flush_interval 超时，批量发送；失败时重新入队（上限 10000）
- `serialize_events()` — 将 Event 数组序列化为 JSON 数组字符串，按类别输出不同字段
- `send_batch()` — libcurl POST 到 `/api/events`，5秒超时

工具函数:
- `json_escape()` — JSON 字符串转义（引号、反斜杠、控制字符）
- `write_callback()` — libcurl 响应回调（丢弃响应体）

#### `container_utils.h` / `container_utils.cpp` — 容器检测

通过读取 `/proc/{pid}/cgroup` 识别进程是否运行在容器中。

结构体 `ContainerInfo`:
- `id` — 容器 ID（短哈希，12 位）
- `name` — 容器名称（从 hostname 或环境变量读取）
- `runtime` — 运行时类型（docker/containerd/crio/podman/lxc）
- `is_container` — 是否为容器进程

类 `ContainerUtils`:

| 方法 | 说明 |
|------|------|
| `get_container_info(pid)` | 获取容器信息（带缓存） |
| `clear_cache()` | 清除缓存 |

私有方法:
- `parse_cgroup(pid)` — 解析 `/proc/{pid}/cgroup`，按 cgroup 路径特征识别运行时：
  - `/docker/{id}` → Docker
  - `/cri-containerd-{id}` → containerd
  - `/kubepods/.../{id}` → Kubernetes
  - `/crio-{id}` → CRI-O
  - `/libpod-{id}` → Podman
  - `/lxc/{name}` → LXC
- `detect_container_name(pid, cgroup_path)` — 从 `/proc/{pid}/root/etc/hostname` 或 `/proc/{pid}/environ` 的 `HOSTNAME` 变量读取容器名
- `get_namespace_id(pid)` — 从 `/proc/{pid}/ns/mnt` 的 inode 号获取命名空间标识（LXC 使用）

#### `main.cpp` — 程序入口

| 函数 | 说明 |
|------|------|
| `main()` | 初始化日志、注册信号处理、加载 BPF 程序、启动 reader/sender、10 秒统计循环 |
| `signal_handler(sig)` | SIGINT/SIGTERM 处理，设置退出标志 |
| `print_usage(prog)` | 打印命令行帮助信息 |
| `parse_args(argc, argv)` | 解析 CLI 参数：-s/-e/-b/-f/-l/-L/-v/-h |
| `has_type(config, type)` | 检查配置中是否包含指定事件类型 |
| `find_bpf_object(name)` | 查找 .bpf.o 文件：相对二进制路径 → 当前目录 → /opt/ebpf-monitor/bpf/ |

数据流:
1. `main()` 解析参数，初始化 Logger（级别、文件、模块名）
2. 按配置的事件类型加载对应的 .bpf.o，附加到内核 hook 点
3. `EventReader::start()` 启动轮询线程，收到事件后回调：
   - 调用 `ContainerUtils` 识别容器环境
   - 调用 `EventSender::enqueue()` 入队
4. `EventSender` 后台线程按 batch_size/flush_interval 批量 POST 到 Web 服务器
5. 主线程每 10 秒输出统计（read/sent/lost/errors/速率）

---

### 三、Go Web 服务器 (`server/`)

#### `main.go` — 程序入口

| 函数/变量 | 说明 |
|-----------|------|
| `main()` | 解析 --port/--store-size 参数，初始化 EventStore、WSHub、EventHandler，配置 Gin 路由 |
| `corsMiddleware()` | CORS 中间件，允许所有来源（开发模式） |
| `staticFiles` | `//go:embed static/dist/*` 编译时嵌入前端静态文件 |

路由注册:
- `POST /api/events` → `EventHandler.PostEvents`
- `GET /api/events` → `EventHandler.GetEvents`
- `GET /api/stats` → `EventHandler.GetStats`
- `GET /ws` → `WSHub.HandleWebSocket`
- `GET /` → 返回 index.html
- `GET /assets/*` → 返回 Vite 构建的 JS/CSS/SVG
- `NoRoute` → SPA 回退到 index.html

#### `model/event.go` — 事件模型与存储

结构体 `Event`:
- 与 C++ Agent 的 JSON 字段一一对应
- `timestamp`、`category`、`event_type`、`pid`、`ppid`、`uid`、`gid`、`comm`、`container_id`、`container_name`
- 可选字段用 `omitempty`：`filename`、`old_filename`、`exit_code`、`mode`、`src_addr` 等

结构体 `Stats`:
- `total_events` — 总事件数
- `events_per_sec` — 事件速率
- `by_category` — 按类别统计
- `by_type` — 按类型统计
- `connected_clients` — WebSocket 连接数

结构体 `EventStore`（线程安全环形缓冲区）:

| 方法 | 说明 |
|------|------|
| `NewEventStore(capacity)` | 创建指定容量的存储 |
| `Add(e)` | 添加单个事件，超容量时淘汰最旧的 |
| `AddBatch(events)` | 批量添加 |
| `Query(category, type, pid, since, limit)` | 带过滤的查询，从新到旧返回 |
| `Stats(clientCount)` | 返回统计快照 |

#### `handler/events.go` — HTTP 事件处理器

结构体 `EventHandler`:
- 持有 `EventStore` 和 `WSHub` 引用

| 方法 | 说明 |
|------|------|
| `PostEvents(c)` | 接收 Agent 上报的 JSON 事件数组，存入 store，广播给所有 WS 客户端 |
| `GetEvents(c)` | 查询接口，支持 ?category=&type=&pid=&since=&limit= 过滤 |
| `GetStats(c)` | 返回统计信息 JSON |
| `HandleGetRecent(c)` | 返回最近 100 条事件（用于页面初始加载） |

#### `handler/websocket.go` — WebSocket 连接管理

结构体 `WSHub`:
- `clients` — 连接的客户端集合
- 线程安全（sync.RWMutex）

结构体 `WSClient`:
- `hub` — 所属 Hub
- `conn` — WebSocket 连接
- `send` — 发送缓冲 channel（256 容量）

| 方法 | 说明 |
|------|------|
| `NewWSHub()` | 创建 Hub |
| `ClientCount()` | 返回连接数 |
| `Broadcast(message)` | 向所有客户端广播，慢客户端直接跳过（非阻塞） |
| `HandleWebSocket(c)` | HTTP → WebSocket 升级，注册客户端，启动读写协程 |
| `readPump()` | 读协程：60 秒读超时，pong 时刷新超时，断开时从 Hub 移除 |
| `writePump()` | 写协程：从 send channel 读取消息，30 秒 ping 保活，批量发送排队消息 |

---

### 四、Vue 3 前端 (`frontend/`)

#### `src/main.ts` — 应用入口

创建 Vue 应用实例并挂载到 `#app`。

#### `src/App.vue` — 根组件

| 功能 | 说明 |
|------|------|
| 布局 | 顶部 Header → StatsBar → EventFilter → EventTable，flex 纵向排列 |
| WebSocket | 通过 `useWebSocket()` 组合式函数获取 events、stats、connected |
| 过滤器状态 | `ref<FilterState>` 管理类别、类型、PID、进程名、容器过滤 |
| 时钟 | 每秒更新 `currentTime` 显示 |

#### `src/types/event.ts` — TypeScript 类型定义

| 导出 | 说明 |
|------|------|
| `SecurityEvent` | 事件接口，与 Go Event 的 JSON 字段对应 |
| `EventStats` | 统计接口 |
| `EventCategory` | 联合类型 `'process' \| 'network' \| 'file'` |
| `EVENT_TYPE_LABELS` | 事件类型 → 中文标签映射 |
| `CATEGORY_COLORS` | 类别 → 颜色映射（进程蓝、网络绿、文件橙） |
| `EVENT_TYPE_COLORS` | 事件类型 → 颜色映射（权限提升=红色） |

#### `src/composables/useWebSocket.ts` — WebSocket 组合式函数

| 函数/变量 | 说明 |
|-----------|------|
| `events` | 响应式事件数组（最大 10000 条） |
| `stats` | 响应式统计数据 |
| `connected` | 连接状态 |
| `connect()` | 建立 WebSocket 连接，设置 onopen/onmessage/onclose/onerror |
| `scheduleReconnect()` | 指数退避重连（1s → 2s → 4s → ... → 30s 上限） |
| `fetchStats()` | 从 `/api/stats` 拉取统计 |
| `startStatsPolling()` | 每 3 秒轮询统计 |
| `disconnect()` | 关闭连接、清除定时器 |

消息处理:
- 支持批量消息（换行分隔的多条 JSON）
- 超过 10000 条时裁剪旧数据
- `onUnmounted` 时自动清理

#### `src/components/StatsBar.vue` — 统计面板

| 区域 | 说明 |
|------|------|
| 总事件数 | 大字体数字，超过 1K/1M 自动缩写 |
| 事件/秒 | 实时速率 |
| 三类别计数 | 进程(蓝)、网络(绿)、文件(橙) |
| 权限提升计数 | 红色高亮 |
| 连接状态 | 绿色圆点=已连接，红色=未连接 |

#### `src/components/EventFilter.vue` — 事件过滤器

| 过滤项 | 说明 |
|--------|------|
| 类别 | 三个 checkbox：进程/网络/文件 |
| 事件类型 | 下拉选择，选项随类别选择动态变化 |
| PID | 文本输入，精确匹配 |
| 进程名 | 文本输入，模糊匹配（toLowerCase） |
| 容器 | 文本输入，匹配 container_id 或 container_name |
| 清空按钮 | 清除所有已显示事件 |

状态通过 `watch` 实时 emit 给父组件。

#### `src/components/EventTable.vue` — 事件表格

| 功能 | 说明 |
|------|------|
| 表头 | 时间、类别、事件类型、PID、进程、详情、容器 |
| 行样式 | 左边框颜色按事件类型着色，新事件闪烁动画 |
| 权限提升行 | 红色背景 + 脉冲动画 |
| 时间格式 | `HH:MM:SS.mmm`（从纳秒时间戳转换） |
| 详情列 | 进程事件显示文件名；网络事件显示 `TCP src:port → dst:port`；文件 rename 显示 `old → new` |
| 容器列 | 有容器显示 ID/名称 badge，无容器显示 "HOST" |
| 自动滚动 | 新事件到达时滚动到顶部（可关闭） |
| 过滤 | computed 属性实时过滤，最多显示 5000 条 |
| 计数器 | 底部显示 `显示 X / Y 条事件` |

---

## 技术栈

| 组件 | 技术 | 说明 |
|------|------|------|
| 内核采集 | eBPF (C) | tracepoint + kprobe |
| 用户态 | C++17 + libbpf | 高性能事件处理 |
| 日志 | 自研 Logger | 6 级别、彩色控制台、文件轮转 |
| Web服务 | Go + Gin | REST API + WebSocket |
| 前端 | Vue 3 + Vite | 响应式实时UI |
| 通信 | HTTP JSON | 批量上报 |
| 容器检测 | /proc/cgroup | 支持 Docker/K8s/Podman/LXC/CRI-O |

## License

MIT
