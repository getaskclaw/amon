# amon — 阿蒙：只读 Windows 变化监视器

[English](README.en.md)

amon 在旁路观察一个不受信任的 Windows 桌面程序：**只读、不注入、不改动目标**，把"它在我机器上改了什么、连了哪里"写成一条可按来源过滤的事件流，并在报告里如实标出盲区。

原始动机是一个第三方桌面程序的静默行为审计——Windows 默认不保留任何文件级的出网记录，事后无从查证；amon 的答案是：从当下开始，把可观测面尽量铺满，把看不到的部分明确写出来。

## 监视面

只有下面这些**真实发出事件**的来源：

| 来源 | 事件 | 机制 |
|---|---|---|
| `file` | `dir_changed` `created` `modified` `deleted` | `ReadDirectoryChangesW` 通知 + 定期 SHA-256 重扫（防漏通知） |
| `reg` | `key_changed` `added` `modified` `removed` | `RegNotifyChangeKeyValue`（用户态 Run/RunOnce/StartupApproved + HKLM 对应项） |
| `proc` | `started` `exited` | WMI 实时进程创建（`Win32_ProcessStartTrace`）+ Toolhelp 轮询；带映像路径与 ppid |
| `net` | `listen_started` `listen_changed` `listen_stopped` | `GetExtendedTcpTable`（监听表，IPv4） |
| `net` | `conn_opened` `conn_closed` | `GetExtendedTcpTable`（全表，IPv4 + IPv6），按 `(pid, 对端)` 分组 |
| `authdb` | `KEY_CHANGED` `key_appeared` | 只读复制后查询目标的登录库（默认是 Cursor 的 `state.vscdb`），只取键名与长度/短哈希，不回显明文 |
| `device` | `volume_event` | `CM_Register_Notification`（USB 卷到达） |
| `power` | `suspended` `resumed` | 电源广播通知 |
| `meta` | `watch_start` `heartbeat` `baseline_*` `conn_*` | 覆盖度与存活证明——"监视器还活着且在看着什么" |

> `task` 与 `svc` 两个来源在事件模型里已声明（`event.rs`），但**目前没有任何代码发出它们**。这是已知缺口，不是"已支持"。

## TCP 会话面

这是本仓库相对早期版本的重点：从"谁开了个端口"推进到"谁在跟谁说话"。

- **分组，而不是逐行**：key 是 `<pid>|<对端>`。一个浏览器握着 21 个到同一对端的 keep-alive 套接字，是**一条**事件，detail 里 `sockets: 21`。逐套接字上报会让日志变成没有针的草堆。
- **不把残留当会话**：`LISTEN`（监听面的事）、`CLOSED`、`TIME_WAIT`、`DELETE_TCB` 不算会话；`FIN_WAIT1/2`、`CLOSE_WAIT` 算（半关闭的套接字还能发数据）。
- **过滤显式**：回环对端默认隐藏（`--conn-loopback` 打开，本地代理很吵且不说明出网）；pid 0 默认隐藏（`--conn-pid0`）；**永不汇报自己**。
- **只报出现与消失**：套接字数量或状态字符串的变化不产生事件——那会每次轮询都刷屏。数量仍在 detail 里，下一次真实跃迁会带上它。
- **取表失败 ≠ 空表**：读不出来的采样**绝不参与差分**（否则每个没看见的分组都会被伪造成 `conn_closed`），状态翻转时记一次 `meta/conn_fetch_incomplete`；系统报告某地址族不存在（如 IPv6 被禁用）算"面更小"，记一次 `meta/conn_surface_partial`。
- **重启续接**：`baseline.json` 里的 `conn` 段 + `conn-state.json` sidecar（变更即写、节流 15s）。恢复时按**新旧**取种子——sidecar 优先于可能很旧的 baseline——并记 `meta/conn_state_resumed {groups, source}`。

事件样例（`events.jsonl` 一行一条）：

```json
{"ts":"2026-09-18T10:53:34+00:00","local":"2026-09-18 18:53:34","src":"net","action":"conn_opened",
 "target":"chrome.exe -> 127.0.0.1:10808",
 "detail":{"pid":33068,"proc":"chrome.exe","remote":"127.0.0.1:10808","sockets":21,
           "states":["ESTABLISHED"],"locals":["127.0.0.1:10164","127.0.0.1:10266"],"localsOmitted":15}}
```

## 快速开始

需要 Rust 工具链（Windows 原生或从 WSL 交叉编译，见文末）。

```powershell
cargo build --release          # Windows 原生（MSVC）
# 从 WSL 交叉编译见文末

# 0) 先验逻辑：12 项纯逻辑断言，失败会非零退出
.\target\release\amon.exe --selftest --root D:\amon-state

# 1) 打基线（记录"开始观察之前就存在的东西"，避免首次轮询把现状全报一遍）
.\target\release\amon.exe --baseline --root D:\amon-state

# 2) 持续观察
.\target\release\amon.exe --watch --root D:\amon-state

# 3) 取增量报告（只报上次报告之后的新事件）
.\target\release\amon.exe --report --root D:\amon-state
```

`--report` 产出一份中文 Markdown（`report.md`）：覆盖度、高信号事件、全部新增事件。

## 命令行

| 模式 | 说明 |
|---|---|
| `--baseline` `-b` | 采集当前状态写入 `baseline.json` |
| `--watch` `-w` | 持续运行，追加到 `events.jsonl` |
| `--report` `-r` | 输出/收集上次报告以来的新事件 |
| `--selftest` | 写一条合成事件，并运行纯逻辑断言 |

| 选项 | 默认 | 说明 |
|---|---|---|
| `--root <DIR>` | `%LOCALAPPDATA%\amon` | 状态目录（唯一会被写入的地方） |
| `--poll <SEC>` | 5 | 监听表 / 慢快照间隔 |
| `--proc-sec <S>` | 1 | 进程创建轮询间隔 |
| `--conn-sec <S>` | 5 | TCP 会话采样间隔（`0` = 关闭）；**独立于 `--poll`** |
| `--conn-loopback` | 关 | 包含回环对端 |
| `--conn-pid0` | 关 | 包含 pid 0 行 |
| `--file-sec <S>` | 60 | 文件重扫安全网间隔 |
| `--auth-sec <S>` | 60 | 登录库检查间隔 |
| `--heartbeat-sec <S>` | 300 | 存活心跳间隔 |
| `--quiet` `-q` | 关 | 抑制非必要输出 |

## 状态目录

默认 `%LOCALAPPDATA%\amon`，用 `--root` 覆盖：

| 文件 | 内容 |
|---|---|
| `baseline.json` | 基线快照（进程 / 文件 / 注册表 / 监听 / 会话 / 登录库键） |
| `events.jsonl` | 追加式事件流；超过 32MB 轮转为 `events.<时间戳>.jsonl` |
| `conn-state.json` | 会话面 sidecar，供重启续接（原子写：临时文件 + rename） |
| `report-cursor.json` | 报告游标（上次报了多少行） |
| `report.md` | 最近一次 `--report` 的 Markdown 报告（中文） |

## 适配你自己的目标

默认监视目标写在 `src/main.rs` 的 `Config::load` 里三处：

- `install_dirs`：被监视的程序目录（文件通知 + 重扫）
- `watched_procs`：进程名片段（进程事件与"高信号"过滤都按它匹配）
- `auth_db` / `auth_keys`：登录库路径与要盯的键名

出厂默认对应 Cursor 的一个第三方辅助程序，是本工具的原始用途。**把这三处改成你的目标**即可复用其余全部机制。把它们做成 CLI 参数尚未实现（见下）。

## 已知限制（诚实清单）

1. **轮询看不到比间隔更短的会话**：短于 `--conn-sec` 的连接可能整体漏掉（无 open、无 close）。这是轮询的固有代价，不是配置问题。
2. **本机↔本机会话会出现两条事件**（两端套接字各一条）。
3. **换过滤条件却不重打基线会刷屏**：默认基线 + `--conn-loopback` 实测一次冒出上百条；sidecar 能把它压到"差值"，但换过滤本身仍应重打基线。
4. **升级后的第一次运行**会把当时存在的所有会话各报一遍（之后靠 sidecar 续接，不再重复）。
5. **无权限打开的 pid** 会显示 `proc: "?"`（以管理员运行更完整）。
6. **监听面仍是 IPv4-only**，会话面才是 v4+v6。
7. **硬杀最多丢 15s 的 sidecar 更新**，那部分会话下次启动会报一次（节流窗口，见 `CONN_SIDECAR_MIN_SECS`）。
8. **取表真实失败路径未实测**：本机用 2 万多次表变化也没能触发 `GetExtendedTcpTable` 失败，该分支只有代码级保证（可用 `meta/conn_fetch_incomplete` 观测）。
9. **32MB 以上不做内容哈希**：`snapshot.rs` 里超过 32MB 的文件记为 `sha256=BIG_<size>`，
   只有路径、精确字节数和 mtime。盯"几百 MB 的快照"仍然醒目，但没有内容指纹。
10. **状态目录是被信任的**：`--root` 下的 `conn-state.json` 只做**形状**校验，不验真伪。
   能写这个目录的进程可以塞入伪造的分组，从而制造不存在的 `conn_closed`、或让某个未来的
   `conn_opened` 因为"早就在种子"而不再上报。同账号的恶意程序本来就能杀掉监视器本身，
   所以这不是加密能解决的问题——**把 `--root` 放在被监视程序够不着的地方**（独立账号/目录 ACL）
   才是正解，并顺带盯住 amon 自己。注意过滤签名**不是密钥**：它能挡住"换过滤"这类事故，
   挡不住照着格式伪造（实测：连签名一起伪造的 sidecar 仍会被信任并产生 1 条幽灵关闭事件）。
11. **一个 root 同时只能跑一个 watcher**：两个进程共用一个 root 会互相追加 `events.jsonl`、
   争抢 `conn-state.json`，产生看似重复的事件（评审中实际踩到过）。
12. **换过滤条件后会重报一次现状**：sidecar 与 baseline 的会话段都记录**过滤签名**
   （`v1|loopback=…|pid0=…|families=…`）。签名不符就不作为种子，并记一次
   `meta/conn_seed_rejected`，代价是当次把当前存在的会话各报一遍（一次性、诚实）。
   这一条替换掉了早先的行为：以 `--conn-loopback` 跑出的种子配默认过滤时，曾凭空冒出
   58 条 `conn_closed`（其中 55 条是回环组）——那些会话在本轮过滤下根本不可能被"打开"。
   **该缺陷已修复并实测复现。**
   旧格式（无签名）的 sidecar/baseline 一律不信任，同样是一次性重报。
13. 报告文本为中文；`task` / `svc` 两个来源尚未发射事件。
14. **地址族不对称**：IPv6 表读不到（rc 50/87）会优雅降级成只用 IPv4，但 IPv4 表**任何**错误都会让
   本轮 `complete=false` 并永久不产会话事件（保守方向：宁沉默、不编造）。IPv6-only 主机等于没有会话面。
   另外，IPv6 栈**瞬时**返回"不支持"会被当作"本机真的没有 IPv6"，那种情况下 v6 组会被报成关闭
   （未实测，本机无法注入该错误）。
15. **`conn_seed_rejected` 会说明原因**：`different surface`（换了过滤条件）/`legacy or corrupt file`
   （旧格式或垃圾文件，附实际组数）/`unreadable or corrupt`（读不出来或不是 JSON）/
   `surface unknown`（首次采样不完整）。缺文件**不**记行——新目录不该刷屏。
16. **baseline 的陈旧签名不会自愈**：换过滤条件后，每次启动都会各记一行拒绝（baseline 一行、sidecar 一行），
   直到重新跑 `--baseline`。这是**有意的**——它在持续告诉你"这份基线对这个表面不可用"，
   而不是只提一次然后让你以为没问题。
17. **baseline.json 与 sidecar 同级可信**：它的会话行不做逐行形状过滤，手改 baseline 可以注入
   一对 open+close（与限制 10 同源：能写 `--root` 的人本来就能改 events）。另有一个纯观感项：
   极小概率下（rename 覆盖目录失败）会留下一个内容有效的孤儿 `conn-state.json.tmp`。
18. **未自带常驻方式**：想长期运行请自行注册计划任务，例如（管理员）：
    ```powershell
    $a = New-ScheduledTaskAction -Execute 'D:\tools\amon.exe' -Argument '--watch --root D:\amon-state --quiet'
    Register-ScheduledTask -TaskName amon -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) -RunLevel Highest
    ```

## 只读保证

代码里没有任何路径以写方式打开被监视目标；注册表用 `KEY_READ`，进程用
`PROCESS_QUERY_LIMITED_INFORMATION`，登录库**先复制再查询**。唯一的写入发生在
`--root` 之下。

## 验证

- `amon --selftest`：12 项纯逻辑断言（状态分类、分组身份、IPv6 端点渲染含 scope 与
  v4-mapped、回环分类、端口字节序只交换一次），逐条打印，失败非零退出。这是最快的一条命令。
- `scripts/` 下的探针脚本，在真实 Windows 上跑，不依赖外网（用本机 LAN 地址当对端）：
  - `probe-conn-lifecycle.ps1`：v4 非回环的 opened/closed 两端、默认隐藏回环、`--conn-loopback` 可见、IPv6 `[::1]` open/ESTABLISHED/close、多套接字分组、监听面无回归
  - `probe-conn-cadence.ps1`：`--conn-sec 2 --poll 30` 下事件必须按 2s 节奏出现（这条曾真实暴露过一个 blocker：连接轮询被嵌在 `--poll` 分支里，参数形同虚设）
  - `probe-conn-resume.ps1`：两个 watch 会话共用一个 root，跨会话保持的套接字在第二轮**不得**被重复上报
  - `probe-conn-baseline-compat.ps1`：旧版 `baseline.json`（无 `conn` 段）必须能加载
- 开发过程中做了三轮独立对抗式盲检（审查者与写者不是同一个模型家族），每一轮都挖出真缺陷并逐一复现、修复、复测，记录见 [VERIFICATION.md](VERIFICATION.md)。

## 构建

**Windows 原生（MSVC）**：`cargo build --release`（需要 Rust + VC 工具链）。

**从 WSL/Linux 交叉编译**（`x86_64-pc-windows-gnu` 目标，需 `mingw-w64`）：

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
# 产物：target/x86_64-pc-windows-gnu/release/amon.exe
```

`.cargo/config.toml` 里固定了 gnu 目标的 linker/ar（**没有**设置默认 target，因此
Windows 原生 `cargo build` 保持按宿主目标构建）。

**注意**：本 crate 面向 Windows API，**不为 Linux 编译**（`--target x86_64-unknown-linux-gnu` 会因缺少 `windows` 绑定而失败）；因此纯逻辑断言通过 `--selftest` 在 Windows 上执行，CI 也跑在 `windows-latest`。

## 许可

MIT，见 [LICENSE](LICENSE)。
