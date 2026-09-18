# 验证记录 / Verification record

**English summary.** This tool was hardened by three rounds of independent adversarial
blind review performed by model families other than the one that wrote the code. Every
round found defects that self-testing had missed — including one where a "fix" from the
previous round covered only half the cases it claimed to. Each finding below is listed with
how it was reproduced, what changed, and how the fix was re-measured. A round-3 re-check was
still in flight when this repository was first published; its findings land as follow-up
commits. The author's own test suite is listed separately and is **not** counted as
independent verification.

---

## 方法

- 代码由编排席编写；**判定权交给另一个模型家族的审查者**，每轮盲检只看契约 + 代码 + 二进制，
  不接受"作者说测过了"。
- 每轮开工前把契约文件与源码 sha256 钉死；作者自测只算冒烟，不算通过。
- 每条发现都先**独立复现**再改；改完必须给出**新的实测数字**，不接受"应该修好了"。
- 二进制在真实 Windows 上跑，探针用 PowerShell 造真实 TCP 会话（对端用本机 LAN 地址，
  不依赖外网可达性）。

## 作者自测（不作为独立验证）

| 项 | 结果 |
|---|---|
| 构建 `cargo build --release`（x86_64-pc-windows-gnu） | 通过，无新增告警 |
| `amon --selftest` 纯逻辑断言 | **12/12 通过**，退出码 0 |
| 生命周期探针（v4 非回环两端 open/close、默认隐藏回环、`--conn-loopback` 可见、IPv6 `[::1]` open/ESTABLISHED/close、多套接字分组、监听面无回归） | **15/15 通过** |
| 旧版 `baseline.json`（无 `conn` 段）加载 | 通过（靠 `serde(default)`，首次轮询把现状各报一遍） |

## 第 1 轮盲检 — 结论 FIX

| # | 严重度 | 发现 | 复现 | 修复与复测 |
|---|---|---|---|---|
| A1 | **blocker** | `--conn-sec` 形同虚设：连接轮询被嵌在 `--poll` 分支内，任何比 `--poll` 小的采样间隔都被静默钳住 | `--conn-sec 2 --poll 30`：连接 18:18:03 建立，事件 18:18:30 才出现（落在 :00/:30 边界） | 提出为独立定时器。复测：连接 18:53:33.772 建立 → 事件 18:53:34（+0s），整轮 14.2s（旧代码下这一轮根本不会出事件） |
| A2 | non-blocker | `baseline.json` 从不回写会话段，升级后**每次重启**都重报一遍 | 去掉 `conn` 段后跑 watch，文件里 `"conn": {}` 一直不变 | 新增 `conn-state.json` sidecar 续接（原子写） |
| A3 | non-blocker | `::ffff:127.0.0.1` 能绕过回环过滤（`Ipv6Addr::is_loopback()` 只认 `::1`） | 本机无法造出 v4-mapped 套接字（审查者同样受限） | 加 `to_ipv4_mapped()` 判定，并把规则做成**二进制内可执行断言** |
| A4 | non-blocker | 取表失败与空表不可区分：失败会被当成"没有会话"，并伪造一堆 `conn_closed` | 代码级；真实 API 失败无法复现 | `Result<Vec<u8>, u32>` + `ConnSweep{complete,note,families}`：**不完整采样绝不参与差分**，状态翻转记一次 `meta/conn_fetch_incomplete` |
| A5 | tradeoff | 分组 key 含进程名，名字在 `?`/真名间抖动会伪造一对 close+open | 代码级 + sidecar 键形核对 | key 改为 `<pid>|<对端>`，进程名只留在 detail |
| A6 | deferred | pid 0 / 自己 pid 的过滤只做了代码级核对 | 无法按需造出 pid 0 行 | 保留为待办，如实标注 |

## 第 2 轮盲检 — 结论 FIX（打中第 1 轮的"修复"本身）

| # | 严重度 | 发现 | 复现 | 修复与复测 |
|---|---|---|---|---|
| B1 | **blocker** | 第 1 轮的续接只处理了"baseline 无 conn 段"这一种情况；普通格式 baseline 下 sidecar 被**忽略**，于是 baseline 之后建立、但上一轮已经报过的会话会在每次重启重复上报 | 压住两条套接字跨两个 watch 会话：`baseline.conn=18 / sidecar=21 / run2 opened=4`，其中 **3 条 key 早就在 sidecar 里**；对照组（conn 显式清空）反而正常 | 种子改为**按新旧取**（sidecar 优先，baseline 兜底），恢复事件带 `source` 字段。复测：`run2 opened=0`、`already-in-sidecar=0`、`resume {groups:17, source:"sidecar"}`、被压住的 key 未重复上报 |
| B1b | non-blocker（同一轮的补充） | sidecar 一会话只写一次会变陈旧 | 代码级 | 改为**变更即写、节流 15s**；如实记录残留窗口：硬杀最多丢 15s，这部分下次启动报一次 |
| B2 | deferred | 真实 `GetExtendedTcpTable` 失败仍未触发 | 审查者 churn 了 22,783 次表变化都没触发 | 保持"未实测"标注 |

### 该轮附带自查发现（作者自己的断言的错，不是产品错）

写二进制内断言时暴露出：`v6_endpoint` 的端口参数按契约是 **MIB 原始网络序**，而我的断言传了
host 序。生产调用一直是对的（真机 `[::1]:18483` 渲染正确），但这属于"契约没写下来"。现已
改名 `port_net_order` 并加断言「端口字节序只交换一次」。

### 损坏 sidecar 加固（同一轮顺带）

截断 JSON / 纯垃圾 / 合法 JSON 但值形状不对，三种都必须降级而非造假：全部回落 baseline
（`source: "baseline"`），不为伪造键产生事件，不崩。三种情形 **15/15 断言通过**。

## 第 3 轮盲检（复检 + 第二席）— 结论 SHIP

对第 2 轮修复的复检（审查者自己复现，不接受作者数字）：**SHIP**。

| 项 | 结果 |
|---|---|
| B1 种子按新旧（第 2 轮的 blocker） | **已核实修复**。它自建场景：3 条套接字跨两个 watch 会话（`--conn-sec 1 --poll 30`）→ 第二轮 `meta/conn_state_resumed {"groups":18,"source":"sidecar"}`、`conn_opened` 为 0、种子内的 key 无一条被重复上报；第一轮显示 `source:"baseline"` |
| B2 取表真实失败路径 | **仍未实测**（三次尝试、约 70 轮连接churn 未触发）。结构核对通过：有界三次重试 + `Err → complete=false` → 保留 `prev`、只记一次 meta、永不差分 |
| 契约 9 节奏 | 已复核（`--conn-sec 2 --poll 30`：open +0.3s、close +1.0s） |
| 契约 14/16 节流 | 已复核（变更 5s 一次的节奏下，sidecar 写入间隔 ≥15s） |
| 契约 8 只读 | 所有写入均为 `root.join(...)`，成立 |

### 新发现（非阻塞，但值得知道）：状态目录是被信任的

审查者构造了一个**形状完全合法**的 `conn-state.json`（键是 `pid|对端`、值是完整 JSON 对象），
里面全是**编造的**分组：amon 照单全收，于是产生

- 对从未存在过的键报 `conn_closed`（幽灵关闭）
- 若伪造的键和未来真实连接吻合，该连接会因为"种子已知"而**不再上报**（抑制）

严重度按非阻塞定级：能写 `--root` 的进程（同账号、同用户 profile）本来就能直接杀掉
监视器或改它的二进制，密码学在这里救不了。因此处理方式是**写进文档而不是写进代码**：
把 `--root` 放在被监视程序够不着的地方（独立账号 / 目录 ACL），并顺带监视 amon 自己。
见 README「已知限制」第 10 条。

### 另一条操作教训

评审过程中出现过"重复的 `conn_closed`"，经核查是**两个 watch 进程共用一个 root** 造成的
（其中一个是评审工具超时留下的），不是代码缺陷。已作为「一个 root 同一时间只跑一个 watcher」
写入 README 已知限制第 11 条。

### 第二席：forge（GLM 家族，与写者、红道三方跨脑）

forge **跑出了实质结果，但没来得及写结论**——它在自定义用例 C8a/…/C9 中途被我设的 1700s
上限杀掉。以下是从它的会话记录里逐条恢复的实测（不是它的自述，是它自己的命令输出）：

| 用例 | 它测什么 | 结果 |
|---|---|---|
| C2 | 硬杀留下的文档化缺口 | 套接字 20:31:17 建立 → 20:31:22 硬杀 → sidecar 里没有该键 → **下次启动重报 1 次**，**再下一次 0 次**。与契约 16 完全一致 |
| C6 | 抖动 | 25 秒内"键状态跃迁 ≥4 次"的键：**0**（无刷屏） |
| C7 | 干净重启 | opened=0 closed=0 |
| C8a | 空 sidecar | opened=0 closed=0 |
| E4 | pid-0 与自己 | `--conn-pid0` 下 pid-0 行=**0**；chmon 自身套接字=**0**（这条正是红道列为"无法验证"的契约 4 剩余部分） |
| — | 发布版 `amon.exe` | `--selftest` 14 行、**12/12 通过、exit 0** —— 对改名后的二进制独立确认 |
| C5 | **新发现** | 见下 |

### forge 的新发现（非阻塞）：换过滤条件 + sidecar 会冒出一批 `conn_closed`

它先用 `--conn-loopback` 跑（sidecar 里 76 组，其中 **55 组是回环**），再用**默认过滤**重启：
得到 `opened=0 closed=58`，其中 **55 条是回环组**——这些组在新过滤下根本不会被"打开"，
却因为"种子里有、当前采样里没有"被报成关闭。

即：第 3 条已知限制（换过滤刷屏）的**镜像**，而且方向更难看——不是多报一批 opened，
而是凭空多出一批 closed。修复方向已明确（在 sidecar 里记录过滤签名，签名不符则不作为种子并记一次 meta），
**尚未实现**，已写入 README 已知限制第 14 条。

### 红道 vs forge 在同一个用例上的冲突（已用独立实验裁定事实）

- 红道报"形状合法的伪造 sidecar 会产生幽灵 `conn_closed`"；
- forge 的 C8b 同一场景报 **0 条幽灵事件**。
- **我按红道的构造独立复现**：往 `--root` 放一个形状完全合法的伪造 `conn-state.json`
  （两个不存在的 `pid|对端`，值为完整 JSON 对象）→ `meta/conn_state_resumed {"groups":2,"source":"sidecar"}`
  → **恰好 2 条幽灵 `conn_closed`**（`evil.exe -> 203.0.113.7:443`、`evil2.exe -> 198.51.100.9:8443`）。
- 结论：**红道的构造成立**。forge 那个 0 我无法从它的残留输出里判定原因（它没留 evil seed 的写入路径与时机），
  因此标注为"该用例未复现"，而不是"forge 错了"。

### 第二席的另一位（chisel）仍然无产出

chisel（cursor-acp）第三次尝试仍未产出 verdict：它卡在"PowerShell 被此模式拦截"，
只能读到审计留下的证据，没能跑自己的活体攻击（它明确表示"不想借别人的判决"）。

## 限制 12/14 的修复（0.1.1）：持久化状态带上过滤签名

**动因**：第二席 forge 的 C5 用例——以 `--conn-loopback` 跑出的种子，配默认过滤重启时，
凭空冒出 58 条 `conn_closed`（55 条是回环组）。这不是漏报，是**发明**：那些会话在默认过滤下
不可能被"打开"。

**改法**：`conn-state.json` 与 baseline 的会话段都记录过滤签名
（`v1|loopback=…|pid0=…|families=…`）。签名不符、无法确定表面、或是旧格式（无签名）→
**不作为种子**，记一次 `meta/conn_seed_rejected`，代价是当次把当前会话各报一遍。
签名里的地址族来自"决定种子之前先做的一次采样"——因为族集合只有采样之后才知道。

**同一台真机上的前后对照**

| 场景 | 修复前 | 修复后 |
|---|---|---|
| 回环种子 + 默认过滤重启 | `opened=0 closed=58`（回环关闭 55 条） | `closed=2`，**回环关闭 0 条**，并记录 `conn_seed_rejected {groups:130, reason:"different or unknown surface"}` |
| 同表面重复重启 | 正常续接 | 仍正常续接（`conn_state_resumed {groups:37, source:"sidecar"}`），仅真实 churn（opened=3 closed=7） |
| 旧格式（纯 map）sidecar | 被信任 → 幽灵关闭事件 | 拒绝 → 伪造键 **0 条事件** |
| 旧 baseline（无 `conn_sig`） | 被信任 | 拒绝 + 一次重报（opened=32）+ 记录原因 |
| **连签名一起伪造**的 sidecar | 被信任 | **仍被信任**（1 条幽灵关闭）——签名不是密钥，这条限制成立并已写进 README 第 10 条 |

**回归**：`--selftest` 12/12 exit 0；生命周期探针（v4 非回环 / 回环 / IPv6 `[::1]`）全部通过。
二进制 sha256 `849a4dbba32f29fc986da00758b9e4b05cfe39642a867243d3d58a5b8631e5d7`。

## 第 4 轮盲检（对 0.1.1 签名门）— 两席独立 **SHIP**

两席都自建证据树、各自复跑，不借用作者的场景脚本：

| 席 | 结论 | 它自己做的 |
|---|---|---|
| audit（devin swe-2） | **SHIP** | 核验 4 个源文件与 exe 的 pin；在**自己的 root** 上跑 `sig-fix-test.ps1`（R1→R2 无回环伪造关闭，旧代码 55 条）；自建伪造用例（复制签名 → 1 条幽灵关闭，与文档量级一致）；`--conn-sec 0` 探针 |
| forge（GLM 家族，第二席） | **SHIP** | 自建 `bkr3`（6 用例）+ `bkr3v2`（5 用例 A–E）+ 四探针全部复跑；核验"rows 与 sig 取自同一次 sweep"（节流不拆散二者）；遗留 sidecar/baseline 路径；伪造限制与 `CHANGELOG.md` 记载**逐字一致**；只读性（root 外零写入） |

两席一致确认：**原缺陷（回环种子 + 默认过滤 → 伪造关闭）不再复现**，遗留文件走同一拒绝路径，
签名门是真实修复而非规避。未验证项（两席均如实列出）：真实 `rc!=0` 不完整采样、运行中地址族翻转、
IPv6-only 主机——都是"无法在本机注入"而非"没看"。

### 两席独立发现的非阻塞项（本轮已修，0.1.2）

1. `conn_seed_rejected` 对 sidecar 恒报 `groups: 0`（我传的是硬编码 0）→ 现在报**实际组数**。
2. 遗留文件、垃圾文件、换了表面的文件三者不可区分（同走 `OtherSurface`）→ 现在分成
   `different surface` / `legacy or corrupt file` / `unreadable or corrupt` / `surface unknown` 四种。
3. `--conn-sec 0` 仍会跑预采样、加载种子、写一行 `conn_state_resumed` → 现在关闭面时**完全不跑**、
   不写 sidecar、不记行。

### 两席提出的取舍（已写进 README 限制 14）

- 地址族不对称：IPv4 表任何错误 → `complete=false`，该轮不产会话事件；IPv6-only 主机等于没有会话面。
- IPv6 栈**瞬时**"不支持"被当作"本机没有 IPv6"，该轮 v6 组会被报成关闭——两席均**未能实测**，仅代码级判断。

### 本轮修复的验证强度

上述 0.1.2 的三项改动由**作者自测**（真机：遗留 map 2 组 → `legacy or corrupt file, groups: 2`；
截断非 JSON → `unreadable or corrupt`；新 root → 无行；`--conn-sec 0` → 无行/无 sidecar/零会话事件；
同表面重启 → `source: sidecar` 且零重报）。**这三项改动尚未经过独立盲检**——它们不改判定、只改日志措辞
与关闭态行为，故按非阻塞项处理并如实标注，而不是冒充"已复核"。
二进制 sha256 `547a11e27c7958cb…`。
