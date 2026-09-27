# PR #222 CNB 性能验收：资源门槛检查点

**状态：BLOCKED_RESOURCE_LIMIT_EVIDENCE。** 这是环境阻塞记录，不是性能 PASS 或业务 FAIL；没有启动 A/B 负载。

## 固定版本

- A（基线生产源码）：`0c70d7464576138af0b3f8a39530d6615ee7a363`
- B（候选生产源码）：`462626b29be202c04f2e4482ade6ab5f5f6267c5`
- H（两组共同 harness）：`462626b29be202c04f2e4482ade6ab5f5f6267c5`
- 固定任务书：`346382e4dee4f3009813d603d8b8d589f166fc27`，SHA256 `7c5bc3c4ea6b509d9d7228f816cd93c092549a046e02f42a5345d697d2cb46e0`
- PR 分支原先从 B 前进到上述任务书提交；核对结果只有该任务书文档，不含新的候选生产代码。

## 环境证据（2026-09-26 22:02:53 UTC）

- CPU 型号报告为 AMD EPYC 9K65，拓扑为 192 个逻辑 CPU、96 个物理核、每核 2 个 SMT 线程。SSH 进程 affinity mask 是 `24-56,161-191`（64 个 ID），但内核在线 CPU 只有 `0-63`；与 mask 相交后是 `24-56`（33 个在线逻辑 CPU，17 个可见物理核组：16 组有两个在线 SMT 线程、1 组只有一个）。可见 cgroup v1 CPU quota 为 `6,400,000 / 100,000 = 64` CPU，采样时 `nr_throttled=0`。
- 当前可见 memory cgroup 上限 128 GiB，使用 10,525,335,552 bytes；该叶子 cgroup 的可见剩余为 126,913,617,920 bytes。`MemAvailable` 为 134,055,468 KiB。
- 固定 B 的 `.cnb.yml` 声明 `runner.cpus: 64`（SHA256 `c25e926e26930bd7734548d07901bf136fc0a00773333c2a2f2f1e227765177a`），与 leaf quota 一致；该配置不暴露父级 cgroup 的实际值。
- Docker Engine 报告 64 CPU、597,651,193,856 bytes 总内存，版本 29.6.2-7、cgroup driver `none`。工作区盘可用约 496G、Docker 数据盘可用约 256G（`df -h` 输出）。
- Python 3.11.2、Compose 5.3.1、k6 2.1.0、GCC 12.2.0 可用；静态链接能力探针成功；原始输出在 CNB `/tmp/pr222-acceptance-kMhxkB/evidence/static-link-probe.log`，SHA256 `87b8ede575fa3470e7d5a8b06ef8f7d429f166ef607cfe5f4f8003398ec0d90b`。
- Docker 上原先已有其他 `pr222-*` 服务，未触碰。该任务的独占 compose project 尚未启动。

## 阻塞原因

`/proc/self/mountinfo` 显示 cgroup 控制器挂载的根是当前 CNB cgroup，父级层次不可读。Docker daemon 的总资源信息也不能证明 CNB 父级 quota。SSH 环境没有可用的 CNB 元数据 CLI 或公开的父级限制变量，因此无法按任务书计算并验证包含父级的 `CPU_BUDGET` 及有效内存下限。另一个待验证项是 affinity mask 含 CPU 161–191，但内核报告仅 CPU 0–63 在线；任务书要求再与负载镜像的真实 affinity 求交集并验证线程绑定，这一步尚未运行。

任务书明确规定必要配额证据缺失时必须 `BLOCKED`。因此没有生成正式 `cpu-plan.json` 或 `machine.json`，也没有开始构建、pilot、参数冻结或性能负载；不猜测父级无限制，不用 64 CPU 替代所需的有效最小值。

## 未运行项目

| 项目 | 状态 |
| --- | --- |
| A/B/H 镜像与二进制证明 | `NOT_RUN_RESOURCE_GATE` |
| Docker 实际 affinity 与 CPU 规划 | `BLOCKED_PARENT_CGROUP_LIMITS` |
| Pilot、formal profile、同组 A/B 参数冻结 | `NOT_RUN_RESOURCE_GATE` |
| 16 个 ABBA 点 | `NOT_RUN_RESOURCE_GATE` |
| 容量探索 | `NOT_RUN_RESOURCE_GATE` |
| 4 个 1800 秒有效稳态点 | `NOT_RUN_RESOURCE_GATE` |
| 审计链、队列 drain、refresh 不变量 | `NOT_RUN_RESOURCE_GATE` |
| P95/P99、成功吞吐、容量边界、WAL 与锁等待 | `NOT_RUN_NO_LOAD` |

## 原始证据

资源发现原文位于 CNB `/tmp/pr222-acceptance-kMhxkB/evidence/resource-discovery.txt`，SHA256 `b6eedffe17776529b74b1ad41cdddec3a9fbe4e4861f5dae46d1e3d033def941`。准备日志位于 `/tmp/pr222-acceptance-kMhxkB/logs/prepare.log`，SHA256 `b079838e4d523800abf3560efb764f2e0fe2897ae0edece662920545fca67de0`。两者的留存归档为 `D:\self\artifacts\pr222-acceptance-20260927-kmhxkb\resource-evidence.zip`，SHA256 `4ddd84a2bacf251ea746e79342f28a25f64a42bf648dd69081afd5924f395d5b`。

补充拓扑与 `.cnb.yml` 证据：CNB `/tmp/pr222-acceptance-kMhxkB/evidence/cnb-config-and-topology.txt`，SHA256 `3d547527d7f8ab2576cf80b6361eed7ba54cd73c6c1e89478333c30b407ebcf7`。结构化检查点：`perf/results/diagnostics/pr222-acceptance-kmhxkb/resource-gate.json`。

## 继续条件

需要由 CNB 侧提供可验证的父级 CPU/内存限制证据，或在测试容器中开放父级 cgroup 读取。补齐后重新计算有效资源预算，再从任务书的环境阶段继续。当前没有把阻塞升级为性能结论。

以上是 `08453247` 时按旧任务书得出的历史继续条件，现已由[续跑指令](2026-09-27-pr222-cnb-resume.md)替代：不要求平台开放父级；使用实际CPU探针、有界校准与可选诊断降级继续。原 NOT_RUN 仍如实保留，只有实际执行的新结果才能更新验收结论。

## 2026-09-27 02:50 UTC 续跑：单逻辑 CPU client_credentials ABBA

- A=`0c70d7464576138af0b3f8a39530d6615ee7a363`，B/H=`462626b29be202c04f2e4482ade6ab5f5f6267c5`。A、B 实际二进制 SHA256 分别为 `0013eec95c96aa04e563a62b7677329d9e72f9af3625cac637deef1470daf15d` 与 `13925e2219045119dc89d820ac6524e63b4cf5b6bc988d21ef55fda178cc394b`。
- 执行顺序 A1/B1/B2/A2，`cap_client_credentials`，共同速率32逻辑操作/秒；每点预热120秒，正式窗口120秒。应用 affinity 集合大小为1个逻辑CPU；不据此声称物理核独占。profile SHA256 `d00ecf53ce2ec9f825a3616fbcdd60c2f6c8e0d4518265b03a11b98b591e3723`，`pool_size=90`、users=64、vectors=12288、主场景预分配16 VU。pilot 峰值内存没有可信聚合采样，profile 明确标记 `UNMEASURED_ESTIMATE`；此组不是内存或最大容量证明。
- 每行 P95/P99 均是该运行正式窗口的完整逻辑迭代分位数，不跨运行平均。HTTP 请求单独列出，计数覆盖该点预热及正式窗口。

| 点 | 有效窗口成功逻辑操作 | 成功操作/秒 | HTTP请求数 | P50/P95/P99（ms） | 丢弃/预期拒绝/意外错误 | 点门槛 |
| --- | ---: | ---: | --- | --- | --- | --- |
| A1 | 3840/3840 | 32.000 | 7680 | 4.423 / 11.339 / 27.306 | 0 / 0 / 0 | PASS |
| B1 | 3840/3840 | 32.000 | 7681 | 4.308 / 8.589 / 16.174 | 0 / 0 / 0 | PASS |
| B2 | 3840/3840 | 32.000 | 7681 | 4.040 / 7.950 / 14.292 | 0 / 0 / 0 | PASS |
| A2 | 3840/3840 | 32.000 | 7680 | 4.009 / 8.509 / 18.902 | 0 / 0 / 0 | PASS |

四点均为120秒有效窗口，capacity gate 与全部点健康检查通过，审计状态检查 PASS；该场景未产生审计事件，审计队列前后均为空。ABBA 阶段完成。首次 A1 启动尝试因 SSH 调用未传递固定 `A/B` 环境变量，在负载前退出，日志 `formal-single-cc-a1-attempt1.log` 单独保留，不计作测试点；随后以固定 SHA 启动的 A1 有效通过。

原始点证据在测试容器 `/tmp/pr222-acceptance-kMhxkB/results/acceptance/single-cc-{a1,b1,b2,a2}/`，日志在同目录 `/tmp/pr222-acceptance-kMhxkB/logs/`。结构化小证据见本报告旁的 `single-cc-abba.json`，其中列出每个 `acceptance.json` 的 SHA256。过程采样/WAL/PG 统计文件与点结果一同保留；该阶段不据单核点推出容量边界。

## 后续状态（02:50 UTC）

- 多核 `cap_mixed` ABBA 已进入执行：A1 主点与 sidecar gate 通过；B1 主 capacity gate 通过，但 sidecar gate 未通过（Argon2/FAPI/refresh 报告调度 drop，详情见保留的原始点证据）。B2 当前运行，配置冻结；不据候选表现单独调整负载。
- 多核 ABBA 尚未完成；共同负载 A/B 各1800秒有效稳态、容量搜索、完整 WAL/锁等待汇总尚未运行，整体验收仍为 `IN_PROGRESS`。
- 宿主物理拓扑、宿主总资源及隐藏父级限制属于 `OUT_OF_SCOPE`。本报告只记录本部署逻辑CPU affinity 与各组件自身可得指标；缺失项标记 N/A/未知，不阻止已开始的运行，也不被解释为零。

## 2026-09-27 03:09 UTC 续跑：多逻辑 CPU mixed ABBA

配置沿用冻结 profile `d00ecf53ce2ec9f825a3616fbcdd60c2f6c8e0d4518265b03a11b98b591e3723`：应用 affinity 集合32个逻辑CPU，mixed 主负载1024 ops/s；120秒预热、120秒有效窗口；pool90、users64、vectors12288；sidecar 为 Argon2 3/s、metadata 68/s、FAPI 10/s、refresh 205/s，VU 与pilot配置一致。每点主负载正式窗口均完成122880个成功逻辑操作，测量窗口丢弃/拒绝/意外错误均为0，主 capacity gate、审计校验、健康检查与sidecar时序均通过。HTTP 请求数为完整点预热+测量计数，与逻辑操作分开列出。

| 点 | 主成功 ops/s | 主逻辑 P50/P95/P99（ms） | 主 HTTP 请求（全点） | 主窗口丢弃 | 审计事件增量 | Sidecar gate |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| A1 | 1024.000 | 3.429 / 10.920 / 28.968 | 358310 | 0 | 353823 | PASS |
| B1 | 1024.000 | 3.372 / 11.958 / 146.862 | 357298 | 0 | 352872 | NOT_PASS |
| B2 | 1024.000 | 3.228 / 9.109 / 28.660 | 358086 | 0 | 353663 | PASS |
| A2 | 1024.000 | 3.355 / 9.860 / 26.509 | 357874 | 0 | 353351 | PASS |

B1 主 load 的 full-run dropped 计数为666，但完整测量窗口队列仍为0；该主点 capacity gate 通过。B1 sidecars 的全程摘要分别为 Argon2 3 drops、FAPI 1 drop、refresh 204 drops，状态 `target_miss`；均自然结束、summary完整、k6 exit0、无协议错误。refresh 测量窗口单独有效，205 ops/s，完整逻辑迭代 P95/P99=10/22ms，窗口内drop/error=0。由于固定sidecar gate要求全程零drop，B1 sidecar gate未通过；不把它改写为业务容量失败，也不调整本组参数。A1/B2/A2 四个sidecar均自然结束、summary完整、exit0、全程零drop并通过gate。因此本ABBA主负载四点通过，但混合组整体为 `NOT_PASS_SIDECAR_GATE`，B1原始证据保留。

四点安全/审计检查均 PASS：receiver与DB锚点一致、checkpoint推进、journal事件数与审计链范围相等，journal连续，无malformed/foreign deployment/sequence gap/duplicate；审计队列 `enqueued=persisted`，pending=0、dropped=0。单点事件增量和队列统计见脱敏JSON。审计链原始journal仅留在任务证据目录，不提交PR。

有效共同短点包括 A1 与 B2 的相同1024 ops/s配置，故已按计划启动 A 版共同mixed稳态：预热120秒、有效窗口1800秒；证据目录 `results/acceptance/steady-common-a/`，日志 `logs/formal-steady-common-a.log`。B 版稳态待A点完整结束后启动，并受原04:20 UTC停止新负载时间约束。

多核ABBA原始点在测试容器 `/tmp/pr222-acceptance-kMhxkB/results/acceptance/multi-mixed-{a1,b1,b2,a2}/`；每点摘要文件SHA256与精简统计见旁侧 `multi-mixed-abba.json`。整体验收仍为 `IN_PROGRESS`，尚未完成1800秒A/B稳态或容量搜索。
