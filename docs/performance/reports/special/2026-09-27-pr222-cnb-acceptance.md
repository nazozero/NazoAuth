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
