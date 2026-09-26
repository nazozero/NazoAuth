# PR #222：Sol 提交复核与七小时执行任务

日期：2026-09-27（Asia/Shanghai）。这是一次静态复核和待执行的性能任务书，不是新压测结果。

## 复核结论

审查范围为 `442ad35c..462626b2`，逐项追踪调用链、状态变化和测试消费者：

| 提交 | 复核结果 |
| --- | --- |
| `c771f50e` | 成功路径使用真实生成的 P-256 公钥；没有放宽曲线点或 JWK 校验。 |
| `ece640dd` | 外部密钥注册在进入更新/CAS 之前，调用生成验证快照使用的同一解析函数；无效曲线点和不可验证的 `key_ops` 不得污染持久状态。回归测试检查 revision、私钥材料、公开元数据、当前快照和重新加载。未发现新增写入后失败窗口。 |
| `866409a3` | 定向测试、真实 SQL 和锁顺序证据有来源及边界；没有把一次热缓存 EXPLAIN 宣称为生产 P99 或净写入收益。 |
| `462626b2` | 两处 OpenID4VC 测试密钥在创建对应 repository 时随机生成；后续使用同一对象，不依赖删除的常量。生产密钥行为未变。 |

未发现这四个提交需要纠正的代码问题，因此没有为了制造修复提交而改动生产代码。
精确 HEAD `462626b29be202c04f2e4482ade6ab5f5f6267c5` 的 GitHub 检查已核实：11 项成功，2 项按 workflow 条件跳过。
本次本地只做静态检查；Sol 的 84 次定向执行是既有证据，不声称本次重新运行。
本任务书的内嵌 Python、Bash 和 Python 命令片段已做语法检查；资源公式做了无 Docker 的最小执行检查（pilot/formal、预算减半及缺失实测输入拒绝）。这些不构成 CNB 运行验证。
尚未验收索引净写入收益、生产数据分布、规模化锁等待、真实 SMTP、所有协议端点或全链路性能。

## 给执行模型的约束

只执行本任务书，不自行设计优化、改业务代码、调整安全语义、修正阈值或重写 harness。
先读根目录 `AGENTS.md`、本文件、`docs/performance/measurement-accounting.md`。
使用现有 GitHub 授权提交每个完成阶段的脱敏小型证据/报告 checkpoint，并在 PR #222 回复对应 SHA、结果和剩余时间；不修改 git 用户身份，不添加署名，不推 CNB 镜像仓库。
不要创建 worktree，不合并 PR，不部署。测试用独占 Docker compose project、独占目录和新测试数据库，禁止清理其他任务资源。
遇到业务代码、工具语义或缺失权限问题，保留失败证据并报告，不临时发明替代路径。

目标机器：`ssh cnb-kml-1k3f9j3os-001.ebab2059-bd0f-423f-b655-1f64ea683f73-urr@cnb.space`。
整个任务从收到指令起最多 **420 分钟**，包括环境、构建、seed、重试、清理和报告；每 10 分钟给出进度。
任何长命令都要记录 PID、日志路径、超时和阶段截止时间。禁止无界等待，禁止反复重跑失败点。
到 390 分钟停止开启新负载，最迟 420 分钟交付；缺失项明确 `NOT_RUN_TIME_BUDGET` / `BLOCKED`，不得改成通过。

## 固定版本与环境

| 身份 | 固定值 |
| --- | --- |
| A：基线生产源码 | `0c70d7464576138af0b3f8a39530d6615ee7a363` |
| B：候选生产源码 | `462626b29be202c04f2e4482ade6ab5f5f6267c5` |
| H：两组共同的 harness、配置和构建 recipe | 同 B |
| 报告分支 | `perf/db-hotpath-minimal-0c70d746`，PR #222 |

任务书的后续文档提交不改变 A/B/H。若 PR 又出现生产代码变更，报告版本漂移，不偷偷更换 B。
只用一个应用实例；业务连接池、VU、数据准备量、构建并发和负载由下述机器资源规则生成，A/B 使用同一结果。RS256 主路径及既有 PS256/FAPI fixture 保持原样。
PG/Valkey 镜像、持久化参数、数据量、运行角色、监控、审计 worker/receiver、应用配置在 A/B 之间相同。
保留 H 的 PG `fsync/synchronous_commit/full_page_writes=on` 和 Valkey 测试配置；不得为过门槛关闭审计、加密、Argon2 或一致性检查。

准备命令模板（`REPO` 填机器上已确认的 NazoAuth 仓库绝对路径；不得覆盖已有未提交内容）：

```bash
export A=0c70d7464576138af0b3f8a39530d6615ee7a363
export B=462626b29be202c04f2e4482ade6ab5f5f6267c5
export H="$B"
export TASK_ROOT="$(mktemp -d /tmp/pr222-acceptance-XXXXXX)"
export TASK_STARTED_EPOCH="$(date +%s)"
# 若准备这些命令时已有耗时，TASK_STARTED_EPOCH 必须改为收到任务的实际 epoch。
export SIS_PROJECT="pr222-$(basename "$TASK_ROOT" | tr '[:upper:]' '[:lower:]')"
export SIS_WORKSPACE="$TASK_ROOT/harness"
export SIS_RESULTS="$TASK_ROOT/results"
export SIS_BIN="$TASK_ROOT/bin"
export SIS_PERF_IMAGE="$SIS_PROJECT-perf"
export SIS_RCV_IMAGE="$SIS_PROJECT-audit-receiver"
export SIS_HARNESS_SHA="$H"
export SIS_LOAD_BUDGET_S=18000
export IMAGE_A="$SIS_PROJECT-a"
export IMAGE_B="$SIS_PROJECT-b"
mkdir -p "$SIS_WORKSPACE" "$SIS_RESULTS" "$SIS_BIN" "$TASK_ROOT/source-a" "$TASK_ROOT/source-b"
git -C "$REPO" archive "$H" | tar -x -C "$SIS_WORKSPACE"
git -C "$REPO" archive "$A" | tar -x -C "$TASK_ROOT/source-a"
git -C "$REPO" archive "$B" | tar -x -C "$TASK_ROOT/source-b"
```

顺序构建，禁止边构建边测量。两源码使用同一 H Containerfile；`SOURCE_SHA` 隔离 target cache，防止旧二进制污染。
先核实有效 CPU 配额 `CPU_BUDGET` 和有效剩余内存 `MEM_AVAILABLE_GIB`（取宿主与所有生效 cgroup 的可用量最小值，不能用宿主总内存）。构建并发 `BUILD_JOBS=max(1,min(floor(CPU_BUDGET),floor(MEM_AVAILABLE_GIB/2)))`；2 GiB/任务只是初始编译内存估算，不是机器固定上限，发生真实内存不足时仅允许减半重试一次并记录。两组同用最终并发。
在任务目录共同 recipe 中添加可配置的 `ARG CARGO_BUILD_JOBS`（位于 `FROM build-base AS product-builder` 后）；记录 recipe SHA256。
用阶段剩余时间包裹以下命令的 `timeout --kill-after=30s`，单次构建失败最多重试一次，总计不得越过第 80 分钟。

```bash
export BUILD_JOBS="$(python3 -c 'import os; cpu=int(float(os.environ["CPU_BUDGET"])); mem=int(float(os.environ["MEM_AVAILABLE_GIB"])/2); print(max(1,min(cpu,mem)))')"
sed '/^FROM build-base AS product-builder$/a ARG CARGO_BUILD_JOBS' "$SIS_WORKSPACE/Containerfile" > "$TASK_ROOT/Containerfile.common"
sha256sum "$TASK_ROOT/Containerfile.common" > "$SIS_RESULTS/build-recipe.sha256"
docker build -f "$TASK_ROOT/Containerfile.common" --target perf-runtime --build-arg CARGO_BUILD_JOBS="$BUILD_JOBS" --build-arg SOURCE_SHA="$A" -t "$IMAGE_A" "$TASK_ROOT/source-a"
docker build -f "$TASK_ROOT/Containerfile.common" --target perf-runtime --build-arg CARGO_BUILD_JOBS="$BUILD_JOBS" --build-arg SOURCE_SHA="$B" -t "$IMAGE_B" "$TASK_ROOT/source-b"
docker build -f "$SIS_WORKSPACE/perf/runner/Containerfile" --build-arg SOURCE_SHA="$H" -t "$SIS_PERF_IMAGE" "$SIS_WORKSPACE"
docker build -f "$SIS_WORKSPACE/perf/keyset/Containerfile" -t "$SIS_PROJECT-keyset" "$SIS_WORKSPACE"
docker build -f "$SIS_WORKSPACE/perf/audit-anchor-receiver/Containerfile" -t "$SIS_RCV_IMAGE" "$SIS_WORKSPACE"
docker volume create --label "sis.owner=$SIS_PROJECT" "$SIS_PROJECT-keys"
PYTHONPATH="$SIS_WORKSPACE/perf/tools" python3 "$SIS_WORKSPACE/perf/tools/single_instance_scaling.py" pinset-build
```

保存 CPU 型号/拓扑、内存、磁盘、内核、Docker/k6/Rust/Postgres/Valkey 版本和镜像 ID。
检查主机、CNB 容器、Docker daemon/负载容器的有效 cpuset、CPU quota、内存限制及 throttling；不能只读宿主 `MemTotal/nproc`。
宿主工具需 Python3、Docker compose、gcc 静态编译能力；依赖缺失的环境修复也计入 80 分钟。记录完整实际命令和退出码，日志不输出秘密。

## 动态 CPU 与单核组

不能直接使用旧 `env-check` 的 `X8` 规划：它要求固定八个完整 SMT 对。
使用以下规划代码，保存为 `$TASK_ROOT/cpu_plan.py`。`CPU_BUDGET` 必须填已核实的**最小有效 CPU 配额**（CPU 个数，允许小数），包括父 cgroup；确实无限制时填允许 affinity 的逻辑 CPU 数。`DOCKER_ALLOWED_CPUS` 从负载镜像的真实 affinity 获取，不能填猜测值。

```bash
export DOCKER_ALLOWED_CPUS="$(docker run --rm --entrypoint python "$SIS_PERF_IMAGE" -c 'import os; cpus=sorted(os.sched_getaffinity(0)); print(",".join(map(str,cpus)))')"
# CPU_BUDGET 的来源：cgroup v2 cpu.max 的 quota/period；v1 cpu.cfs_quota_us/cpu.cfs_period_us。
# 沿实际 cgroup 层级检查可见父级，再与 CNB/daemon 限额取最小值。缺少必要限额证据则 BLOCKED，不声称无限制。
```

```python
# cpu_plan.py
import json
import math
import os
from pathlib import Path

allowed = set(os.sched_getaffinity(0)) & {
    int(x) for x in os.environ["DOCKER_ALLOWED_CPUS"].split(",")
}
groups = {}
for cpu in sorted(allowed):
    topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
    key = (int((topology / "physical_package_id").read_text()),
           int((topology / "core_id").read_text()))
    if min(key) < 0:
        raise SystemExit("BLOCKED_CPU_TOPOLOGY")
    groups.setdefault(key, []).append(cpu)
cores = sorted(groups.values(), key=min)
budget = float(os.environ["CPU_BUDGET"])
if not math.isfinite(budget) or budget <= 0:
    raise SystemExit("BLOCKED_CPU_BUDGET")
n = min(len(cores) // 2, math.floor(budget / 2))
if n < 1:
    raise SystemExit("BLOCKED: need one app core and separate infrastructure")
app = [min(group) for group in cores[:n]]
infra = sorted(cpu for group in cores[n:] for cpu in group)
plan = {"allowed": sorted(allowed), "physical_cores": cores,
        "cpu_budget": budget, "multi": app, "single": app[:1], "infra": infra}
assert infra and not set(infra) & {cpu for group in cores[:n] for cpu in group}
Path(os.environ["SIS_RESULTS"], "cpu-plan.json").write_text(json.dumps(plan, indent=2))
print(json.dumps(plan))
```

运行 `python3 "$TASK_ROOT/cpu_plan.py"` 后保存结果，整个测试固定这份规划。
多核组：从可用物理核中动态分配 N 核，每核只使用一个逻辑 CPU；单核组：应用只使用其中一个逻辑 CPU。
两组 infrastructure CPU 集合相同；应用物理核的 SMT 兄弟不放给 PG/Valkey/k6/observer。单核组剩余应用核闲置，避免跨组资源变化。
如果动态 N=1，只执行 single 组；multi 重复组标 NOT_APPLICABLE，后续容量/稳态也使用 single，不冒充多核数据。
这是“应用单逻辑 CPU、独占其物理核”的基准，不是把全栈挤在一核；不能把结果称为整个容器一核吞吐量。
每点验证实际线程 affinity、运行二进制 hash 和 pool 配置；配额/权限不满足则停止正式测量，不修改 CPU 编号或安全配置来绕过。

## 动态资源配置：先探测，再冻结

不把旧机器的 pool32、2048VU、14GiB、48000 vectors、3000/s 当作本机要求。以下系数是公开的探测/余量策略，不是实测容量或通用推荐。**安全不变量、统计口径和1800秒有效窗口不随硬件放宽。**
先生成 `resource-profile.json` 的 pilot 版本并运行 A/B 各一个 multi mixed 点（预热120s、测量60s）；两组使用相同参数。无需改生产代码，按下列公式填数字即可：

| 参数 | pilot / formal 的确定规则 |
| --- | --- |
| pool_size | 从真实 PG `SHOW max_connections` 得到 P，预留 `max(8,ceil(0.1P))` 给审计/观察/管理，其余取 `min(4N,P-预留)`；小于1则 BLOCKED。single/multi/A/B 共用，避免单核对比同时改变池。 |
| pilot 主 VU Vp | `max(1,floor(min(16N,8×有效剩余内存GiB)))`，全部预分配；pilot 速率为 `2Vp`。这是有界探测起点，非正式容量结论。 |
| pilot sidecar | 各速率为 `max(1,round(pilot速率×旧速率/3000))`。VU 初始按旧 max_vus/旧rate 的比例向上取整，pre=max；pilot 阶段若发生器无效，速率和各 VU 减半共同重试 A/B 一次。 |
| pilot 数据 | users=`max(64,ceil(Vp/8))`；vectors=`max(1000,24Vp)`，A/B 相同。 |
| formal 总 VU 预算 T | 在两次 pilot 中记录全部主/sidecar k6 容器实际内存峰值之和 M、栈启动后有效剩余内存 F，及实际总预分配 VU V；取更保守的 A/B 数据。`T=floor(V×sqrt(0.60F/(1.25M)))`，单位均为 bytes。平方根按 fixture 随 VU 增长可能放大的成本保守外推，**仍须实时验证**，不是内存保证。数据缺失则 BLOCKED，不猜常量。 |
| formal 主 VU ceiling | `C=max(1,floor(0.70T))`；每点按 Little's law 用 `ceil(rate×0.250×2)` 个主 VU，pre=max，不在测量中临时扩容。超过 C 则该目标为 GENERATOR_BUDGET_LIMIT，不冒充业务极限。 |
| formal 初始速率 R0 | 每模式 `min(375×该模式应用核数,floor(1.2C))`；若主+sidecar VU 总和超 T，将该 R0 乘0.8向下取整，直到满足。375/核只是探测种子，后续搜索可超过它，不是硬上限。 |
| formal sidecar | 同模式固定为 `max(1,round(R0×旧速率/3000))`，容量搜索时保持不变；其预分配 VU 为 `ceil(rate×max(pilot实测完整迭代P99秒,0.25)×2)`。两 pilot 取较慢值，不拿 HTTP P99 替代；缺失则 BLOCKED。 |
| formal 数据 | 所有点共用 users=`max(64,ceil(C/8))`、vectors=`max(1000,24C)`。保留 fixture 下限64/1000，避免变为小样本模型；它们不是硬件上限。 |
| formal 内存预检 | `memory_required_gib=(1.25M×(本点总VU/V)^2)/2^30`；启动栈后的有效剩余内存必须同时满足该值和20%有效内存限制的保留量。主机与cgroup两者都检查。 |

formal 配置验证点使用最终数据量，A/B 各跑一次动态 R0 的60秒测量（另加120秒预热），计入探测预算。若真实 OOM/发生器瓶颈/内存压力触发，仅允许使用下述程序的 `CALIBRATION_SCALE=0.5` 将共同预算下调并重跑双方一次；保留旧失败。下调后的速率由同一公式重算。之后冻结 profile SHA256，禁止根据 B 的成绩单独调参。
采样当前任务所有负载容器的 cgroup memory/CPU，而不是把 PG backend RSS 相加。当总生效内存使用≥85%限制，或主机 MemAvailable<10%总量时，中止本任务负载、保留证据，标记 RESOURCE_ABORT；如没有有限内存限制，使用宿主可用量条件。只中止本任务已登记且标签匹配的容器。
CPU 持续 throttling / 分析流积压 / 本地 socket 耗尽也是发生器归因证据；单纯达到 VU ceiling 不等于发生器有错。

用以下程序生成 profile，不手工改算出的值。保存为 `$TASK_ROOT/profile.py`。
输入 `$SIS_RESULTS/machine.json` 包含真实 `free_gib`、`pg_max_connections`；`pilot-facts.json` 包含 `free_bytes`（两组栈启动后的有效可用内存较小值）、`peak_bytes`（每组全部 k6 容器内存峰值之和，取两组较大值）、`total_vus`（实际主+sidecar预分配总数）、`sidecar_p99_ms`（键为 argon2/meta/fapi/refresh，取两组各自完整 iteration_duration P99 的较大值）。
M 使用容器 cgroup memory.current 或 Docker stats 的内存字节数，不用 PG 进程 RSS。至少每2秒采样所有任务 k6 容器并保存 timestamp、ID、配置VU、memory、CPU、OOM/throttle；同时保存相应 k6 JSON。缺字段停止，不用0补齐。
先运行 `python3 "$TASK_ROOT/profile.py" pilot`；完成 pilot 后运行 `python3 "$TASK_ROOT/profile.py" formal`。每次生成前保存旧 profile 及 SHA256，测量点保存所用 profile 副本。估算只能在 pilot 使用，formal 必须使用真实采样输入。

```python
# profile.py
import json
import math
import os
import sys
from pathlib import Path

root = Path(os.environ["SIS_RESULTS"])
sys.path.insert(0, str(Path(os.environ["SIS_WORKSPACE"]) / "perf/tools"))
from pool_size_ab import SIDECARS_120

stage = sys.argv[1]
assert stage in ("pilot", "formal")
scale = float(os.environ.get("CALIBRATION_SCALE", "1"))
assert scale in (1, 0.5)
plan = json.loads((root / "cpu-plan.json").read_text())
machine = json.loads((root / "machine.json").read_text())
n = len(plan["multi"])
p = int(machine["pg_max_connections"])
pool = min(4 * n, p - max(8, math.ceil(0.1 * p)))
assert pool > 0 and machine["free_gib"] > 0

def sidecars(rate, users, p99=None):
    result = []
    for original in SIDECARS_120:
        r = max(1, math.floor(rate * original["rate"] / 3000 + 0.5))
        factor = original["max_vus"] / original["rate"] if p99 is None else 2 * max(0.25, p99[original["name"]] / 1000)
        vu = max(1, math.ceil(r * factor))
        result.append(dict(original, rate=r, pre_vus=vu, max_vus=vu, user_count=users))
    return result

if stage == "pilot":
    c = max(1, math.floor(scale * min(16 * n, 8 * machine["free_gib"])))
    users = max(64, math.ceil(c / 8))
    sc = sidecars(2 * c, users)
    v = t = c + sum(s["max_vus"] for s in sc)
    m = v * 32 * 2**20  # initial estimate, never a measured result
    modes = {mode: {"start_rate": 2 * c, "abba_rate": 2 * c, "sidecars": sc}
             for mode in ("single", "multi")}
else:
    facts = json.loads((root / "pilot-facts.json").read_text())
    v, m, f = facts["total_vus"], facts["peak_bytes"], facts["free_bytes"]
    assert v > 0 and m > 0 and f > 0
    p99 = facts["sidecar_p99_ms"]
    assert all(math.isfinite(p99[s["name"]]) and p99[s["name"]] > 0 for s in SIDECARS_120)
    t = math.floor(scale * v * math.sqrt(0.60 * f / (1.25 * m)))
    c = math.floor(0.70 * t)
    if c < 1:
        raise SystemExit("BLOCKED_GENERATOR_MEMORY")
    users = max(64, math.ceil(c / 8))
    modes = {}
    for mode in ("single", "multi"):
        r = max(1, min(375 * len(plan[mode]), math.floor(1.2 * c)))
        while True:
            sc = sidecars(r, users, p99)
            if math.ceil(r * 0.5) + sum(s["max_vus"] for s in sc) <= t:
                break
            if r == 1:
                raise SystemExit("BLOCKED_GENERATOR_VU_BUDGET")
            r = max(1, math.floor(r * 0.8))
        modes[mode] = {"start_rate": r, "abba_rate": max(1, math.floor(0.6 * r)), "sidecars": sc}
profile = dict(stage=stage, calibration_scale=scale, pool_size=pool, user_count=users, vector_count=max(1000, 24*c),
               pilot_total_vus=v, pilot_peak_bytes=m, total_vu_budget=t, main_vu_cap=c, **modes)
(root / "resource-profile.json").write_text(json.dumps(profile, indent=2))
print(json.dumps(profile))
```

探测前检查 PG 持久化参数和可用磁盘。测试配置中现存的数据库参数属于共同配置基线，不在此次任务里改为另一套调优实验。按 pilot 的实际 WAL/结果增长率估算最长单点磁盘开销，留20%磁盘余量；空间不足则资源阻塞，不能删除别人的数据或关闭持久化。不同机器的动态资源表必须随报告发布，历史绝对吞吐量不可直接作为同环境 A/B。

## 单点执行器

将下一段原样保存为 `$TASK_ROOT/point.py`；它只复用 H 的执行/判定函数，不改变协议和统计定义。
命令格式：`python3 "$TASK_ROOT/point.py" NAME A或B single或multi SCENARIO RATE WARMUP_S MEASURE_S`。
每次调用外层 `timeout` 上限为 `WARMUP_S + MEASURE_S + 480` 秒，并受阶段截止时间约束；被截断的点为无效，保留目录并仅清理任务自己的资源。
主报告里 `rec.ok` 只是执行器完成，绝不是性能通过。

```python
# point.py
import json
import math
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(os.environ["SIS_WORKSPACE"]) / "perf/tools"))
import single_instance_scaling as sis
import point_runner as pr
import capacity_search as cs
import pool_size_ab as pool

name, variant, mode, scenario, rate, warm, measure = sys.argv[1:]
assert re.fullmatch(r"[a-z0-9-]+", name)
assert variant in ("A", "B") and mode in ("single", "multi")
assert scenario in ("cap_client_credentials", "cap_mixed")
rate, warm, measure = int(rate), int(warm), int(measure)
assert rate > 0 and warm >= 60 and measure >= 60
total = warm + measure
deadline = int(os.environ["TASK_STARTED_EPOCH"]) + 390 * 60
if time.time() + total + 480 > deadline:
    raise SystemExit("NOT_RUN_TIME_BUDGET")
out = sis.RESULTS / "acceptance" / name
if out.exists():
    raise SystemExit("REFUSE_OVERWRITE_POINT")
plan = json.loads((sis.RESULTS / "cpu-plan.json").read_text())
profile = json.loads((sis.RESULTS / "resource-profile.json").read_text())
main_vus = math.ceil(rate * 0.250 * 2)
sidecars = [dict(sc, duration=f"{total + 30}s") for sc in profile[mode]["sidecars"]] if scenario == "cap_mixed" else []
total_vus = main_vus + sum(sc["max_vus"] for sc in sidecars)
if main_vus > profile["main_vu_cap"] or total_vus > profile["total_vu_budget"]:
    raise SystemExit("GENERATOR_BUDGET_LIMIT")
mem_gib = 1.25 * profile["pilot_peak_bytes"] * (total_vus / profile["pilot_total_vus"]) ** 2 / 2**30
cpus = {"X8": plan[mode], "INFRA": plan["infra"]}  # historical parameter name only
image = os.environ[f"IMAGE_{variant}"]
os.environ["SIS_SOURCE_SHA"] = os.environ[variant]
pr.KEYSET_VOLUME = f"{sis.PROJECT}-keys"
binary = pr.image_binary_sha(image)
assert binary
role, _ = pr.runtime_role_from_image(image)
mixed = scenario == "cap_mixed"
point = pr._point(
    name, "acceptance", image, cpus, scenario=scenario,
    executor="constant-arrival-rate", rate=rate, duration=f"{total}s",
    warmup_ms=warm * 1000, pre_vus=main_vus, max_vus=main_vus, user_count=profile["user_count"],
    vector_count=profile["vector_count"], formal_preflight=True, stream_evidence=True,
    expected_binary_sha256=binary, generator_mem_min_gib=mem_gib,
    app_env_overrides={"DATABASE_MAX_CONNECTIONS": str(profile["pool_size"])},
    residency_observer={"runtime_role": role, "interval_s": "0.25"},
    sidecar_delay_s=0,
    sidecars=sidecars,
)
rec = pr.run_ab_point(point)
(out / "resource-profile.json").write_text(json.dumps(profile, indent=2))
rec["audit_queue_post_drain"] = pr.audit_queue_final(out)
checks = pr._health_checks(rec, mixed=mixed)
q = rec["audit_queue_post_drain"]
checks["queue_drained"] = (q.get("collected") is True and q.get("dropped") == 0
    and q.get("pending_in_process") == 0 and isinstance(q.get("enqueued"), int)
    and q.get("enqueued") == q.get("persisted"))
load = rec.get("load") or {}
files = list((out / "load").glob("*.summary.json"))
gate, metrics = "INVALID", {"reason": "expected_one_summary"}
if len(files) == 1:
    gate, metrics = cs.evaluate(json.loads(files[0].read_text()), files[0], rate, total,
        scenario, generator_facts={"oom_killed": load.get("main_oom_killed"),
        "exit_code": load.get("main_exit_code"), "load_status": load.get("load_status")},
        require_stream=True)
checks["measurement_length"] = metrics.get("window_seconds") == measure
checks["main_natural_completion"] = (load.get("load_status") == "completed"
    and str(load.get("main_exit_code")) == "0"
    and load.get("main_oom_killed") is False)
# This is the Python runner container exit; raw k6 threshold exit is separate evidence.
timing = pool._sidecar_timing_gate(out, load.get("sidecars") or [],
    (rec.get("metrics") or {}).get("window_start_ms")) if mixed else {"ok": True}
checks["sidecar_timing"] = timing["ok"]
if mixed:
    checks["four_sidecars"] = {s["name"] for s in load.get("sidecars", [])} == {"argon2", "meta", "fapi", "refresh"}
side = {}
for sc in load.get("sidecars") or []:
    directory = out / sc["name"]
    summaries = list(directory.glob("*.summary.json"))
    entry = {"process": sc, "status": "MISSING_SUMMARY"}
    if len(summaries) == 1:
        summary = json.loads(summaries[0].read_text())
        entry.update(status=summary.get("status"), k6=summary.get("k6"),
                     summary=str(summaries[0]), k6_exit_code=summary.get("k6_exit_code"))
    side[sc["name"]] = entry
result = {"name": name, "variant": variant, "mode": mode, "app_cpu_count": len(plan[mode]),
    "capacity_gate": gate, "capacity_metrics": metrics, "health_checks": checks,
    "sidecars": side, "sidecar_timing": timing,
    "status": "REQUIRES_SIDECAR_REVIEW" if mixed else
        ("PASS" if gate == "PASS" and all(checks.values()) else "NOT_PASS"),
    "note": "Mixed requires the explicit sidecar gate in the task document; never promote rec.ok to PASS."}
out.mkdir(parents=True, exist_ok=True)
(out / "point.json").write_text(json.dumps(rec, indent=2))
(out / "acceptance.json").write_text(json.dumps(result, indent=2))
print(json.dumps({"name": name, "capacity_gate": gate, "failed_health": [k for k,v in checks.items() if not v],
                  "status": result["status"], "path": str(out)}))
```

执行前额外核实上文动态内存预检（结合 `memory.max/current` 或 v1 等效值）；旧 helper 的宿主 `MemAvailable` 不能替代这一检查。每点检查，不够则停止，不在已冻结的点里减 VU 偷换模型。
`X8` 只是旧 `_point` 的字段名，传入内容来自动态规划，不代表固定八核。
不要调用 `pool_size_ab.py --phase run/stability`、`capacity_search.py` 的搜索入口、`make perf` 或 `extended_capacity_matrix.sh`：它们分别是池大小实验、不同搜索策略或扩展矩阵，不是本任务。

## 阶段、顺序和预算

所有 A/B 负载**串行**。每点由现有执行器重建自己的 PG/Valkey/审计状态，保留同一受控密钥卷。
`cap_mixed` 为 userinfo30/client_credentials25/authorization_code15/refresh15/token_exchange15；四 sidecar 保留旧 refresh600/冷登录8/metadata200/FAPI30 的比例基准，具体速率按机器和single/multi模式缩放并冻结。
因此复用旧场景与统计口径，但不是强称所有机器都在旧绝对速率下；跨模式结果须注明负载也按核数/资源缩放。同模式 A/B 始终使用完全相同的 sidecar。冻结后过载是结果，不是改单边负载的理由。

| 从任务开始计时 | 执行内容 |
| --- | --- |
| 0–80 分钟 | 环境、动态 CPU 规划、A/B/H 源码/镜像/binary 证据及构建；失败立即报告 BLOCKED。 |
| 80–115 分钟 | 上述有界 pilot、资源测量与共同配置验证，冻结 resource-profile；检查权限、seed、stream、四 sidecar、审计/affinity。权限/证据失败不进入正式矩阵。容量失败与发生器/证据缺失分别处理。 |
| 115–205 分钟 | 以下四组逐组 ABBA，每点预热120s、测量120s：single CC；multi CC；single mixed；multi mixed。速率均取对应 profile.abba_rate。每组命名 `single-cc-a1/b1/b2/a2` 等。共16点。 |
| 205–240 分钟 | multi mixed A/B 交替、每版本至多4个点，预热120s、测量60s；按下述算法找容量边界。 |
| 240–390 分钟 | multi mixed 稳态四点：A共同负载、B共同负载、B自身最高已通过短点、A自身最高已通过短点。每点预热120s+**测量1800s**，总 duration1920s，sidecar1950s。不同目标速率的后两点不称为同负载 ABBA。 |
| 390–420 分钟 | 停止新负载、归档、脱敏、生成报告、checkpoint 与 PR 回复、清理本任务独占资源。 |

单点示例：

```bash
export R_SINGLE="$(python3 -c 'import json,os; print(json.load(open(os.environ["SIS_RESULTS"]+"/resource-profile.json"))["single"]["abba_rate"])')"
timeout --kill-after=30s 720s python3 "$TASK_ROOT/point.py" single-cc-a1 A single cap_client_credentials "$R_SINGLE" 120 120
# 稳态示例，R_COMMON 必须按以下算法得到：
timeout --kill-after=30s 2400s python3 "$TASK_ROOT/point.py" steady-common-a A multi cap_mixed "$R_COMMON" 120 1800
```

容量搜索是固定决策：每版本从 profile.multi.start_rate 开始（已完成同配置验证点可复用，不重复跑）；精度 d=`max(1,ceil(R0/30))`。通过则下一目标 `ceil(1.5×当前速率)`，直到首次失败；首次失败前没有通过点则速率减半寻找通过点（最小1）。取得通过 L 和失败 U 后，下一点取区间中点向下对齐 d，并限制在 `[L+1,U-1]`；`U-L<=d` 停止。A/B 交替执行，不同时运行。每版本最多4个新增点，预算不足停止。这取代旧机器固定+500/-100搜索，缩短找边界的链路，不改变通过门槛。
只有本文件全部点级门槛 PASS 才更新 L；证据/发生器 INVALID 不当作业务容量失败、不更新边界，同一点最多因明确基础设施故障重试一次且计入四点预算。资源 ceiling 拦截则报告 GENERATOR_BUDGET_LIMIT，不再向上，不能称业务已到极限。
记录区间 `[L,U)`；没有失败上界则只称“至少 L”，四点未收敛则报告当前宽区间，不能说找到精确极限。
取每版本最高**完整 PASS**的 multi mixed 短点速率为 `R_A/R_B`（可包含 ABBA）；`R_COMMON=min(R_A,R_B)`。任一版本无 PASS 则其稳态依赖项标 BLOCKED，不猜数值。
若 `R_A==R_B`，后两稳态仍运行，成为同负载重复点。否则分别报告共同负载对比和各自稳定上界，不在不同负载间计算“同压提升”。短点极限尚未通过1800s时不得称稳态容量。
阶段落后时依次取消剩余容量探索、两点自身极限稳态；优先保留单核/多核 ABBA 与共同负载稳态 A/B。取消须显式 NOT_RUN，不能缩短1800s。

## 点级判定与证据

1. 主容量权威判定使用 `capacity_search.evaluate(... require_stream=True)`：成功逻辑操作/s≥目标的99.5%，测量 cohort 的丢弃率≤0.1%，unexpected=0，prepare_sut_failed=0，完整迭代 P95≤100ms、P99≤250ms。缺失/无效 stream 不回退 HTTP RPS。99.5%门槛通过不等于严格达到3000成功/s；后者另按实际成功数判断。
2. `acceptance.json` 的全部 health_checks 必须 true；业务池配置等于 profile.pool_size，不强求低负载下实际连接数恰好填满。验证 app_cpu_count、线程 affinity 和实际 binary SHA；所有 A/B/H/image/digest 对应关系写进报告。
3. mixed 另外逐个检查四个 sidecar：自然结束、未中断、终端 summary、无进程 OOM、预备阶段错误、流解析错误或未解释协议错误；保存各自实际速率、drop 和 P99。refresh 使用相同 cap gate、profile中的target及自己的完整测量窗口。其他三者保持其 H 原有 checks/threshold；要求 summary.status=passed、k6_exit_code=0、dropped_iterations=0。不能把冷登录多请求 HTTP RPS 当成逻辑操作/s，也不能将主容量250ms阈值套给 Argon2 整个场景。
4. 四 sidecar `k6-started.json` 必须匹配本 run_id 且开始早于主测量开始5秒；用实际 k6 开始时间+配置持续时间和自然退出证据确认覆盖到主窗口结束。没有实际时间证据即 LOAD_MODEL_INVALID。`common_window_s` 的旧容器时间估算不能独自证明1800s覆盖。
5. 审计 Required 路径无 drop/queue_full、drain后pending=0/enqueued=persisted、DB与receiver/日志链reconcile PASS、无断号/重复、refresh active≤10/spent≤64/expired backlog=0、无重启/OOM。不能以吞吐更高抵消这些失败。
6. 保存每点 P50/P95/P99、attempts/s、successful/s、expected rejection、local_no_request、unexpected、preparation failure、dropped/unfinished、窗口长度；分开 HTTP/操作/完整迭代，不平均多个 P99，也不把 sidecar 成功数加进主分母。
7. 保存 PG/WAL、CPU/RSS、pool wait、runtime backend、锁等待、pg_stat_statements、审计链和队列、Valkey/refresh 状态、发生器 CPU/memory/throttle/analyzer 证据。WAL/CPU per success 只在**同一时间窗与对应分母**有证据时计算；旧混合 CPU 分母不可用时写 N/A，不拿 pg_stat_statements 总时长充当 CPU。混合 WAL 若含 sidecar 工作必须注明，不能归因于单一路径索引。

判定顺序：来源/资源/负载模型/证据无效 → INVALID 对应子类；有效但任一业务/sidecar/健康门槛失败 → FAIL；全部通过 → PASS。保留 evaluator 原始原因。
ABBA 每次结果单列；A1/A2 成功率或 P99 相差>10%则该组比较 INCONCLUSIVE。B 两次都比两个 A 的最高 P99 恶化>10%且>20ms，标记稳定尾延迟回归；只有一次出现则标可疑回归，不声称已证明稳定。小样本不宣称统计显著。
单核报告写明应用只使用1个逻辑 CPU、物理核/SMT隔离方式、固定sidecar争用场景；multi 写动态 N。不同机器/不同N不得直接把绝对数字与历史8核结果当作优化幅度。

## 交付与停止

报告写到 `docs/performance/reports/special/<实际日期>-pr222-cnb-acceptance.md`，小型 JSON/manifest 放 `perf/results/diagnostics/pr222-acceptance-<运行ID>/`。
大体积原始证据保留 CNB 绝对路径和逐文件 SHA256 清单，另提供实际可取回的归档位置；不要只给模型会话中的 `/tmp` 路径而没有留存说明。不要提交 keyset、token、私钥、DSN或未经脱敏的请求日志。
每阶段只 stage 明确新增报告/脱敏证据，不 `git add .`；每个 commit 后在 PR #222 回复。同分支如有他人新增提交，先检查是否仅报告变更，禁止 force push/覆盖。
最终交付：精确 A/B/H、CPU规划/配额、构建recipe和二进制证明、逐点结果表、main与sidecar gate、单核/多核各自结论、容量边界、1800s稳态、失败/未测清单、原始证据和 PR checkpoint。
本轮不执行全 workspace 测试、完整22项审计故障注入、全协议矩阵、生产分布/真实SMTP或新增索引净写入实验；不能将本轮窄场景结果扩大为“项目几乎没有性能问题”。
