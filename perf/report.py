"""Validate per-window evidence and generate the public comparison (Python standard library)."""
import argparse
import hashlib
import json
import math
import random
import os
import subprocess
import sys
import shutil
import tarfile
import tempfile
from collections import defaultdict
from pathlib import Path
from statistics import median

from monitor.summarize import summarize

HERE = Path(__file__).resolve().parent
SERVICES = {"nazo": "NazoAuth", "rauthy": "Rauthy", "kanidm": "Kanidm", "keycloak": "Keycloak", "hydra": "Hydra"}
FLOWS = {"machine": "机器令牌签发", "introspect": "机器令牌内省", "user-introspect": "用户令牌内省",
         "userinfo": "用户资料", "exchange": "授权码兑换（PKCE）", "refresh": "刷新令牌轮换",
         "authorize-silent": "已登录静默授权＋兑换", "authorize": "已登录授权＋兑换",
         "mixed": "两类混合", "mixed-core": "五类混合"}


def scenario(row):
    name = row.get("scenario", row["flow"])
    return "introspect" if name == "machine-introspect" else name


def group(row):
    fixture = row.get("refresh_fixture") or {}
    return (scenario(row), row["rate"], row["peer"], row.get("generator_profile") or "base",
            row["warm_seconds"], row["seconds"], fixture.get("users", 0), fixture.get("families_per_user", 0))


def verify_row(row):
    a = row["operations"]["all"]
    if row.get("invalid_reasons") or row["status"] not in ("PASS", "FAIL"):
        raise ValueError("invalid window")
    if a["planned"] != row["rate"] * row["seconds"] or a["sent"] + a["not_sent"] != a["planned"]:
        raise ValueError("arrival accounting")
    if a["success"] + a["failed"] != a["sent"] or not math.isclose(a["successful_tps"], a["success"] / row["seconds"]):
        raise ValueError("completion accounting")
    quantiles = a["offered_to_completion_success_ms"]
    if a["success"]:
        values = [quantiles[k] for k in ("50", "95", "99", "99.9", "100")]
        if sorted(values) != values: raise ValueError("latency percentiles")
    elif quantiles:
        raise ValueError("latency without successful operations")
    roles = {"app"} | ({"postgres"} if row["peer"] != "kanidm" else set()) | ({"valkey"} if row["peer"] == "nazo" else set())
    if any(row["resources"][role]["affinity_mismatches"] for role in roles | {"generator"}):
        raise ValueError("CPU affinity")
    cpu = sum(row["resources"][role]["mean_cpu_cores"] for role in roles)
    if not math.isclose(cpu, row["server_total_cpu_cores"], abs_tol=1e-8):
        raise ValueError("aggregate CPU")
    if row["flow"] in ("mixed", "mixed-core"):
        for key in ("planned", "sent", "success", "failed", "not_sent"):
            if sum(v[key] for k,v in row["operations"].items() if k != "all") != a[key]:
                raise ValueError("mixed operation accounting")


def validate_ledgers(rows):
    by_id = {r["id"]: r for r in rows}
    with tempfile.TemporaryDirectory() as work:
        ledger = Path(work) / "arrivals.tsv"
        for sample in sorted((HERE / "evidence/samples").glob("*.tar.gz")):
            row = by_id[sample.name.removesuffix(".tar.gz")]
            if os.name == "posix" and Path("/proc/stat").exists():
                # seal.py uses the Linux procfs clock tick unit to integrate CPU samples.
                with tempfile.TemporaryDirectory(dir=work) as tmp, tarfile.open(sample) as archive:
                    for member in archive:
                        if not member.isfile() or Path(member.name).name != member.name:
                            raise ValueError(f"unexpected sample file in {sample.name}")
                        with archive.extractfile(member) as inp, (Path(tmp)/member.name).open("wb") as out:
                            shutil.copyfileobj(inp,out)
                    command = [sys.executable, str(HERE/"monitor/seal.py"), tmp, row["peer"],
                               row["flow"], str(row["rate"]), str(row["seconds"])]
                    measured = json.loads(subprocess.check_output(command))
                    for k in ("host_cpu_psi_pct","server_total_cpu_cores","server_peak_rss_sum_mib"):
                        if not math.isclose(measured[k],row[k],rel_tol=1e-12,abs_tol=1e-12):
                            raise ValueError(f"{sample.name}: {k}")
                    for role, counters in row["resources"].items():
                        for k in ("cpu_seconds","mean_cpu_cores","peak_rss_sum_mib"):
                            if not math.isclose(measured["resources"][role][k],counters[k],rel_tol=1e-12):
                                raise ValueError(f"{sample.name}: {role}/{k}")
            else:
                with tarfile.open(sample) as archive, archive.extractfile("arrivals.tsv") as inp, ledger.open("wb") as out:
                    shutil.copyfileobj(inp, out)
                measured = summarize(ledger, row["rate"], row["warm_seconds"], row["seconds"])
            if measured["operations"] != row["operations"]:
                raise ValueError(f"{sample.name}: operation ledger differs")


def formatted(values, digits=2):
    data = [v for v in values if v is not None]
    return f"{median(data):,.{digits}f}" if data else "—"


def table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    return "\n".join(lines + ["| " + " | ".join(map(str, row)) + " |" for row in rows])


def render(rows, published):
    cells = defaultdict(list)
    for row in rows: cells[group(row)].append(row)
    blocks = ["# OAuth / OIDC 单实例性能基准", INTRO] if published else ["# OAuth / OIDC 本次测量"]
    blocks.append(f"共 **{len(rows)} 个有效窗口**。各列取同一配置逐轮指标的中位数。失败、未发出以次/轮计，偶数轮的中位数可能为半整数。延迟从计划到达到成功完成，包含调度等待。无成功响应的轮次保留在吞吐及计数中，该轮没有延迟分位数。")
    output = []
    for key, group_rows in sorted(cells.items(), key=lambda kv: (list(FLOWS).index(kv[0][0]),kv[0][1],kv[0][3],list(SERVICES).index(kv[0][2]),kv[0][6:])):
        flow,rate,peer,profile,warm,seconds,users,families = key
        ops = [r["operations"]["all"] for r in group_rows]
        def metric(k,d=2):return formatted([o[k] for o in ops],d)
        def stat(k,d=2):return formatted([r[k] for r in group_rows],d)
        lat = [formatted([(o["offered_to_completion_success_ms"] or {}).get(q) for o in ops]) for q in ("50","95","99","99.9")]
        cpu = formatted([r["resources"]["app"]["mean_cpu_cores"] for r in group_rows]) + " / " + stat("server_total_cpu_cores")
        mem = formatted([r["resources"]["app"]["peak_rss_sum_mib"] for r in group_rows],1) + " / " + stat("server_peak_rss_sum_mib",1)
        label=FLOWS[flow] + (f"（{users}×{families}）" if users else "")
        output.append([label, SERVICES[peer], format(rate,","), "宽" if profile=="journal-wide" else "标准",
                       formatted([a["sent"]/seconds for a in ops]),metric("successful_tps"),metric("failed",1),metric("not_sent",1),
                       *lat,cpu,mem,stat("host_cpu_psi_pct"),len(ops)])
    blocks.extend(["## 固定到达率对照", table(["业务","服务","目标 TPS","发压","发出 TPS","成功 TPS","失败","未发出","P50 ms","P95 ms","P99 ms","P99.9 ms","CPU 主 / 总（核）","峰值 RSS 主 / 总（MiB）","CPU PSI %","轮数"],output)])
    if published: blocks.append(METHOD)
    return "\n\n".join(blocks)+"\n"


INTRO = """在同一类 CNB 主机上，每次运行一个 OAuth 服务，将主服务绑定到 **8 个不同物理核心，各使用 1 个逻辑 CPU**。CPU 列同时展示主服务与含外部依赖的消耗。各家保留原生签名、客户端认证和持久化行为。四家在隔离网络内使用 HTTP/1.1，Kanidm 的 TLS 开销计入测量。

| 服务 | 被测版本 | 机器令牌与认证 | 运行配置 |
|---|---|---|---|
| NazoAuth | `af4b849c63e1e8a68b5d7564f3513a54f991a5fc` ＋随附令牌入口开关补丁 | RS256 JWT、Basic | PostgreSQL 池 32、Valkey，令牌入口 IP 配额关闭 |
| Rauthy | 0.37.2 · 标签 `fe6bcb95192e8a83c29e2b525bf4960933bea3bd` | RS256 JWT、表单凭据 | PostgreSQL 池 32、内嵌缓存；令牌签发事件关闭 |
| Kanidm | 1.12.1 · 标签 `fb052e5357cf09dcdffd07fef4045e8066a68c0b` | JWE、Basic | 内嵌数据库计入主服务，HTTPS/1.1，验证测试 CA |
| Keycloak | 26.8.2 · 镜像修订 `26018f2a4c6155cfe2c28f078996390bf5191946` | RS256 JWT、Basic | PostgreSQL 池 32、JVM 堆 512 MiB–4 GiB，JVM 可见处理器参数 16，实际执行受 8 核亲和性约束 |
| Ory Hydra | 26.2.0 · 镜像修订 `0b84568fffccf151dc5e6c7955fdfb738555bf4b` | RS256 JWT、Basic | PostgreSQL 池 32，私网隔离管理入口，以 `serve all --dev` 运行 |

**同档观察。** 在 1,000 TPS 的 UserInfo 测试中，五家成功吞吐均接近目标。Kanidm 的 P99 最低（1.56 ms）；NazoAuth 主服务平均使用 0.11 核，计入依赖后为 0.49 核。相同档位的授权码兑换，Keycloak P99 为 5.59 ms，NazoAuth 为 11.55 ms，Rauthy 为 48.96 ms。Hydra 在 12,000 TPS 的 UserInfo 测试中实际成功约 3,145 TPS，表中同时保留未发出量。

**覆盖范围。** 当前 NazoAuth 在刷新、兑换、已登录授权、UserInfo 和两种令牌内省上有符合版本条件的记录。机器签发及混合负载缺少该构建的独立测量。空缺表示未测或业务边界不同。单轮点只代表该次观察；固定档最高值也不足以确定系统容量上限。"""

METHOD = """## 读表与可比性

- **查询。** UserInfo 读取用户资料；内省读取令牌有效状态。机器令牌和用户令牌分别统计。Hydra 内省由私网管理端承接，调用者认证边界与另四家不同。
- **签发与授权。** 机器签发包含客户端认证和实际签发。授权码在测前用真实用户会话及 S256 PKCE 准备，测量时每个授权码只兑换一次。已登录链路包含重定向、必要的授权确认和兑换，免交互与显式同意各自成组。Hydra 的外部身份和同意服务未计入共同端到端授权组。
- **轮换。** 表中括号表示用户数 × 每用户独立令牌族数。成功后用返回的后继令牌继续该族。Rauthy 被测配置的后继令牌有约 240 秒生效等待；Kanidm 的重复消费行为与严格一次性兑换及即时轮换组不同。这些场景没有共同的安全和时序前提。
- **混合。** 两类混合每三次安排一次机器签发、两次内省；五类混合的签发、内省、兑换、刷新、已登录授权分别占 30%、50%、10%、5%、5%。有效机器令牌集由 16 个客户端各签发 32 枚；授权码兑换使用 32 个用户。登录、造数通过各项目管理或协议接口完成，每家使用自己的数据库。逐业务项计数和延迟见每轮 JSON 的 `operations`。
- **过载。** 成功 TPS = 测量期内计划到达、最终成功的业务数 ÷ 测量秒数，包含窗口结束后返回的成功。多 HTTP 步骤构成的一笔授权只算一次业务。未发出可能来自调度迟到、在途槽耗尽或前一个刷新未完成。只读成功请求的延迟会低估过载影响，应同时看成功、失败和未发出。特别是 Kanidm 混合过载时，成功样本可能全部来自内省。
- **资源。** CNB Linux x86-64。四家对照项目的环境快照为 AMD EPYC 9K65、无 Swap；当前 NazoAuth 归档保留了核与 SMT 映射，未单独保留 CPU 型号快照。主服务没有硬内存上限，数据库、缓存、Goose 及采集器使用独立核。常规配置分别给 PostgreSQL、Valkey、Goose 分配 14、2、15 个逻辑 CPU。内存取测量窗口内采样到的进程 RSS；服务端总峰值按同时刻汇总，共享页可能重复计入。CPU 是平均占用核数，宿主 CPU PSI 是存在可运行任务等待 CPU 的时间占比。
- **发压。** Goose 0.19.2，调度迟到 5 ms 放弃发出，HTTP 超时 5 秒，共享 HTTP 连接池，固定计划到达，无自动重试。标准配置为 8,192 在途槽、15 工作线程，宽配置为 32,768 槽、24 线程、独立日志写入及扩展源端口范围。只在相同配置内聚合。除兑换和五类混合为预热 5 秒、测量 20 秒外，其余为 10 秒和 36 秒。每个计划操作记录计划、实际发出与完成时间。P99.9 在低样本量窗口可能仅由少数样本决定。
- **有效性。** 只纳入夹具校验成功、计数可对账、资源采样及亲和性合格的窗口。Goose 调度迟发超过计划数 0.1% 或存在发压端资源瓶颈时排除；服务端过载仍保留。宿主干扰结合 PSI、所分配核心的非测试负载和调度等待判断。高整机 CPU 利用率本身不构成排除依据。有效轮数表示测量质量，与产品延迟门槛分开计算。

## 复现

离线重建只需 Python 3.10+。`--check --raw` 校验归档摘要并重算逐请求数据；在 Linux 上还会从采样文件重算 CPU、总峰值 RSS 和 PSI。从仓库根目录执行：

```sh
python3 perf/report.py --check --raw
python3 perf/report.py --output /tmp/oauth-benchmark.md
```

在专用 CNB 的 Linux x86-64 环境重新发压需要 Docker、Git、Bash、Python 3、C 编译器及静态 libc、jq、OpenSSL、patch、flock 和 taskset。克隆时保留上表 NazoAuth 提交。以下命令依次构建锁定版本、部署服务、通过产品接口准备数据、运行三个窗口并生成该次报告：

```sh
bash perf/bench.sh setup
bash perf/bench.sh run nazo userinfo 1000 3
python3 perf/report.py --input perf/.work/windows --output /tmp/fresh.md
```

`bash perf/bench.sh matrix` 按固定种子交错重放所选发压配置已经发表的业务、档位、轮数和刷新数据规模。宽配置使用新的独立 CNB，先以 `BENCH_NETWORK=wide bash perf/bench.sh setup` 部署，再以 `BENCH_PROFILE=journal-wide bash perf/bench.sh matrix` 运行。每个窗口必须有唯一输出路径。私有凭据和新结果保存在忽略提交的 `perf/.work/`。

逐轮原始统计和分项业务结果位于 [evidence/windows](evidence/windows/)。[逐操作采样包](evidence/samples/)保留当前 NazoAuth 有效窗口的到达账本及资源采样；四个对照项目保存到逐轮统计粒度，其逐请求时间戳无法从分位数还原。原生配置及发压校准见 [环境快照](evidence/environment/)。部署参数和镜像摘要见 [deploy.sh](deploy.sh) 与 [native-deploy.sh](native-deploy.sh)。[运行开关补丁](fixture/token-ip-quota.patch)使被测提交支持该配置，测试只关闭所列令牌入口 IP 配额。"""


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,help="fresh windows directory")
    parser.add_argument("--output",type=Path)
    parser.add_argument("--check",action="store_true")
    parser.add_argument("--raw",action="store_true",help="recalculate all available arrival ledgers")
    parser.add_argument("--plan",action="store_true")
    args=parser.parse_args()
    files=sorted(args.input.glob("*/*/*/summary.json") if args.input else (HERE/"evidence/windows").glob("*.json"))
    rows=[]
    for path in files:
        row=json.loads(path.read_bytes())
        if args.input:
            if row["status"]=="INVALID": continue
            row["scenario"]=path.parents[1].name
        try:verify_row(row)
        except (KeyError,ValueError) as err:raise ValueError(f"{path}: {err}") from err
        rows.append(row)
    if not rows:raise SystemExit("No valid windows")
    if args.check and args.input is None:
        directory = HERE/"evidence"
        manifest = (directory/"SHA256SUMS").read_text().splitlines()
        current = {p.relative_to(directory).as_posix(): p for p in directory.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
        expected = dict(line.split("  ",1)[::-1] for line in manifest)
        if current.keys() != expected.keys():
            raise ValueError("evidence file set differs from manifest")
        for name, path in current.items():
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected[name]:
                raise ValueError(f"evidence checksum mismatch: {name}")
    if args.raw:
        if args.input:parser.error("--raw verifies published sample bundles")
        validate_ledgers(rows)
    if args.plan:
        plan=[]
        for r in rows:
            flow,rate,peer,profile,_,_,users,families=group(r)
            if profile!=os.getenv("BENCH_PROFILE","base"):continue
            plan.append((peer,flow,rate,r["id"],users or 32,families or 8,profile))
        random.Random(19716).shuffle(plan)
        for entry in plan: print(*entry,sep="\t")
        return
    result=render(rows,args.input is None)
    dest=args.output or HERE/"README.md"
    if args.input and dest.resolve()==(HERE/"README.md").resolve():parser.error("specify a separate --output for new runs")
    if args.check:
        if dest.read_text(encoding="utf8")!=result:raise SystemExit("Report differs from its window data")
        print(f"{len(rows)} windows verified")
    else:dest.write_text(result,encoding="utf8",newline="\n")


if __name__=="__main__":
    main()
