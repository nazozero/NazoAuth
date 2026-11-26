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


def overview(output):
    # Bars use a common zero-based scale within each table and the printed values.
    blocks = ["## 主要对照"]
    for title, flow, rate, column, unit, exclude in (
        ("UserInfo · 12,000 TPS · 成功吞吐", "用户资料", "12,000", 5, "TPS", ()),
        ("UserInfo · 1,000 TPS · P99", "用户资料", "1,000", 10, "ms", ()),
        ("机器令牌内省 · 3,000 TPS · P99", "机器令牌内省", "3,000", 10, "ms", ("Hydra",)),
    ):
        points = [r for r in output if r[0] == flow and r[2] == rate
                  and r[3] == "标准" and r[1] not in exclude and r[column] != "—"]
        if not points:
            continue
        maximum = max(float(r[column].replace(",", "")) for r in points)
        chart = []
        for r in points:
            value = float(r[column].replace(",", ""))
            count = math.floor(value / maximum * 24 + 0.5) if maximum else 0
            bar = "`" + "█" * count + "`" if count else "—"
            chart.append([r[1], r[column], bar, r[5], r[10], r[12], r[15]])
        blocks.extend(["### " + title, table(["服务", unit, "相对长度", "成功 TPS", "P99 ms", "CPU 主／总", "有效轮数"], chart)])
        if exclude:
            blocks.append("Hydra 使用管理端内省入口，结果列于下方完整表。")
    return blocks


def section_tables(output):
    sections = defaultdict(list)
    for r in output:
        sections[r[0]].append([
            r[2], r[1], r[3], r[4] + " / " + r[5], r[6] + " / " + r[7],
            " / ".join(r[8:12]), r[12], r[13], r[14], r[15],
        ])
    blocks = ["## 固定到达率结果"]
    header = ["目标 TPS", "服务", "发压", "发出／成功 TPS", "失败／未发出",
              "P50 / P95 / P99 / P99.9 ms", "CPU 主／总（核）",
              "RSS 主／总（MiB）", "PSI %", "有效轮数"]
    for label, rows in sections.items():
        if label not in ("两类混合", "五类混合"):
            blocks.extend(["### " + label, table(header, rows)])
    mixed = [(label, rows) for label, rows in sections.items()
             if label in ("两类混合", "五类混合")]
    if mixed:
        blocks.append("<details>\n<summary>混合负载补充数据</summary>")
        for label, rows in mixed:
            blocks.extend(["### " + label, table(header, rows)])
        blocks.append("</details>")
    return blocks


def render(rows, published):
    cells = defaultdict(list)
    for row in rows: cells[group(row)].append(row)
    blocks = ["# OAuth / OIDC 单实例性能基准", INTRO] if published else ["# OAuth / OIDC 本次测量"]
    blocks.append(f"共 **{len(rows)} 个有效窗口**。下表为同配置有效窗口的逐项中位数。TPS 为每秒成功业务操作数；失败和未发出为每轮次数。延迟从计划到达到成功完成，包含调度等待。CPU 为平均用核，RSS 为采样峰值（MiB）。主／总分别表示主服务及含活跃外部依赖的整个服务端。`—` 表示没有成功延迟样本。不同配置分别列出。")
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
    if published:
        blocks.extend(overview(output))
    blocks.extend(section_tables(output))
    if published: blocks.append(METHOD)
    return "\n\n".join(blocks)+"\n"


INTRO = """每次运行一个 OAuth 服务，主服务绑定 **8 个不同物理核心，各使用 1 个逻辑 CPU**。数据库、缓存和发压端独立分配 CPU。Goose 0.19.2 以固定到达率发压。各服务使用原生认证、令牌格式和存储，Kanidm 使用 HTTPS/1.1，其余使用隔离网络内的 HTTP/1.1。

| 服务 | 被测版本 | 机器令牌与认证 | 运行配置 |
|---|---|---|---|
| NazoAuth | `af4b849c63e1e8a68b5d7564f3513a54f991a5fc` ＋随附令牌入口开关补丁 | RS256 JWT、Basic | PostgreSQL 池 32、Valkey，令牌入口 IP 配额关闭 |
| Rauthy | 0.37.2 · 标签 `fe6bcb95192e8a83c29e2b525bf4960933bea3bd` | RS256 JWT、表单凭据 | PostgreSQL 池 32、内嵌缓存；令牌签发事件关闭 |
| Kanidm | 1.12.1 · 标签 `fb052e5357cf09dcdffd07fef4045e8066a68c0b` | JWE、Basic | 内嵌数据库计入主服务，HTTPS/1.1，验证测试 CA |
| Keycloak | 26.8.2 · 镜像修订 `26018f2a4c6155cfe2c28f078996390bf5191946` | RS256 JWT、Basic | PostgreSQL 池 32、JVM 堆 512 MiB–4 GiB，JVM 可见处理器参数 16，实际执行受 8 核亲和性约束 |
| Ory Hydra | 26.2.0 · 镜像修订 `0b84568fffccf151dc5e6c7955fdfb738555bf4b` | RS256 JWT、Basic | PostgreSQL 池 32，私网隔离管理入口，以 `serve all --dev` 运行 |

NazoAuth 使用表中源码提交及令牌入口 IP 配额补丁。本构建的独立机器令牌签发和混合负载尚无有效记录；这两项保留对照服务实测数据，不沿用 NazoAuth 历史构建成绩。"""

METHOD = """## 测试方法

- **查询。** UserInfo 读取用户资料；内省读取令牌有效状态。机器令牌和用户令牌分别统计。Hydra 内省由私网管理端承接，调用者认证边界与另四家不同。
- **签发与授权。** 机器签发包含客户端认证和实际签发。授权码在测前用真实用户会话及 S256 PKCE 准备，测量时每个授权码只兑换一次。已登录链路包含重定向、必要的授权确认和兑换，免交互与显式同意各自成组。Hydra 的外部身份和同意服务未计入共同端到端授权组。
- **轮换。** 表中括号表示用户数 × 每用户独立令牌族数。成功后用返回的后继令牌继续该族。Rauthy 被测配置的后继令牌有约 240 秒生效等待；Kanidm 的重复消费行为与严格一次性兑换及即时轮换组不同。这些场景没有共同的安全和时序前提。
- **混合。** 两类混合每三次安排一次机器签发、两次内省；五类混合的签发、内省、兑换、刷新、已登录授权分别占 30%、50%、10%、5%、5%。有效机器令牌集由 16 个客户端各签发 32 枚；授权码兑换使用 32 个用户。登录、造数通过各项目管理或协议接口完成，每家使用自己的数据库。逐业务项计数和延迟见每轮 JSON 的 `operations`。
- **过载。** 成功 TPS = 测量期内计划到达、最终成功的业务数 ÷ 测量秒数，包含窗口结束后返回的成功。多 HTTP 步骤构成的一笔授权只算一次业务。未发出可能来自调度迟到、在途槽耗尽或前一个刷新未完成。成功请求延迟与成功数、失败数、未发出数一起阅读。Kanidm 在部分混合档位的成功样本全部来自内省。
- **资源。** CNB Linux x86-64。对照项目的 CPU 为 AMD EPYC 9K65、无 Swap；NazoAuth 归档记录了核与 SMT 映射。主服务无硬内存上限，数据库、缓存、Goose 及采集器使用独立核。常规配置分别给 PostgreSQL、Valkey、Goose 分配 14、2、15 个逻辑 CPU。内存取测量窗口内采样到的进程 RSS；服务端总峰值按同时刻汇总，共享页可能重复计入。CPU 是平均占用核数，宿主 CPU PSI 是存在可运行任务等待 CPU 的时间占比。
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
