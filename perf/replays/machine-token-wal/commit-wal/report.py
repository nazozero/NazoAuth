"""Report the fixed-PostgreSQL application comparison and the stock peer reference."""

import json
import statistics
import sys
from pathlib import Path

root = Path(sys.argv[1])
output = root.parent


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def latency(d, key):
    return d[key] if d["success"] and d[key] is not None else None


def table(head, rows):
    def line(cells):
        return "| " + " | ".join(map(str, cells)) + " |"

    return "\n".join([line(head), line(["---"] * len(head)), *(line(r) for r in rows)])


arms = {
    "F": "NazoAuth 原版",
    "E": "NazoAuth 合并复查与写入",
    "K": "Keycloak",
    "H": "Ory Hydra",
}
rates = (400, 2400, 6000, 8000)
retested = "--replace-third-8000" in sys.argv[2:]
windows = {}
for arm in arms:
    for rate in rates:
        has_repeat = retested and arm in ("F", "E") and rate == 8000
        for rep in range(1, 5 if has_repeat else 4):
            d = read(root / f"{arm}-{rate}-{rep}.json")
            assert d["offered_per_second"] == rate and d["k6_exit"] == 0
            assert d["outcome"] in ("accepted", "load")
            assert all(r["affinity_mismatches"] == 0 for r in d["resources"].values())
            if arm in ("F", "E"):
                assert (
                    d["whole_success"]
                    == d["wal_committed_audit_rows"]
                    == d["durable_token_issued"]
                    > 0
                )
                assert d["wal_uncommitted_audit_inserts"] == 0
            windows[arm, rate, rep] = d

summary, rounds, resources = [], [], []
for rate in rates:
    cols = []
    for arm in arms:
        chosen = (
            (1, 2, 4) if retested and arm in ("F", "E") and rate == 8000 else (1, 2, 3)
        )
        rows = [windows[arm, rate, i] for i in chosen]

        def median_latency(key):
            values = [latency(d, key) for d in rows]
            return f"{statistics.median(values):.2f}" if None not in values else "—"

        cols.append(
            [
                f"{statistics.median(d['success_per_second'] for d in rows):,.1f}",
                median_latency("p95_ms"),
                median_latency("p99_ms"),
                f"{sum(d['accepted'] for d in rows)}/3",
            ]
        )
    for i, title in enumerate(
        ("实际成功请求/秒", "P95（ms）", "P99（ms）", "严格通过轮数")
    ):
        summary.append([f"{rate:,}", title] + [c[i] for c in cols])
    for i in range(1, 5):
        for arm in arms:
            d = windows.get((arm, rate, i))
            if d is None:
                continue
            name = f"{arm}-{rate}-{i}"
            if retested and arm in ("F", "E") and rate == 8000 and i == 3:
                name += " *"

            def count(key):
                v = d.get(key)
                return f"{v:,}" if isinstance(v, int) else "—"

            rounds.append(
                [
                    name,
                    f"{d['success_per_second']:,.1f}",
                    f"{d['p95_ms']:.2f}" if latency(d, "p95_ms") is not None else "—",
                    f"{d['p99_ms']:.2f}" if latency(d, "p99_ms") is not None else "—",
                    count("whole_success"),
                    count("durable_token_issued"),
                    count("wal_committed_audit_rows"),
                    count("dropped_whole_trial"),
                    count("whole_failed"),
                    f"{d['host_cpu_psi_pct']:.2f}",
                ]
            )
            roles = d["resources"]
            resources.append(
                [name]
                + [
                    f"{roles[k]['mean_cpu_cores']:.2f} / {roles[k]['max_single_process_rss_mib']:.1f}"
                    if k in roles
                    else "—"
                    for k in ("app", "postgres", "valkey", "generator")
                ]
            )

phases = [read(root / f"diag-{rate}.phases.json") for rate in (400, 6000)]
phase_labels = [
    ("total", "应用发 COMMIT 至驱动读到成功应答"),
    ("app_to_pg", "应用发送至数据库读入"),
    ("wal_write", "写 WAL"),
    ("wal_sync", "本事务执行 WAL 刷盘系统调用"),
    ("wal_group_wait", "等待其他事务释放 WAL 写锁"),
    ("pg_runnable", "数据库进程可运行但等待 CPU"),
    ("pg_cpu", "数据库进程实际使用 CPU"),
    ("pg_to_app", "数据库发送至应用驱动读应答"),
]
phase_rows = [
    [label]
    + [f"{v['phases_ms'][k]['95']:.3f} / {v['phases_ms'][k]['99']:.3f}" for v in phases]
    for k, label in phase_labels
]
phase_table = table(
    ["COMMIT 分段（P95 / P99，ms）", "400 请求/秒", "6,000 请求/秒"], phase_rows
)
timings = [read(root / f"http-{r}.timing.json") for r in (400, 6000)]
http_windows = [read(root / f"http-{r}.json") for r in (400, 6000)]
for timing, window in zip(timings, http_windows, strict=True):
    assert timing["measured_success"]["count"] == window["success"]
    assert 100 <= timing["postcommit_samples"]["count"] <= window["success"]
    assert (
        window["whole_success"]
        == window["durable_token_issued"]
        == window["wal_committed_audit_rows"]
    )
http_table = table(
    ["HTTP 分段（P95 / P99，ms）", "400 请求/秒", "6,000 请求/秒"],
    [
        [label, *[f"{t[key]['p(95)']:.3f} / {t[key]['p(99)']:.3f}" for t in timings]]
        for key, label in [
            ("after_commit_ms", "应用确认事务成功至 HTTP 响应准备就绪"),
            ("wait_first_byte_ms", "k6 发完请求至收到响应首字节"),
            ("receive_ms", "k6 收到首字节至收完响应"),
        ]
    ],
)
sum_table = table(["目标请求/秒", "指标", *arms.values()], summary)
all_rows = table(
    [
        "轮次",
        "成功请求/秒",
        "P95 ms",
        "P99 ms",
        "成功签发",
        "应用提交确认",
        "WAL 已提交审计行",
        "漏发",
        "失败",
        "宿主 CPU PSI %",
    ],
    rounds,
)
res_table = table(["轮次", "应用", "PostgreSQL", "Valkey", "k6"], resources)
total = sum(
    d["whole_success"] for (arm, _, _), d in windows.items() if arm in ("F", "E")
)
audited = sum(arm in ("F", "E") for arm, _, _ in windows)
repeat_note = (
    "8,000 档第 3 对的原版窗口和环境指纹读取重叠，已在查看该轮结果前决定成对重测。"
    "主表采用第 1、2、4 对，带星号的原窗口保留在逐轮表中。"
    if retested
    else ""
)
events = read(root / "keycloak-events.json")
assert isinstance(events["eventsEnabled"], bool)
events_status = "开启" if events["eventsEnabled"] else "关闭"
report = f"""# 机器访问令牌签发延迟

## 同负载直接比较

{sum_table}

每格取三轮中位数。P95 和 P99 分别表示 95% 和 99% 的成功请求在该时间内完成，越低越快。严格通过要求含预热零漏发、零失败、负载发生器有余量且采样有效。NazoAuth 还要求审计计数相符。吞吐只统计计时段成功响应。漏发计入稳定性判定，成功响应延迟不包含漏发。Keycloak 26.8.2 的 realm 管理 API 显示本次用户事件持久化{events_status}。{repeat_note}

## COMMIT 拆分

{phase_table}

400 和 6,000 档分别匹配 {phases[0]["samples"]:,}、{phases[1]["samples"]:,} 笔 COMMIT。每档最慢 5% 中，WAL 写、同步及等待其他事务刷盘合计超过一半的分别有 {phases[0]["wal_majority_slowest5"]}/{phases[0]["slowest5"]}、{phases[1]["wal_majority_slowest5"]}/{phases[1]["slowest5"]} 笔。本事务没有负责刷盘时，本地同步列记零。运行队列时间取 Linux schedstat，可能与系统调用墙钟时间重叠，各列分位数不可相加。收发端点为应用 PostgreSQL 驱动与数据库套接字。探针仅在诊断轮开启。

## HTTP 响应耗时

{http_table}

这两轮单独使用原应用的采样构建和原 PostgreSQL。每 16 个请求抽一个，在仓储收到成功提交、归还连接时打点，到最外层 HTTP 中间件备好响应时读取同一请求的时钟。两个档位分别收到 {int(timings[0]["postcommit_samples"]["count"]):,} 和 {int(timings[1]["postcommit_samples"]["count"]):,} 个时间标记。首字节和接收时间由 k6 在计时段的所有成功请求上测得。首字节等待包括服务端处理，和应用分段相互重叠。诊断轮的请求独立对账，未计入对照表。

## 逐轮对账

F 为原版，E 为合并语句候选，K 为 Keycloak，H 为 Ory Hydra。NazoAuth {audited} 个窗口共成功签发 {total:,} 次。每轮核对 k6 成功响应、应用提交确认和 PostgreSQL 已刷 WAL 区间内具有对应事务提交记录的审计表插入。区间在夹具验证之后开始，覆盖预热、计时和在途请求排空。此专用窗口只有机器令牌签发写审计。WAL 按物理表与事务 ID 计数，应用按事件类型计数。测试数据来自产品 CLI 和 HTTP API。

{all_rows}

## 每轮资源

每格为平均 CPU 核数 / 单进程峰值 RSS（MiB）。PostgreSQL 有多个进程，该列为进程中的最高值。各角色的网络字节数及共享 cgroup 的磁盘 I/O、内存与节流数据在每轮汇总 JSON 中。

{res_table}

## 环境与限制

k6 2.1.0 恒定到达率。应用使用 16 个物理核、PostgreSQL 14 个逻辑 CPU、Valkey 2 个、k6 15 个，采样另绑 1 核。逐轮核验线程亲和性。两版相同 32 连接池、产品数据库、持久卷和 API 夹具。使用原有 PostgreSQL 18.7 进程和启动参数，fsync、同步提交与整页写开启，wal_sync_method=fdatasync、commit_delay=0。NazoAuth 在一个显式事务内持久化签发审计；外部锚定关闭。

每轮重启应用，PostgreSQL 持续运行。10 秒预热后，400 档计时 30 秒，其余档 36 秒。NazoAuth 两版交替运行。Keycloak 的 400、6,000 和 8,000 档在首轮应用对照后测量，2,400 档轮换 NazoAuth 两版和 Keycloak。Hydra 在轮换结束后测量。各产品使用独立数据库。绑核不能消除共享宿主及存储波动。未通过稳定性判定的完整窗口也在表中。某轮没有成功响应时，该轮延迟及对应的三轮延迟中位数记作“—”。
"""
(output / "report.md").write_text(report, encoding="utf-8")
prsum = []
for r in summary:
    translated = {
        "实际成功请求/秒": "Successful req/s",
        "P95（ms）": "P95 ms",
        "P99（ms）": "P99 ms",
        "严格通过轮数": "Passing trials",
    }[r[1]]
    prsum.append([r[0], translated, *r[2:]])
(output / "tables-pr.md").write_text(
    table(
        [
            "Offered/s",
            "Metric",
            "NazoAuth current",
            "NazoAuth combined statement",
            "Keycloak",
            "Ory Hydra",
        ],
        prsum,
    )
    + "\n\n<details><summary>Individual k6 windows and committed WAL reconciliation</summary>\n\n"
    + table(
        [
            "Window",
            "Delivered/s",
            "P95 ms",
            "P99 ms",
            "HTTP success",
            "Adapter ACK",
            "WAL rows",
            "Dropped",
            "Failed",
            "CPU PSI %",
        ],
        rounds,
    )
    + "\n\n</details>\n",
    encoding="utf-8",
)
