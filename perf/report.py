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
import gzip
import struct
import zipfile
from collections import defaultdict
from pathlib import Path
from statistics import median

from monitor.summarize import summarize
from monitor.memory_window import smaps_peaks
from monitor.pg_window import peak as pg_peak, totals as pg_totals

HERE = Path(__file__).resolve().parent
SERVICES = {"nazo": "NazoAuth", "rauthy": "Rauthy", "kanidm": "Kanidm", "keycloak": "Keycloak", "hydra": "Hydra"}
FLOWS = {"machine": "机器令牌签发", "introspect": "机器令牌内省", "user-introspect": "用户令牌内省",
         "userinfo": "用户资料", "exchange": "授权码兑换（PKCE）", "refresh": "刷新令牌轮换",
         "authorize-consent": "已登录授权＋兑换（显式同意）", "authorize-silent": "已登录静默授权＋兑换", "authorize": "已登录授权＋兑换",
         "mixed": "两类混合", "mixed-core": "五类混合", "mixed-core-consent": "五类混合（授权子操作含同意）"}


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


def reconstruct_window(archive, row, sample, tmp):
    for member in archive:
        if member.name == "pg-maps" or member.name.startswith("pg-maps/"):
            continue
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
    for k in ("app_peak_pss_mib", "server_peak_pss_mib", "role_peak_rss_mib", "server_peak_rss_mib"):
        if measured.get(k) != row.get(k):
            raise ValueError(f"{sample.name}: {k}")
    for role, counters in row["resources"].items():
        for k in ("cpu_seconds","mean_cpu_cores","peak_rss_sum_mib"):
            if not math.isclose(measured["resources"][role][k],counters[k],rel_tol=1e-12):
                raise ValueError(f"{sample.name}: {role}/{k}")
    return measured


def validate_ledgers(rows):
    by_id = {r["id"]: r for r in rows}
    with tempfile.TemporaryDirectory() as work:
        ledger = Path(work) / "arrivals.tsv"
        for sample in sorted((HERE / "evidence/samples").glob("*.tar.gz")):
            row = by_id[sample.name.removesuffix(".tar.gz")]
            if os.name == "posix" and Path("/proc/stat").exists():
                # seal.py uses the Linux procfs clock tick unit to integrate CPU samples.
                with tempfile.TemporaryDirectory(dir=work) as tmp, tarfile.open(sample) as archive:
                    measured = reconstruct_window(archive, row, sample, tmp)
            else:
                with tarfile.open(sample) as archive, archive.extractfile("arrivals.tsv") as inp, ledger.open("wb") as out:
                    shutil.copyfileobj(inp, out)
                measured = summarize(ledger, row["rate"], row["warm_seconds"], row["seconds"])
            if measured["operations"] != row["operations"]:
                raise ValueError(f"{sample.name}: operation ledger differs")


def validate_memory_tails():
    evidence = HERE / "evidence"
    observations = [json.loads(s) for s in (evidence / "protocol-memory.jsonl").read_bytes().splitlines()]
    with zipfile.ZipFile(evidence / "memory-success-latencies.zip") as vectors, tempfile.TemporaryDirectory() as tmp:
        expected_entries = set()
        for r in observations:
            standard = evidence / "windows" / (r["window"] + ".json")
            reference = evidence / "userinfo-reference" / (r["window"] + ".tar.gz")
            if standard.is_file():
                # validate_ledgers independently reconstructs the underlying performance window.
                op = json.loads(standard.read_bytes())["operations"]["all"]
            elif reference.is_file():
                with tarfile.open(reference) as archive, archive.extractfile("arrivals.tsv") as src:
                    path = Path(tmp) / "arrivals.tsv"
                    with path.open("wb") as dest:
                        shutil.copyfileobj(src, dest)
                    op = summarize(path, r["target_tps"], 10, r["seconds"])["operations"]["all"]
            else:
                name = f"{r['peer']}-{r['start_ns']}.u64le"
                expected_entries.add(name)
                values = [v for (v,) in struct.iter_unpack("<Q", vectors.read(name))]
                if len(values) != r["success"] or any(b < a for a,b in zip(values,values[1:])):
                    raise ValueError(f"invalid duration series: {name}")
                if any(values[(q*len(values)+99)//100-1] / 1e6 != r["successful_tail_ms"][str(q)] for q in (95,99)):
                    raise ValueError(f"tail latency mismatch: {name}")
                continue
            if any(op[k] != r[k] for k in ("planned","sent","success","failed")) or any(
                    op["offered_to_completion_success_ms"][q] != r["successful_tail_ms"][q] for q in ("95","99")):
                raise ValueError(f"memory and arrival evidence differ: {r['window']}")
        if expected_entries != set(vectors.namelist()):
            raise ValueError("unexpected latency vector files")


def validate_pg_ledgers():
    evidence = HERE / "evidence"
    with gzip.open(evidence / "postgres-maps.jsonl.gz", "rt") as stream, zipfile.ZipFile(
            evidence / "pg-arrivals.zip") as archive, tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "arrivals.tsv"
        seen = set()
        for line in stream:
            row = json.loads(line)
            name = f"{row['peer']}-{row['start_ns']}.tsv"
            if name in seen:
                raise ValueError("duplicate PostgreSQL window")
            seen.add(name)
            with archive.open(name) as src, path.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            op = summarize(path, row["rate"], row["warm_seconds"], row["seconds"])["operations"]["all"]
            if (any(op[k] != row[k] for k in ("planned","sent","success","failed","http_requests","outcomes")) or
                op["not_sent"] != row["unsent"]) or any(
                    op["offered_to_completion_success_ms"][q] != row["successful_tail_ms"][q] for q in ("95","99")):
                raise ValueError(f"PostgreSQL window ledger mismatch: {name}")
        if seen != set(archive.namelist()):
            raise ValueError("unexpected PostgreSQL ledger files")


def formatted(values, digits=2):
    data = [v for v in values if v is not None]
    return f"{median(data):,.{digits}f}" if data else "—"


def table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    return "\n".join(lines + ["| " + " | ".join(map(str, row)) + " |" for row in rows])


def common_coverage(rows):
    tiers = defaultdict(set)
    for row in rows:
        flow, rate, peer, profile, *_ = group(row)
        if profile != "base" or rate not in (100, 1000, 3000, 6000, 12000):
            continue
        if flow == "authorize":
            flow = "authorize-consent" if peer == "nazo" else "authorize-native"
        if flow == "mixed-core" and peer == "nazo":
            flow = "mixed-core-consent"
        tiers[flow, peer].add(rate)
    scenarios = ("machine", "introspect", "user-introspect", "userinfo", "exchange", "refresh",
                 "authorize-native", "authorize-silent", "authorize-consent", "mixed", "mixed-core", "mixed-core-consent")
    separate = {
        "exchange": {"kanidm"}, "refresh": {"kanidm", "rauthy"},
        "authorize-native": {"hydra", "nazo"}, "authorize-consent": {"hydra", "kanidm"}, "authorize-silent": {"hydra"},
        "mixed-core": {"hydra", "kanidm", "rauthy", "nazo"},
        "mixed-core-consent": {"hydra", "kanidm", "rauthy"},
    }
    data = []
    for flow in scenarios:
        cells = []
        for peer in SERVICES:
            rates = tiers[flow, peer]
            cells.append("、".join(f"{r:,}" for r in sorted(rates)) if rates else
                         "独立语义" if peer in separate.get(flow, ()) else "无有效窗口")
        label = {"authorize-native": "已登录授权＋兑换（已授权客户端）",
                 "mixed-core": "五类混合（授权子操作免同意）"}.get(flow) or FLOWS[flow]
        data.append([label, *cells])
    return table(["业务／目标 TPS", *SERVICES.values()], data)


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


def login_table():
    directory = HERE / "evidence/login"
    rows = []
    for run in (1, 2, 3):
        batches = [json.loads((directory / f"{run}-{i}.json").read_bytes()) for i in (1, 2, 3)]
        if any(len(batch["operations"]) != 32 or batch["ms"] <= 0 for batch in batches):
            raise ValueError("incomplete login batch")
        ok = sorted(ms for batch in batches for status, ms in batch["operations"] if status == "ok")
        duration = sum(batch["ms"] for batch in batches) / 1000
        cold, _ = map(int, (directory / f"{run}-cold.kib").read_text().split())
        idle, peak = map(int, (directory / f"{run}-3.kib").read_text().split())
        tail = [f"{ok[math.ceil(q * len(ok)) - 1]:.2f}" if ok else "—" for q in (.95, .99)]
        rows.append([run, f"{len(ok)} / {96-len(ok)}", f"{len(ok)/duration:.2f}", *tail,
                     f"{cold/1024:.1f}", f"{idle/1024:.1f}", f"{peak/1024:.1f}"])
    return table(["轮次", "成功／失败", "批内成功 TPS", "P95 ms", "P99 ms", "启动 PSS MiB",
                  "登录后 PSS MiB", "进程峰值 RSS MiB"], rows)


def memory_table(observations):
    observations = list(observations)
    if len({r.get("product_revision") for r in observations if r["peer"] == "nazo"}) > 1:
        raise ValueError("mixed NazoAuth builds in memory observations")
    cells = defaultdict(list)
    seen = set()
    for r in observations:
        peer, rate = r["peer"], r["target_tps"]
        key = peer, r["start_ns"]
        if key in seen:
            raise ValueError("duplicate memory window")
        seen.add(key)
        seconds = r["seconds"]
        if (r["planned"] != rate * seconds or r["success"] + r["failed"] != r["sent"]
                or r["sent"] + r["unsent"] != r["planned"] or r["success"] <= 0):
            raise ValueError("memory window traffic accounting")
        samples = r["smaps_kib"] if "smaps_kib" in r else r["pss_kib"]
        measured = smaps_peaks(peer, r["start_ns"], seconds, samples)
        if any(measured[k] != r[k] for k in ("pss_samples", "role_peak_pss_mib", "server_peak_pss_mib")):
            raise ValueError("PSS differs from the role samples")
        if any(measured.get(k) != r.get(k) for k in ("role_peak_rss_mib", "server_peak_rss_mib")):
            raise ValueError("RSS differs from the smaps samples")
        flow = r.get("scenario", "userinfo")
        cells["introspect" if flow == "machine-introspect" else flow, rate, peer].append(r)

    rows = []
    for (flow, rate, peer), group in sorted(cells.items(), key=lambda item: (
            list(FLOWS).index(item[0][0]), item[0][1], list(SERVICES).index(item[0][2]))):
        traffic = [formatted([r[k] / r["seconds"] for r in group]) for k in ("sent", "success")]
        tail = [formatted([(r.get("successful_tail_ms") or {}).get(q) for r in group]) for q in ("95", "99")]
        components = []
        for role in ("app", "postgres", "valkey"):
            values = [formatted([r.get(f"role_peak_{kind}_mib", {}).get(role) for r in group], 1)
                      for kind in ("rss", "pss")]
            components.append(" / ".join(values) if values != ["—", "—"] else "—")
        total = [formatted([r.get(f"server_peak_{kind}_mib") for r in group], 1) for kind in ("rss", "pss")]
        totals = [r["server_peak_pss_mib"] for r in group]
        label = FLOWS[flow]
        if flow == "authorize":
            label += "（显式同意）" if peer == "nazo" else "（已授权客户端）"
        rows.append([label, f"{rate:,}", SERVICES[peer], " / ".join(traffic), " / ".join(tail), *components,
                     " / ".join(total), f"{min(totals):,.1f}–{max(totals):,.1f}",
                     f"{len(group)} / {sum(r['performance_status'] in ('PASS', 'FAIL') for r in group)}",
                     sum("external_cpu_contention" in r["performance_invalid_reasons"] for r in group)])
    return table(["业务", "目标 TPS", "服务", "实发 / 成功 TPS", "观测 P95 / P99 ms", "主服务 RSS / PSS", "PostgreSQL RSS / PSS",
                  "Valkey RSS / PSS", "服务端 RSS / PSS", "总 PSS 范围", "内存 / 性能有效轮数", "受宿主干扰轮数"], rows)


def validate_pool_ledgers():
    with tempfile.TemporaryDirectory() as tmp:
        ledger = Path(tmp) / "arrivals.tsv"
        for path in sorted((HERE / "evidence/pool-locality").glob("*.tar.gz")):
            with tarfile.open(path) as archive:
                row = json.load(archive.extractfile("summary.json"))
                if os.name == "posix" and Path("/proc/stat").exists():
                    with tempfile.TemporaryDirectory(dir=tmp) as work:
                        measured = reconstruct_window(archive, row, path, work)
                    if measured["operations"] != row["operations"]:
                        raise ValueError(f"pool comparison ledger differs: {path.name}")
                    continue
                with archive.extractfile("arrivals.tsv") as stream, ledger.open("wb") as dest:
                    shutil.copyfileobj(stream, dest)
                ops = summarize(ledger, row["rate"], row["warm_seconds"], row["seconds"])["operations"]
                if ops != row["operations"]:
                    raise ValueError(f"pool comparison ledger differs: {path.name}")
                epoch = int(next(line.split()[0].split(b"=")[1] for line in archive.extractfile("window") if line.startswith(b"epoch_ns=")))
                samples = [list(map(int, line.split())) for line in archive.extractfile("pss.tsv")]
                m = smaps_peaks(row["peer"], epoch + row["warm_seconds"]*10**9, row["seconds"], samples)
                for k in ("role_peak_rss_mib", "role_peak_pss_mib", "server_peak_pss_mib"):
                    if row[k] != m[k]:
                        raise ValueError(f"pool comparison smaps differs: {path.name}, {k}")


def pool_report():
    samples = defaultdict(list)
    root = HERE / "evidence/pool-locality"
    for archive in sorted(root.glob("*.tar.gz")):
        trial, name = archive.name.removesuffix(".tar.gz").split("-", 1)
        flow, variant = name.rsplit("-", 1)
        with tarfile.open(archive) as t:
            r = json.load(t.extractfile("summary.json"))
            db_bytes = json.load(t.extractfile("pg-maps/before.json"))["db_bytes"]
        samples[flow, trial].append((variant, r, db_bytes))
    result = []
    for flow in ("exchange", "refresh", "authorize-silent", "authorize"):
        pairs = [g for (f, _), g in samples.items() if f == flow]
        for pair in pairs:
            if len(pair) != 2 or {v for v, _, _ in pair} != {"fifo", "lifo"} or pair[0][2] != pair[1][2]:
                raise ValueError(f"incomplete pool comparison or unequal starting database sizes: {flow}")
        valid = [g for g in pairs if all(r["status"] in ("PASS", "FAIL") and not r["invalid_reasons"] for _, r, _ in g)]
        for variant in ("fifo", "lifo"):
            subset = [r for g in valid for v, r, _ in g if v == variant]
            ops = [r["operations"]["all"] for r in subset]
            latency = " / ".join(formatted([op["offered_to_completion_success_ms"][q] for op in ops]) for q in ("95", "99"))
            pg = " / ".join(formatted([r[k]["postgres"] for r in subset], 1) for k in ("role_peak_rss_mib", "role_peak_pss_mib"))
            cpu = " / ".join((formatted([r["resources"]["app"]["mean_cpu_cores"] for r in subset]),
                              formatted([r["server_total_cpu_cores"] for r in subset])))
            pss = " / ".join(formatted([r[k] for r in subset], 1) for k in ("app_peak_pss_mib", "server_peak_pss_mib"))
            result.append([("已登录显式同意＋兑换" if flow == "authorize" else FLOWS[flow]), variant.upper(), formatted([op["successful_tps"] for op in ops]), latency, pg, pss, cpu, len(valid)])
    return table(["业务","策略","成功 TPS","P95 / P99 ms","PG RSS / PSS（MiB）","主服务 / 总 PSS（MiB）","主服务 / 总 CPU（核）","有效配对组数"], result)


def pg_context_table():
    captures = json.loads((HERE / "evidence/environment/pg-contexts.json").read_bytes())
    result = []
    for capture in captures:
        sample = json.loads((HERE / "evidence/windows" / (capture["after_window"] + ".json")).read_bytes())
        if sample["peer"] != capture["peer"] or sample["flow"] != "exchange" or sample["rate"] != 1000:
            raise ValueError("PostgreSQL context sample is linked to a different workload")
        backends = list(capture["backends"].values())
        total = [sum(b["total"][i] for b in backends) / 2**20 for i in range(3)]
        def allocated(*contexts):
            return sum(b["contexts"].get(k, [0])[0] for k in contexts for b in backends) / 2**20
        result.append([SERVICES[capture["peer"]], len(backends), *(f"{v:.1f}" for v in total),
                       f"{allocated('CacheMemoryContext'):.1f}", f"{allocated('CachedPlan', 'CachedPlanSource'):.1f}"])
    return table(["服务", "空闲连接数", "分配", "其中空闲", "在用", "CacheMemoryContext 分配",
                  "CachedPlan 与 CachedPlanSource 分配"], result)


def pg_tables():
    with gzip.open(HERE / "evidence/postgres-maps.jsonl.gz", "rt", encoding="utf8") as stream:
        records = [json.loads(line) for line in stream]
    sequences = defaultdict(list)
    for row in records:
        if "sequence" in row:
            sequences[row["sequence"]].append(row)
    for block in sequences.values():
        block.sort(key=lambda row: row["start_ns"])
        if ([(r["stage"], r["scenario"], r["mode"]) for r in block] != [
                ("1", "authorize", "restart"), ("2", "authorize", "retain"), ("3", "userinfo", "retain")] or
            len({(r["samples"][0]["device"], r["samples"][0]["inode"]) for r in block}) != 1 or
            any((r["samples"][0]["device"], r["samples"][0]["inode"]) !=
                (r["disconnected"]["device"], r["disconnected"]["inode"]) for r in block)):
            raise ValueError("inconsistent PostgreSQL repeat sequence")
    groups = defaultdict(list)
    for r in records:
        groups[r["scenario"], r["rate"], r["peer"], r.get("stage", "cold")].append((r, pg_peak(r)))
    cold, repeat, activity = [], [], []
    for (flow, rate, peer, stage), group in sorted(groups.items(), key=lambda kv: (
            list(FLOWS).index(kv[0][0]), kv[0][1], list(SERVICES).index(kv[0][2]), kv[0][3])):
        records, peaks = zip(*group)
        def field(i):
            return formatted([p[i] / 1024 for p in peaks], 1)
        tail = " / ".join(formatted([r["successful_tail_ms"][q] for r in records]) for q in ("95","99"))
        footprint = field(1) + " / " + field(2)
        if stage == "cold":
            cold.append([("已登录授权＋兑换（显式同意）" if flow == "authorize" and peer == "nazo" else FLOWS[flow]), f"{rate:,}", SERVICES[peer], formatted([r["success"]/r["seconds"] for r in records]),
                         tail, formatted([p[0] for p in peaks], 0), footprint, field(3), field(5) + " / " + field(6),
                         formatted([100*(p[5]-p[6])/(p[1]-p[2]) for p in peaks], 1),
                         formatted([r["before"]["db_bytes"]/2**20 for r in records], 1),
                         f"{len(group)} / {sum(r['performance_status'] != 'INVALID' for r in records)}"])
            if peer == "nazo":
                def changes(keys):
                    return formatted([sum(r["after"][k] - r["before"][k] for k in keys) for r in records], 0)
                activity.append([FLOWS[flow], f"{rate:,}", changes(("hits",)), changes(("reads",)),
                                 changes(("inserts",)), changes(("updates",)), changes(("deletes",))])
        else:
            after = [pg_totals(r["disconnected"]) for r in records]
            idle = " / ".join(formatted([a[i]/1024 for a in after],1) for i in (1,2))
            repeat.append([stage, FLOWS[flow], tail, footprint, field(3), idle,
                           formatted([a[3]/1024 for a in after], 1), len(group)])
    return [table(["业务", "目标 TPS", "服务", "成功 TPS", "观测 P95 / P99 ms", "PG 进程", "PG RSS / PSS",
                   "PG 私有页", "主共享映射 RSS / PSS", "差额解释比例 %", "测前库大小", "观测 / 性能有效轮数"], cold),
            "NazoAuth 的四条授权写链路均跑到约 1,000 成功 TPS。与 UserInfo 相比，它们在 RSS 峰值时有更多数据库进程，主共享映射被更多进程同时计入 RSS，私有页和 PSS 也有实际增加。下表是每轮准备夹具前至停压后的 PostgreSQL 统计增量中位数，包含夹具、预热和正式窗口。缓冲区读取计数可包含操作系统页缓存命中，无法由此推算物理磁盘读取量。",
            table(["NazoAuth 业务", "目标 TPS", "缓冲区命中", "读入缓冲区的块", "插入行", "更新行", "删除行"], activity),
            "同库重复试验使用同一个 NazoAuth 数据库，每组依次运行以下三步。组内只在第一步重启 PostgreSQL。每步结束后停止应用，再采集 PostgreSQL；三步的开始时间、共享映射标识和断连后读数均保存在附件。",
            table(["顺序", "业务", "观测 P95 / P99 ms", "峰时 PG RSS / PSS", "峰时私有页", "断连后 PG RSS / PSS", "断连后私有页", "轮数"], sorted(repeat)),
            "断连后的读数只统计仍在运行的 PostgreSQL 进程所映射的页。内核仍可保留文件缓存与共享内存对象；进程 PSS 的下降不能单独证明整机释放了等量内存。本试验观察短时负载和连接生命周期，无法判断长期泄漏。"]

def section_tables(output):
    pss_sections = {r[0] for r in output if r[16] != "—"}
    sections = defaultdict(list)
    for r in output:
        sections[r[0]].append([
            r[2], r[1], r[3], r[4] + " / " + r[5], r[6] + " / " + r[7],
            " / ".join(r[8:12]), r[12], r[13], *([r[16]] if r[0] in pss_sections else []), r[14], r[15],
        ])
    blocks = ["## 固定到达率结果"]
    header = ["目标 TPS", "服务", "发压", "发出／成功 TPS", "失败／未发出",
              "P50 / P95 / P99 / P99.9 ms", "CPU 主／总（核）",
              "RSS 主／总（MiB）", "PSI %", "有效轮数"]
    for label, rows in sections.items():
        if label != "两类混合" and not label.startswith("五类混合"):
            blocks.append("### " + label)
            columns = header[:-2] + ["峰值 PSS 主／PG／Valkey／总（MiB，采样轮数）"] + header[-2:] if label in pss_sections else header
            blocks.append(table(columns, rows))
    mixed = [(label, rows) for label, rows in sections.items()
             if label == "两类混合" or label.startswith("五类混合")]
    if mixed:
        blocks.append("<details>\n<summary>混合负载补充数据</summary>")
        for label, rows in mixed:
            columns = header[:-2] + ["峰值 PSS 主／PG／Valkey／总（MiB，采样轮数）"] + header[-2:] if label in pss_sections else header
            blocks.extend(["### " + label, table(columns, rows)])
        blocks.append("</details>")
    return blocks


def render(rows, published):
    cells = defaultdict(list)
    for row in rows:
        revision = row.get("product_revision", "unknown") if row["peer"] == "nazo" else ""
        cells[(*group(row), revision, "role_peak_pss_mib" in row)].append(row)
    blocks = ["# OAuth / OIDC 单实例性能基准", INTRO] if published else ["# OAuth / OIDC 本次测量"]
    blocks.append(f"固定到达率测试共 **{len(rows)} 个有效窗口**。下表为同配置有效窗口的逐项中位数。发出／成功 TPS 分别为每秒发出／成功的业务操作数；失败和未发出为每轮次数。延迟从计划到达到成功完成，包含调度等待。CPU 为平均用核，RSS 为采样峰值（MiB）。主／总分别表示主服务及含活跃外部依赖的整个服务端。`—` 表示缺少相应样本。有无 PSS 采样的窗口分行汇总；每行吞吐、分位延迟和内存使用同一组窗口。PSS 栏括号内为实采轮数，各组件单列峰值，服务端总值取同批读数之和的峰值。不同配置分别列出。")
    output = []
    for key, group_rows in sorted(cells.items(), key=lambda kv: (list(FLOWS).index(kv[0][0]),kv[0][1],kv[0][3],list(SERVICES).index(kv[0][2]),kv[0][6:])):
        flow,rate,peer,profile,warm,seconds,users,families,revision,has_pss = key
        ops = [r["operations"]["all"] for r in group_rows]
        def metric(k,d=2):return formatted([o[k] for o in ops],d)
        def stat(k,d=2):return formatted([r[k] for r in group_rows],d)
        lat = [formatted([(o["offered_to_completion_success_ms"] or {}).get(q) for o in ops]) for q in ("50","95","99","99.9")]
        cpu = formatted([r["resources"]["app"]["mean_cpu_cores"] for r in group_rows]) + " / " + stat("server_total_cpu_cores")
        mem = formatted([r["role_peak_rss_mib"]["app"] if "role_peak_rss_mib" in r
                         else r["resources"]["app"]["peak_rss_sum_mib"] for r in group_rows], 1) + " / " + formatted(
                             [r.get("server_peak_rss_mib", r["server_peak_rss_sum_mib"]) for r in group_rows], 1)
        sampled = [r for r in group_rows if "role_peak_pss_mib" in r]
        pss = "—"
        if sampled:
            roles = [formatted([r["role_peak_pss_mib"].get(role) for r in sampled], 1)
                     for role in ("app", "postgres", "valkey")]
            pss = " / ".join([*roles, formatted([r["server_peak_pss_mib"] for r in sampled], 1)]) + f"（{len(sampled)}）"
        label=FLOWS[flow] + (f"（{users}×{families}）" if users else "")
        if flow == "authorize":
            label += "（显式同意）" if peer == "nazo" else "（已授权客户端）"
        if flow == "mixed-core":
            label += "（授权子操作含同意）" if peer == "nazo" else "（授权子操作免同意）"
        service = SERVICES[peer] + (f" (`{revision[:7]}`)" if peer == "nazo" and not published else "")
        output.append([label, service, format(rate,","), "宽" if profile=="journal-wide" else "标准",
                       formatted([a["sent"]/seconds for a in ops]),metric("successful_tps"),metric("failed",1),metric("not_sent",1),
                       *lat,cpu,mem,stat("host_cpu_psi_pct"),len(ops),pss])
    if published:
        blocks.extend(["## 五服务覆盖", "下表列出五个规定档位中，各服务在标准发压配置下有有效窗口的目标 TPS。各档轮数、成功吞吐及尾延迟见下方明细。“独立语义”所指的协议差异见测试方法。“无有效窗口”表示缺少可发表的观测；有效窗口中测得的零成功会列为 0。", common_coverage(rows)])
        blocks.extend(overview(output))
        blocks.extend(["## NazoAuth 密码登录", login_table(),
                       "每轮启动新进程，32 个已注册账户以 8 并发登录三批，每批 32 次。客户端核验登录响应和 CSRF Cookie。批内吞吐为成功数除以三批实际耗时之和，排除批间 3 秒空闲。延迟从客户端发起登录计至响应及 Cookie 检查完成，每轮 96 个样本，P99 为最慢一次。登录后 PSS 取末批结束 3 秒时的读数，峰值 RSS 为该进程的内核高水位。该闭环登录诊断未同步采集宿主 PSI，延迟与吞吐仅描述此次运行。Hydra 将密码验证委托给外部身份系统，其余服务的密码验证策略在此项中也未统一。"])
    if published:
        blocks.extend(["## 服务进程内存",
                       "单位为 MiB。每格为逐轮采样峰值的中位数。RSS 将各进程映射的共享页分别计入，PSS 按共享比例分摊。服务端合计取同批读数之和的峰值；单个组件的峰值可能出现在不同时刻。PostgreSQL 的多个后端可同时映射共享缓冲区，评估部署占用时应优先读服务端 PSS。横线表示无此依赖或缺少对应读数。Kanidm 的内嵌存储和 Rauthy 的内嵌缓存计入主服务。[Linux 内存统计](https://docs.kernel.org/filesystems/proc.html) · [PostgreSQL 共享缓冲区](https://www.postgresql.org/docs/18/runtime-config-resource.html#GUC-SHARED-BUFFERS)",
                       memory_table(map(json.loads, (HERE / "evidence/protocol-memory.jsonl").read_bytes().splitlines())),
                       "每约 2 秒读取服务进程树的 Linux `smaps_rollup`。原始行依次为起止时间（Unix 纳秒）、各角色 PSS、已采集时的各角色 RSS（KiB）；角色顺序为主服务、适用的数据库及缓存。各角色同批采集，跨度最多 1 秒，每轮至少覆盖正式窗口的 65%。UserInfo 使用 32 个不同用户的真实令牌。NazoAuth 每轮重启主服务，UserInfo 专项在组前重启 PostgreSQL，组内延续数据库状态。授权等常规窗口使用该服务已有的数据；逐映射专项按下节说明重启数据库。PostgreSQL 配置为 1 GiB 共享缓冲区、128 个最大连接，应用池为 32。本表的吞吐、P95/P99 和内存均来自同一组观测轮次；延迟按计划到达至成功完成计算，各轮分位数再取中位数。包含宿主干扰或发压迟到的观测仅供参考。“受宿主干扰轮数”是其中被核心调度与 PSI 核查标记的轮数。只有满足整套性能有效性标准的窗口才进入下方吞吐与延迟对照。[逐轮采样与业务计数](evidence/protocol-memory.jsonl) · [12,000 TPS 原始到达记录](evidence/userinfo-reference/) · [其余未归档窗口的成功耗时序列](evidence/memory-success-latencies.zip)"])
    if published:
        blocks.extend(["## PostgreSQL 驻留页核查",
                       "下表各轮在发压前重启数据库进程，保留该服务已有的业务数据和操作系统页缓存。每约 2 秒从 PostgreSQL 各 PID 的 smaps 读取一次页统计。每轮选 PG 合计 RSS 最高的完整采样，取该时刻的 PSS、私有页（Private_Clean + Private_Dirty）、进程数及主共享映射。一个采样批次最多 1 秒。表中为各轮中位数，内存单位 MiB。兑换预热 5 秒、测量 20 秒，其余预热 10 秒、测量 36 秒。P95/P99 取当轮成功业务的计划到达至完成耗时。最后一列分别给出内存采样有效、同时满足正式性能观测条件的轮数。",
                       "主共享映射取 postmaster 最大的可写共享映射，按设备号与 inode 在所有数据库进程中匹配。差额解释比例 =（该映射 RSS − PSS）/（全部 PG RSS − PSS）。该映射包含 PostgreSQL 主共享内存。采样可以识别同一对象被重复计数的部分，无法据此分辨对象中每页的数据库用途。[Linux 内存统计](https://docs.kernel.org/filesystems/proc.html) · [PostgreSQL 共享内存](https://www.postgresql.org/docs/18/runtime-config-resource.html)",
                       *pg_tables(),
                       "Keycloak 静默授权的三轮都完成了计划请求，宿主 CPU PSI 为 18.05%–22.51%，该行延迟仅供参考。Hydra 的兑换与轮换未达到 1,000 成功 TPS，表中保留实得吞吐。各项目测前数据库的物理大小也有差异，跨项目的内存差值同时受数据规模和实现方式影响。Hydra 的外部同意流程与共同授权链路边界不同；Kanidm 使用内嵌存储。静默授权使用已登录会话和 `prompt=none`；成功流程为授权与兑换两个 HTTP 请求。NazoAuth 显式同意多一次提交决定，共三个请求。Keycloak 显式同意使用单独的 S256 机密客户端及 `prompt=consent`，逐次提交原生同意表单后兑换。[逐 PID 原始采样与数据库统计](evidence/postgres-maps.jsonl.gz) · [诊断轮 Goose 账本](evidence/pg-arrivals.zip)"])
    if published:
        blocks.extend(["## PostgreSQL 连接复用对照", "目标 1,000 TPS，连接池上限 32。同一配对内，两种策略各从一份相同的数据库快照恢复独立副本，测前库大小逐对相等。前三轮的先后顺序依次为 FIFO 先、LIFO 先、FIFO 先；显式同意的两组补测均为 FIFO 先。FIFO 先取最早归还的空闲连接，LIFO 先取最近归还的空闲连接。仅汇总两侧均有效的配对组。本表的 RSS、PSS 各取当轮采样峰值；上一节的逐映射分解取 RSS 峰值时刻。", pool_report(),
                       "连接复用改变了哪些进程会访问同一批共享页。四条链路的合计 RSS 都降低，按共享比例分摊后的 PSS 变化小得多，轮换的 PSS 反而上升。13 个有效配对中，总 CPU 均降低 0.19–0.41 核；三个轮换配对的数据库 PSS 均上升（2.4–32.7 MiB）。显式同意的四个配对中，P99 差值从 −13.17 到 +168.27 ms。正式服务保留 FIFO。",
                       "授权码兑换在持久化时校验主体并写入一次性消费凭据；刷新轮换还需更新令牌族和重放凭据。静默授权在同一事务中锁定客户端、用户和既有授权，核查范围后提交决定；提交函数还会校验客户端和用户世代。显式同意同时更新用户授权，并以决定记录约束重复消费。现有观测无法把 PSS 差额归因于其中某条 SQL。[兑换与消费凭据](../crates/persistence-postgres/src/repositories/token_issuance.rs) · [授权事务](../crates/persistence-postgres/src/repositories/authorization_flow.rs) · [决定提交函数](../migrations/20261125000100_authorization_decision_epoch/up.sql)",
                       "授权码兑换 1,000 TPS 停压后，保留应用连接，读取当时所有空闲业务后端的 PostgreSQL 内存上下文。下表单位为 MiB，每个服务各一次诊断。分配量包含上下文可复用的空闲空间；共享缓冲区、进程映射与操作系统页缓存另计。空闲连接数只含该业务数据库的客户端后端；逐映射表的 PG 进程数还含后台进程。最后两列仅汇总日志点名的上下文。",
                       pg_context_table(),
                       "在 NazoAuth 的 32 个后端中，已列出的计划及其源对象共 17.8 MiB。这部分分配量只能解释部分内存差异。复现时在普通兑换窗口结束、应用仍连库时执行 `python3 perf/monitor/pg_contexts.py 数据库容器 数据库名 监控角色`。[逐后端分配计数](evidence/environment/pg-contexts.json) · [PostgreSQL 内存诊断接口](https://www.postgresql.org/docs/18/functions-admin.html)",
                       "两份独立数据库快照中，授权和安全审计事件表连同索引分别占数据库磁盘空间约 85% 和 92%。这些读数记录了不同的历史业务规模。磁盘大小无法直接换算成内存占用。[关系大小与估算行数](evidence/environment/nazo-pg-relations.json)",
                       "复现时先按下文部署被测提交。以同一份已应用令牌入口开关补丁的源码构建两个 release 二进制，第二个构建前额外应用下方连接补丁。使用相同构建镜像及 `cargo build --locked --release -p nazo-server --bin nazoauth`。停止测试应用并保存基准数据库快照，每个变体均使用该快照的新副本、连接池 32 和原 CPU 绑定。对四个场景分别执行 `bash perf/bench.sh pg-memory nazo SCENARIO 1000`，轮间交替变体顺序。每轮先恢复数据库副本，再部署该轮二进制。",
                       "[逐轮原始记录](evidence/pool-locality/) · [候选连接补丁](fixture/pool-locality.patch) · [构建与应用摘要](evidence/environment/pool-locality.json)"])
    blocks.extend(section_tables(output))
    if published: blocks.append(METHOD)
    return "\n\n".join(blocks)+"\n"


INTRO = """每次运行一个 OAuth 服务，主服务绑定 **8 个不同物理核心，各使用 1 个逻辑 CPU**。数据库、缓存和发压端独立分配 CPU。Goose 0.19.2 以固定到达率发压。各服务使用原生认证、令牌格式和存储，Kanidm 使用 HTTPS/1.1，其余使用隔离网络内的 HTTP/1.1。

| 服务 | 被测版本 | 机器令牌与认证 | 运行配置 |
|---|---|---|---|
| NazoAuth | 源码 `33984220ed1f48228e4b0f4ed8c345c2f63feb3b`，应用随附令牌入口开关补丁 | RS256 JWT、Basic | PostgreSQL 池 32、Valkey，令牌入口 IP 配额关闭 |
| Rauthy | 0.37.2 · 标签 `fe6bcb95192e8a83c29e2b525bf4960933bea3bd` | RS256 JWT、表单凭据 | PostgreSQL 池 32、内嵌缓存；令牌签发事件关闭 |
| Kanidm | 1.12.1 · 标签 `fb052e5357cf09dcdffd07fef4045e8066a68c0b` | JWE、Basic | 内嵌数据库计入主服务，HTTPS/1.1，验证测试 CA |
| Keycloak | 26.8.2 · 镜像修订 `26018f2a4c6155cfe2c28f078996390bf5191946` | RS256 JWT、Basic | PostgreSQL 池 32、JVM 堆 512 MiB–4 GiB，JVM 可见处理器参数 16，实际执行受 8 核亲和性约束 |
| Ory Hydra | 26.2.0 · 镜像修订 `0b84568fffccf151dc5e6c7955fdfb738555bf4b` | RS256 JWT、Basic | PostgreSQL 池 32，私网隔离管理入口，以 `serve all --dev` 运行 |

UserInfo 的 12,000 TPS 档列出实发、成功吞吐和观测 P95/P99；用于正式性能对照的轮数按宿主与发压核查单独统计。"""

METHOD = """## 测试方法

- **查询。** UserInfo 读取用户资料；内省读取令牌有效状态。机器令牌和用户令牌分别统计。用户令牌内省使用 32 个用户各自通过授权码签发的 16 枚令牌；发压前逐枚核对内省的 active 和用户主体，并通过签名令牌验证主体来源。Keycloak 使用列入令牌 audience 的机密客户端进行内省。Hydra 内省由私网管理端承接，调用者认证边界与另四家不同。
- **签发与授权。** 机器签发包含客户端认证和实际签发。授权码在测前用真实用户会话及 S256 PKCE 准备，测量时每个授权码只兑换一次。已登录链路包含重定向、必要的授权确认和兑换，免交互与显式同意各自成组。Hydra 的完整授权需要外部身份和同意服务。Kanidm 的既有会话可以发起静默授权，但该版本还未实现 `prompt=consent` 强制重复同意，常规授权单列。Rauthy 的常规授权使用原生会话续授权接口。[Kanidm 1.12.1 授权实现](https://github.com/kanidm/kanidm/blob/v1.12.1/server/lib/src/idm/oauth2.rs#L8117)
- **轮换。** 表中括号表示用户数 × 每用户独立令牌族数。成功后用返回的后继令牌继续该族。Rauthy 被测配置的后继令牌有约 240 秒生效等待；Kanidm 的重复消费行为与严格一次性兑换及即时轮换组不同。这些场景没有共同的安全和时序前提。
- **混合。** 两类混合每三次安排一次机器签发、两次内省；五类混合的签发、内省、兑换、刷新、已登录授权分别占 30%、50%、10%、5%、5%。有效机器令牌集由 16 个客户端各签发 32 枚；授权码兑换使用 32 个用户。登录、造数通过各项目管理或协议接口完成，每家使用自己的数据库。已登录授权需要显式同意的五类混合单独列组。重复安排到同一刷新令牌族的操作共享最新后继，逐业务项计数和延迟见每轮 JSON 的 `operations`。[四次连续轮换的驱动核验](evidence/environment/refresh-driver.json)
- **过载。** 成功 TPS = 测量期内计划到达、最终成功的业务数 ÷ 测量秒数，包含窗口结束后返回的成功。多 HTTP 步骤构成的一笔授权只算一次业务。未发出可能来自调度迟到、在途槽耗尽或前一个刷新未完成。成功请求延迟与成功数、失败数、未发出数一起阅读。Kanidm 在部分混合档位的成功样本全部来自内省。
- **资源。** CNB Linux x86-64。对照项目的 CPU 为 AMD EPYC 9K65、无 Swap；NazoAuth 的处理器同为 AMD EPYC 9K65。主服务无硬内存上限，数据库、缓存、Goose 及采集器使用独立核。常规配置分别给 PostgreSQL、Valkey、Goose 分配 14、2、15 个逻辑 CPU。内存取测量窗口内采样到的进程 RSS；服务端总峰值按同时刻汇总，共享页可能重复计入。带 PSS 采样的窗口将共享页按持有进程分摊，主／总分别为主服务和该部署服务端合计的采样峰值。内存专项和 NazoAuth 对照表优先使用同批 smaps 的 RSS 与 PSS；其余固定到达率窗口使用进程 stat 的 RSS。各角色同批采样，每次采样跨度不超过 1 秒。CPU 是平均占用核数，宿主 CPU PSI 是存在可运行任务等待 CPU 的时间占比。
- **发压。** Goose 0.19.2，调度迟到 5 ms 放弃发出，HTTP 超时 5 秒，共享 HTTP 连接池，固定计划到达，无自动重试。标准配置为 8,192 在途槽、15 工作线程，宽配置为 32,768 槽、24 线程、独立日志写入及扩展源端口范围。只在相同配置内聚合。除兑换和五类混合为预热 5 秒、测量 20 秒外，其余为 10 秒和 36 秒。每个计划操作记录计划、实际发出与完成时间。P99.9 在低样本量窗口可能仅由少数样本决定。
- **有效性。** 只纳入夹具校验成功、计数可对账、资源采样及亲和性合格的窗口。Goose 调度迟发超过计划数 0.1% 或存在发压端资源瓶颈时排除；服务端过载仍保留。宿主干扰结合 PSI、所分配核心的非测试负载和调度等待判断。高整机 CPU 利用率本身不构成排除依据。有效轮数表示测量质量，与产品延迟门槛分开计算。

## 复现

离线重建只需 Python 3.10+。`--check --raw` 校验归档摘要并重算逐请求数据；在 Linux 上还会从采样文件重算 CPU、总峰值 RSS 和 PSI。从仓库根目录执行：

```sh
python3 perf/report.py --check --raw
python3 perf/report.py --output /tmp/oauth-benchmark.md
```

在专用 CNB 的 Linux x86-64 环境重新发压需要 Docker、Git、Bash、Python 3、C 编译器及静态 libc、jq、OpenSSL、patch、flock 和 taskset。克隆时保留上表 NazoAuth 提交。以下命令默认构建表中 NazoAuth 版本、部署服务、通过产品接口准备数据、运行三个窗口并生成该次报告：

```sh
bash perf/bench.sh setup
bash perf/bench.sh login
bash perf/bench.sh run nazo userinfo 1000 3
bash perf/bench.sh pg-memory nazo exchange 1000
python3 perf/report.py --input perf/.work/windows --output /tmp/fresh.md
```

`bash perf/bench.sh matrix` 依据部署的 NazoAuth 版本，按固定种子交错重放所选发压配置已经发表的业务、档位、轮数和刷新数据规模。宽配置使用新的独立 CNB，先以 `BENCH_NETWORK=wide bash perf/bench.sh setup` 部署，再以 `BENCH_PROFILE=journal-wide bash perf/bench.sh matrix` 运行。每个窗口必须有唯一输出路径。私有凭据和新结果保存在忽略提交的 `perf/.work/`。

[登录逐次耗时和内存读数](evidence/login/)及[NazoAuth 构建信息](evidence/environment/nazo-build.json)可用于复算本次测量。用 `bash perf/bench.sh memory nazo` 运行 UserInfo 五个档位。替换末尾服务名可测对照服务。其他 NazoAuth 链路使用 `bash perf/bench.sh run nazo SCENARIO TPS 3`，支持 `machine-introspect`、`user-introspect`、`exchange`、`refresh`、`authorize-silent` 和 `authorize`。`pg-memory` 每次测一轮；末尾加 `retain` 会沿用已运行的 PostgreSQL。重复组依次执行 `pg-memory nazo authorize 1000`、`pg-memory nazo authorize 1000 retain` 和 `pg-memory nazo userinfo 1000 retain`。原始 smaps 行的 PID 后依次为总 RSS、PSS、私有页、共享页、主共享映射 RSS 与 PSS（KiB）。可用 `python3 perf/monitor/pg_window.py 窗口目录` 导出本轮原始证据。每轮 `memory.json` 保存进程树采样与业务计数；`python3 perf/report.py --memory-input perf/.work/windows` 可重建内存表。逐轮原始统计和分项业务结果位于 [evidence/windows](evidence/windows/)。[逐操作采样包](evidence/samples/)包含有逐操作账本的窗口及其资源采样。其余窗口保存逐轮统计。另附内存诊断的成功耗时序列，以及 PostgreSQL 专项全部逐请求账本。原生配置及发压校准见 [环境快照](evidence/environment/)。部署参数和镜像摘要见 [deploy.sh](deploy.sh) 与 [native-deploy.sh](native-deploy.sh)。[运行开关补丁](fixture/token-ip-quota.patch)使被测提交支持该配置，测试只关闭所列令牌入口 IP 配额。"""


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,help="fresh windows directory")
    parser.add_argument("--memory-input", type=Path, help="print RSS and PSS from measured protocol windows")
    parser.add_argument("--output",type=Path)
    parser.add_argument("--check",action="store_true")
    parser.add_argument("--raw",action="store_true",help="recalculate all available arrival ledgers")
    parser.add_argument("--plan",action="store_true")
    args=parser.parse_args()
    if args.memory_input:
        if args.input or args.check or args.raw or args.plan or args.output:
            parser.error("--memory-input prints a standalone table")
        files = sorted(args.memory_input.glob("*/*/*/memory.json"))
        if not files:
            parser.error("no memory observations found")
        print(memory_table(json.loads(path.read_bytes()) for path in files))
        return
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
        validate_memory_tails()
        validate_pg_ledgers()
        validate_pool_ledgers()
    if args.plan:
        plan=[]
        for r in rows:
            flow,rate,peer,profile,_,_,users,families=group(r)
            revision = os.environ.get("BENCH_NAZO_REVISION")
            if peer == "nazo" and revision and revision != r["product_revision"]:
                continue
            if profile!=os.getenv("BENCH_PROFILE","base"):continue
            plan.append((peer,flow,rate,r["id"],users or 32,families or 8,profile, int("role_peak_pss_mib" in r)))
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
