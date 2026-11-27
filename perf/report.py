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
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from statistics import median

from monitor.summarize import summarize
from monitor.memory_window import smaps_peaks

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
    if row["peer"] == "rauthy" and scenario(row) == "authorize-silent" and not a["failed"]:
        if a["http_requests"] != 3 * a["success"]:
            raise ValueError("incomplete Rauthy page, session authorization or exchange")
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


def formatted(values, digits=2):
    data = [v for v in values if v is not None]
    return f"{median(data):,.{digits}f}" if data else "—"


def table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    return "\n".join(lines + ["| " + " | ".join(map(str, row)) + " |" for row in rows])


def verify_memory(observations):
    if len({r.get("product_revision") for r in observations if r["peer"] == "nazo"}) > 1:
        raise ValueError("mixed NazoAuth builds in memory observations")
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


def memory_table(observations):
    observations = list(observations)
    verify_memory(observations)
    cells = defaultdict(list)
    for r in observations:
        peer, rate = r["peer"], r["target_tps"]
        flow = r.get("scenario", "userinfo")
        if peer == "nazo" and flow == "authorize":
            flow = "authorize-consent"
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



def label(flow, peer, users=0, families=0):
    name = FLOWS[flow]
    if flow == "authorize":
        name += "（显式同意）" if peer == "nazo" else "（已授权客户端）"
    if users:
        name += f"（{users}×{families}）"
    return name


def aggregates(rows):
    cells = defaultdict(list)
    for row in rows:
        revision = row.get("product_revision", "unknown") if row["peer"] == "nazo" else ""
        cells[(*group(row), revision, "role_peak_pss_mib" in row, row.get("generator_sha256") or "",
               row.get("generator_slots") or 0, row.get("generator_workers") or 0)].append(row)
    results = []
    for key, samples in sorted(cells.items(), key=lambda item: (
            list(FLOWS).index(item[0][0]), item[0][1], item[0][3], list(SERVICES).index(item[0][2]), item[0][6:])):
        flow, rate, peer, profile, warm, seconds, users, families, revision, has_pss, driver, slots, workers = key
        ops = [r["operations"]["all"] for r in samples]
        quantiles = [o["offered_to_completion_success_ms"] for o in ops if o["success"]]
        q = {p: (max(v[p] for v in quantiles) if p == "100" else median(v[p] for v in quantiles)) if quantiles else None
             for p in ("50", "95", "99", "99.9", "100")}
        result = dict(flow=flow, rate=rate, peer=peer, profile=profile, warm=warm, seconds=seconds,
                      users=users, families=families, revision=revision, has_pss=has_pss, driver=driver, slots=slots, workers=workers,
                      raw_samples=sum(r.get("_has_ledger", (HERE / "evidence/samples" / (r["id"] + ".tar.gz")).is_file()) for r in samples),
                      name=label(flow, peer, users, families), samples=len(samples), latency_samples=len(quantiles),
                      ids=sorted(r["id"] for r in samples),
                      tps=median(o["successful_tps"] for o in ops), sent=median(o["sent"] / seconds for o in ops),
                      failed=sum(o["failed"] for o in ops), unsent=sum(o["not_sent"] for o in ops), q=q,
                      app_cpu=median(r["resources"]["app"]["mean_cpu_cores"] for r in samples),
                      cpu=median(r["server_total_cpu_cores"] for r in samples),
                      app_rss=median(r.get("role_peak_rss_mib", {}).get("app", r["resources"]["app"]["peak_rss_sum_mib"]) for r in samples),
                      rss=median(r.get("server_peak_rss_mib", r["server_peak_rss_sum_mib"]) for r in samples),
                      psi_min=min(r["host_cpu_psi_pct"] for r in samples),
                      psi_max=max(r["host_cpu_psi_pct"] for r in samples))
        if has_pss:
            result["app_pss"] = median(r["app_peak_pss_mib"] for r in samples)
            result["pss"] = median(r["server_peak_pss_mib"] for r in samples)
        results.append(result)
    return results


def fmt(value, digits=2):
    return "—" if value is None else f"{value:,.{digits}f}"


def coverage(data):
    lines = []
    for flow in ("machine", "introspect", "user-introspect", "userinfo", "exchange", "refresh", "authorize-silent", "authorize-consent"):
        cells = []
        for peer in SERVICES:
            subset = [g for g in data if g["peer"] == peer and g["profile"] == "base"
                      and (g["flow"] == flow or flow == "authorize-consent" and peer == "nazo" and g["flow"] == "authorize")]
            rates = sorted({g["rate"] for g in subset})
            cells.append("、".join(f"{rate:,}" for rate in rates) if rates else "—")
        lines.append([FLOWS[flow], *cells])
    return table(["业务／已测目标 TPS", *SERVICES.values()], lines)


def details(data, include_revision=False):
    blocks = ["## 全部结果", "同一行按产品构建、场景、令牌族规模、已记录的驱动二进制与参数、采样方式分组。未知驱动参数单独列组。分位延迟、吞吐、CPU、内存各取逐轮中位数，Max 取全部轮次最大值；**失败与未发出为所列轮次合计**。最后一列为总轮数／有成功延迟的轮数／有原始账本的轮数。驱动栏为二进制 SHA-256 前八位、在途槽和线程数；未记录的字段以 `?` 标明，单轮结果单列。"]
    names = list(dict.fromkeys(g["name"] for g in data))
    for name in names:
        subset = [g for g in data if g["name"] == name]
        entries = []
        for g in subset:
            profile = "宽" if g["profile"] == "journal-wide" else "标准"
            profile += "＋PSS" if g["has_pss"] else ""
            memory = fmt(g["app_pss"], 1) + " / " + fmt(g["pss"], 1) if g["has_pss"] else "—"
            count = f'{g["samples"]} / {g["latency_samples"]} / {g["raw_samples"]}' + ("（单轮）" if g["samples"] == 1 else "")
            service = SERVICES[g["peer"]] + (f' (`{g["revision"][:8]}`)' if include_revision and g["peer"] == "nazo" else "")
            driver = (g["driver"][:8] or "?") + " / " + str(g["slots"] or "?") + " / " + str(g["workers"] or "?")
            entries.append([f'{g["rate"]:,}', service, profile, driver,
                            fmt(g["sent"]) + " / " + fmt(g["tps"]),
                            f'{g["failed"]:,} / {g["unsent"]:,}',
                            " / ".join(fmt(g["q"][q]) for q in ("50", "95", "99", "99.9", "100")),
                            fmt(g["app_cpu"]) + " / " + fmt(g["cpu"]),
                            fmt(g["app_rss"], 1) + " / " + fmt(g["rss"], 1), memory,
                            fmt(g["psi_min"]) + "–" + fmt(g["psi_max"]), count])
        blocks.extend([f"<details>\n<summary>{name}</summary>\n",
                       table(["目标 TPS", "服务", "采样", "驱动／槽／线程", "发出／成功 TPS", "失败／未发出合计",
                              "P50 / P95 / P99 / P99.9 / Max ms", "CPU 主／总（核）", "RSS 主／总 MiB",
                              "PSS 主／总 MiB", "宿主 PSI 范围 %", "轮数／延迟／账本"], entries), "</details>"])
    return blocks


def reference_memory():
    rows = [json.loads(line) for line in (HERE / "evidence/protocol-memory.jsonl").read_bytes().splitlines()]
    verify_memory(rows)
    return rows


def exclusion_table(observations):
    cells = defaultdict(list)
    for row in observations:
        if row["performance_status"] == "INVALID":
            cells[row["peer"], row.get("scenario", "userinfo"), row["target_tps"]].append(row)
    rows = []
    reasons = {"external_cpu_contention": "宿主 CPU 竞争", "generator_scheduling": "发压迟到",
               "resource_sampling": "资源采样不足", "pss_sampling": "内存采样不足",
               "refresh_family_pool": "令牌族不足"}
    for (peer, flow, rate), samples in sorted(cells.items(), key=lambda pair: (
            list(SERVICES).index(pair[0][0]), pair[0][1], pair[0][2])):
        counts = defaultdict(int)
        for row in samples:
            for reason in row["performance_invalid_reasons"]:
                counts[reason] += 1
        rows.append([SERVICES[peer], label("introspect" if flow == "machine-introspect" else flow, peer), f"{rate:,}", len(samples),
                     "、".join(f"{reasons.get(k, k)} {v}" for k, v in sorted(counts.items()))])
    return table(["服务", "业务", "目标 TPS", "排除轮数", "原因（可同时出现）"], rows)


def chart_specs(data, observations):
    def points(flow, rate):
        found = [g for g in data if g["flow"] == flow and g["rate"] == rate and g["profile"] == "base"]
        # The overview scenarios have one sampling configuration per service.
        # A new configuration must be shown separately, never silently chosen.
        if len({g["peer"] for g in found}) != len(found):
            raise ValueError(f"overview requires separate sampling panels: {flow}/{rate}")
        return {g["peer"]: g for g in found}
    throughput = [dict(title=title, rate=rate, points=points(flow, rate)) for title, flow, rate in (
        ("机器令牌签发 · 1,000 TPS", "machine", 1000),
        ("机器令牌签发 · 6,000 TPS", "machine", 6000),
        ("UserInfo · 1,000 TPS", "userinfo", 1000),
        ("UserInfo · 12,000 TPS", "userinfo", 12000))]
    reads = [dict(title="UserInfo · 1,000 TPS", rate=1000, points=points("userinfo", 1000))]
    memory = []
    for peer in SERVICES:
        subset = [r for r in observations if r["peer"] == peer and r.get("scenario", "userinfo") == "userinfo" and r["target_tps"] == 1000]
        if subset:
            memory.append(dict(peer=peer, pss=median(r["server_peak_pss_mib"] for r in subset),
                               tps=median(r["success"] / r["seconds"] for r in subset),
                               samples=len(subset), performance_samples=sum(r["performance_status"] != "INVALID" for r in subset),
                               windows=sorted(r["window"] for r in subset)))
    return {"throughput": throughput, "read-latency": reads, "read-cpu": reads, "memory": memory}


def chart_digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def check_charts(specs):
    for name, data in specs.items():
        path = HERE / "charts" / (name + ".svg")
        root = ET.parse(path).getroot()
        digest = root.find(".//{http://purl.org/dc/elements/1.1/}description")
        if digest is None or digest.text != "data-sha256:" + chart_digest(data):
            raise ValueError(f"{path}: regenerate charts from the current observations")


def write_charts(specs):
    # Rendering is optional; ordinary validation needs only the Python standard library.
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import FuncFormatter
    plt.rcParams.update({"font.family": ["Noto Sans CJK JP", "DejaVu Sans"], "font.size": 11,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "axes.spines.left": False, "axes.spines.bottom": False,
                         "svg.hashsalt": "nazoauth-oauth-benchmark", "figure.facecolor": "white"})
    colors = dict(zip(SERVICES, ("#12766D", "#386CB0", "#925FA8", "#D48729", "#64748B")))
    directory = HERE / "charts"
    directory.mkdir(exist_ok=True)
    for name, spec in specs.items():
        if name == "memory":
            fig, axis = plt.subplots(figsize=(12, 5.2))
            maximum = max(row["pss"] for row in spec)
            for i, row in enumerate(spec):
                axis.barh(i, row["pss"], height=.48, color=colors[row["peer"]])
                axis.text(row["pss"] + maximum * .02, i, f'{row["pss"]:,.1f} MiB', va="center", fontsize=11)
                axis.text(maximum * 1.30, i, f'{row["tps"]:,.2f} TPS · {row["performance_samples"]}/{row["samples"]} 轮', va="center", fontsize=10)
            axis.set_yticks(range(len(spec)), [SERVICES[row["peer"]] for row in spec])
            axis.invert_yaxis()
            axis.set_xlim(0, maximum * 1.95)
            axis.set_xticks([0, 250, 500, 750, 1000])
            axis.set_xlabel("全服务端峰值 PSS（MiB）· 越低，占用越少")
            axis.set_title("部署内存 · UserInfo 计划 1,000 TPS", loc="left", fontsize=16, pad=24)
            axis.text(maximum * 1.30, -.65, "同批成功 TPS · 性能有效／内存观测轮数", fontsize=9)
            axis.grid(axis="x", color="#E5E7EB", zorder=0)
            axis.set_axisbelow(True)
            fig.text(.12, .02, "PSS 按共享比例分摊内存；内存观测保留宿主干扰轮次。吞吐与延迟排名使用通过性能核查的窗口。", fontsize=10, color="#475569")
            fig.subplots_adjust(left=.12, right=.98, bottom=.18, top=.83)
        else:
            cols = 2 if name == "throughput" else 1
            rows = 2 if name == "throughput" else 1
            fig, axes = plt.subplots(rows, cols, figsize=(13.8 if cols == 2 else 10.8, 7.7 if rows == 2 else 4.6), squeeze=False)
            for axis, panel in zip(axes.flat, spec):
                entries = panel["points"]
                values = []
                for peer in SERVICES:
                    row = entries.get(peer)
                    values.append(0 if row is None else row["tps"] if name == "throughput" else row["q"]["99"] if name == "read-latency" else row["cpu"])
                maximum = panel["rate"] if name == "throughput" else max(values) * 1.08
                for i, (peer, value) in enumerate(zip(SERVICES, values)):
                    row = entries.get(peer)
                    if row is None:
                        axis.text(maximum * .025, i, "无有效测量", va="center", fontsize=10, color="#64748B")
                        continue
                    axis.barh(i, value, height=.5, color=colors[peer], zorder=3,
                              alpha=1 if row["samples"] >= 3 else .40)
                    if name == "read-latency":
                        axis.plot(row["q"]["95"], i, "|", color="white", markersize=15, markeredgewidth=2.8, zorder=4)
                        text_value = f'{value:,.2f} ms'
                    elif name == "read-cpu":
                        text_value = f'{value:.2f} 核'
                    else:
                        text_value = f'{value:,.2f}'
                    suffix = f' · n={row["samples"]}' + (" 单轮" if row["samples"] == 1 else "")
                    if not (row["driver"] and row["slots"] and row["workers"]):
                        suffix += " †"
                    axis.text(value + maximum * .025, i, text_value + suffix, va="center", fontsize=9.5)
                axis.set_yticks(range(len(SERVICES)), list(SERVICES.values()))
                axis.invert_yaxis()
                axis.set_xlim(0, maximum * 1.60)
                axis.set_xticks([maximum * x for x in (0, .25, .5, .75, 1)] if name == "throughput" else axis.get_xticks()[axis.get_xticks() <= maximum])
                axis.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{x:,.2f}" if name == "read-cpu" else f"{x:,.0f}"))
                axis.set_title(panel["title"], loc="left", fontsize=14, pad=16)
                axis.grid(axis="x", color="#E5E7EB", zorder=0)
                axis.set_axisbelow(True)
                axis.tick_params(axis="both", length=0)
                axis.set_xlabel("成功业务／秒" if name == "throughput" else "P99 ms · 白线为 P95" if name == "read-latency" else "全服务端 CPU（核）")
            notes = {"throughput": "逐轮中位数；n 为纳入轮数，浅色为不足 3 轮。†：旧汇总未记录全部驱动参数。无有效测量不等于零吞吐。",
                     "read-latency": "从计划到达到成功完成，包含排队。五服务使用同一已记录驱动 357a8ea7，各 3 轮，均接近 1,000 成功 TPS。",
                     "read-cpu": "应用＋实际使用的 PostgreSQL／Valkey；Kanidm 内嵌数据库计入应用。五服务使用同一已记录驱动 357a8ea7。"}
            fig.text(.09, .02, notes[name], fontsize=10, color="#475569")
            fig.subplots_adjust(left=.09, right=.97, bottom=.12 if rows == 2 else .22, top=.93 if rows == 2 else .84, hspace=.65, wspace=.40)
        path = directory / (name + ".svg")
        fig.savefig(path, metadata={"Date": None, "Description": "data-sha256:" + chart_digest(spec)}, bbox_inches="tight")
        path.write_text("\n".join(line.rstrip() for line in path.read_text().splitlines()) + "\n", encoding="utf8")
        plt.close(fig)


INTRO = """**被测构建：[`33984220`](https://github.com/nazozero/NazoAuth/commit/33984220ed1f48228e4b0f4ed8c345c2f63feb3b)＋[令牌入口开关补丁](fixture/token-ip-quota.patch)。PR #310 的后续代码修订尚未进行五服务负载复测。**

主服务使用 **8 个物理核心，每核 1 个逻辑 CPU**。PostgreSQL、Valkey 和发压端使用独立核心。每次只运行一个 OAuth 服务，以 Goose 0.19.2 的固定到达率测量真实协议请求。

**TPS 是每秒成功业务数，P99 是 99% 成功业务完成所需的时间。** 授权和兑换的多次 HTTP 请求合算一笔业务。图中的 `n` 是有效测量轮数；不足三轮的结果单独标明。

[结果概览](#结果概览) · [部署内存](#部署内存) · [全部结果](#全部结果) · [测试条件](#测试条件) · [复现](#复现)
"""

CONDITIONS = """## 测试条件

| 服务 | 被测版本 | 机器令牌／客户端认证 | 服务配置 |
|---|---|---|---|
| NazoAuth | [`33984220`](https://github.com/nazozero/NazoAuth/commit/33984220ed1f48228e4b0f4ed8c345c2f63feb3b)＋[令牌入口开关补丁](fixture/token-ip-quota.patch) | RS256 JWT／Basic | PostgreSQL 池 32、Valkey；机器签发成功审计和令牌入口 IP 配额关闭；用户签发及轮换保留事务审计，外部导出关闭 |
| Rauthy | 0.37.2 · `fe6bcb95` | RS256 JWT／表单凭据 | PostgreSQL 池 32、内嵌缓存；令牌签发事件关闭 |
| Kanidm | 1.12.1 · `fb052e53` | JWE／Basic | 内嵌数据库，HTTPS/1.1，验证测试 CA |
| Keycloak | 26.8.2 · `26018f2a` | RS256 JWT／Basic | PostgreSQL 池 32；堆 512 MiB–4 GiB；JVM 可见处理器参数 16，执行受 8 核亲和性约束 |
| Ory Hydra | 26.2.0 · `0b84568f` | RS256 JWT／Basic | PostgreSQL 池 32；`serve all --dev`，管理端口仅开放给隔离网络 |

这是上述配置下的产品部署对照。原生令牌格式、客户端认证方式、状态读写和审计语义均随服务保留。机器令牌的 RS256 组使用 2,048 位密钥及 300 秒有效期；Kanidm 的 JWE 令牌为 900 秒。机器签发返回的 scope 为 `profile`，Rauthy 为 `openid profile`。除 Kanidm 外，流量使用隔离网络内的 HTTP/1.1。请求准备时核对签名、令牌属性与内省结果。镜像摘要、构建哈希和运行参数见 [环境快照](evidence/environment/)、[部署脚本](deploy.sh)及[原生服务配置](native-deploy.sh)。

| 项目 | 设置与计量边界 |
|---|---|
| 硬件 | CNB Linux x86-64、AMD EPYC 9K65、无 Swap。批次使用相同 CPU 型号和角色分配；各角色核心互不重叠 |
| 资源 | 应用 8 个逻辑 CPU，PostgreSQL 14、Valkey 2、Goose 15；主服务无硬内存上限。应用 CPU 与全服务端 CPU 分列 |
| 持久化 | PostgreSQL：1 GiB shared buffers、128 个最大连接，fsync、synchronous_commit、full_page_writes 开启。Valkey：RDB/AOF 关闭。数据库状态在同一服务各轮间延续 |
| 窗口 | 授权码兑换预热 5 秒、测量 20 秒；其余正式链路预热 10 秒、测量 36 秒。应用在每轮前重启；内存专项在组前重启 PostgreSQL |
| 发压 | 标准：8,192 在途槽、15 工作线程；宽：32,768 槽、24 线程、独立日志写入、扩展源端口。不同配置分行汇总 |
| 时序 | 计划到达固定，调度迟到 5 ms 放弃发出；单次 HTTP 超时 5 秒，不自动重试。延迟包含计划到达到发出之间的等待 |
| 计数 | 成功 TPS = 正式窗口内计划到达并最终成功的业务数 ÷ 窗口秒数，包含窗口后返回的成功。失败和未发出另列，原始 JSON 保留窗口结束时在途数 |
| 统计 | 吞吐、延迟、CPU、内存取逐轮中位数，分位数不跨轮合并，Max 取所有轮次最大值。失败／未发出取合计。零成功轮没有成功延迟分位数，单列延迟样本轮数 |
| CPU 与内存 | CPU 按进程时间增量计算；RSS/PSS 为窗口内采样峰值。全服务端峰值按同时刻求和，组件峰值不能直接相加 |

### 各条链路做什么

| 业务 | 计时范围及共同前提 |
|---|---|
| 机器令牌签发 | 客户端凭据认证、签发新的访问令牌，核对成功响应的 token_type、有效期和非空令牌 |
| UserInfo | 32 个真实用户令牌轮流读取资料，核对返回的用户主体 |
| 机器／用户令牌内省 | 核对 `active: true`。机器集为 16 个客户端各 32 枚令牌，用户集为 32 个用户各 16 枚令牌；Hydra 使用受信任管理入口 |
| 授权码兑换 | 计时前通过真实会话和 S256 PKCE 准备，每码只兑换一次；测量前检查整批授权码的过期预算 |
| 刷新轮换 | 32/64/128 个用户，各自持有独立令牌族；同一族仅使用最新返回的后继令牌。用户数×族数在表标题中给出 |
| 静默授权＋兑换 | 从带 `prompt=none` 的授权请求开始至令牌响应。NazoAuth、Keycloak 通常为 2 次 HTTP，Rauthy 包含原生会话续授权提交，共 3 次 |
| 显式同意＋兑换 | 从授权请求开始，实际提交同意决定，再兑换授权码；与免交互流程分组 |

Rauthy 的被测刷新配置存在约 240 秒的后继生效等待，Kanidm 的重复消费与即时严格轮换组语义不同，所以没有合并到该组。Hydra 的完整授权依赖外部身份与同意服务。Kanidm 1.12.1 未实现 `prompt=consent` 强制重复同意；Rauthy 的该参数在所用账户配置中返回登录交互，因此只比较各自已验证的链路。[轮换驱动核验](evidence/environment/refresh-driver.json) · [Rauthy 授权实现](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/src/api/src/oidc.rs) · [Kanidm 授权实现](https://github.com/kanidm/kanidm/blob/v1.12.1/server/lib/src/idm/oauth2.rs)

### 纳入规则

不同驱动二进制、槽数、线程数、采样方式分别汇总；旧归档未记录的字段保持未知，不填成标准配置。

夹具核验、业务计数、资源采样和 CPU 亲和性均通过才进入正式对照。调度迟发超过计划数 0.1%、发压端资源不足或无法排除宿主竞争的窗口不纳入。服务端自身过载、HTTP 失败和未达到目标吞吐的有效窗口保留。`PASS`/`FAIL` 是负载目标与延迟门槛的结果，`INVALID` 是测量条件不合格，两者分开处理。具体判定见 [seal.py](monitor/seal.py) 和 [placement.py](monitor/placement.py)。

本页记录上述被测构建与配置的结果。新的实现与配置使用新的窗口文件及报告，不覆盖已发表测量。当前发压器将本地源端口不可用单列为 `transport_addr_unavailable`，供发压质量门槛识别；历史归档中的通用传输错误保留原分类。
"""

REPRODUCE = """## 复现

在仓库根目录运行，离线验证只需 Python 3.10+：

```sh
python3 perf/report.py --check --raw
python3 perf/report.py --output /tmp/oauth-benchmark.md
```

`--check` 检查每轮计数、完整文件清单、SHA-256、文档及图表的数据摘要。`--raw` 重算已归档逐请求账本；在 Linux 上还会重算这些窗口的 CPU、RSS 和 PSI。图表使用 Matplotlib 生成，更新数据后执行 `python3 perf/report.py --charts`；中文字体使用 Noto Sans CJK。

重新发压需要专用 Linux x86-64 环境、Docker、Git、Bash、Python 3、C 编译器与静态 libc、jq、OpenSSL、patch、flock 和 taskset。默认复现上表的被测 NazoAuth 构建。部署脚本要求单 NUMA 节点至少 25 个独立物理核，为服务与发压端分别分配资源。

```sh
bash perf/bench.sh setup
bash perf/bench.sh run nazo machine 1000 3
bash perf/bench.sh run nazo exchange 1000 3
bash perf/bench.sh run nazo refresh 1000 3
bash perf/bench.sh run nazo authorize-silent 1000 3
bash perf/bench.sh run nazo authorize 1000 3
bash perf/bench.sh run nazo userinfo 1000 3
python3 perf/report.py --input perf/.work/windows --output /tmp/fresh.md
```

`run` 的服务名为 `nazo`、`rauthy`、`kanidm`、`keycloak` 或 `hydra`，还支持 `machine-introspect`、`user-introspect` 和 `authorize-consent`。`bash perf/bench.sh matrix` 按固定种子交错重放已发表的场景、档位、轮数和令牌族规模；用 `BENCH_PROFILE=journal-wide` 选择宽配置，并先在独立环境以 `BENCH_NETWORK=wide bash perf/bench.sh setup` 部署。每轮使用唯一目录，凭据和新结果保存在忽略提交的 `perf/.work/`。

`bash perf/bench.sh memory nazo` 运行 UserInfo 的五个档位；`bash perf/bench.sh pg-memory nazo exchange 1000` 采集单轮数据库映射，末尾加 `retain` 沿用正在运行的数据库。`python3 perf/report.py --memory-input perf/.work/windows` 重建新测量的内存表。`bash perf/bench.sh login` 运行独立密码登录诊断，所得闭环数据单独保存，不并入本页的固定到达率结果。
"""


def publication_selection(rows):
    control = json.loads((HERE / "evidence/environment/refresh-driver.json").read_bytes())
    disputed = control["legacy_buffered_binary_sha256"]
    excluded = [row for row in rows if row["flow"] == "refresh" and row.get("generator_sha256") == disputed]
    ids = {row["id"] for row in excluded}
    return [row for row in rows if row["id"] not in ids], excluded


def driver_exclusions(rows):
    entries = []
    for row in sorted(rows, key=lambda r: (r["peer"], r["rate"], r["id"])):
        op = row["operations"]["all"]
        entries.append([f'[`{row["id"]}`](evidence/windows/{row["id"]}.json)', SERVICES[row["peer"]],
                        f'{row["rate"]:,}', fmt(op["successful_tps"]), f'{op["failed"]:,}'])
    return table(["窗口", "服务", "目标 TPS", "原记录成功 TPS", "原记录失败数"], entries)


def render(rows, published):
    archived_count = len(rows)
    eligible, conflicts = publication_selection(rows) if published else (rows, [])
    data = aggregates(eligible)
    if not published:
        return "\n\n".join(["# OAuth / OIDC 本次测量", *details(data, include_revision=True)]) + "\n"
    observations = reference_memory()
    samples = {p.name.removesuffix(".tar.gz") for p in (HERE / "evidence/samples").glob("*.tar.gz")}
    failures = sum(r["operations"]["all"]["failed"] for r in eligible)
    invalid = sum(r["performance_status"] == "INVALID" for r in observations)
    blocks = ["# OAuth / OIDC 单实例性能基准", INTRO,
              f"归档保存 **{archived_count} 个单链路窗口**，正式对照纳入 **{len(eligible)} 个**，{len(conflicts)} 个因轮换驱动证据冲突单列保留。纳入窗口中，{sum(r['status'] == 'FAIL' for r in eligible)} 个未达到负载或延迟门槛，**{failures:,} 次已发业务失败全部计入**。另保留 {len(observations)} 个内存观测及其测量质量标记。",
              "## 结果概览", "### 成功吞吐",
              "![机器令牌签发与 UserInfo 固定到达率成功吞吐，含有效轮数和缺测标记](charts/throughput.svg)",
              "NazoAuth 的 UserInfo 12,000 TPS 有 9 个内存观测，均未通过性能有效性核查，因此该档显示**无有效测量**。NazoAuth 机器签发 3,000 TPS、Rauthy 机器签发 1,000 TPS 各只有一轮有效测量；这些结果保留在明细中。",
              "### UserInfo 尾延迟", "![UserInfo 在同一发压二进制、每秒一千次业务下的 P95 和 P99](charts/read-latency.svg)",
              "### UserInfo CPU", "![UserInfo 的全服务端平均 CPU 核数](charts/read-cpu.svg)",
              "## 部署内存", "![UserInfo 每秒一千次计划业务下的全服务端 PSS，附同批成功吞吐和有效轮数](charts/memory.svg)",
              "PSS 按共享比例分摊进程内存，适合观察部署占用。PostgreSQL 共享页会在多个进程的 RSS 中重复计数，所以不能把 RSS 合计当作实际物理内存。图中内存观测包括宿主干扰轮，右侧同时显示实际成功 TPS 和性能有效轮数；它们不进入正式吞吐及延迟排名。不同服务沿用各自业务数据。[原始内存观测](evidence/protocol-memory.jsonl) · [Linux 内存计量](https://docs.kernel.org/filesystems/proc.html)",
              "<details>\n<summary>五服务场景覆盖</summary>\n", coverage(data), "— 表示没有该共同语义下的有效测量；各档轮数见全部结果。", "</details>",
              *details(data), CONDITIONS,
              "<details>\n<summary>轮换驱动证据冲突：保留原记录，排除正式汇总</summary>\n",
              "已归档的单令牌族控制实验中，驱动 `357a8ea7` 四次请求依次为 200/400/400/400，`ee4a059e` 为四次 200。以下窗口却同时记录 `357a8ea7` 与持续轮换夹具。原始 `driver.sha256` 和 JSON 一致；账本未保存每次后继令牌，无法消除该冲突。这些记录不计入正式轮换比较，原始文件和重算入口保留。[驱动控制实验](evidence/environment/refresh-driver.json)",
              driver_exclusions(conflicts),
              "NazoAuth 刷新轮换在 1,000 TPS 下只有两轮可纳入记录。", "</details>",
              "<details>\n<summary>已归档的无效内存观测及原因</summary>\n", exclusion_table(observations),
              f"这里列出保留的 {invalid} 个 INVALID 内存观测。归档范围为本页所用单链路窗口、证据冲突记录及内存专项，未包含全部历史试跑。一次窗口可同时触发多个排除原因。", "</details>",
              "### 可追溯数据",
              f"[逐轮 JSON](evidence/windows/)保存 {archived_count} 个窗口的业务计数、分位数、资源和原始质量判定。其中 {len(samples)} 个有[逐操作账本及资源采样包](evidence/samples/)，其余保留逐轮统计。内存专项另有[成功耗时序列](evidence/memory-success-latencies.zip)与[UserInfo 12,000 TPS 到达记录](evidence/userinfo-reference/)。[SHA-256 清单](evidence/SHA256SUMS)覆盖所有归档文件；文档、图表和原始账本的核验范围分别列明。", REPRODUCE]
    return "\n\n".join(block.strip() for block in blocks) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="fresh windows directory")
    parser.add_argument("--memory-input", type=Path, help="print RSS and PSS from measured protocol windows")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--raw", action="store_true", help="recalculate all available arrival ledgers")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--charts", action="store_true", help="render published SVG charts (requires Matplotlib)")
    args = parser.parse_args()
    if args.memory_input:
        if args.input or args.check or args.raw or args.plan or args.output or args.charts:
            parser.error("--memory-input prints a standalone table")
        files = sorted(args.memory_input.glob("*/*/*/memory.json"))
        if not files:
            parser.error("no memory observations found")
        print(memory_table(json.loads(path.read_bytes()) for path in files))
        return
    if args.charts and (args.input or args.plan):
        parser.error("--charts renders the published observations")
    files = sorted(args.input.glob("*/*/*/summary.json") if args.input else (HERE / "evidence/windows").glob("*.json"))
    rows = []
    for path in files:
        row = json.loads(path.read_bytes())
        if args.input:
            if row["status"] == "INVALID":
                continue
            row["scenario"] = path.parents[1].name
            row.setdefault("id", str(path.parent.relative_to(args.input)))
            row["_has_ledger"] = path.with_name("arrivals.tsv").is_file()
        try:
            verify_row(row)
        except (KeyError, ValueError) as err:
            raise ValueError(f"{path}: {err}") from err
        rows.append(row)
    if not rows:
        raise SystemExit("No valid windows")
    if args.input is None:
        build = json.loads((HERE / "evidence/environment/nazo-build.json").read_bytes())["git"]
        if any(row.get("product_revision") != build for row in rows if row["peer"] == "nazo"):
            raise ValueError("published NazoAuth windows do not match the declared build")
    if args.check and args.input is None:
        directory = HERE / "evidence"
        expected = dict(line.split("  ", 1)[::-1] for line in (directory / "SHA256SUMS").read_text().splitlines())
        current = {p.relative_to(directory).as_posix(): p for p in directory.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
        if current.keys() != expected.keys():
            raise ValueError("evidence file set differs from manifest")
        for name, path in current.items():
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected[name]:
                raise ValueError(f"evidence checksum mismatch: {name}")
    if args.raw:
        if args.input:
            parser.error("--raw verifies published sample bundles")
        validate_ledgers(rows)
        validate_memory_tails()
    if args.plan:
        plan = []
        for row in publication_selection(rows)[0] if args.input is None else rows:
            flow, rate, peer, profile, _, _, users, families = group(row)
            revision = os.environ.get("BENCH_NAZO_REVISION")
            if peer == "nazo" and revision and revision != row["product_revision"]:
                continue
            if profile != os.getenv("BENCH_PROFILE", "base"):
                continue
            plan.append((peer, flow, rate, row["id"], users or 32, families or 8, profile, int("role_peak_pss_mib" in row)))
        random.Random(19716).shuffle(plan)
        for entry in plan:
            print(*entry, sep="\t")
        return
    if args.input is None:
        specs = chart_specs(aggregates(publication_selection(rows)[0]), reference_memory())
        if args.charts:
            write_charts(specs)
        if args.check:
            check_charts(specs)
    result = render(rows, args.input is None)
    dest = args.output or HERE / "README.md"
    if args.input and dest.resolve() == (HERE / "README.md").resolve():
        parser.error("specify a separate --output for new runs")
    if args.check:
        if dest.read_text(encoding="utf8") != result:
            raise SystemExit("Report differs from its window data")
        print(f"{len(rows)} windows verified")
    else:
        dest.write_text(result, encoding="utf8", newline="\n")


if __name__ == "__main__":
    main()
