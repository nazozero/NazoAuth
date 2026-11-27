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
FLOWS_ZH = {"machine": "机器令牌签发", "introspect": "机器令牌内省", "user-introspect": "用户令牌内省",
         "userinfo": "用户资料", "exchange": "授权码兑换（PKCE）", "refresh": "刷新令牌轮换",
         "authorize-consent": "已登录授权＋兑换（显式同意）", "authorize-silent": "已登录静默授权＋兑换", "authorize": "已登录授权＋兑换",
         "mixed": "两类混合", "mixed-core": "五类混合", "mixed-core-consent": "五类混合（授权子操作含同意）"}
FLOWS = dict(zip(FLOWS_ZH, ("Machine token issuance", "Machine token introspection", "User token introspection",
             "UserInfo", "Authorization code exchange (PKCE)", "Refresh token rotation",
             "Signed-in authorization + exchange (explicit consent)", "Signed-in silent authorization + exchange",
             "Signed-in authorization + exchange", "Two-flow mix", "Five-flow mix", "Five-flow mix (consent)")))
LANGUAGES = {"en": "README.md", "zh_CN": "README.zh_CN.md"}


def text(language, english, chinese):
    return chinese if language == "zh_CN" else english


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


def memory_table(observations, language="en"):
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
        rows.append([label(flow, peer, language=language), f"{rate:,}", SERVICES[peer], " / ".join(traffic), " / ".join(tail), *components,
                     " / ".join(total), f"{min(totals):,.1f}–{max(totals):,.1f}",
                     f"{len(group)} / {sum(r['performance_status'] in ('PASS', 'FAIL') for r in group)}",
                     sum("external_cpu_contention" in r["performance_invalid_reasons"] for r in group)])
    return table(text(language,
                 ["Flow", "Offered TPS", "Service", "Sent / successful TPS", "Observed P95 / P99 ms", "App RSS / PSS", "PostgreSQL RSS / PSS",
                  "Valkey RSS / PSS", "Server RSS / PSS", "Total PSS range", "Memory / performance-valid rounds", "Host-contention rounds"],
                 ["业务", "目标 TPS", "服务", "实发 / 成功 TPS", "观测 P95 / P99 ms", "主服务 RSS / PSS", "PostgreSQL RSS / PSS",
                  "Valkey RSS / PSS", "服务端 RSS / PSS", "总 PSS 范围", "内存 / 性能有效轮数", "受宿主干扰轮数"]), rows)



def label(flow, peer, users=0, families=0, language="en"):
    name = (FLOWS_ZH if language == "zh_CN" else FLOWS)[flow]
    if flow == "authorize":
        name += text(language, " (explicit consent)", "（显式同意）") if peer == "nazo" else text(language, " (previously approved client)", "（已授权客户端）")
    if users:
        name += text(language, f" ({users} users × {families} families)", f"（{users}×{families}）")
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
                      success=sum(o["success"] for o in ops), planned=sum(o["planned"] for o in ops),
                      maximum_success_samples=max(o["success"] for o in ops),
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


def coverage(data, language):
    lines = []
    for flow in ("machine", "introspect", "user-introspect", "userinfo", "exchange", "refresh", "authorize-silent", "authorize-consent"):
        cells = []
        for peer in SERVICES:
            subset = [g for g in data if g["peer"] == peer and g["profile"] == "base"
                      and (g["flow"] == flow or flow == "authorize-consent" and peer == "nazo" and g["flow"] == "authorize")]
            rates = sorted({g["rate"] for g in subset})
            cells.append(text(language, "; ", "、").join(f"{rate:,}" for rate in rates) if rates else "—")
        lines.append([(FLOWS_ZH if language == "zh_CN" else FLOWS)[flow], *cells])
    return table([text(language, "Flow / measured offered TPS", "业务／已测目标 TPS"), *SERVICES.values()], lines)


def details(data, language="en", include_revision=False):
    blocks = [text(language, "## Full results", "## 全部结果"), text(language,
              "Each row groups one product build, flow, token-family size, recorded driver binary and parameters, and sampling method. Unknown driver parameters form separate groups. Latency percentiles, throughput, CPU and memory are medians across rounds; Max is the maximum across all rounds. **Failures and unsent operations are totals across the displayed rounds.** The final column lists total rounds / rounds with successful latency samples / rounds with a raw ledger. The driver column shows the first eight SHA-256 characters, in-flight slots and worker threads. `?` means unrecorded; single rounds are marked.",
              "同一行按产品构建、场景、令牌族规模、已记录的驱动二进制与参数、采样方式分组。未知驱动参数单独列组。分位延迟、吞吐、CPU、内存各取逐轮中位数，Max 取全部轮次最大值；**失败与未发出为所列轮次合计**。最后一列为总轮数／有成功延迟的轮数／有原始账本的轮数。驱动栏为二进制 SHA-256 前八位、在途槽和线程数；未记录的字段以 `?` 标明，单轮结果单列。")]
    names = list(dict.fromkeys(g["name"] for g in data))
    for name in names:
        subset = [g for g in data if g["name"] == name]
        entries = []
        for g in subset:
            profile = text(language, "Wide", "宽") if g["profile"] == "journal-wide" else text(language, "Standard", "标准")
            profile += " + PSS" if g["has_pss"] else ""
            memory = fmt(g["app_pss"], 1) + " / " + fmt(g["pss"], 1) if g["has_pss"] else "—"
            count = f'{g["samples"]} / {g["latency_samples"]} / {g["raw_samples"]}' + (text(language, " (single round)", "（单轮）") if g["samples"] == 1 else "")
            service = SERVICES[g["peer"]] + (f' (`{g["revision"][:8]}`)' if include_revision and g["peer"] == "nazo" else "")
            driver = (g["driver"][:8] or "?") + " / " + str(g["slots"] or "?") + " / " + str(g["workers"] or "?")
            entries.append([f'{g["rate"]:,}', service, profile, driver,
                            fmt(g["sent"]) + " / " + fmt(g["tps"]),
                            f'{g["failed"]:,} / {g["unsent"]:,}',
                            " / ".join(fmt(g["q"][q]) for q in ("50", "95", "99", "99.9", "100")),
                            fmt(g["app_cpu"]) + " / " + fmt(g["cpu"]),
                            fmt(g["app_rss"], 1) + " / " + fmt(g["rss"], 1), memory,
                            fmt(g["psi_min"]) + "–" + fmt(g["psi_max"]), count])
        g = subset[0]
        title = label(g["flow"], g["peer"], g["users"], g["families"], language)
        blocks.extend([f"<details>\n<summary>{title}</summary>\n",
                       table(text(language,
                             ["Offered TPS", "Service", "Sampling", "Driver / slots / threads", "Sent / successful TPS", "Failed / unsent totals",
                              "P50 / P95 / P99 / P99.9 / Max ms", "CPU app / total (cores)", "RSS app / total MiB",
                              "PSS app / total MiB", "Host PSI range %", "Rounds / latency / raw"],
                             ["目标 TPS", "服务", "采样", "驱动／槽／线程", "发出／成功 TPS", "失败／未发出合计",
                              "P50 / P95 / P99 / P99.9 / Max ms", "CPU 主／总（核）", "RSS 主／总 MiB",
                              "PSS 主／总 MiB", "宿主 PSI 范围 %", "轮数／延迟／账本"]), entries), "</details>"])
    return blocks


def reference_memory():
    rows = [json.loads(line) for line in (HERE / "evidence/protocol-memory.jsonl").read_bytes().splitlines()]
    verify_memory(rows)
    return rows


def exclusion_table(observations, language):
    cells = defaultdict(list)
    for row in observations:
        if row["performance_status"] == "INVALID":
            cells[row["peer"], row.get("scenario", "userinfo"), row["target_tps"]].append(row)
    rows = []
    reasons = dict(zip(("external_cpu_contention", "generator_scheduling", "resource_sampling", "pss_sampling", "refresh_family_pool"),
                      text(language, ("host CPU contention", "late scheduling", "insufficient resource samples", "insufficient memory samples", "insufficient token families"),
                           ("宿主 CPU 竞争", "发压迟到", "资源采样不足", "内存采样不足", "令牌族不足"))))
    for (peer, flow, rate), samples in sorted(cells.items(), key=lambda pair: (
            list(SERVICES).index(pair[0][0]), pair[0][1], pair[0][2])):
        counts = defaultdict(int)
        for row in samples:
            for reason in row["performance_invalid_reasons"]:
                counts[reason] += 1
        rows.append([SERVICES[peer], label("introspect" if flow == "machine-introspect" else flow, peer, language=language), f"{rate:,}", len(samples),
                     text(language, "; ", "、").join(f"{reasons.get(k, k)} {v}" for k, v in sorted(counts.items()))])
    return table(text(language, ["Service", "Flow", "Offered TPS", "Excluded rounds", "Reasons (may overlap)"],
                      ["服务", "业务", "目标 TPS", "排除轮数", "原因（可同时出现）"]), rows)


def chart_specs(data, observations):
    driver = "357a8ea751112a6606d14cfe4feea95ef50bafcc52646b216d01b4a9383309fb"

    def points(flow, warm, seconds):
        found = [g for g in data if g["flow"] == flow and g["rate"] == 1000 and g["profile"] == "base"
                 and g["driver"] == driver and g["slots"] == 8192 and g["workers"] == 15
                 and g["warm"] == warm and g["seconds"] == seconds]
        if len({g["peer"] for g in found}) != len(found):
            raise ValueError(f"overview requires separate sampling panels: {flow}/1000")
        return {g["peer"]: g for g in found}

    latency = [dict(title=title, flow=flow, warm=warm, seconds=seconds, points=points(flow, warm, seconds))
               for title, flow, warm, seconds in (
                   ("UserInfo", "userinfo", 10, 36),
                   ("Machine token issuance", "machine", 10, 36),
                   ("Authorization code exchange (PKCE)", "exchange", 5, 20))]
    memory = []
    for peer in SERVICES:
        subset = [r for r in observations if r["peer"] == peer and r.get("scenario", "userinfo") == "userinfo" and r["target_tps"] == 1000]
        if subset:
            memory.append(dict(peer=peer, pss=median(r["server_peak_pss_mib"] for r in subset),
                               tps=median(r["success"] / r["seconds"] for r in subset),
                               samples=len(subset), performance_samples=sum(r["performance_status"] != "INVALID" for r in subset),
                               windows=sorted(r["window"] for r in subset)))
    return {"latency": latency, "read-cpu": latency[0], "memory": memory}


def chart_digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def check_charts(specs):
    for name, data in specs.items():
        for language in LANGUAGES:
            suffix = ".zh_CN" if language == "zh_CN" else ""
            path = HERE / "charts" / (name + suffix + ".svg")
            root = ET.parse(path).getroot()
            digest = root.find(".//{http://purl.org/dc/elements/1.1/}description")
            if digest is None or digest.text != "data-sha256:" + chart_digest([language, data]):
                raise ValueError(f"{path}: regenerate charts from the current observations")


def write_charts(specs, language="en"):
    # Rendering is optional; ordinary validation needs only the Python standard library.
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    from matplotlib.ticker import FuncFormatter
    plt.rcParams.update({"font.family": ["Noto Sans CJK JP", "DejaVu Sans"] if language == "zh_CN" else ["DejaVu Sans"], "font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "axes.spines.left": False, "axes.spines.bottom": False,
                         "svg.hashsalt": "nazoauth-oauth-benchmark", "figure.facecolor": "white"})
    colors = dict(zip(SERVICES, ("#12766D", "#386CB0", "#925FA8", "#D48729", "#64748B")))
    directory = HERE / "charts"
    directory.mkdir(exist_ok=True)
    for name, spec in specs.items():
        if name == "latency":
            fig = plt.figure(figsize=(14.5, 12))
            grid = fig.add_gridspec(3, 2, width_ratios=[1, 1.40], left=.12, right=.99,
                                   top=.91, bottom=.14, hspace=.72, wspace=.08)
            percentiles = (("95", "o", "#2D718E"), ("99", "s", "#B36B16"), ("99.9", "D", "#9B3E63"))
            for j, panel in enumerate(spec):
                axis, stats = fig.add_subplot(grid[j, 0]), fig.add_subplot(grid[j, 1])
                entries = panel["points"]
                for i, peer in enumerate(SERVICES):
                    row = entries.get(peer)
                    if row is None:
                        missing = text(language, "Driver metadata unrecorded; excluded", "驱动参数未记录，未纳入该组") if panel["flow"] == "machine" and peer == "rauthy" else text(language, "No comparable window", "无可比窗口")
                        stats.text(.015, i, missing, va="center", color="#64748B", fontsize=9)
                        continue
                    values = [row["q"][q] for q, _, _ in percentiles]
                    axis.plot([min(values), max(values)], [i, i], color="#CBD5E1", linewidth=2.4, zorder=2)
                    for value, (_, marker, color) in zip(values, percentiles):
                        axis.scatter(value, i, s=40, marker=marker, color=color, zorder=3)
                    stats.text(.015, i, " / ".join(fmt(value) for value in values), va="center", fontsize=9)
                    stats.text(.48, i, fmt(row["tps"]), va="center", ha="right", fontsize=9)
                    stats.text(.70, i, f'{row["success"]:,} / {row["planned"]:,}', va="center", ha="right", fontsize=9)
                    stats.text(.92, i, f'{row["failed"]:,} / {row["unsent"]:,}', va="center", ha="right", fontsize=9,
                               color="#9B3E63" if row["failed"] else "#0F172A")
                    stats.text(1.0, i, str(row["samples"]), va="center", ha="right", fontsize=9)
                labels = [SERVICES[peer] + ("*" if entries.get(peer, {}).get("has_pss") else "")
                          + ("†" if peer in entries and entries[peer]["maximum_success_samples"] < 1000 else "") for peer in SERVICES]
                axis.set_yticks(range(len(SERVICES)), labels)
                for ax in (axis, stats):
                    ax.set_ylim(len(SERVICES) - .5, -.65)
                if panel["flow"] == "userinfo":
                    axis.set_xlim(0, 7)
                    axis.set_xticks([0, 2, 4, 6])
                    axis.set_xlabel(text(language, "Successful-operation latency (ms)", "成功业务延迟（ms）"))
                else:
                    axis.set_xscale("log")
                    axis.set_xlim(1, 10000)
                    axis.set_xticks([1, 10, 100, 1000, 10000])
                    axis.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{x:,.0f}"))
                    axis.set_xlabel(text(language, "Successful-operation latency (ms; log scale)", "成功业务延迟（ms，对数轴）"))
                title = text(language, panel["title"], {"userinfo": "UserInfo", "machine": "机器令牌签发", "exchange": "授权码兑换（PKCE）"}[panel["flow"]])
                axis.set_title(title + text(language, " · 1,000 offered TPS", " · 每秒计划 1,000 次业务"), loc="left", pad=28, fontsize=12)
                axis.grid(axis="x", color="#E5E7EB")
                axis.set_axisbelow(True)
                axis.tick_params(axis="both", which="both", length=0)
                stats.set_xlim(0, 1)
                stats.axis("off")
                for x, title, align in ((.015, "P95 / P99 / P99.9 (ms)", "left"), (.48, text(language, "Success TPS", "成功 TPS"), "right"),
                                         (.70, text(language, "Success / planned", "成功／计划数"), "right"), (.92, text(language, "Failed / unsent", "失败／未发出"), "right"), (1.0, "n", "right")):
                    stats.text(x, -.88, title, va="center", ha=align, fontsize=9, fontweight="bold")
            fig.suptitle(text(language, "Tail latency at the same offered load", "同一计划负载下的尾延迟"), x=.12, y=.985, ha="left", fontsize=19)
            handles = [Line2D([], [], linestyle="", marker=marker, color=color, label="P" + q)
                       for q, marker, color in percentiles]
            fig.legend(handles=handles, loc="upper right", bbox_to_anchor=(.99, .988), ncol=3, frameon=False)
            fig.text(.12, .064, text(language, "Latency and success TPS: medians across rounds. Operation counts: totals; n: included rounds. Latency includes queueing.", "延迟与成功 TPS 为逐轮中位数；业务计数为合计，n 为纳入轮数。延迟包含排队。"), fontsize=9, color="#475569")
            fig.text(.12, .045, text(language, "Driver 357a8ea7 · 8,192 slots · 15 workers. * Extra PSS sampling. Warm-up / measurement: 10 / 36 s; code exchange: 5 / 20 s.", "驱动 357a8ea7 · 8,192 在途槽 · 15 线程。* 额外采集 PSS。预热／测量 10／36 秒，授权码兑换 5／20 秒。"), fontsize=9, color="#475569")
            fig.text(.12, .026, text(language, "Latency covers successful completions only. † Fewer than 1,000 successes per round: P99.9 is near the maximum of a small surviving sample.", "延迟仅统计成功业务。† 每轮成功样本不足 1,000，P99.9 接近这一小批成功样本的最大值。"), fontsize=9, color="#475569")
            fig.text(.12, .007, text(language, "Overloaded runs can have very few successful samples; their percentiles do not describe the experience of all planned operations.", "过载轮次可能只剩很少成功样本，这些分位数不能代表全部计划业务的体验。"), fontsize=9, color="#475569")
        elif name == "memory":
            fig, axis = plt.subplots(figsize=(12, 5.2))
            maximum = max(row["pss"] for row in spec)
            for i, row in enumerate(spec):
                axis.barh(i, row["pss"], height=.48, color=colors[row["peer"]])
                axis.text(row["pss"] + maximum * .02, i, f'{row["pss"]:,.1f} MiB', va="center", fontsize=11)
                axis.text(maximum * 1.30, i, f'{row["tps"]:,.2f} TPS · {row["performance_samples"]}/{row["samples"]}' + text(language, "", " 轮"), va="center", fontsize=10)
            axis.set_yticks(range(len(spec)), [SERVICES[row["peer"]] for row in spec])
            axis.invert_yaxis()
            axis.set_xlim(0, maximum * 1.95)
            axis.set_xticks([0, 250, 500, 750, 1000])
            axis.set_xlabel(text(language, "Whole-server peak PSS (MiB)", "全服务端峰值 PSS（MiB）"))
            axis.set_title(text(language, "Deployment memory · UserInfo at 1,000 offered TPS", "部署内存 · UserInfo 每秒计划 1,000 次业务"), loc="left", fontsize=16, pad=28)
            axis.text(maximum * 1.30, -.65, text(language, "Success TPS · valid / memory rounds", "成功 TPS · 性能有效／内存观测轮数"), fontsize=9)
            axis.grid(axis="x", color="#E5E7EB", zorder=0)
            axis.set_axisbelow(True)
            fig.text(.12, .02, text(language, "PSS apportions shared pages. Rounds affected by host contention are retained here and excluded from latency comparisons.", "PSS 按比例分摊共享页。此处保留受宿主竞争影响的内存观测，这些轮次不进入延迟对照。"), fontsize=8.5, color="#475569")
            fig.subplots_adjust(left=.12, right=.98, bottom=.18, top=.83)
        else:
            fig, axis = plt.subplots(figsize=(10.8, 4.6))
            entries = spec["points"]
            maximum = max(row["cpu"] for row in entries.values())
            for i, peer in enumerate(SERVICES):
                row = entries[peer]
                axis.barh(i, row["cpu"], height=.48, color=colors[peer])
                axis.text(row["cpu"] + maximum * .025, i, f'{row["cpu"]:.2f}' + text(language, " cores", " 核") + f' · n={row["samples"]}', va="center", fontsize=10)
            axis.set_yticks(range(len(SERVICES)), [SERVICES[peer] + ("*" if entries[peer]["has_pss"] else "") for peer in SERVICES])
            axis.invert_yaxis()
            axis.set_xlim(0, maximum * 1.6)
            axis.set_xticks([0, .25, .5, .75, 1, 1.25])
            axis.xaxis.set_major_formatter(FuncFormatter(lambda x, _: f"{x:.2f}"))
            axis.set_title(text(language, "UserInfo CPU · 1,000 offered TPS", "UserInfo CPU · 每秒计划 1,000 次业务"), loc="left", fontsize=16, pad=22)
            axis.set_xlabel(text(language, "Whole-server mean CPU (cores)", "全服务端平均 CPU（核）"))
            axis.grid(axis="x", color="#E5E7EB", zorder=0)
            axis.set_axisbelow(True)
            fig.text(.12, .045, text(language, "Application + PostgreSQL / Valkey where used; Kanidm's embedded database is included in the application.", "应用加实际使用的 PostgreSQL／Valkey；Kanidm 内嵌数据库计入应用。"), fontsize=8.5, color="#475569")
            fig.text(.12, .012, text(language, "Same windows as the UserInfo latency panel. * Extra PSS sampling.", "与 UserInfo 延迟图使用相同窗口。* 额外采集 PSS。"), fontsize=8.5, color="#475569")
            fig.subplots_adjust(left=.12, right=.97, bottom=.22, top=.84)
        suffix = ".zh_CN" if language == "zh_CN" else ""
        path = directory / (name + suffix + ".svg")
        fig.savefig(path, metadata={"Date": None, "Description": "data-sha256:" + chart_digest([language, spec])}, bbox_inches="tight")
        path.write_text("\n".join(line.rstrip() for line in path.read_text().splitlines()) + "\n", encoding="utf8")
        plt.close(fig)


INTRO = {"en": """**Measured build: [`33984220`](https://github.com/nazozero/NazoAuth/commit/33984220ed1f48228e4b0f4ed8c345c2f63feb3b) + [token-endpoint quota switch patch](fixture/token-ip-quota.patch). Subsequent changes in PR #310 have not been retested in the five-service benchmark.**

The application uses **8 physical cores, one logical CPU per core**. PostgreSQL, Valkey and the load generator use separate cores. One OAuth service runs at a time; Goose 0.19.2 schedules real protocol requests at a fixed arrival rate.

**P95, P99 and P99.9 describe successful-operation latency, including queueing from the scheduled arrival.** Authorization and exchange may contain several HTTP requests per operation. The charts compare these percentiles at the same offered load and show successful, failed and unsent operation counts alongside them. Achieved TPS is load context; these measurements do not establish maximum sustainable throughput. `n` is the number of included rounds.

[Latency overview](#latency-overview) · [Deployment memory](#deployment-memory) · [Full results](#full-results) · [Test conditions](#test-conditions) · [Reproduction](#reproduction)
""", "zh_CN": """**被测构建：[`33984220`](https://github.com/nazozero/NazoAuth/commit/33984220ed1f48228e4b0f4ed8c345c2f63feb3b)＋[令牌入口开关补丁](fixture/token-ip-quota.patch)。PR #310 的后续代码修订尚未进行五服务负载复测。**

主服务使用 **8 个物理核心，每核 1 个逻辑 CPU**。PostgreSQL、Valkey 和发压端使用独立核心。每次只运行一个 OAuth 服务，以 Goose 0.19.2 的固定到达率测量真实协议请求。

**P95、P99、P99.9 表示成功业务的完成延迟，包含从计划到达开始的排队时间。** 授权和兑换的多次 HTTP 请求合算一笔业务。图表比较同一计划负载下的这三个分位数，并同时显示成功、失败和未发出业务数。实际 TPS 作为负载背景；这些测量没有确定最大可持续吞吐。`n` 是纳入轮数。

[延迟概览](#延迟概览) · [部署内存](#部署内存) · [全部结果](#全部结果) · [测试条件](#测试条件) · [复现](#复现)
"""}

CONDITIONS = {"en": """## Test conditions

| Service | Measured version | Machine token / client authentication | Service configuration |
|---|---|---|---|
| NazoAuth | [`33984220`](https://github.com/nazozero/NazoAuth/commit/33984220ed1f48228e4b0f4ed8c345c2f63feb3b) + [quota switch patch](fixture/token-ip-quota.patch) | RS256 JWT / Basic | PostgreSQL pool 32, Valkey; successful machine-issuance audit and token-endpoint IP quota disabled; user issuance and rotation retain transactional audit, external export disabled |
| Rauthy | 0.37.2 · `fe6bcb95` | RS256 JWT / form credentials | PostgreSQL pool 32, embedded cache; token-issuance events disabled |
| Kanidm | 1.12.1 · `fb052e53` | JWE / Basic | Embedded database, HTTPS/1.1, test CA verified |
| Keycloak | 26.8.2 · `26018f2a` | RS256 JWT / Basic | PostgreSQL pool 32; heap 512 MiB–4 GiB; JVM processor setting 16, execution constrained by 8-core affinity |
| Ory Hydra | 26.2.0 · `0b84568f` | RS256 JWT / Basic | PostgreSQL pool 32; `serve all --dev`, administrative port confined to the isolated network |

This comparison covers these deployments and configurations. Each service retains its native token format, client authentication, state access and audit semantics. RS256 machine tokens use 2,048-bit keys and a 300-second lifetime; Kanidm's JWE tokens use 900 seconds. Machine issuance returns scope `profile`, or `openid profile` for Rauthy. All timed traffic uses HTTP/1.1 inside the isolated network; Kanidm uses HTTPS and the other services use HTTP. Preparation checks signatures, token properties and introspection responses. Image digests, build hashes and runtime settings are recorded in the [environment snapshots](evidence/environment/), [deployment script](deploy.sh) and [native service configuration](native-deploy.sh).

| Item | Setting and measurement boundary |
|---|---|
| Hardware | CNB Linux x86-64, AMD EPYC 9K65, no swap. Batches use the same CPU model and role allocation; CPU sets do not overlap |
| Resources | Application: 8 logical CPUs; PostgreSQL: 14; Valkey: 2; Goose: 15. No hard application memory limit. Application and whole-server CPU are reported separately |
| Persistence | PostgreSQL: 1 GiB shared buffers, 128 maximum connections; fsync, synchronous_commit and full_page_writes enabled. Valkey: RDB/AOF disabled. Database state persists between rounds of the same service |
| Windows | Code exchange: 5-second warm-up and 20-second measurement; other included flows: 10-second warm-up and 36-second measurement. The application restarts before each round; memory studies restart PostgreSQL before each group |
| Generator | Standard: 8,192 in-flight slots and 15 worker threads. Wide: 32,768 slots, 24 threads, separate journal writer and expanded source-port range. Configurations are aggregated separately |
| Timing | Fixed scheduled arrivals; arrivals more than 5 ms late are not sent. Each HTTP request has a 5-second timeout and no automatic retry. Latency includes the wait between scheduled arrival and transmission |
| Counts | Successful TPS = operations scheduled inside the measurement window that eventually succeed / window duration. This includes successes returning after the window. Failed and unsent operations are listed separately; raw JSON retains the in-flight count at the window boundary |
| Statistics | Throughput, latency, CPU and memory use medians across rounds. Percentiles are not pooled across rounds; Max is the maximum across all rounds. Failed / unsent counts are summed. Rounds with zero successes have no successful-latency percentiles; latency-sample round counts are reported separately |
| CPU and memory | CPU comes from process-time deltas. RSS/PSS are sampled peaks within the window. Whole-server peaks sum components at the same instant; separate component peaks cannot simply be added |

### What each flow measures

| Flow | Timed work and shared prerequisites |
|---|---|
| Machine token issuance | Authenticate client credentials, issue a new access token, verify token_type, lifetime and a nonempty token in the successful response |
| UserInfo | Rotate through 32 real user tokens, read profiles and verify the returned subject |
| Machine / user token introspection | Verify `active: true`. Machine set: 16 clients with 32 tokens each; user set: 32 users with 16 tokens each. Hydra uses its trusted administrative endpoint |
| Authorization code exchange | Prepare real sessions and S256 PKCE before timing. Exchange each code once and check the expiry budget for the entire prepared batch before measurement |
| Refresh token rotation | 32/64/128 users with independent token families; each family uses only the latest returned successor. Table titles show users × families per user |
| Silent authorization + exchange | From the authorization request with `prompt=none` through the token response. Usually two HTTP requests for NazoAuth and Keycloak; Rauthy includes its native session-authorization submission, making three |
| Explicit consent + exchange | Start an authorization request, submit an actual consent decision, then exchange the code. Grouped separately from flows requiring no interaction |

Rauthy's measured refresh configuration delays successor activation by about 240 seconds. Kanidm's repeated-consumption semantics differ from immediate strict rotation, so neither is merged into that group. Hydra's complete authorization flow depends on an external identity and consent service. Kanidm 1.12.1 does not implement repeated consent enforcement through `prompt=consent`; Rauthy returns login interaction for that parameter in the measured account configuration. Only verified flows are compared. [Rotation driver check](evidence/environment/refresh-driver.json) · [Rauthy authorization implementation](https://github.com/sebadob/rauthy/blob/fe6bcb95192e8a83c29e2b525bf4960933bea3bd/src/api/src/oidc.rs) · [Kanidm authorization implementation](https://github.com/kanidm/kanidm/blob/v1.12.1/server/lib/src/idm/oauth2.rs)

### Inclusion rules

Driver binaries, slot counts, worker counts and sampling methods are aggregated separately. Missing fields in older records remain unknown; they are not assigned standard defaults.

Fixture checks, operation accounting, resource sampling and CPU affinity must pass before inclusion. Windows are excluded if late scheduling exceeds 0.1% of planned operations, the generator lacks resources, or host contention cannot be ruled out. Valid measurements of server overload, HTTP failures and missed throughput targets remain included. `PASS`/`FAIL` describe load and latency thresholds; `INVALID` describes unsuitable measurement conditions. The rules are implemented in [seal.py](monitor/seal.py) and [placement.py](monitor/placement.py).

This report describes the recorded build and configuration. New implementations and configurations produce new window files and reports, preserving published measurements. The current generator labels unavailable local source addresses as `transport_addr_unavailable` for the generator-quality gate; historical generic transport errors retain their original classification.
""", "zh_CN": """## 测试条件

| 服务 | 被测版本 | 机器令牌／客户端认证 | 服务配置 |
|---|---|---|---|
| NazoAuth | [`33984220`](https://github.com/nazozero/NazoAuth/commit/33984220ed1f48228e4b0f4ed8c345c2f63feb3b)＋[令牌入口开关补丁](fixture/token-ip-quota.patch) | RS256 JWT／Basic | PostgreSQL 池 32、Valkey；机器签发成功审计和令牌入口 IP 配额关闭；用户签发及轮换保留事务审计，外部导出关闭 |
| Rauthy | 0.37.2 · `fe6bcb95` | RS256 JWT／表单凭据 | PostgreSQL 池 32、内嵌缓存；令牌签发事件关闭 |
| Kanidm | 1.12.1 · `fb052e53` | JWE／Basic | 内嵌数据库，HTTPS/1.1，验证测试 CA |
| Keycloak | 26.8.2 · `26018f2a` | RS256 JWT／Basic | PostgreSQL 池 32；堆 512 MiB–4 GiB；JVM 可见处理器参数 16，执行受 8 核亲和性约束 |
| Ory Hydra | 26.2.0 · `0b84568f` | RS256 JWT／Basic | PostgreSQL 池 32；`serve all --dev`，管理端口仅开放给隔离网络 |

这是上述配置下的产品部署对照。原生令牌格式、客户端认证方式、状态读写和审计语义均随服务保留。机器令牌的 RS256 组使用 2,048 位密钥及 300 秒有效期；Kanidm 的 JWE 令牌为 900 秒。机器签发返回的 scope 为 `profile`，Rauthy 为 `openid profile`。全部计时流量均在隔离网络内使用 HTTP/1.1；Kanidm 使用 HTTPS，其他服务使用 HTTP。请求准备时核对签名、令牌属性与内省结果。镜像摘要、构建哈希和运行参数见 [环境快照](evidence/environment/)、[部署脚本](deploy.sh)及[原生服务配置](native-deploy.sh)。

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
"""}

REPRODUCE = {"en": """## Reproduction

From the repository root, offline validation requires only Python 3.10+:

```sh
python3 perf/report.py --check --raw
python3 perf/report.py --output /tmp/oauth-benchmark.md
python3 perf/report.py --language zh_CN --output /tmp/oauth-benchmark.zh_CN.md
```

With no `--output`, the generator writes both `README.md` (English) and `README.zh_CN.md` (Chinese) from the same observations; `--check` verifies both reports and both language versions of the charts. With `--output`, it writes or checks only that file, in English by default; `--language zh_CN` selects Chinese. `--check` also verifies per-round accounting, the complete evidence file list, SHA-256 and chart data digests. `--raw` reconstructs available operation ledgers; on Linux it also recomputes CPU, RSS and PSI for those windows. Run `python3 perf/report.py --charts` to regenerate both SVG language versions with Matplotlib; English uses its bundled DejaVu Sans font, and Chinese uses Noto Sans CJK.

New load tests need a dedicated Linux x86-64 environment, Docker, Git, Bash, Python 3, a C compiler and static libc, jq, OpenSSL, patch, flock and taskset. The default reproduces the measured NazoAuth build above. Deployment requires at least 25 distinct physical cores in one NUMA node to isolate services and the generator.

```sh
bash perf/bench.sh setup
bash perf/bench.sh run nazo machine 1000 3
bash perf/bench.sh run nazo exchange 1000 3
bash perf/bench.sh run nazo refresh 1000 3
bash perf/bench.sh run nazo authorize-silent 1000 3
bash perf/bench.sh run nazo authorize 1000 3
bash perf/bench.sh run nazo userinfo 1000 3
python3 perf/report.py --input perf/.work/windows --output /tmp/fresh.md
python3 perf/report.py --input perf/.work/windows --language zh_CN --output /tmp/fresh.zh_CN.md
```

`--input` requires a separate `--output` and never overwrites either published report. Fresh reports contain the new measurements and their recorded build identifiers, with the same grouping and statistics in either language.

Service names for `run` are `nazo`, `rauthy`, `kanidm`, `keycloak` and `hydra`; other supported flows include `machine-introspect`, `user-introspect` and `authorize-consent`. `bash perf/bench.sh matrix` replays the published scenarios, offered rates, round counts and token-family sizes in a fixed-seed interleaved order. Use `BENCH_PROFILE=journal-wide` for the wide profile, after deploying a separate environment with `BENCH_NETWORK=wide bash perf/bench.sh setup`. Every round gets a unique directory; credentials and new results remain in the ignored `perf/.work/` directory.

`bash perf/bench.sh memory nazo` measures five UserInfo load levels. `bash perf/bench.sh pg-memory nazo exchange 1000` captures one round of database mappings; append `retain` to reuse the running database. `python3 perf/report.py --memory-input perf/.work/windows` rebuilds the memory table from new measurements; add `--language zh_CN` for Chinese. `bash perf/bench.sh login` runs separate password-login diagnostics; its closed-loop results are stored separately from these fixed-arrival-rate measurements.
""", "zh_CN": """## 复现

在仓库根目录运行，离线验证只需 Python 3.10+：

```sh
python3 perf/report.py --check --raw
python3 perf/report.py --output /tmp/oauth-benchmark.md
python3 perf/report.py --language zh_CN --output /tmp/oauth-benchmark.zh_CN.md
```

不指定 `--output` 时，生成器从同一批观测同时生成英文 `README.md` 和中文 `README.zh_CN.md`；`--check` 同时核验两份文档与对应语言的图表。指定 `--output` 时只写入或核验该文件，默认英文，`--language zh_CN` 选择中文。`--check` 还核验每轮计数、完整归档清单、SHA-256 和图表数据摘要。`--raw` 重算已归档逐请求账本；在 Linux 上还重算这些窗口的 CPU、RSS 和 PSI。执行 `python3 perf/report.py --charts` 用 Matplotlib 生成中英文 SVG；英文使用自带的 DejaVu Sans 字体，中文使用 Noto Sans CJK。

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
python3 perf/report.py --input perf/.work/windows --language zh_CN --output /tmp/fresh.zh_CN.md
```

`--input` 必须搭配独立的 `--output`，不会覆盖任一已发表报告。新报告保留本次测量和记录的构建标识，两种语言使用相同的分组与统计口径。

`run` 的服务名为 `nazo`、`rauthy`、`kanidm`、`keycloak` 或 `hydra`，还支持 `machine-introspect`、`user-introspect` 和 `authorize-consent`。`bash perf/bench.sh matrix` 按固定种子交错重放已发表的场景、档位、轮数和令牌族规模；用 `BENCH_PROFILE=journal-wide` 选择宽配置，并先在独立环境以 `BENCH_NETWORK=wide bash perf/bench.sh setup` 部署。每轮使用唯一目录，凭据和新结果保存在忽略提交的 `perf/.work/`。

`bash perf/bench.sh memory nazo` 运行 UserInfo 的五个档位；`bash perf/bench.sh pg-memory nazo exchange 1000` 采集单轮数据库映射，末尾加 `retain` 沿用正在运行的数据库。`python3 perf/report.py --memory-input perf/.work/windows` 重建新测量的内存表，加 `--language zh_CN` 输出中文。`bash perf/bench.sh login` 运行独立密码登录诊断，所得闭环数据单独保存，不并入本页的固定到达率结果。
"""}

def publication_selection(rows):
    control = json.loads((HERE / "evidence/environment/refresh-driver.json").read_bytes())
    disputed = control["legacy_buffered_binary_sha256"]
    excluded = [row for row in rows if row["flow"] == "refresh" and row.get("generator_sha256") == disputed]
    ids = {row["id"] for row in excluded}
    return [row for row in rows if row["id"] not in ids], excluded


def driver_exclusions(rows, language):
    entries = []
    for row in sorted(rows, key=lambda r: (r["peer"], r["rate"], r["id"])):
        op = row["operations"]["all"]
        entries.append([f'[`{row["id"]}`](evidence/windows/{row["id"]}.json)', SERVICES[row["peer"]],
                        f'{row["rate"]:,}', fmt(op["successful_tps"]), f'{op["failed"]:,}'])
    return table(text(language, ["Window", "Service", "Offered TPS", "Recorded successful TPS", "Recorded failures"],
                      ["窗口", "服务", "目标 TPS", "原记录成功 TPS", "原记录失败数"]), entries)


def render(rows, published, language="en"):
    archived_count = len(rows)
    eligible, conflicts = publication_selection(rows) if published else (rows, [])
    data = aggregates(eligible)
    if not published:
        return "\n\n".join([text(language, "# OAuth / OIDC measurement results", "# OAuth / OIDC 本次测量"),
                              *details(data, language, include_revision=True)]) + "\n"
    observations = reference_memory()
    samples = {p.name.removesuffix(".tar.gz") for p in (HERE / "evidence/samples").glob("*.tar.gz")}
    failures = sum(r["operations"]["all"]["failed"] for r in eligible)
    failed_windows = sum(r["status"] == "FAIL" for r in eligible)
    invalid = sum(r["performance_status"] == "INVALID" for r in observations)
    machine = chart_specs(data, observations)["latency"][1]["points"]
    low_sample_counts = {peer: f'{machine[peer]["success"]:,} / {machine[peer]["planned"]:,}' for peer in ("kanidm", "hydra")}
    blocks = [text(language, "# OAuth / OIDC single-instance benchmark", "# OAuth / OIDC 单实例性能基准"),
              text(language, "[简体中文](README.zh_CN.md)", "[English](README.md)"), INTRO[language],
              text(language,
                   f"The archive contains **{archived_count} single-flow windows**: **{len(eligible)} are included** in the comparison, and {len(conflicts)} with conflicting rotation-driver evidence are retained separately. Among the included windows, {failed_windows} missed load or latency thresholds; **all {failures:,} failed operations are counted**. Another {len(observations)} memory observations retain their measurement-quality labels.",
                   f"归档保存 **{archived_count} 个单链路窗口**，正式对照纳入 **{len(eligible)} 个**，{len(conflicts)} 个因轮换驱动证据冲突单列保留。纳入窗口中，{failed_windows} 个未达到负载或延迟门槛，**{failures:,} 次已发业务失败全部计入**。另保留 {len(observations)} 个内存观测及其测量质量标记。"),
              text(language, "## Latency overview", "## 延迟概览"),
              text(language, "![P95, P99 and P99.9 at 1,000 offered TPS, with success counts, failures, unsent operations and round counts](charts/latency.svg)",
                   "![每秒一千次计划业务下的 P95、P99、P99.9，附成功数、失败数、未发出数和轮数](charts/latency.zh_CN.svg)"),
              text(language,
                   "The panels use the same recorded driver (`357a8ea7`), 8,192 slots and 15 threads. Windows have the same duration within each flow. `*` marks extra PSS sampling for NazoAuth UserInfo and code exchange. The code-exchange and machine-issuance panels use logarithmic millisecond axes. Rauthy's single machine-issuance round at this rate lacks driver metadata; Kanidm has no comparable code-exchange window. Their records are not inserted into matched comparisons. Full results include other rates and driver groups; no refresh comparison containing NazoAuth has a shared recorded driver across services.",
                   "三个场景使用相同的已记录驱动（`357a8ea7`）、8,192 在途槽及 15 线程，同场景的窗口时长相同。`*` 表示 NazoAuth 的 UserInfo 与授权码兑换额外采集 PSS。机器签发和兑换图使用对数毫秒轴。Rauthy 该档机器签发的唯一轮次未记录驱动参数；Kanidm 没有可比兑换窗口，所以不补入这组对照。其他档位和驱动组见完整结果；含 NazoAuth 的刷新轮换没有跨服务共同驱动组。"),
              text(language,
                   f"**Latency covers successful completions only.** Overloaded runs can have very few successful samples: machine issuance completed only **{low_sample_counts['kanidm']}** planned operations for Kanidm and **{low_sample_counts['hydra']}** for Hydra. Each round had fewer than 1,000 successes, so its P99.9 lies near the largest successful sample. These percentiles do not describe all planned operations. The chart shows success / planned counts and failed / unsent totals to keep that distinction visible.",
                   f"**延迟只统计成功完成的业务。** 过载轮次可能只剩很少成功样本：机器签发中，Kanidm 仅成功 **{low_sample_counts['kanidm']}** 次计划业务，Hydra 仅 **{low_sample_counts['hydra']}** 次。各轮成功样本均不足 1,000，P99.9 接近这一小批成功样本的最大值，不能代表全部计划业务的体验。图中同时显示成功／计划数及失败／未发出合计。"),
              text(language,
                   "NazoAuth's nine UserInfo memory observations at 12,000 offered TPS all failed performance-validity checks: **no valid performance measurement is available at that rate**. NazoAuth machine issuance at 3,000 TPS and Rauthy at 1,000 TPS each have only one valid round, retained in the full results.",
                   "NazoAuth 的 UserInfo 12,000 TPS 有九个内存观测，均未通过性能有效性核查：**该档没有有效性能测量**。NazoAuth 机器签发 3,000 TPS、Rauthy 机器签发 1,000 TPS 各只有一轮有效测量，保留在完整结果中。"),
              text(language, "### UserInfo CPU", "### UserInfo CPU"),
              text(language, "![Whole-server mean CPU for the same UserInfo latency windows](charts/read-cpu.svg)",
                   "![与 UserInfo 延迟图相同窗口的全服务端平均 CPU 核数](charts/read-cpu.zh_CN.svg)"),
              text(language, "## Deployment memory", "## 部署内存"),
              text(language, "![Whole-server PSS at 1,000 offered UserInfo TPS, with achieved load and valid round counts](charts/memory.svg)",
                   "![UserInfo 每秒一千次计划业务下的全服务端 PSS，附实际负载与有效轮数](charts/memory.zh_CN.svg)"),
              text(language,
                   "PSS apportions shared pages across processes. PostgreSQL shared pages appear in several processes' RSS, so summed RSS is not physical memory usage. These memory observations include rounds affected by host contention; achieved TPS and performance-valid round counts are shown alongside them. Invalid rounds do not enter the latency comparison. Each service retains its own business data. [Raw memory observations](evidence/protocol-memory.jsonl) · [Linux memory accounting](https://docs.kernel.org/filesystems/proc.html)",
                   "PSS 按共享比例分摊进程内存。PostgreSQL 共享页会在多个进程的 RSS 中重复计数，所以 RSS 合计不等于实际物理内存。图中内存观测包括宿主干扰轮，右侧同时显示实际成功 TPS 和性能有效轮数；无效轮不进入延迟对照。不同服务沿用各自业务数据。[原始内存观测](evidence/protocol-memory.jsonl) · [Linux 内存计量](https://docs.kernel.org/filesystems/proc.html)"),
              "<details>\n<summary>" + text(language, "Scenario coverage", "五服务场景覆盖") + "</summary>\n", coverage(data, language),
              text(language, "— means no valid measurement with the shared semantics. Round counts appear in the full results.",
                   "— 表示没有该共同语义下的有效测量；各档轮数见完整结果。"), "</details>",
              *details(data, language), CONDITIONS[language],
              "<details>\n<summary>" + text(language, "Rotation-driver evidence conflicts: records retained, excluded from the comparison",
                                                   "轮换驱动证据冲突：保留原记录，排除正式汇总") + "</summary>\n",
              text(language,
                   "In the archived single-family control, driver `357a8ea7` returned 200/400/400/400 over four requests, while `ee4a059e` returned four 200s. The windows below nevertheless record both `357a8ea7` and a continuously rotating fixture. The raw `driver.sha256` agrees with the JSON; the ledger did not retain every successor token, so the conflict cannot be resolved. These records are excluded from formal rotation comparisons, while the original files and reconstruction path remain available. [Driver control experiment](evidence/environment/refresh-driver.json)",
                   "已归档的单令牌族控制实验中，驱动 `357a8ea7` 四次请求依次为 200/400/400/400，`ee4a059e` 为四次 200。以下窗口却同时记录 `357a8ea7` 与持续轮换夹具。原始 `driver.sha256` 和 JSON 一致；账本未保存每次后继令牌，无法消除该冲突。这些记录不计入正式轮换比较，原始文件和重算入口保留。[驱动控制实验](evidence/environment/refresh-driver.json)"),
              driver_exclusions(conflicts, language),
              text(language, "Only two NazoAuth refresh-rotation rounds at 1,000 TPS remain eligible.",
                   "NazoAuth 刷新轮换在 1,000 TPS 下只有两轮可纳入记录。"), "</details>",
              "<details>\n<summary>" + text(language, "Archived invalid memory observations and their reasons", "已归档的无效内存观测及原因") + "</summary>\n",
              exclusion_table(observations, language),
              text(language,
                   f"These are the {invalid} retained INVALID memory observations. The archive covers the single-flow windows used here, evidence-conflict records and memory studies; it does not contain every historical trial. A window may trigger several exclusion reasons.",
                   f"这里列出保留的 {invalid} 个 INVALID 内存观测。归档范围为本页所用单链路窗口、证据冲突记录及内存专项，未包含全部历史试跑。一次窗口可同时触发多个排除原因。"), "</details>",
              text(language, "### Traceable data", "### 可追溯数据"),
              text(language,
                   f"[Per-round JSON](evidence/windows/) stores operation counts, percentiles, resources and original quality judgments for {archived_count} windows. Of these, {len(samples)} have [operation ledgers and resource-sample bundles](evidence/samples/); the others retain per-round statistics. The memory study also includes [successful-duration vectors](evidence/memory-success-latencies.zip) and [UserInfo 12,000 TPS arrival records](evidence/userinfo-reference/). The [SHA-256 manifest](evidence/SHA256SUMS) covers every archived file. Report, chart and raw-ledger verification scopes are documented separately.",
                   f"[逐轮 JSON](evidence/windows/)保存 {archived_count} 个窗口的业务计数、分位数、资源和原始质量判定。其中 {len(samples)} 个有[逐操作账本及资源采样包](evidence/samples/)，其余保留逐轮统计。内存专项另有[成功耗时序列](evidence/memory-success-latencies.zip)与[UserInfo 12,000 TPS 到达记录](evidence/userinfo-reference/)。[SHA-256 清单](evidence/SHA256SUMS)覆盖所有归档文件；文档、图表和原始账本的核验范围分别列明。"),
              REPRODUCE[language]]
    return "\n\n".join(block.strip() for block in blocks) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="fresh windows directory")
    parser.add_argument("--memory-input", type=Path, help="print RSS and PSS from measured protocol windows")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--language", choices=LANGUAGES, help="language for --output or --memory-input (default: en)")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--raw", action="store_true", help="recalculate all available arrival ledgers")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--charts", action="store_true", help="render published SVG charts (requires Matplotlib)")
    args = parser.parse_args()
    language = args.language or "en"
    if args.language and not (args.output or args.memory_input):
        parser.error("--language requires --output or --memory-input; the default generates or checks both published languages")
    if args.input and not args.output:
        parser.error("--input requires a separate --output")
    if args.input and args.output.resolve() in {(HERE / name).resolve() for name in LANGUAGES.values()}:
        parser.error("new runs cannot overwrite either published report")
    if args.memory_input:
        if args.input or args.check or args.raw or args.plan or args.output or args.charts:
            parser.error("--memory-input prints a standalone table")
        files = sorted(args.memory_input.glob("*/*/*/memory.json"))
        if not files:
            parser.error("no memory observations found")
        print(memory_table((json.loads(path.read_bytes()) for path in files), language))
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
            for chart_language in LANGUAGES:
                write_charts(specs, chart_language)
        if args.check:
            check_charts(specs)
    outputs = {language: args.output} if args.output else {lang: HERE / name for lang, name in LANGUAGES.items()}
    for lang, dest in outputs.items():
        result = render(rows, args.input is None, lang)
        if args.check:
            if dest.read_text(encoding="utf8") != result:
                raise SystemExit(f"{dest}: report differs from its window data")
        else:
            dest.write_text(result, encoding="utf8", newline="\n")
    if args.check:
        print(f"{len(rows)} windows and {len(outputs)} report(s) verified")


if __name__ == "__main__":
    main()
