"""Render explicitly selected aggregate windows as comparable Markdown tables."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
from statistics import median

ARMS = {"B": "NazoAuth 修前", "A": "NazoAuth 审计开", "N": "NazoAuth 审计关",
        "P": "NazoAuth 审计关，行锁隐式提交", "K": "Keycloak", "H": "Ory Hydra"}
ROLES = ("app", "postgres", "valkey", "generator")

def quant(values, places=2):
    return f"{median(values):,.{places}f}" if values and all(v is not None for v in values) else "—"

def resource(row, role):
    data = row.get("resources", {}).get(role)
    if not data or any(data.get(key) is None for key in ("mean_cpu_cores", "max_single_process_rss_mib")):
        return "—"
    return f"{data['mean_cpu_cores']:.2f} / {data['max_single_process_rss_mib']:.1f}"

def table(header, rows):
    print("| " + " | ".join(header) + " |")
    print("| " + " | ".join(["---"] * len(header)) + " |")
    for row in rows:
        print("| " + " | ".join(map(str, row)) + " |")
    print()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("windows", type=Path, nargs="+")
    parser.add_argument("--details", action="store_true")
    args = parser.parse_args()
    groups = defaultdict(lambda: defaultdict(list))
    for path in sorted(set(args.windows)):
        label = path.stem
        arm, rate, _ = label.split("-")
        row = json.loads(path.read_text())
        assert int(rate) == row["offered_per_second"]
        if arm in "BANP":
            assert row["expected_audit_rows"] == row["wal_committed_audit_rows"] == row["durable_token_issued"]
            assert row["wal_uncommitted_audit_inserts"] == 0
        groups[(row["case"], int(rate))][arm].append((label, row))

    for (case, rate), arms in sorted(groups.items()):
        title = {"machine": "机器令牌签发", "introspect": "查询有效令牌"}[case]
        print(f"### {title} · 目标 {rate:,} 请求/秒\n")
        overview = []
        details = []
        for arm in ARMS:
            if arm not in arms:
                continue
            pairs = arms[arm]
            data = [row for _, row in pairs]
            ok = sum(row["accepted"] for row in data)
            audits = sum(row["wal_committed_audit_rows"] for row in data) if arm in "BANP" else "—"
            overview.append((ARMS[arm], quant([r["success_per_second"] for r in data], 1),
                quant([r.get("p95_ms") for r in data]), quant([r.get("p99_ms") for r in data]),
                f"{ok}/{len(data)}", f"{sum(r['whole_success'] for r in data):,}", audits))
            for label, row in pairs:
                details.append((label, row["outcome"], f"{row['success_per_second']:.1f}",
                    quant([row.get("p95_ms")]), quant([row.get("p99_ms")]),
                    row["whole_success"], row["whole_failed"], row["dropped_whole_trial"],
                    row.get("durable_token_issued", "—"), row.get("wal_committed_audit_rows", "—"), *(resource(row, r) for r in ROLES),
                    quant([row.get("host_cpu_psi_pct")])))
        table(("服务与配置", "成功请求/秒", "P95 毫秒", "P99 毫秒", "通过轮数", "全窗口成功", "审计落盘"), overview)
        if args.details:
            table(("轮次", "判定", "成功/秒", "P95", "P99", "成功", "失败", "漏发", "提交确认", "WAL 落盘",
                "应用 CPU / MiB", "PG CPU / MiB", "Valkey CPU / MiB", "k6 CPU / MiB", "宿主 CPU PSI %"), details)

if __name__ == "__main__":
    main()
