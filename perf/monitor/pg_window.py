"""Reconstruct PostgreSQL residency from a pg-memory window (all sizes in KiB)."""
import json
import sys
from pathlib import Path

if __package__:
    from .memory_window import protocol_window
else:
    from memory_window import protocol_window


def totals(sample):
    pids = sample["pids"]
    if not pids or len({p[0] for p in pids}) != len(pids) or not any(p[0] == 1 for p in pids):
        raise ValueError("incomplete PostgreSQL process sample")
    for _, rss, pss, private, shared, map_rss, map_pss in pids:
        if not (rss == private + shared and 0 <= pss <= rss and
                0 <= map_pss <= min(pss, map_rss) and map_rss <= rss):
            raise ValueError("inconsistent PostgreSQL page accounting")
    return [len(pids), *(sum(p[i] for p in pids) for i in range(1, 7))]


def peak(row):
    start = row["start_ns"]
    end = start + row["seconds"] * 10**9
    points = [s for s in row["samples"] if start <= s["begin_ns"] <= s["end_ns"] < end
              and s["end_ns"] - s["begin_ns"] <= 10**9]
    if len(points) < row["seconds"] // 4 or points[-1]["end_ns"] - points[0]["begin_ns"] < (end-start)*.65:
        raise ValueError("insufficient PostgreSQL sampling coverage")
    if len({(s["device"], s["inode"], s["size_kib"]) for s in row["samples"]}) != 1:
        raise ValueError("postmaster mapping changed during window")
    return max(map(totals, points), key=lambda t: t[1])


def read_window(path):
    directory = path / "pg-maps"
    summary, proof, o, start_ns = protocol_window(path)
    mode_file = directory / "mode"
    disconnected = directory / "disconnected.json"
    row = dict(peer=summary["peer"], scenario=path.parent.name, rate=summary["rate"], seconds=summary["seconds"],
               warm_seconds=summary["warm_seconds"],
               proof={k: proof[k] for k in ("users", "fixtures", "scope", "id_token_verified",
                      "access_token_userinfo_verified", "fixture_contract", "families_per_user") if k in proof},
               start_ns=start_ns, mode=mode_file.read_text().strip() if mode_file.exists() else "restart",
               before=json.loads((directory/"before.json").read_bytes()), after=json.loads((directory/"after.json").read_bytes()),
               planned=o["planned"], sent=o["sent"], success=o["success"], failed=o["failed"], unsent=o["not_sent"],
               http_requests=o["http_requests"], outcomes=o["outcomes"],
               successful_tail_ms={q:o["offered_to_completion_success_ms"][q] for q in ("95","99")},
               performance_status=summary["status"], invalid_reasons=summary["invalid_reasons"],
               host_cpu_psi_pct=summary["host_cpu_psi_pct"], generator_sha256=summary["generator_sha256"],
               product_revision=summary.get("product_revision"),
               samples=[json.loads(line) for line in (directory/"maps.jsonl").read_bytes().splitlines()])
    if disconnected.exists():
        row["disconnected"] = json.loads(disconnected.read_bytes())
        totals(row["disconnected"])
    if row["peer"] in ("nazo", "keycloak") and row["scenario"] in ("authorize-silent","authorize") and not row["failed"]:
        calls = 3 if row["peer"] == "nazo" and row["scenario"] == "authorize" else 2
        if row["http_requests"] != calls * row["success"]:
            raise ValueError("unexpected request count in authorization chain")
    peak(row)
    return row


if __name__ == "__main__":
    print(json.dumps(read_window(Path(sys.argv[1])), separators=(",", ":")))
