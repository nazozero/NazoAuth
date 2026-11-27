"""Extract UserInfo memory observations independently of latency or scheduling SLOs."""
import json
import re
import sys
from pathlib import Path


def pss_peaks(peer, start, seconds, samples):
    roles = ["app"]
    if peer != "kanidm":
        roles.append("postgres")
    if peer == "nazo":
        roles.append("valkey")
    stop = start + seconds * 10**9
    points = [p for p in samples if len(p) == 2 + len(roles)
              and start <= p[0] <= p[1] < stop and p[1] - p[0] <= 10**9 and min(p[2:]) > 0]
    if not points or len(points) < seconds // 4 or points[-1][0] - points[0][0] < seconds * .65 * 10**9:
        raise ValueError("insufficient in-window PSS coverage")
    peaks = {role: max(p[i] for p in points) / 1024 for i, role in enumerate(roles, 2)}
    return dict(role_peak_pss_mib=peaks, app_peak_pss_mib=peaks["app"],
                server_peak_pss_mib=max(sum(p[2:]) for p in points) / 1024, pss_samples=len(points))


def memory_window(path):
    row = json.loads((path / "summary.json").read_bytes())
    proof = json.loads((path / "proof.json").read_bytes())
    state = json.loads((path / "app-state.json").read_bytes())
    ops = row["operations"]["all"]
    if not (row["flow"] == "userinfo" and proof["users"] == proof["fixtures"] == 32
            and proof["access_token_userinfo_verified"] and state["Running"] and not state["OOMKilled"]
            and 0 < ops["success"] <= ops["sent"] and ops["sent"] + ops["not_sent"] == ops["planned"]
            and ops["success"] + ops["failed"] == ops["sent"] and not ops["outcomes"].get("protocol_error")):
        raise ValueError("incomplete UserInfo workload or service state")
    epoch = int(re.search(r"^epoch_ns=(\d+)", (path / "window").read_text(), re.M)[1])
    start_ns = epoch + row["warm_seconds"] * 10**9
    start = start_ns // 10**6
    end = start + row["seconds"] * 1000
    samples = [list(map(int, line.split())) for line in (path / "pss.tsv").read_text().splitlines()]
    pss = pss_peaks(row["peer"], start_ns, row["seconds"], samples)
    for role in [*pss["role_peak_pss_mib"], "generator"]:
        timestamps = set()
        for line in (path / (role + ".cpu.tsv")).read_text().splitlines():
            at, _, name, _, _, threads, mismatched, _ = line.split("\t")
            if not start <= int(at) < end or name in ("read-pss", "sample-cpu") or name.startswith("runc:"):
                continue
            if int(mismatched):
                raise ValueError(f"{role}/{name} affinity mismatch")
            if int(threads):
                timestamps.add(int(at))
        if len(timestamps) < 4:
            raise ValueError(f"missing {role} affinity samples")
    return dict(start_ns=start_ns, pss_kib=samples,
                peer=row["peer"], target_tps=row["rate"], window=path.name, seconds=row["seconds"],
                planned=ops["planned"], sent=ops["sent"], success=ops["success"], failed=ops["failed"],
                unsent=ops["not_sent"], success_tps=ops["successful_tps"], outcomes=ops["outcomes"],
                generator_sha256=row["generator_sha256"],
                **pss,
                host_cpu_psi_pct=row["host_cpu_psi_pct"], performance_status=row["status"],
                performance_invalid_reasons=row["invalid_reasons"])


if __name__ == "__main__":
    try:
        print(json.dumps(memory_window(Path(sys.argv[1])), indent=2))
    except ValueError as error:
        sys.exit(f"Excluded PSS observation: {error}")
