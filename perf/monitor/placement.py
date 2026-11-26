import json
import re
import sys
from pathlib import Path

window = Path(sys.argv[1])
summary_file = window / "summary.json"
data = json.loads(summary_file.read_text())
epoch = int(re.search(r"^epoch_ns=(\d+)", (window / "window").read_text(), re.M)[1]) // 10**6
start = epoch + data["warm_seconds"] * 1000
end = start + data["seconds"] * 1000

def cpuset(mask):
    cpus = set()
    for component in mask.split(","):
        first, _, last = component.partition("-")
        cpus.update(range(int(first), int(last or first) + 1))
    return cpus

def expanded(mask):
    return set().union(*(cpuset(Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
                               .read_text().strip()) for cpu in cpuset(mask)))

samples = []
for line in (window / "pressure.jsonl").open():
    point = json.loads(line)
    if start <= point["t"] < end and "version 15" in point["sched"]:
        times = {int(f[0][3:]): (int(f[7]), int(f[8]))
                 for line in point["sched"]
                 if (f := line.split())[0].startswith("cpu") and f[0][3:].isdigit()}
        samples.append((point["t"], times))
roles = {}
for role in ("app", "postgres", "valkey", "generator"):
    counters = data["resources"].get(role, {})
    if role not in data["resources"]:
        continue
    with (window / f"{role}.cpu.tsv").open() as sample:
        first_row = sample.readline().strip()
    if len(samples) < 2 or not first_row or "mean_cpu_cores" not in counters:
        continue
    cpus = expanded(first_row.split("\t")[-1])
    t0, initial = samples[0]
    t1, final = samples[-1]
    duration = (t1 - t0) * 10**6
    if duration <= 0 or not (cpus <= initial.keys() and cpus <= final.keys()):
        continue
    busy, wait = (sum(final[c][i] - initial[c][i] for c in cpus) / duration
                  for i in range(2))
    background = max(0, busy - counters["mean_cpu_cores"])
    roles[role] = dict(background_cores=background, physical_core_scheduler_wait=wait,
                       clear=wait <= 0.5)
data["role_placement"] = roles
data["role_placement_clear"] = set(roles) == set(data["resources"]) and all(row["clear"] for row in roles.values())
if "app" in roles:
    data["assigned_background_cores"] = roles["app"]["background_cores"]
pre, post = (json.loads((window / name).read_text()) for name in ("pre.json","post.json"))
psi = data.get("host_cpu_psi_pct")
app = roles.get("app", {})
wait = sum(r["physical_core_scheduler_wait"] for r in roles.values())
app_wait = app.get("physical_core_scheduler_wait", 0)
attributed = (pre["quiet"] and post["quiet"] and app_wait >= 4 and app_wait >= .9 * wait
              and app.get("background_cores", float("inf")) <= .5
              and all(r["physical_core_scheduler_wait"] <= 1 for k,r in roles.items() if k != "app"))
if psi is None or not (data["role_placement_clear"] or (psi <= 2 and pre["quiet"]) or attributed):
    data["invalid_reasons"].append("external_cpu_contention")
    data["status"] = "INVALID"
summary_file.write_text(json.dumps(data, indent=2) + "\n")
