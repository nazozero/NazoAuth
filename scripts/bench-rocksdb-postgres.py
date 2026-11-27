#!/usr/bin/env python3
"""Run the same repository workload with local, synchronous durable backends.

Linux /proc supplies CPU seconds and proportional resident memory. PostgreSQL
server processes are included, not just the Rust client. No third-party Python
packages are required. Use a disk-backed work directory, not tmpfs.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import signal
import subprocess
import time


class Resources:
    def __init__(self, roots):
        self.roots = roots
        self.ticks = os.sysconf("SC_CLK_TCK")
        self.baseline = {}
        self.latest = {}
        self.peak_kib = {name: 0 for name in roots}
        self.combined_peak_kib = 0
        self.sample()
        self.baseline = self.latest.copy()

    def sample(self):
        processes = {}
        for directory in Path("/proc").iterdir():
            if not directory.name.isdigit():
                continue
            try:
                stat = (directory / "stat").read_text()
                fields = stat[stat.rfind(")") + 2:].split()
                processes[int(directory.name)] = (int(fields[1]), int(fields[19]), int(fields[11]) + int(fields[12]))
            except (FileNotFoundError, ProcessLookupError):
                continue
        totals = {}
        for group, root in self.roots.items():
            members = {root}
            while True:
                children = {pid for pid, (parent, _, _) in processes.items() if parent in members}
                if children <= members:
                    break
                members |= children
            pss = 0
            for pid in members:
                if pid not in processes:
                    continue
                _, started, ticks = processes[pid]
                self.latest[(group, pid, started)] = ticks
                try:
                    lines = Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines()
                    pss += next(int(line.split()[1]) for line in lines if line.startswith("Pss:"))
                except (FileNotFoundError, ProcessLookupError):
                    continue
            totals[group] = pss
            self.peak_kib[group] = max(self.peak_kib[group], pss)
        self.combined_peak_kib = max(self.combined_peak_kib, sum(totals.values()))

    def result(self, seconds):
        self.sample()
        groups = {}
        for group in self.roots:
            cpu = sum(value - self.baseline.get(key, 0) for key, value in self.latest.items() if key[0] == group) / self.ticks
            groups[group] = {"cpu_seconds": cpu, "cpu_percent_one_core": 100 * cpu / seconds, "peak_pss_mib": self.peak_kib[group] / 1024}
        cpu = sum(value["cpu_seconds"] for value in groups.values())
        return {"components": groups, "combined_cpu_seconds": cpu,
                "combined_cpu_percent_one_core": 100 * cpu / seconds,
                "combined_peak_pss_mib": self.combined_peak_kib / 1024,
                "sampling_interval_seconds": 0.05}


def sql(pg_bin, port, command):
    return subprocess.check_output([str(pg_bin / "psql"), "-X", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-p", str(port), "-U", "agent", "-d", "postgres", "-Atc", command], text=True).strip()


def run_trial(args, postgres, backend, concurrency, trial):
    database = f"bench_{backend}_{concurrency}_{trial}"
    path = args.work_dir / database
    environment = os.environ.copy()
    if backend == "postgres":
        sql(args.pg_bin, args.port, f'CREATE DATABASE "{database}"')
        environment["DATABASE_URL"] = f"postgresql://agent@127.0.0.1:{args.port}/{database}"
    command = [str(args.binary), "--backend", backend, "--flows", str(args.flows), "--concurrency", str(concurrency), "--rocksdb-path", str(path)]
    with (args.work_dir / f"{database}.log").open("w") as log:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, env=environment)
        try:
            ready = process.stdout.readline()
            if not ready or json.loads(ready).get("phase") != "ready":
                raise RuntimeError(f"{database} failed before ready; see {log.name}")
            roots = {"application": process.pid}
            if backend == "postgres":
                roots["postgresql"] = postgres.pid
            resources = Resources(roots)
            process.stdin.write("\n")
            process.stdin.flush()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while not selector.select(timeout=0.05):
                    resources.sample()
                line = process.stdout.readline()
            if not line:
                raise RuntimeError(f"{database} failed during measurement; see {log.name}")
            measured = json.loads(line)
            if measured.get("phase") != "measured":
                raise RuntimeError(f"unexpected measurement boundary: {measured}")
            usage = resources.result(measured["elapsed_seconds"])
            process.stdin.write("\n")
            process.stdin.flush()
            result = json.loads(process.stdout.readline())
            result["resources"] = usage
            result["trial"] = trial
            if process.wait(timeout=30) != 0 or result["errors"]:
                raise RuntimeError(f"{database} returned failed operations: {result}")
            print(json.dumps(result), flush=True)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    if backend == "postgres":
        sql(args.pg_bin, args.port, f'DROP DATABASE "{database}"')
    else:
        shutil.rmtree(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Release token_repository_bench executable")
    parser.add_argument("--pg-bin", type=Path, required=True, help="Directory containing postgres, initdb and psql")
    parser.add_argument("--work-dir", type=Path, required=True, help="New disk-backed benchmark directory")
    parser.add_argument("--flows", type=int, default=50000)
    parser.add_argument("--concurrency", type=int, nargs="+", default=[1, 8, 32])
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--port", type=int, default=55439)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    args.pg_bin = args.pg_bin.resolve()
    args.work_dir = args.work_dir.resolve()
    args.work_dir.mkdir(parents=True, exist_ok=False)
    data = args.work_dir / "postgres"
    subprocess.run([str(args.pg_bin / "initdb"), "-D", str(data), "--username=agent", "--auth=trust", "--no-locale", "--encoding=UTF8"], check=True, stdout=subprocess.DEVNULL)
    with (args.work_dir / "postgres.log").open("w") as log:
        postgres = subprocess.Popen([str(args.pg_bin / "postgres"), "-D", str(data), "-h127.0.0.1", f"-p{args.port}", "-c", "unix_socket_directories=", "-c", "fsync=on", "-c", "synchronous_commit=on", "-c", "full_page_writes=on"], stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                if "ready to accept connections" in Path(log.name).read_text():
                    break
                if postgres.poll() is not None:
                    raise RuntimeError(f"PostgreSQL startup failed; see {log.name}")
                time.sleep(0.05)
            else:
                raise RuntimeError("PostgreSQL startup timed out")
            settings = sql(args.pg_bin, args.port, "SELECT json_object_agg(name,setting) FROM pg_settings WHERE name IN ('server_version','fsync','synchronous_commit','full_page_writes','shared_buffers','wal_sync_method')")
            print(json.dumps({"phase": "environment", "platform": platform.platform(), "cpu_count": os.cpu_count(), "postgresql": json.loads(settings), "work_dir": str(args.work_dir), "binary": str(args.binary), "workload": "one authorization-code commit, one OIDC refresh snapshot, one rotation commit per flow; one user per worker"}), flush=True)
            for concurrency in args.concurrency:
                for trial in range(1, args.repetitions + 1):
                    # Alternate order to avoid giving one backend every first run.
                    backends = ["rocksdb", "postgres"] if trial % 2 else ["postgres", "rocksdb"]
                    for backend in backends:
                        run_trial(args, postgres, backend, concurrency, trial)
        finally:
            if postgres.poll() is None:
                postgres.send_signal(signal.SIGINT)
                postgres.wait(timeout=30)


if __name__ == "__main__":
    main()
