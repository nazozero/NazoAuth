#!/usr/bin/env python3
"""Bounded single-instance throughput scaling probe (remote host only).

Runs inside the perf-runner image on the benchmark host. It uses the
*unmodified* `docker-compose.perf.yml` topology (postgres, postgres-init,
valkey, keyset, migrate, nazoauth) exactly like perf/tools/soak_run.sh,
plus an in-container `pinset` helper to place the app on a nested logical
CPU set while postgres/valkey/k6/audit/samplers share the complementary
infra set. Docker-level cpuset controls are ineffective on this host's
nested cgroup-v1 setup, so affinity is applied to the live PID trees.

Subcommands (executed remotely, never on a workstation):

    env-check     capture host/cgroup/image evidence
    pinset-build  compile the static pinset helper into SIS_BIN
    up            fresh stack for a point: down -v + up + pin + audit pair
    run           execute one load point (main + optional phase-3 sidecars)
    ledger        pre/post window ledgers (pg ledger.sql + vkledger)
    eval          evaluate retention gates from collected point.json files
    report        write scaling-points.json aggregate

All durations are hard-bounded per point; total NEW load wall-clock is
tracked in budget.json and capped (failed attempts count against it).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------
# Environment / topology constants
# ---------------------------------------------------------------------

WORKSPACE = os.environ.get("SIS_WORKSPACE", "/workspace")
RESULTS = Path(os.environ.get("SIS_RESULTS", f"{WORKSPACE}/perf-results/sis"))
BIN_DIR = os.environ.get("SIS_BIN", f"{WORKSPACE}/perf-results/sis/bin")
COMPOSE_FILE = f"{WORKSPACE}/docker-compose.perf.yml"
# The compose project identity is the cleanup ownership boundary. It must
# be set explicitly per task and must never be the shared historical
# project — a shared project would make `down -v` destroy other runs'
# volumes, and name-prefix sweeping must never stand in for ownership.
PROJECT = os.environ.get("SIS_PROJECT", "")


def require_project() -> str:
    if not PROJECT:
        raise RuntimeError(
            "SIS_PROJECT must name an explicit, exclusive compose project "
            "(the shared 'nazoauth-perf' is not allowed)")
    if PROJECT == "nazoauth-perf":
        raise RuntimeError(
            "SIS_PROJECT=nazoauth-perf is the shared historical project; "
            "choose an exclusive project identity")
    return PROJECT


NETWORK = f"{PROJECT}_perf_net"
PERF_IMAGE = os.environ.get("SIS_PERF_IMAGE", "sis-perf:latest")
TOOLS = f"{WORKSPACE}/perf/tools"

# Ownership label stamped on every container this harness creates outside
# compose. Cleanup matches the label value exactly; names are display
# metadata only and are never used as an ownership credential.
SIS_LABEL = "sis.owner"

# Registry of containers this run created outside compose. Cleanup only
# removes a container when BOTH conditions hold: its ID was recorded here
# at creation time, and its ownership label still matches this project.
EXTRA_CONTAINERS = RESULTS / f"{PROJECT}-extra-containers.jsonl"

APP = f"{PROJECT}-nazoauth-1"
POSTGRES = f"{PROJECT}-postgres-1"
VALKEY = f"{PROJECT}-valkey-1"
KEYSET = f"{PROJECT}-keyset-1"
MIGRATE = f"{PROJECT}-migrate-1"

DEPID_EPOCH = "019c8ca2-30a6-7000-8000-00000000e103"
CLIENT_PEPPER = "perf-client-secret-pepper-000000000000000001"

# Budget: the plan caps total *load* wall-clock at 30 minutes including
# failed attempts. Setup/teardown time is not load.
LOAD_BUDGET_S = int(os.environ.get("SIS_LOAD_BUDGET_S", "1800"))

# ---------------------------------------------------------------------
# pinset helper (static C source; compiled on the remote host)
# ---------------------------------------------------------------------

PINSET_C = r'''
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

static int parse_list(const char *s, cpu_set_t *set) {
    CPU_ZERO(set);
    while (*s) {
        char *end;
        long a = strtol(s, &end, 10);
        if (end == s || a < 0 || a >= CPU_SETSIZE) return -1;
        long b = a;
        if (*end == '-') {
            s = end + 1;
            b = strtol(s, &end, 10);
            if (end == s || b < a || b >= CPU_SETSIZE) return -1;
        }
        for (long i = a; i <= b; i++) CPU_SET(i, set);
        if (*end == ',') { s = end + 1; continue; }
        if (*end == '\0') break;
        return -1;
    }
    return 0;
}

static long pin_tree(const char *pid, cpu_set_t *set) {
    char dir[64];
    snprintf(dir, sizeof dir, "/proc/%s/task", pid);
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    long ok = 0, fail = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        long tid = strtol(e->d_name, NULL, 10);
        if (tid <= 0) continue;
        if (sched_setaffinity((pid_t)tid, sizeof(*set), set) == 0) ok++;
        else if (errno != ESRCH) fail++;
    }
    closedir(d);
    return fail ? -fail : ok;
}

/* pinset CPULIST --pid TID    retarget one thread
 * pinset CPULIST --tree PID   retarget every thread of a process
 * pinset CPULIST --all        retarget every task visible in this pidns
 * pinset CPULIST --show PID   print Cpus_allowed_list of PID
 * pinset CPULIST CMD [ARGS]   pin self, then exec
 */
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: pinset CPULIST (--pid TID|--tree PID|--all|--show PID|CMD [ARGS...])\n");
        return 64;
    }
    cpu_set_t set;
    if (parse_list(argv[1], &set)) {
        fprintf(stderr, "pinset: bad cpulist %s\n", argv[1]);
        return 64;
    }
    if (argv[2][0] == '-') {
        if (strcmp(argv[2], "--all") == 0 && argc == 3) {
            DIR *d = opendir("/proc");
            if (!d) { perror("opendir"); return 1; }
            struct dirent *e; long ok = 0, bad = 0;
            while ((e = readdir(d))) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                long r = pin_tree(e->d_name, &set);
                if (r >= 0) ok += r; else bad++;
            }
            closedir(d);
            printf("pinned_tasks=%ld failed_procs=%ld\n", ok, bad);
            return bad ? 1 : 0;
        }
        if (strcmp(argv[2], "--tree") == 0 && argc == 4) {
            long r = pin_tree(argv[3], &set);
            if (r < 0) { fprintf(stderr, "pinset: --tree %s failed\n", argv[3]); return 1; }
            printf("pinned_tasks=%ld\n", r);
            return 0;
        }
        if (strcmp(argv[2], "--show") == 0 && argc == 4) {
            char p[64]; snprintf(p, sizeof p, "/proc/%s/status", argv[3]);
            FILE *f = fopen(p, "r"); if (!f) { perror("fopen"); return 1; }
            char line[256];
            while (fgets(line, sizeof line, f))
                if (strncmp(line, "Cpus_allowed_list", 17) == 0) { fputs(line, stdout); break; }
            fclose(f);
            return 0;
        }
        if (argc != 4 || strcmp(argv[2], "--pid") != 0) {
            fprintf(stderr, "usage: pinset CPULIST --pid TID\n");
            return 64;
        }
        long tid = strtol(argv[3], NULL, 10);
        if (sched_setaffinity((pid_t)tid, sizeof(set), &set)) {
            perror("sched_setaffinity");
            return 1;
        }
        return 0;
    }
    if (sched_setaffinity(0, sizeof(set), &set)) {
        perror("sched_setaffinity");
        return 1;
    }
    execvp(argv[2], &argv[2]);
    perror("execvp");
    return 127;
}
'''


# ---------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------

def sh(cmd: list[str], check: bool = True, capture: bool = True,
       timeout: int | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    proc = subprocess.run(
        cmd, text=True, capture_output=capture, timeout=timeout, env=merged)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed rc={proc.returncode}: {shlex.join(cmd)}\n"
            f"stdout={proc.stdout[-2000:]}\nstderr={proc.stderr[-2000:]}")
    return proc


def dc(*args: str, check: bool = True, timeout: int | None = None) -> subprocess.CompletedProcess:
    require_project()
    return sh(["docker", *args], check=check, timeout=timeout)


def dcx(container: str, inner: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return dc("exec", container, *inner, check=check)


def compose(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return dc("compose", "-f", COMPOSE_FILE, "-p", PROJECT, *args,
              check=check, timeout=600)


def psql(sql: str, check: bool = True) -> str:
    proc = dc("exec", "-i", POSTGRES,
              "psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
              "-U", "postgres", "-d", "oauth", "-c", sql,
              check=check, timeout=60)
    return proc.stdout.strip()


def psql_file(path: str, out: Path, extra: list[str] | None = None) -> None:
    require_project()
    with open(path, "rb") as fh:
        proc = subprocess.run(
            ["docker", "exec", "-i", POSTGRES,
             "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "oauth",
             *(extra or [])],
            stdin=fh, text=False, capture_output=True, timeout=120)
    out.write_bytes(proc.stdout)
    if proc.returncode != 0:
        raise RuntimeError(f"psql file failed: {proc.stderr[:500]}")


def jdump(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def _duration_seconds(spec: str) -> int:
    m = re.fullmatch(r"(\d+)(s|m|h)?", spec.strip())
    if not m:
        raise ValueError(f"bad duration spec: {spec!r}")
    mult = {"s": 1, "m": 60, "h": 3600, None: 1}[m.group(2)]
    return int(m.group(1)) * mult


# ---------------------------------------------------------------------
# CPU set algebra (SMT-aware nested subsets)
# ---------------------------------------------------------------------

def parse_cpu_list(spec: str) -> frozenset[int]:
    if not spec or not spec.strip():
        raise ValueError("empty cpu list")
    cpus: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if hi < lo:
                raise ValueError(f"inverted range {part!r}")
            cpus.update(range(lo, hi + 1))
        else:
            cpus.add(int(part))
    return frozenset(cpus)


def format_cpu_list(cpus) -> str:
    cpus = sorted(cpus)
    if not cpus:
        return ""
    out, run_start, prev = [], cpus[0], cpus[0]
    for c in cpus[1:]:
        if c == prev + 1:
            prev = c
            continue
        out.append(f"{run_start}-{prev}" if prev != run_start else f"{run_start}")
        run_start = prev = c
    out.append(f"{run_start}-{prev}" if prev != run_start else f"{run_start}")
    return ",".join(out)


def smt_groups(allowed: set[int]) -> list[frozenset[int]]:
    """Group siblings by reading /sys topology on the orchestrating host."""
    groups: dict[int, set[int]] = {}
    for cpu in sorted(allowed):
        path = Path(
            f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
        sibs = {cpu}
        try:
            sibs = set(parse_cpu_list(path.read_text().strip()))
        except OSError:
            pass
        key = min(sibs)
        groups.setdefault(key, set()).add(cpu)
    return [frozenset(sorted(g & allowed)) for g in
            sorted(groups.values(), key=min)]


def plan_cpu_sets(allowed: set[int], groups: list[frozenset[int]]) -> dict:
    """Nested app sets X4<X8<X16 on whole cores; infra gets the rest."""
    whole = sorted((g for g in groups if len(g) == 2), key=min)
    if len(whole) < 8:
        raise ValueError(
            f"need >=8 complete SMT pairs inside the allowed set, got {len(whole)}")
    reserved: list[int] = []
    for g in whole[:8]:
        reserved.extend(sorted(g))
    reserved.sort()
    # X4/X8 pick one sibling per distinct physical core (whole-core sets).
    x4 = sorted(min(g) for g in whole[:4])
    x8 = sorted(min(g) for g in whole[:8])
    x16 = list(reserved)
    infra = sorted(allowed - set(reserved))
    return {
        "X4": x4, "X8": x8, "X16": x16,
        "APP_RESERVED": reserved, "INFRA": infra,
    }


def pin_argv(pinset_path: str, cpus: str, cmd: list[str]) -> list[str]:
    return [pinset_path, cpus, *cmd]


# ---------------------------------------------------------------------
# pinning (runtime affinity — docker cpuset is a no-op on this host)
# ---------------------------------------------------------------------

def ensure_pinset(container: str) -> None:
    # docker cp preserves the source mode; make it executable host-side so
    # non-root container users (the app runs as uid 10001) can exec it.
    os.chmod(Path(BIN_DIR) / "pinset", 0o755)
    dc("cp", f"{BIN_DIR}/pinset", f"{container}:/tmp/pinset")
    dcx(container, ["chmod", "+x", "/tmp/pinset"], check=False)


def container_uid(container: str) -> str:
    """UID that owns PID 1; docker exec must match it because default
    containers lack CAP_SYS_NICE (sched_setaffinity on other uids -> EPERM)."""
    proc = dcx(container, ["sh", "-c",
                           "awk '/^Uid:/{print $2}' /proc/1/status"],
               check=False)
    return proc.stdout.strip() or "0"


def pin_container(container: str, cpus: str) -> dict:
    ensure_pinset(container)
    uid = container_uid(container)
    # --all is best-effort: a stray proc owned by another uid cannot be
    # retargeted without CAP_SYS_NICE; the masks audit + verify_pin on
    # PID 1 record the effective coverage instead of aborting the point.
    out = dc("exec", "-u", uid, container,
             "/tmp/pinset", cpus, "--all", check=False)
    show = dc("exec", "-u", uid, container,
              "/tmp/pinset", cpus, "--show", "1", check=False)
    masks = dc("exec", "-u", uid, container, "sh", "-c",
               "for p in /proc/[0-9]*; do c=$(cat $p/comm 2>/dev/null); "
               "a=$(awk '/Cpus_allowed_list/{print $2}' $p/status 2>/dev/null); "
               "[ -n \"$a\" ] && echo \"$p $c $a\"; done",
               check=False)
    return {
        "container": container,
        "uid": uid,
        "requested": cpus,
        "pin_rc": out.returncode,
        "pin_output": out.stdout.strip(),
        "pid1_allowed": (show.stdout or "").strip(),
        "proc_masks": masks.stdout.strip().splitlines(),
    }


def verify_pin(container: str, cpus: str) -> bool:
    """PID 1's allowed list must equal the requested set exactly."""
    show = dc("exec", "-u", container_uid(container), container,
              "/tmp/pinset", cpus, "--show", "1", check=False)
    m = re.search(r"Cpus_allowed_list:\s*(\S+)", show.stdout or "")
    return bool(m) and parse_cpu_list(m.group(1)) == parse_cpu_list(cpus)


# ---------------------------------------------------------------------
# stack lifecycle
# ---------------------------------------------------------------------

def wait_healthy(container: str, timeout_s: int = 240) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        proc = dc("inspect", container,
                  "--format", "{{json .State.Health.Status}}", check=False)
        # Exact match required: "unhealthy" contains "healthy" as a
        # substring and must not be accepted.
        if proc.stdout.strip().strip('"') == "healthy":
            return True
        running = dc("inspect", container,
                     "--format", "{{.State.Running}}", check=False)
        if "true" not in running.stdout:
            return False
        time.sleep(3)
    return False


def wait_app_ready(timeout_s: int = 240) -> bool:
    """The app service has no compose healthcheck: probe its HTTP port."""
    deadline = time.time() + timeout_s
    probe = ["python3", "-c",
             "import socket; socket.create_connection(('nazoauth',8000),3)"]
    while time.time() < deadline:
        running = dc("inspect", APP, "--format", "{{.State.Running}}",
                     check=False)
        if "true" not in running.stdout:
            return False
        proc = dc("run", "--rm", "--network", NETWORK,
                  "--label", f"{SIS_LABEL}={PROJECT}",
                  PERF_IMAGE, *probe, check=False, timeout=30)
        if proc.returncode == 0:
            return True
        time.sleep(3)
    return False


def wait_exited(container: str, timeout_s: int = 240) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        proc = dc("inspect", container,
                  "--format", "{{.State.Status}}", check=False)
        if proc.stdout.strip() in ("exited", "created", ""):
            return True
        time.sleep(3)
    return False


def _record_extra(cid: str, name: str, service: str) -> None:
    """Record a container this run created outside compose so teardown
    can later verify BOTH recorded identity and ownership label."""
    cid = (cid or "").strip()
    if not cid:
        return
    EXTRA_CONTAINERS.parent.mkdir(parents=True, exist_ok=True)
    with EXTRA_CONTAINERS.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "id": cid, "name": name, "service": service,
            "ts": round(time.time(), 3)}) + "\n")


def _label_of(cid: str) -> str | None:
    proc = dc("inspect", cid, "--format",
              '{{index .Config.Labels "' + SIS_LABEL + '"}}',
              check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _remove_owned_by_name(name: str, stop: bool = False) -> bool:
    """Remove a container by *recorded-style* lookup: resolve the name to
    an ID and only act when the ownership label matches this project.
    A same-named foreign container is left untouched."""
    proc = dc("inspect", name, "--format", "{{.Id}}", check=False)
    cid = (proc.stdout or "").strip()
    if proc.returncode != 0 or not cid:
        return False
    if _label_of(cid) != PROJECT:
        return False
    if stop:
        dc("stop", cid, check=False, timeout=20)
    dc("rm", "-f", cid, check=False)
    return True


def _remove_recorded_extras() -> None:
    """Remove only containers recorded by this run whose ownership label
    still matches. Unrecorded or foreign-labeled resources — including
    same-named ones — are never stopped or removed."""
    if not EXTRA_CONTAINERS.exists():
        return
    for line in EXTRA_CONTAINERS.read_text(errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        cid = entry.get("id")
        if cid and _label_of(cid) == PROJECT:
            dc("rm", "-f", cid, check=False)
    EXTRA_CONTAINERS.unlink(missing_ok=True)


def stack_down() -> None:
    """Tear down only what this project owns: the exclusive compose
    project handles its services/volumes/one-off containers via its own
    project membership, and raw `docker run` containers are removed by
    recorded ID after an exact ownership-label match. Foreign tasks'
    resources (other sis runs, scratch databases, historical soak
    projects, the shared nazoauth-perf project) are never touched —
    not by name prefix, not by prune."""
    compose("down", "-v", "--remove-orphans", check=False)
    _remove_recorded_extras()


def stack_up(point: dict) -> dict:
    """Fresh stack: tag app image, down -v, up, pin, audit pair, seed-ready."""
    evidence: dict = {"point": point["name"], "image": point["image"]}
    # Tag the point's app image into every compose service name that
    # consumes perf-runtime, then bring the stack up from scratch.
    for svc in ("nazoauth", "migrate", "audit-worker"):
        dc("tag", point["image"], f"{PROJECT}-{svc}")
    compose("up", "-d", "--no-build",
            "postgres", "valkey", "postgres-init", "keyset", "migrate",
            "nazoauth")
    evidence["healthy"] = {
        "postgres": wait_healthy(POSTGRES),
        "valkey": wait_healthy(VALKEY),
        "migrate": wait_healthy(MIGRATE),
        "nazoauth": wait_app_ready(),
    }
    if not all(evidence["healthy"].values()):
        raise RuntimeError(f"stack unhealthy: {evidence['healthy']}")

    app_cpus = format_cpu_list(point["app_cpus"])
    infra_cpus = format_cpu_list(point["infra_cpus"])
    evidence["pin"] = {
        "app": pin_container(APP, app_cpus),
        "postgres": pin_container(POSTGRES, infra_cpus),
        "valkey": pin_container(VALKEY, infra_cpus),
        "keyset": pin_container(KEYSET, infra_cpus),
    }
    evidence["pin"]["app_verified"] = verify_pin(APP, app_cpus)
    evidence["pin"]["pg_verified"] = verify_pin(POSTGRES, infra_cpus)

    depid = ""
    for _ in range(30):
        depid = dcx(VALKEY, ["valkey-cli", "keys", "nazo:state:v1:*"],
                    check=False).stdout.split("\n")[0].strip().split(":")
        depid = depid[3] if len(depid) > 3 else ""
        if depid:
            break
        time.sleep(2)
    evidence["deployment_id"] = depid or None
    return evidence


def audit_pair_up(run_id: str, depid: str) -> dict:
    """Launch the audit receiver + worker exactly like soak_run.sh."""
    tls_host = f"{WORKSPACE}/perf-results/anchor-tls/{run_id}"
    Path(tls_host).mkdir(parents=True, exist_ok=True)
    cert, key, verify_key_holder = _gen_receiver_cert(f"sis-rcv-{run_id}")
    (Path(tls_host) / "receiver.crt").write_text(cert)
    (Path(tls_host) / "receiver.key").write_text(key)
    token = _rand_hex(32)
    seed = _rand_b64url(32)
    psql(
        "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname="
        "'nazoauth_perf_exporter') THEN CREATE ROLE nazoauth_perf_exporter "
        "LOGIN PASSWORD 'exporter' NOSUPERUSER NOBYPASSRLS NOINHERIT; END IF; "
        "END $$; GRANT CONNECT ON DATABASE oauth TO nazoauth_perf_exporter; "
        "GRANT USAGE ON SCHEMA public TO nazoauth_perf_exporter; "
        "GRANT EXECUTE ON FUNCTION "
        "public.nazo_security_audit_shared_privilege_preflight(BOOLEAN,BOOLEAN,BOOLEAN),"
        "public.nazo_persist_security_audit_event(UUID,TEXT,TEXT,JSONB,TIMESTAMPTZ),"
        "public.nazo_security_audit_chain_head_for_update(),"
        "public.nazo_security_audit_batch_members(),"
        "public.nazo_claim_security_audit_pending(BIGINT),"
        "public.nazo_open_security_audit_batch(BIGINT,BIGINT,INTEGER,BYTEA,INTEGER),"
        "public.nazo_reclaim_security_audit_batch(BYTEA,INTEGER),"
        "public.nazo_append_security_audit_chain(BIGINT,BYTEA,UUID[],BYTEA[]),"
        "public.nazo_ack_security_audit_batch(BIGINT,BIGINT,BIGINT,INTEGER,BYTEA,BYTEA,TEXT),"
        "public.nazo_fail_security_audit_batch(BIGINT,TIMESTAMPTZ,TEXT,BOOLEAN),"
        "public.nazo_observe_security_audit_anchor(TEXT),"
        "public.nazo_record_security_audit_genesis(TEXT,BYTEA),"
        "public.nazo_security_audit_shared_anchor_health() "
        "TO nazoauth_perf_exporter;")
    rcv_name = f"sis-rcv-{run_id}"
    compose("run", "-d", "--name", rcv_name, "--no-deps",
            "-e", "ANCHOR_RECEIVER_LISTEN=0.0.0.0:9443",
            "-e", f"ANCHOR_RECEIVER_TLS_CERT=/run/anchor-tls/{run_id}/receiver.crt",
            "-e", f"ANCHOR_RECEIVER_TLS_KEY=/run/anchor-tls/{run_id}/receiver.key",
            "-e", f"ANCHOR_RECEIVER_DEPLOYMENT={depid}",
            "-e", f"ANCHOR_RECEIVER_TOKEN={token}",
            "-e", f"ANCHOR_RECEIVER_SIGNING_KEY={seed}",
            "-e", "ANCHOR_RECEIVER_DATA_DIR=/data",
            "audit-receiver")
    verify_key = ""
    for _ in range(20):
        logs = dc("logs", rcv_name, check=False).stdout + \
            dc("logs", rcv_name, check=False).stderr
        m = re.search(r"pubkey=(\S+)", logs)
        if m:
            verify_key = m.group(1)
            break
        time.sleep(1.5)
    if not verify_key:
        raise RuntimeError("audit receiver pubkey unavailable")
    worker_name = f"sis-worker-{run_id}"
    compose("run", "-d", "--name", worker_name, "--no-deps",
            "-e", "AUDIT_ANCHOR_MODE=optional",
            "-e", f"DEPLOYMENT_ID={depid}",
            "-e", f"AUDIT_ANCHOR_URL=https://{rcv_name}:9443/checkpoint",
            "-e", f"AUDIT_ANCHOR_TOKEN={token}",
            "-e", f"AUDIT_ANCHOR_RECEIPT_VERIFY_KEY={verify_key}",
            "-e", f"AUDIT_ANCHOR_CA_BUNDLE=/run/anchor-tls/{run_id}/receiver.crt",
            "-e", "AUDIT_ANCHOR_DATABASE_URL="
                  "postgresql://nazoauth_perf_exporter:exporter@postgres:5432/oauth",
            "-e", "AUDIT_ANCHOR_POLL_INTERVAL_SECONDS=2",
            "-e", "AUDIT_ANCHOR_BATCH_SIZE=256",
            "audit-worker")
    pin_container(rcv_name, format_cpu_list(CURRENT_POINT["infra_cpus"]))
    pin_container(worker_name, format_cpu_list(CURRENT_POINT["infra_cpus"]))
    return {"receiver": rcv_name, "worker": worker_name, "deployment": depid}


def _rand_hex(n: int) -> str:
    return os.urandom(n).hex()


def _rand_b64url(n: int) -> str:
    import base64
    return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")


def _gen_receiver_cert(cn: str) -> tuple[str, str, None]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.ExtendedKeyUsage(
            [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM).decode()
    pem_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    return pem_cert, pem_key, None


# ---------------------------------------------------------------------
# samplers / observers
# ---------------------------------------------------------------------

def start_samplers(run_id: str, out_host: str, tick: int = 2) -> dict:
    """soak_sampler.py (pg/vk/app metrics) + proc_detail_sampler.py."""
    sampler = f"sis-sampler-{run_id}"
    _remove_owned_by_name(sampler)
    proc = dc("run", "-d", "--name", sampler, "--network", NETWORK,
              "--label", f"{SIS_LABEL}={PROJECT}",
              "-v", f"{TOOLS}/soak_sampler.py:/tmp/sampler.py:ro",
              "-v", f"{out_host}:/out",
              "-e", f"RUN_ID={run_id}", "-e", "OUT_PATH=/out/soak-metrics.jsonl",
              "-e", f"INTERVAL_S={tick}",
              PERF_IMAGE, "python3", "/tmp/sampler.py")
    _record_extra(proc.stdout, sampler, "sampler")
    detail = f"sis-proc-{run_id}"
    _remove_owned_by_name(detail)
    proc = dc("run", "-d", "--name", detail, "--network", NETWORK,
              "--label", f"{SIS_LABEL}={PROJECT}",
              "-v", "/var/run/docker.sock:/var/run/docker.sock",
              "-v", f"{TOOLS}/proc_detail_sampler.py:/tmp/proc.py:ro",
              "-v", f"{out_host}:/out",
              "-e", f"RUN_ID={run_id}", "-e", "OUT_PATH=/out/proc-detail.jsonl",
              "-e", f"TICK_S={max(tick, 5)}",
              "-e", f"PROJECT={PROJECT}",
              PERF_IMAGE, "python3", "/tmp/proc.py")
    _record_extra(proc.stdout, detail, "proc_detail")
    infra = format_cpu_list(CURRENT_POINT["infra_cpus"])
    pin_container(sampler, infra)
    pin_container(detail, infra)
    return {"sampler": sampler, "proc_detail": detail}


def stop_samplers(run_id: str) -> None:
    for name in (f"sis-sampler-{run_id}", f"sis-proc-{run_id}"):
        _remove_owned_by_name(name, stop=True)


# ---------------------------------------------------------------------
# workspace / mount-source / sampler / binary provenance
# ---------------------------------------------------------------------

WORKSPACE_FILES = (
    "docker-compose.perf.yml",
    "Containerfile",
    "perf/env.yaml",
    "perf/runner.py",
    "perf/seed.py",
    "perf/k6/oauth.js",
    "perf/k6/measurement_clock.js",
    "perf/k6/subject_state.js",
    "perf/runner/Containerfile",
    "perf/keyset/Containerfile",
    "perf/audit-anchor-receiver/Containerfile",
    "perf/audit-anchor-receiver/Cargo.toml",
    "perf/audit-anchor-receiver/src/main.rs",
    "perf/audit-anchor-receiver/src/store.rs",
    "perf/audit-anchor-receiver/src/wire.rs",
    "scripts/ensure_runtime_keyset.py",
    "perf/tools/single_instance_scaling.py",
    "perf/tools/point_runner.py",
    "perf/tools/pool_size_ab.py",
    "perf/tools/capacity_search.py",
    "perf/tools/soak_sampler.py",
    "perf/tools/proc_detail_sampler.py",
    "perf/tools/residency_observer.py",
    "perf/tools/checkpoint_analyze.py",
    "perf/tools/stability_analyze.py",
    "perf/tools/vkledger.py",
    "perf/tools/ledger.sql",
    "perf/tools/ledger_check.py",
    "perf/tools/audit_anchor_fault_regression.sh",
)


def file_sha256(path) -> str | None:
    import hashlib
    p = Path(path)
    if not p.is_file():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


def workspace_provenance() -> dict:
    """Bind this run to ONE checkout: record the workspace realpath, git
    HEAD and sha256 of every harness file the run mounts or executes.
    A missing/empty file is fatal — docker would silently turn a missing
    host path into an empty directory inside the container."""
    root = Path(WORKSPACE).resolve()
    files = {}
    missing = []
    for rel in WORKSPACE_FILES:
        p = root / rel
        sha = file_sha256(p)
        size = p.stat().st_size if p.is_file() else 0
        files[rel] = {"sha256": sha, "size": size}
        if not p.is_file() or size <= 0:
            missing.append(rel)
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False).stdout.strip()
    # Whole-tree harness hash: the runner image bakes all of perf/ via
    # `COPY perf /perf`, so provenance binds the tree, not only the files
    # this driver happens to mount today.
    import hashlib
    tree = hashlib.sha256()
    perf_root = root / "perf"
    if perf_root.is_dir():
        for f in sorted(perf_root.rglob("*")):
            if f.is_file():
                tree.update(str(f.relative_to(perf_root)).encode())
                tree.update(hashlib.sha256(f.read_bytes()).digest())
    tree_sha = tree.hexdigest()
    return {"workspace_realpath": str(root), "git_head": head or None,
            "file_sha256": files, "missing": missing,
            "perf_tree_sha256": tree_sha,
            "ok": not missing}


def verify_mount_sources() -> dict:
    """Every file bind-mounted into containers must exist non-empty on
    the host BEFORE docker creates it as a stray directory."""
    mounts = (
        f"{TOOLS}/soak_sampler.py",
        f"{TOOLS}/proc_detail_sampler.py",
        f"{TOOLS}/residency_observer.py",
        f"{TOOLS}/vkledger.py",
        f"{TOOLS}/ledger.sql",
    )
    out = {}
    for f in mounts:
        p = Path(f)
        out[f] = p.is_file() and p.stat().st_size > 0
    return out


def _meta_sha_ok(path: Path, src: str) -> bool | None:
    """First line of a sampler jsonl must be the meta row whose
    script_sha256 equals the mounted worktree file. None = file not
    there yet; False = present but wrong."""
    if not path.is_file() or path.stat().st_size == 0:
        return None
    try:
        with path.open("r", errors="replace") as fh:
            row = json.loads(fh.readline())
    except (OSError, json.JSONDecodeError):
        return False
    if row.get("kind") != "meta":
        return False
    want = file_sha256(src)
    return want is not None and row.get("script_sha256") == want


def sampler_health(run_id: str, out_dir: Path,
                   expect_residency: bool = False,
                   timeout_s: float = 5.0) -> dict:
    """Fail-fast sampler gate run BEFORE real load: each sampler
    container must still be running and must have emitted a meta row
    whose script_sha256 matches the current worktree file. Anything else
    means the run would produce partial/absent observability — stop
    before load instead of discovering it at teardown."""
    specs = [
        ("soak", f"sis-sampler-{run_id}", out_dir / "soak-metrics.jsonl",
         f"{TOOLS}/soak_sampler.py"),
        ("proc", f"sis-proc-{run_id}", out_dir / "proc-detail.jsonl",
         f"{TOOLS}/proc_detail_sampler.py"),
    ]
    if expect_residency:
        specs.append(("residency", f"sis-residency-{run_id}",
                      out_dir / "residency.jsonl",
                      f"{TOOLS}/residency_observer.py"))
    checks = {k: {"container": c, "running": None, "meta_ok": None,
                  "detail": "pending"}
              for k, c, _, _ in specs}
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        done = True
        for k, cname, path, src in specs:
            ch = checks[k]
            if ch["detail"] != "pending":
                continue
            running = (dc("inspect", cname, "--format",
                          "{{.State.Running}}", check=False)
                       .stdout.strip() == "true")
            ch["running"] = running
            if not running:
                code = dc("inspect", cname, "--format",
                          "{{.State.ExitCode}}", check=False
                          ).stdout.strip()
                ch["detail"] = f"container_not_running:exit={code or '?'}"
                continue
            meta = _meta_sha_ok(path, src)
            ch["meta_ok"] = meta
            if meta is True:
                ch["detail"] = "ok"
            else:
                done = False
        if done:
            break
        time.sleep(0.5)
    for k, cname, path, src in specs:
        ch = checks[k]
        if ch["detail"] == "pending":
            ch["detail"] = ("meta_row_missing_or_sha_mismatch"
                            if ch["meta_ok"] is not True
                            else "timeout")
    ok = all(c["detail"] == "ok" for c in checks.values())
    return {"ok": ok, "checks": checks}


def app_perf_schema(out_path: Path | None = None) -> dict:
    """Fetch /__perf/metrics inside the APP container's own network
    namespace (127.0.0.1) — never via the shared DNS name, which could
    resolve to a different responder on a shared network. The schema
    contract requires both db_pool and audit_queue."""
    helper = (  # noqa: E501 - inline python one-liner for the perf image
        "import urllib.request,sys;"
        "sys.stdout.write(urllib.request.urlopen("
        "'http://127.0.0.1:8000/__perf/metrics',timeout=10)"
        ".read().decode())")
    proc = dc("run", "--rm", "--network", f"container:{APP}",
              "--label", f"{SIS_LABEL}={PROJECT}",
              PERF_IMAGE, "python3", "-c", helper, check=False)
    body = None
    parse_error = None
    try:
        body = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        parse_error = (proc.stdout + proc.stderr)[:300]
    out = {
        "http_ok": proc.returncode == 0 and body is not None,
        "has_db_pool": isinstance(body, dict) and "db_pool" in body,
        "has_audit_queue": isinstance(body, dict)
                         and "audit_queue" in body,
        "app_container": APP,
        "via": "container-netns 127.0.0.1:8000",
    }
    if parse_error:
        out["parse_error"] = parse_error
    out["ok"] = (out["http_ok"] and out["has_db_pool"]
                 and out["has_audit_queue"])
    if out_path is not None:
        jdump(out_path, {"response": body, "check": out})
    return out


def runtime_binary_provenance(image_sha: str | None = None,
                              expected_sha: str | None = None) -> dict:
    """Running-PID1 binary identity vs the image's recorded binary.

    The app entrypoint pinset-execs nazoauth, so /proc/1/exe inside the
    container IS the served binary. Read it through the host pid —
    image/Cmd metadata alone proved insufficient last round."""
    info = json.loads(dc("inspect", APP, check=True).stdout)
    if isinstance(info, list):
        info = info[0]
    pid = info.get("State", {}).get("Pid")
    container_id = info.get("Id")
    image_id = info.get("Image")
    # Hash the live PID1 executable INSIDE the container's own pid
    # namespace. A host-side /proc/<pid> read only works when the docker
    # daemon shares the driver's pid namespace — on sandboxed dev hosts
    # (dockerd as sibling) the daemon pid is invisible locally, so the
    # authoritative probe is `docker exec APP sha256sum /proc/1/exe`.
    proc = dcx(APP, ["sha256sum", "/proc/1/exe"], check=False)
    pid_sha = None
    sha_err = None
    if proc.returncode == 0 and proc.stdout.strip():
        pid_sha = proc.stdout.split()[0]
    else:
        sha_err = (proc.stderr or proc.stdout).strip()[:200]
    out = {
        "container_id": container_id,
        "image_id": image_id,
        "host_pid": pid,
        "running_pid1_binary_sha256": pid_sha,
        "image_binary_sha256": image_sha,
        "pid1_eq_image": (pid_sha is not None and image_sha is not None
                          and pid_sha == image_sha),
        "expected_binary_sha256": expected_sha,
        "pid1_eq_expected": (expected_sha is not None
                             and pid_sha == expected_sha),
    }
    if sha_err:
        out["pid1_sha_error"] = sha_err
    out["ok"] = (out["pid1_eq_image"]
                 and (expected_sha is None or out["pid1_eq_expected"]))
    return out


def ledger(phase: str, run_id: str, out_dir: Path) -> None:
    psql_file(f"{TOOLS}/ledger.sql", out_dir / f"ledger-{phase}.txt",
              ["-v", f"run_id={run_id}", "-v", f"phase={phase}"])
    proc = dc("run", "--rm", "--network", NETWORK,
              "--label", f"{SIS_LABEL}={PROJECT}",
              "-e", f"RUN_ID={run_id}",
              "-v", f"{TOOLS}/vkledger.py:/tmp/vkledger.py:ro",
              PERF_IMAGE, "python3", "/tmp/vkledger.py", check=False)
    (out_dir / f"vkledger-{phase}.json").write_text(
        proc.stdout if proc.returncode == 0 else '{"error":"vkledger failed"}')


def pgss_snapshot(tag: str, out_dir: Path) -> dict:
    """pg_stat_statements snapshot with full row identity.

    Identity for a delta is (dbid, userid, toplevel, queryid) — queryid
    alone does not distinguish roles or nested vs top-level execution.
    `stats_reset` is captured per snapshot; a changed reset epoch makes
    any cross-snapshot subtraction invalid."""
    snap = {
        "tag": tag, "ts": time.time(),
        "stats_reset": psql(
            "SELECT extract(epoch from stats_reset) "
            "FROM pg_stat_statements_info", check=False),
        "statements": json.loads(psql(
            "SELECT COALESCE(json_agg(t),'[]') FROM ("
            "SELECT s.dbid, d.datname, s.userid, r.rolname,"
            " s.toplevel, s.queryid, s.calls, s.total_exec_time, s.rows,"
            " left(s.query,160) AS q"
            " FROM pg_stat_statements s"
            " JOIN pg_database d ON d.oid = s.dbid"
            " JOIN pg_roles r ON r.oid = s.userid"
            " ORDER BY s.calls DESC LIMIT 800) t", check=False) or "[]"),
        "wal": psql("SELECT wal_bytes::bigint FROM pg_stat_wal", check=False),
        "checkpointer": psql(
            "SELECT row_to_json(pg_stat_checkpointer) "
            "FROM pg_stat_checkpointer", check=False),
    }
    jdump(out_dir / f"pgss-{tag}.json", snap)
    return snap


def wal_snapshot(tag: str, out_dir: Path) -> dict:
    """PG18 WAL counter snapshot.

    wal_records/fpi/bytes/buffers_full come from pg_stat_wal; flush
    accounting (writes/fsyncs + timing) comes from pg_stat_io
    object='wal' rows at full backend_type/context granularity — PG18
    moved it there; the old pg_stat_wal.wal_sync*/wal_write_time fields
    no longer exist. db_xact_commit is kept only as a population-boundary
    cross-check, never as the business-commit denominator."""
    snap = {
        "tag": tag, "ts": time.time(),
        "pg_stat_wal": json.loads(psql(
            "SELECT row_to_json(w) FROM (SELECT wal_records, wal_fpi,"
            " wal_bytes, wal_buffers_full, stats_reset"
            " FROM pg_stat_wal) w", check=False) or "{}"),
        "pg_stat_io_wal": json.loads(psql(
            "SELECT COALESCE(json_agg(t),'[]') FROM ("
            "SELECT * FROM pg_stat_io WHERE object='wal'"
            " ORDER BY backend_type, context) t", check=False) or "[]"),
        "db_xact": json.loads(psql(
            "SELECT row_to_json(d) FROM (SELECT xact_commit,"
            " xact_rollback FROM pg_stat_database"
            " WHERE datname='oauth') d", check=False) or "{}"),
        "guc": {g: psql(f"SHOW {g}", check=False) for g in (
            "track_wal_io_timing", "commit_delay", "commit_siblings",
            "synchronous_commit", "fsync", "full_page_writes")},
    }
    jdump(out_dir / f"wal-{tag}.json", snap)
    return snap


def _counter_delta(a, b):
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return b - a
    return None


def wal_delta(pre: dict, post: dict) -> dict:
    """Pre/post subtraction for wal_snapshot pairs. Counters only; any
    changed stats_reset epoch marks the delta invalid."""
    pw, qw = pre.get("pg_stat_wal") or {}, post.get("pg_stat_wal") or {}
    io_resets = {r.get("stats_reset")
                 for r in (post.get("pg_stat_io_wal") or [])}
    out = {"valid": True}
    if (pw.get("stats_reset") is None or qw.get("stats_reset") is None
            or pw.get("stats_reset") != qw.get("stats_reset")):
        out["valid"] = False
        out["reason"] = "pg_stat_wal stats_reset changed or missing"
    if len(io_resets) > 1 or (io_resets and None in io_resets):
        out["valid"] = False
        out["reason"] = "pg_stat_io stats_reset inconsistent"
    for k in ("wal_records", "wal_fpi", "wal_bytes", "wal_buffers_full"):
        out[k] = _counter_delta(pw.get(k), qw.get(k))

    def ikey(r):
        return (r.get("backend_type"), r.get("context"))

    pre_io = {ikey(r): r for r in pre.get("pg_stat_io_wal") or []}
    rows = []
    for r in post.get("pg_stat_io_wal") or []:
        b = pre_io.get(ikey(r), {})
        rows.append({
            "backend_type": r.get("backend_type"),
            "context": r.get("context"),
            "writes": _counter_delta(b.get("writes"), r.get("writes")),
            "write_bytes": _counter_delta(b.get("write_bytes"),
                                          r.get("write_bytes")),
            "write_time_ms": _counter_delta(b.get("write_time"),
                                            r.get("write_time")),
            "writeouts": _counter_delta(b.get("writeouts"),
                                        r.get("writeouts")),
            "fsyncs": _counter_delta(b.get("fsyncs"), r.get("fsyncs")),
            "fsync_time_ms": _counter_delta(b.get("fsync_time"),
                                            r.get("fsync_time")),
        })
    out["io_rows"] = rows
    out["writes_total"] = sum(r["writes"] or 0 for r in rows)
    out["write_bytes_total"] = sum(r["write_bytes"] or 0 for r in rows)
    out["write_time_ms_total"] = sum(r["write_time_ms"] or 0 for r in rows)
    out["fsyncs_total"] = sum(r["fsyncs"] or 0 for r in rows)
    out["fsync_time_ms_total"] = sum(r["fsync_time_ms"] or 0
                                   for r in rows)
    out["fsyncs_client_backend"] = sum(
        r["fsyncs"] or 0 for r in rows
        if r.get("backend_type") == "client backend")
    pd, qd = pre.get("db_xact") or {}, post.get("db_xact") or {}
    out["db_xact_commit"] = _counter_delta(pd.get("xact_commit"),
                                         qd.get("xact_commit"))
    out["db_xact_rollback"] = _counter_delta(pd.get("xact_rollback"),
                                           qd.get("xact_rollback"))
    return out


def pgss_reset() -> str:
    """Harness-owned reset executed before the pre snapshot — the only
    legitimate reset boundary. Runners must then skip their own reset so
    nothing resets between the baseline and post snapshots."""
    return psql("SELECT pg_stat_statements_reset()::text", check=False)


def pgss_identity(s: dict) -> tuple:
    return (str(s.get("dbid")), str(s.get("userid")),
            str(s.get("toplevel")), str(s.get("queryid")))


def pgss_delta(pre: dict, post: dict, http_reqs: int) -> dict:
    """Pre/post subtraction only across an unchanged stats_reset epoch
    and only on the full (dbid, userid, toplevel, queryid) identity.
    Snapshots lacking identity fields are downgraded to since-reset
    observations — no precise totals are fabricated."""
    pre_reset, post_reset = pre.get("stats_reset"), post.get("stats_reset")
    if not pre_reset or not post_reset or pre_reset != post_reset:
        return {
            "valid": False,
            "reason": "stats_reset changed or missing between snapshots",
            "pre_reset": pre_reset, "post_reset": post_reset,
            "since_reset_observed_calls": sum(
                int(s.get("calls", 0))
                for s in post.get("statements", [])),
        }
    rows_by_id = {}
    identity_complete = True
    for s in post.get("statements", []):
        if None in (s.get("dbid"), s.get("userid"), s.get("toplevel"),
                    s.get("queryid")):
            identity_complete = False
            break
        rows_by_id[pgss_identity(s)] = s
    if not identity_complete:
        return {
            "valid": False,
            "reason": "statement rows missing dbid/userid/toplevel identity",
            "pre_reset": pre_reset, "post_reset": post_reset,
        }
    before = {pgss_identity(s): s for s in pre.get("statements", [])}
    rows = []
    for s in post.get("statements", []):
        b = before.get(pgss_identity(s), {})
        calls = int(s.get("calls", 0)) - int(b.get("calls", 0))
        if calls <= 0:
            continue
        rows.append({
            "queryid": s.get("queryid"), "rolname": s.get("rolname"),
            "toplevel": s.get("toplevel"),
            "calls_delta": calls,
            "total_exec_ms_delta": round(
                float(s.get("total_exec_time", 0))
                - float(b.get("total_exec_time", 0)), 3),
            "rows_delta": int(s.get("rows", 0)) - int(b.get("rows", 0)),
            "q": s.get("q", ""),
        })
    rows.sort(key=lambda r: -r["calls_delta"])

    def cls(pred) -> int:
        return sum(r["calls_delta"] for r in rows if pred(r))

    runtime_top = lambda r: (r.get("rolname") == "nazoauth_perf_runtime"  # noqa: E731
                             and r.get("toplevel") is True)
    classes = {
        "runtime_toplevel": cls(runtime_top),
        "nested": cls(lambda r: r.get("toplevel") is False),
        "exporter": cls(lambda r: r.get("rolname")
                        == "nazoauth_perf_exporter"),
        "observer_other": cls(
            lambda r: not runtime_top(r) and r.get("toplevel") is True
            and r.get("rolname") != "nazoauth_perf_exporter"),
        "combined": cls(lambda r: "locked_client" in r["q"]),
        "client_lock": cls(lambda r: "FOR SHARE" in r["q"].upper()
                           and "oauth_clients" in r["q"]),
        "issuance_insert": cls(lambda r: "oauth_token_issuances" in r["q"]
                               and "INSERT" in r["q"].upper()),
        "audit_append": cls(
            lambda r: "nazo_persist_security_audit_event" in r["q"]
            and "locked_client" not in r["q"]),
        "audit_writer_preflight": cls(
            lambda r: "nazo_security_audit_shared_privilege_preflight"
            in r["q"]),
        "audit_anchor_health": cls(
            lambda r: "nazo_security_audit_shared_anchor_health" in r["q"]),
        # Business write-transaction commits: toplevel COMMIT statements
        # issued by the runtime role (diesel commits explicitly). Not the
        # same population as pg_stat_database.xact_commit — that counter
        # also covers exporter/observer/autocommit writes and is kept as
        # boundary evidence only.
        "commit_txn": cls(
            lambda r: runtime_top(r)
            and r["q"].strip().rstrip(";").upper() in ("COMMIT", "END")),
        "rollback_txn": cls(
            lambda r: runtime_top(r)
            and r["q"].strip().rstrip(";").upper()
            in ("ROLLBACK", "ABORT")),
    }
    total_calls = sum(r["calls_delta"] for r in rows)
    return {
        "valid": True,
        "statements": rows[:60],
        "total_calls_delta": total_calls,
        "calls_per_http_request": (
            round(total_calls / http_reqs, 4) if http_reqs else None),
        "path_classes": classes,
    }


# ---------------------------------------------------------------------
# load execution
# ---------------------------------------------------------------------

CURRENT_POINT: dict = {"app_cpus": [], "infra_cpus": []}
LOAD_LOG = RESULTS / "budget.json"


def budget_state() -> dict:
    if LOAD_LOG.exists():
        try:
            return json.loads(LOAD_LOG.read_text())
        except json.JSONDecodeError:
            pass
    return {"load_seconds_used": 0.0, "points": []}


def budget_spend(name: str, seconds: float | None) -> None:
    """Record load wall-clock. A point whose load container started but
    whose orchestration failed mid-flight is 'unknown', never silently 0:
    we cannot prove how long the load actually ran."""
    state = budget_state()
    if isinstance(seconds, (int, float)):
        state["load_seconds_used"] = round(
            state["load_seconds_used"] + seconds, 1)
        entry = {"name": name, "load_seconds": round(seconds, 1),
                 "status": "completed"}
    else:
        entry = {"name": name, "load_seconds": None, "status": "unknown"}
    state["points"].append(entry)
    jdump(LOAD_LOG, state)


def _spend_load_budget(run_id: str, rec: dict) -> None:
    """Budget entry for a point attempt: measured seconds when run_load
    returned, 'unknown' when it raised after the container may have
    started — never a silently-zero entry."""
    budget_spend(run_id, (rec.get("load") or {}).get("load_seconds"))


def budget_check(planned_s: float) -> None:
    state = budget_state()
    if state["load_seconds_used"] + planned_s > LOAD_BUDGET_S:
        raise RuntimeError(
            f"load budget exceeded: used={state['load_seconds_used']}s "
            f"+ planned={planned_s}s > {LOAD_BUDGET_S}s")


def generator_mem_preflight() -> dict:
    """Host memory evidence captured before the main k6 container starts.

    /proc/meminfo is read inside this container — procfs is not
    namespaced, so MemTotal/MemAvailable describe the benchmark host.
    `docker stats --no-stream` adds a best-effort per-container usage
    snapshot. The caller compares mem_available_gib against the
    pre-registered minimum; nothing here estimates physical usage from
    backend RSS sums (retracted method)."""
    snap: dict = {"captured": False}
    try:
        fields = {}
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            parts = rest.strip().split()
            if parts and parts[0].isdigit():
                fields[key] = int(parts[0])
        snap["mem_total_kb"] = fields.get("MemTotal")
        snap["mem_available_kb"] = fields.get("MemAvailable")
        snap["mem_free_kb"] = fields.get("MemFree")
        if snap["mem_available_kb"]:
            snap["mem_available_gib"] = round(
                snap["mem_available_kb"] / 1048576, 2)
        snap["captured"] = snap["mem_available_kb"] is not None
    except OSError as e:
        snap["error"] = f"meminfo: {e}"
    try:
        stats = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}} {{.MemUsage}}"],
            capture_output=True, text=True, check=False, timeout=30)
        snap["container_mem"] = dict(
            line.split(" ", 1) for line in stats.stdout.splitlines()
            if " " in line)
    except (OSError, subprocess.TimeoutExpired) as e:
        snap["container_mem_error"] = str(e)[:120]
    return snap


def env_list_without(env_list: list[str], prefixes) -> list[str]:
    """Drop `-e KEY=...` pairs whose KEY starts with any prefix. The list
    alternates flag/value, so filtering values alone would leave orphan
    `-e` tokens that misalign the whole docker argv."""
    prefixes = tuple(prefixes)
    out: list[str] = []
    i = 0
    while i < len(env_list):
        flag, val = env_list[i], env_list[i + 1] if i + 1 < len(env_list) else ""
        if flag == "-e":
            key = val.split("=", 1)[0]
            if not any(key.startswith(p) for p in prefixes):
                out += [flag, val]
            i += 2
        else:
            out.append(flag)
            i += 1
    return out


def load_env_list(point: dict, run_id: str) -> list[str]:
    """Shared runner env for main/sidecar/preflight containers."""
    return [
        "-e", "BASE_URL=http://nazoauth:8000",
        "-e", "ISSUER_URL=http://127.0.0.1:8000",
        "-e", "DATABASE_URL=postgresql://postgres:postgres@postgres:5432/oauth",
        "-e", "VALKEY_URL=redis://valkey:6379/0",
        "-e", f"VALKEY_STATE_EPOCH={DEPID_EPOCH}",
        "-e", f"CLIENT_SECRET_PEPPER={CLIENT_PEPPER}",
        "-e", f"COMPOSE_PROJECT_NAME={PROJECT}",
        "-e", "PERF_RESULTS_DIR=/out",
        "-e", "PERF_REPORT_PATH=/out/report.md",
        "-e", "PERF_TENANT_HOST=127.0.0.1:8000",
        "-e", f"PERF_DEPLOYMENT_ID={point.get('deployment_id', '')}",
        "-e", f"PERF_PROFILE={point['profile']}",
        "-e", f"PERF_SCENARIO={point['scenario']}",
        "-e", f"PERF_EXECUTOR={point['executor']}",
        "-e", f"PERF_DURATION={point['duration']}",
        "-e", f"CAP_WARMUP_MS={point.get('warmup_ms', 15000)}",
        "-e", f"PERF_USER_COUNT={point.get('user_count', 64)}",
        "-e", f"PERF_VECTOR_COUNT={point.get('vector_count', 48000)}",
        # The harness owns the only pg_stat_statements reset (executed
        # before the pre snapshot); nothing may reset mid-window.
        "-e", "PERF_SKIP_PG_STATS_RESET=1",
        # Shared perf-state readiness: the seeding runner publishes
        # perf-state-ready.json under this id; sidecars gate on it.
        "-e", f"PERF_STATE_RUN_ID={run_id}",
    ]


def run_load(point: dict, run_id: str, out_dir: Path) -> dict:
    """Launch the main runner container (+ phase-3 sidecars), bounded wait."""
    out_host = str(out_dir)
    (out_dir / "load").mkdir(parents=True, exist_ok=True)
    env_list = load_env_list(point, run_id)
    if point.get("stream_evidence"):
        # Formal/stability points: the k6 point stream is REQUIRED
        # evidence (series/window/analyzer-stats/diag artifacts), not an
        # optional diagnostic.
        env_list += ["-e", "PERF_CHECKPOINT_EVIDENCE=1"]
    if point.get("rate"):
        env_list += ["-e", f"PERF_RATE={point['rate']}"]
    if point.get("vus"):
        env_list += ["-e", f"PERF_VUS={point['vus']}"]
    if point.get("pre_vus"):
        env_list += ["-e", f"PERF_PRE_ALLOCATED_VUS={point['pre_vus']}"]
    if point.get("max_vus"):
        env_list += ["-e", f"PERF_MAX_VUS={point['max_vus']}"]

    main = f"sis-load-{run_id}"
    _remove_owned_by_name(main)
    start_ts = time.time()
    proc = dc("run", "-d", "--name", main, "--network", NETWORK,
              "--label", f"{SIS_LABEL}={PROJECT}",
              "-v", f"{out_host}/load:/out",
              "-v", "/var/run/docker.sock:/var/run/docker.sock",
              "-v", f"{PROJECT}_perf_state:/perf-state",
              *env_list, PERF_IMAGE)
    _record_extra(proc.stdout, main, "load")
    infra = format_cpu_list(point["infra_cpus"])
    time.sleep(2)
    pin_container(main, infra)

    sidecars: list[dict] = []
    if point.get("sidecars"):
        delay = int(point.get("sidecar_delay_s", 120))
        while time.time() - start_ts < delay:
            time.sleep(2)
        for sc in point["sidecars"]:
            name = f"sis-side-{sc['name']}-{run_id}"
            sc_env = env_list_without(env_list,
                                      ("PERF_SCENARIO", "PERF_RATE",
                                       "PERF_VUS", "PERF_PRE_ALLOCATED",
                                       "PERF_MAX_VUS", "PERF_DURATION",
                                       "PERF_USER_COUNT"))
            sc_env += [
                "-e", f"PERF_SCENARIO={sc['scenario']}",
                "-e", f"PERF_RATE={sc['rate']}",
                "-e", f"PERF_PRE_ALLOCATED_VUS={sc['pre_vus']}",
                "-e", f"PERF_MAX_VUS={sc['max_vus']}",
                "-e", f"PERF_DURATION={sc['duration']}",
                "-e", f"PERF_USER_COUNT={sc.get('user_count', 64)}",
                "-e", "PERF_VECTOR_COUNT=2000",
                "-e", "PERF_SKIP_SEED=1",
                "-e", "PERF_SKIP_PG_STATS_RESET=1",
                # Marker wait must cover the seeding runner's full
                # vector/user bootstrap window — the deadline gate
                # (measurement_start-5s) still bounds how LATE a sidecar
                # may actually join, so a long bound here is only a
                # hang guard, not a race escape.
                "-e", f"PERF_STATE_WAIT_S={point.get('state_wait_s', 900)}",
            ]
            (out_dir / sc["name"]).mkdir(parents=True, exist_ok=True)
            _remove_owned_by_name(name)
            proc = dc("run", "-d", "--name", name, "--network", NETWORK,
                      "--label", f"{SIS_LABEL}={PROJECT}",
                      "-v", f"{out_host}/{sc['name']}:/out",
                      "-v", "/var/run/docker.sock:/var/run/docker.sock",
                      "-v", f"{PROJECT}_perf_state:/perf-state",
                      *sc_env, PERF_IMAGE)
            _record_extra(proc.stdout, name, f"sidecar:{sc['name']}")
            sc["container"] = name
            sc["started_ts"] = time.time()
            pin_container(name, infra)
            sidecars.append(sc)

    # Bounded wait: launch + duration + grace; overrun -> INVALID point.
    dur_s = _duration_seconds(point["duration"])
    deadline = start_ts + dur_s + int(point.get("grace_s", 300))
    exit_code = "deadline_exceeded"
    while time.time() < deadline:
        running = dc("inspect", main, "--format",
                     "{{.State.Running}}", check=False)
        if "true" not in running.stdout:
            code = dc("inspect", main, "--format",
                      "{{.State.ExitCode}}", check=False).stdout.strip()
            exit_code = code or "unknown"
            break
        time.sleep(5)
    else:
        dc("stop", main, check=False)
    end_ts = time.time()
    load_status = "completed" if exit_code not in (
        "deadline_exceeded", "unknown") else exit_code
    # Capture OOMKilled before the container is removed — it is
    # independent generator-resource evidence for the evaluator.
    oom = dc("inspect", main, "--format", "{{.State.OOMKilled}}",
             check=False).stdout.strip()
    log = dc("logs", main, check=False)
    (out_dir / "load" / "run.log").write_text(
        log.stdout + log.stderr, encoding="utf-8", errors="replace")
    dc("rm", "-f", main, check=False)
    load_seconds = end_ts - start_ts

    # Sidecars must terminate naturally and keep terminal summaries.
    side_results = []
    for sc in sidecars:
        name = sc["container"]
        side_deadline = sc["started_ts"] + _duration_seconds(sc["duration"]) + 180
        interrupted = False
        while time.time() < side_deadline:
            running = dc("inspect", name, "--format",
                         "{{.State.Running}}", check=False)
            if "true" not in running.stdout:
                break
            time.sleep(5)
        else:
            interrupted = True
            dc("stop", name, check=False)
        code = dc("inspect", name, "--format",
                  "{{.State.ExitCode}}", check=False).stdout.strip()
        slog = dc("logs", name, check=False)
        (out_dir / sc["name"] / "run.log").write_text(
            slog.stdout + slog.stderr, encoding="utf-8", errors="replace")
        summary_ok = (out_dir / sc["name"] / "latest.json").exists() or any(
            (out_dir / sc["name"]).glob("*.summary.json"))
        side_results.append({
            "name": sc["name"], "container": name,
            "exit_code": code or "unknown", "interrupted": interrupted,
            "terminal_summary": summary_ok,
        })
        _remove_owned_by_name(name)
        load_seconds = max(load_seconds, end_ts - start_ts)

    return {
        "main_container": main, "main_exit_code": exit_code,
        "main_oom_killed": oom == "true",
        "load_status": load_status,
        "started_ts": start_ts, "ended_ts": end_ts,
        "load_seconds": round(load_seconds, 1),
        "sidecars": side_results,
    }


# ---------------------------------------------------------------------
# point metrics extraction (runner summary -> normalized record)
# ---------------------------------------------------------------------

def extract_point_metrics(combined: dict) -> dict:
    k6 = combined.get("k6", {}) or {}
    m = k6.get("measure") or {}
    outcomes = m.get("outcomes") or {}
    lat = m.get("latency_ms") or {}
    iter_lat = m.get("iteration_ms") or {}
    contract = m.get("measurement_contract") or {}
    pool = combined.get("db_pool") or {}
    pg = combined.get("postgres") or {}
    return {
        "status": combined.get("status"),
        "k6_exit_code": combined.get("k6_exit_code"),
        "window_valid": bool(m.get("window_valid")),
        "window_seconds": contract.get("window_seconds"),
        "window_start_ms": contract.get("window_start_ms"),
        "window_end_ms": contract.get("window_end_ms"),
        "contract_problems": m.get("contract_problems"),
        "ops_per_s": m.get("ops_per_s"),
        "successful_ops_per_s": m.get("successful_ops_per_s"),
        "measure_ops": m.get("ops"),
        "measure_errors": m.get("errors"),
        # measurement-cohort population (authoritative capRun gate)
        "measure_scheduled": m.get("scheduled"),
        "measure_started": m.get("started"),
        "measure_completed": m.get("completed"),
        "measure_unfinished": m.get("unfinished"),
        "measure_dropped": m.get("dropped"),
        "measure_drop_fraction": m.get("drop_fraction"),
        "measure_schedule_delta": m.get("schedule_delta"),
        "measure_drop_upper_bound": m.get("drop_upper_bound"),
        "measure_drop_fraction_upper": m.get("drop_fraction_upper"),
        "measure_boundary_overshoot": m.get("boundary_overshoot"),
        "cohort_valid": m.get("cohort_valid"),
        "cohort_problems": m.get("cohort_problems"),
        "http_reqs": k6.get("http_reqs"),
        "http_rps": k6.get("rps"),
        # whole-run population — diagnostics only, never a capRun gate
        "full_run_iterations_completed": k6.get("iterations_completed"),
        "full_run_dropped_iterations": k6.get("dropped_iterations"),
        "full_run_drop_fraction": k6.get("drop_fraction"),
        "iterations_completed": k6.get("iterations_completed"),
        "dropped_iterations": k6.get("dropped_iterations"),
        "drop_fraction": k6.get("drop_fraction"),
        "op_p50_ms": lat.get("p50"),
        "op_p95_ms": lat.get("p95"),
        "op_p99_ms": lat.get("p99"),
        "iter_p50_ms": iter_lat.get("p50"),
        "iter_p95_ms": iter_lat.get("p95"),
        "iter_p99_ms": iter_lat.get("p99"),
        "outcome_success": outcomes.get("success"),
        "outcome_expected_rejection": outcomes.get("expected_rejection"),
        "outcome_local_no_request": outcomes.get("local_no_request"),
        "outcome_unexpected": outcomes.get("unexpected"),
        "outcome_prepare_failed": outcomes.get("prepare_failed"),
        "subject_lifecycle": m.get("subject_lifecycle"),
        "late_vu_fraction": (m.get("iterations") or {})
                            .get("late_vu_fraction"),
        "measure_buckets": m.get("buckets"),
        "pool_acquire_count": pool.get("acquire_count"),
        "pool_wait_ms_total": pool.get("wait_ms_total"),
        "pool_wait_ms_avg": pool.get("wait_ms_avg"),
        "pg_statements_per_req": pg.get("statements_per_http_request"),
    }


def _series_value(ev: dict, field: str):
    """Dotted field path: 'wal_bytes' or 'pool.acq'."""
    cur = ev
    for part in field.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def windowed_series_delta(soak_jsonl: Path, field: str,
                          window_start_ms: int | float | None,
                          window_end_ms: int | float | None) -> dict:
    """Cumulative-counter delta inside the k6 measurement window,
    recovered from the saved soak sampler's per-tick series. The pgss
    pre/post snapshots and runner-lifetime counters bracket
    seed+load+drain and must not be divided by the post-warmup cohort;
    this series is the only same-window source. Linear interpolation
    between the ~5s ticks bounds the error to one tick per edge."""
    if not soak_jsonl.exists():
        return {"delta": None, "field": field,
                "reason": "sampler stream missing"}
    if not window_start_ms or not window_end_ms:
        return {"delta": None, "field": field,
                "reason": "measurement window missing"}
    t0, t1 = window_start_ms / 1000.0, window_end_ms / 1000.0
    series = []
    for line in soak_jsonl.read_text(errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        val = _series_value(ev, field)
        ts = ev.get("ts")
        if isinstance(val, (int, float)) and isinstance(ts, (int, float)):
            series.append((ts, val))
    series.sort()
    if len(series) < 2:
        return {"delta": None, "field": field,
                "reason": "insufficient samples"}

    def interp(t: float) -> float | None:
        prev = None
        for ts, val in series:
            if ts <= t:
                prev = (ts, val)
                continue
            if prev is None:
                return val if ts <= t + 6 else None
            if ts == prev[0]:
                return val
            return prev[1] + (val - prev[1]) * (t - prev[0]) / (ts - prev[0])
        return None

    w0, w1 = interp(t0), interp(t1)
    if w0 is None or w1 is None:
        return {"delta": None, "field": field,
                "reason": "window edges outside sampled range",
                "series_span": [series[0][0], series[-1][0]]}
    return {"delta": w1 - w0, "field": field,
            "window_s": round(t1 - t0, 1),
            "sample_span": [series[0][0], series[-1][0]]}


def acquire_per_http(acquire_count, http_reqs) -> dict:
    """Pool acquisitions normalized over the same (full-run) HTTP
    population. The pool counter is app-lifetime; dividing it by the
    post-warmup cohort mixes windows. Background acquisitions cannot be
    separated out — the value carries that bound."""
    if not acquire_count or not http_reqs:
        return {"per_request": None, "reason": "missing inputs"}
    return {"per_request": round(acquire_count / http_reqs, 4),
            "window": "full-run (includes background share)",
            "acquires": acquire_count, "http_reqs": http_reqs}


def wal_per_success(wal_delta_bytes: float | None,
                    success_count: float | None) -> float | None:
    if not wal_delta_bytes or not success_count:
        return None
    return round(wal_delta_bytes / success_count, 3)


# ---------------------------------------------------------------------
# audit drain / runtime health / app log scan
# ---------------------------------------------------------------------

def audit_drain(timeout_s: int = 120) -> dict:
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            row = psql(
                "SELECT (SELECT count(*) FROM security_audit_events),"
                " last_sequence, anchor_sequence"
                " FROM security_audit_chain_state")
            pending, last_seq, anchor = row.split("|")
            last = {"pending": int(pending), "last_sequence": int(last_seq),
                    "anchor_sequence": int(anchor)}
            if int(pending) == 0:
                last["drained"] = True
                return last
        except Exception as e:  # noqa: BLE001 - evidence path
            last = {"error": str(e)[:200]}
        time.sleep(3)
    if last is not None:
        last["drained"] = False
    return last or {"drained": False, "error": "no samples"}


def refresh_invariants(ledger_path: Path) -> dict:
    """Parse the post-window ledger for the refresh-family gate counters."""
    out = {"max_active_per_scope": None, "spent_max_per_family": None,
           "spent_expired_backlog": None}
    if not ledger_path.exists():
        return out
    for line in ledger_path.read_text(errors="replace").splitlines():
        f = line.split("|")
        if len(f) < 4:
            continue
        if f[:3] == ["REFRESH_MODEL", "families", "max_active_per_scope"]:
            out["max_active_per_scope"] = int(f[3])
        elif f[:3] == ["REFRESH_MODEL", "spent", "max_per_family"]:
            out["spent_max_per_family"] = int(f[3])
        elif f[:2] == ["EXPIRED_BACKLOG", "spent_proofs_due"]:
            out["spent_expired_backlog"] = int(f[2])
    return out


def receiver_log_scan(run_id: str) -> dict:
    """Receiver-side audit evidence for this run, scoped to what the log
    actually shows. An absent container or failed collection is missing
    evidence — it is not 'Required lost=0'."""
    name = f"sis-rcv-{run_id}"
    proc = dc("logs", name, check=False)
    if proc.returncode != 0:
        return {"collected": False, "reason": "container logs unavailable",
                "rc": proc.returncode}
    logs = (proc.stdout or "") + "\n" + (proc.stderr or "")
    return {
        "collected": True,
        "lines": logs.count("\n"),
        "ack_markers": len(re.findall(r"(?i)ack|anchor|batch", logs)),
        "error_markers": len(re.findall(r"(?i)error|fail|panic", logs)),
    }


def audit_db_drained_of(drain: dict) -> bool:
    """DB drain gate: pending explicitly 0 AND last_sequence and
    anchor_sequence both present and equal."""
    return (drain.get("pending") == 0
            and isinstance(drain.get("last_sequence"), int)
            and isinstance(drain.get("anchor_sequence"), int)
            and drain["last_sequence"] == drain["anchor_sequence"])


def audit_delivery_reconciled_of(drain: dict, rcv: dict) -> bool | None:
    """End-to-end reconciliation needs real receiver facts (final
    sequence/hash/deployment cross-check), which the current collector
    does not capture — receiver_log_scan only reports log health.

    Therefore this helper has NO True path today:
      - DB drain unsatisfied        -> False (acceptance fails);
      - receiver errors observed    -> False (acceptance fails, though
                                       this alone does not prove events
                                       were lost);
      - log collected and clean, or
        receiver log missing        -> None (UNKNOWN — log health is
                                       not reconciliation)."""
    if not audit_db_drained_of(drain):
        return False
    if rcv.get("collected") is True and rcv.get("error_markers", 0) > 0:
        return False
    return None


def app_log_scan(since_ts: float) -> dict:
    """Scan the app container's combined stdout+stderr stream.

    `docker logs` writes the container's stderr to the CLI's stderr, so
    stdout alone misses error lines. Collection failure is recorded
    separately from an empty-but-collected log — they are not the same
    evidence state."""
    proc = dc("logs", "--since", str(int(since_ts)), APP, check=False)
    logs = (proc.stdout or "") + "\n" + (proc.stderr or "")
    collected = proc.returncode == 0
    return {
        "collected": collected,
        "rc": proc.returncode,
        "since_ts": since_ts,
        "queue_full": len(re.findall(r"queue_full", logs)),
        "dropped_required": len(re.findall(r"dropped_required", logs)),
        "persistence_error": len(re.findall(r"persistence_status.*error", logs)),
        "lines": logs.count("\n"),
    }


def container_health() -> dict:
    out = {}
    for c in (APP, POSTGRES, VALKEY):
        proc = dc("inspect", c, "--format",
                  "{{.State.OOMKilled}} {{.RestartCount}} {{.State.Status}}",
                  check=False)
        parts = (proc.stdout or "").split()
        out[c] = {
            "oom_killed": parts[0] == "true" if parts else None,
            "restart_count": int(parts[1]) if len(parts) > 1 else None,
            "status": parts[2] if len(parts) > 2 else None,
        }
    return out


# ---------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------

def provenance(point: dict, out_dir: Path) -> dict:
    prov: dict = {"point": point["name"]}
    prov["source_sha"] = os.environ.get("SIS_SOURCE_SHA", "unknown")
    prov["app_image_ref"] = point["image"]
    img = dc("inspect", APP, "--format", "{{.Image}}", check=False)
    prov["app_image_id"] = img.stdout.strip()
    exe = dcx(APP, ["sh", "-c", "readlink /proc/1/exe"], check=False)
    prov["binary_path"] = exe.stdout.strip()
    prov["binary_sha256"] = dcx(
        APP, ["sha256sum", prov["binary_path"] or "/proc/1/exe"],
        check=False).stdout.split()[0] if prov["binary_path"] else None
    prov["pg_version"] = psql("SELECT version()", check=False)[:120]
    for s in ("max_wal_size", "checkpoint_timeout",
              "checkpoint_completion_target", "fsync", "synchronous_commit",
              "full_page_writes", "shared_buffers", "max_connections",
              "track_io_timing"):
        prov[f"pg_{s}"] = psql(f"SHOW {s}", check=False)
    prov["applied_migrations_sha256"] = None
    applied = psql(
        "SELECT string_agg(version::text, ',' ORDER BY version) "
        "FROM __diesel_schema_migrations", check=False)
    if applied:
        import hashlib
        prov["applied_migrations_sha256"] = hashlib.sha256(
            applied.encode()).hexdigest()

    # Image <-> source bindings. The app image carries
    # org.opencontainers.image.revision and /etc/nazoauth-source-sha; the
    # runner image bakes the harness (COPY perf /perf) so the in-image k6
    # script hash must equal this checkout's file hash — otherwise the run
    # would measure a stale harness.
    prov["app_image_revision"] = dc(
        "image", "inspect", point["image"], "--format",
        '{{index .Config.Labels "org.opencontainers.image.revision"}}',
        check=False).stdout.strip() or None
    srcfile = dcx(APP, ["cat", "/etc/nazoauth-source-sha"], check=False)
    prov["app_source_sha_file"] = (
        srcfile.stdout.strip() or None if srcfile.returncode == 0 else None)
    declared = prov.get("source_sha")
    prov["source_sha_registered"] = (
        declared is not None and declared != "unknown")
    prov["source_sha_eq_image_revision"] = (
        prov["source_sha_registered"]
        and prov["app_image_revision"] == declared)
    prov["source_sha_eq_file"] = (
        prov["source_sha_registered"]
        and prov["app_source_sha_file"] == declared)

    runner = PERF_IMAGE
    prov["runner_image_ref"] = runner
    prov["runner_image_id"] = dc(
        "image", "inspect", runner, "--format", "{{.Id}}",
        check=False).stdout.strip() or None
    prov["runner_image_revision"] = dc(
        "image", "inspect", runner, "--format",
        '{{index .Config.Labels "org.opencontainers.image.revision"}}',
        check=False).stdout.strip() or None
    k6_in_image = dc("run", "--rm", "--entrypoint", "sha256sum", runner,
                     "/perf/k6/oauth.js", check=False)
    prov["runner_k6_oauth_sha256"] = (
        k6_in_image.stdout.split()[0]
        if k6_in_image.returncode == 0 and k6_in_image.stdout.strip()
        else None)
    prov["workspace_k6_oauth_sha256"] = file_sha256(
        Path(WORKSPACE) / "perf/k6/oauth.js")
    prov["k6_oauth_eq_workspace"] = (
        prov["runner_k6_oauth_sha256"] is not None
        and prov["runner_k6_oauth_sha256"]
        == prov["workspace_k6_oauth_sha256"])
    jdump(out_dir / "provenance.json", prov)
    return prov


# ---------------------------------------------------------------------
# point orchestration
# ---------------------------------------------------------------------

def run_point(point: dict) -> dict:
    run_id = point["name"]
    out_dir = RESULTS / point["phase"] / run_id
    out_host = str(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    global CURRENT_POINT
    CURRENT_POINT = point

    rec: dict = {"point": point, "run_id": run_id}
    planned = _duration_seconds(point["duration"]) + 30
    if point.get("sidecars"):
        planned += _duration_seconds(point["sidecars"][0]["duration"]) + 30
    budget_check(planned)
    started = time.time()

    try:
        stack_down()
        rec["stack"] = stack_up(point)
        rec["provenance"] = provenance(point, out_dir)
        depid = rec["stack"].get("deployment_id")
        if not depid:
            raise RuntimeError("deployment id unavailable after stack up")
        point["deployment_id"] = depid
        rec["audit"] = audit_pair_up(run_id, depid)
        ledger("pre", run_id, out_dir)
        rec["pgss_reset"] = pgss_reset()
        pgss_pre = pgss_snapshot("pre", out_dir)
        rec["samplers"] = start_samplers(run_id, out_host)

        try:
            rec["load"] = run_load(point, run_id, out_dir)
        finally:
            # Load may have started even when run_load raised — the entry
            # is recorded either way, as 'unknown' when unmeasurable.
            _spend_load_budget(run_id, rec)

        rec["audit_drain"] = audit_drain()
        ledger("post", run_id, out_dir)
        pgss_post = pgss_snapshot("post", out_dir)
        rec["app_log_scan"] = app_log_scan(rec["load"]["started_ts"])
        rec["container_health"] = container_health()
        stop_samplers(run_id)

        # Normalize the runner's combined summary.
        summary_files = list((out_dir / "load").glob("*.summary.json"))
        rec["summary_files"] = [f.name for f in summary_files]
        if summary_files:
            combined = json.loads(summary_files[0].read_text())
            rec["metrics"] = extract_point_metrics(combined)
            m = rec["metrics"]
            http = m.get("http_reqs") or 0
            rec["pgss_delta"] = pgss_delta(pgss_pre, pgss_post, http)
            # Numerator and denominator must share one window: the pgss
            # snapshot pair brackets seed+load+drain, so it cannot price a
            # single cohort op. The sampler's wal_bytes/pool.acq series is
            # the same-window source; when it cannot cover the window the
            # value is NOT_COMPARABLE, not silently wrong.
            soak_path = out_dir / "soak-metrics.jsonl"
            wal_w = windowed_series_delta(
                soak_path, "wal_bytes",
                m.get("window_start_ms"), m.get("window_end_ms"))
            acq_w = windowed_series_delta(
                soak_path, "pool.acq",
                m.get("window_start_ms"), m.get("window_end_ms"))
            success = m.get("outcome_success")
            m["wal_snapshot_delta_bytes"] = (
                float(pgss_post["wal"]) - float(pgss_pre["wal"])
                if pgss_post.get("wal") and pgss_pre.get("wal") else None)
            m["wal_windowed"] = wal_w
            m["wal_per_success_bytes"] = (
                round(wal_w["delta"] / success, 3)
                if wal_w.get("delta") and success else None)
            m["acquire_windowed"] = acq_w
            m["acquire_per_op_windowed"] = (
                round(acq_w["delta"] / success, 4)
                if acq_w.get("delta") and success else None)
            m["acquire_per_op_windowed_caveat"] = (
                "same-window sampler delta / measure-cohort success; "
                "background acquisitions inside the window are included "
                "and cannot be separated")
            m["acquire_per_http_full_window"] = acquire_per_http(
                m.get("pool_acquire_count"), http)
        else:
            rec["metrics"] = {"status": "no_summary"}
        # Tri-state aggregation: an inspect failure yields unknown, not
        # a healthy-looking False/0.
        ooms = [(rec["container_health"].get(c) or {}).get("oom_killed")
                for c in rec["container_health"]]
        rec["metrics"]["oom_killed"] = (
            True if any(ooms)
            else False if ooms and all(o is False for o in ooms) else None)
        rsts = [(rec["container_health"].get(c) or {}).get("restart_count")
                for c in rec["container_health"]]
        rec["metrics"]["restart_count"] = (
            sum(rsts) if rsts and all(isinstance(x, int) for x in rsts)
            else None)
        rec["metrics"]["audit_drained"] = (
            rec["audit_drain"].get("drained") is True)
        rec["metrics"]["audit_log_scan"] = rec["app_log_scan"]
        # Evidence-scoped audit reporting: DB pending/anchor facts, the
        # receiver's own log facts, and the app-log anomaly scan are kept
        # distinct. None upgrades into an end-to-end claim it cannot prove.
        rcv = receiver_log_scan(run_id)
        rec["metrics"]["audit_evidence"] = {
            "db": rec["audit_drain"],
            "receiver": rcv,
            "app_log_collected": rec["app_log_scan"].get("collected"),
        }
        rec["metrics"]["audit_db_drained"] = audit_db_drained_of(
            rec["audit_drain"])
        rec["metrics"]["audit_delivery_reconciled"] = (
            audit_delivery_reconciled_of(rec["audit_drain"], rcv))
        rec["metrics"]["refresh_invariants"] = refresh_invariants(
            out_dir / "ledger-post.txt")
        if rec["load"].get("sidecars") is not None:
            rec["metrics"]["sidecar_terminal_complete"] = all(
                s["terminal_summary"] and not s["interrupted"]
                for s in rec["load"]["sidecars"])
        rec["ok"] = True
    except Exception as e:  # noqa: BLE001 - evidence path
        rec["ok"] = False
        rec["error"] = f"{type(e).__name__}: {e}"[:500]
    finally:
        rec["elapsed_s"] = round(time.time() - started, 1)
        stop_samplers(run_id)
        jdump(out_dir / "point.json", rec)
    return rec


# ---------------------------------------------------------------------
# gate evaluation (pre-declared thresholds — no tuning after the fact)
# ---------------------------------------------------------------------

PHASE2_REQUIRED = (
    "window_valid", "successful_ops_per_s", "op_p99_ms",
    "outcome_unexpected", "outcome_local_no_request",
    "oom_killed", "restart_count", "wal_per_success_bytes",
    "audit_log_scan", "audit_db_drained", "audit_delivery_reconciled")


def _missing_required(records: dict, points: tuple, fields: tuple) -> list:
    """Per-point required-evidence check. Missing points, missing fields
    and None (absent/collection-failed) values are all reported by name.
    A legal zero or False is a value, not a gap."""
    missing = []
    for n in points:
        r = records.get(n)
        if r is None:
            missing.append({"point": n, "field": "<point record>"})
            continue
        for f in fields:
            if r.get(f) is None:
                missing.append({"point": n, "field": f})
    return missing


def evaluate_phase2_gates(records: dict) -> dict:
    gates: dict = {}

    # Required evidence per point, BEFORE any comparison math. Missing
    # baselines may never be filtered down to a one-sided "stability"
    # or a one-sided WAL comparison.
    missing = _missing_required(records, ("A1", "A2", "B1", "B2"),
                                PHASE2_REQUIRED)
    gates["required_evidence"] = {"pass": not missing, "missing": missing}
    if missing:
        return {"verdict": "INVALID", "retain": False, "gates": gates}

    a1, a2 = records["A1"], records["A2"]
    b1, b2 = records["B1"], records["B2"]

    invalid = [n for n, r in records.items()
               if r["window_valid"] is not True]
    gates["window_validity"] = {"pass": not invalid, "invalid_points": invalid}

    a_vals = [a1["successful_ops_per_s"], a2["successful_ops_per_s"]]
    amax, amin = max(a_vals), min(a_vals)
    # Legal zero throughput is a real value: no division by zero and no
    # silent downgrade — stability simply cannot be certified.
    a_spread = (amax - amin) / amax if amax else None
    gates["a_stability"] = {
        "pass": a_spread is not None and a_spread <= 0.05,
        "spread": round(a_spread, 4) if a_spread is not None else None,
        "a1": a_vals[0], "a2": a_vals[1]}

    b_gain_rows = []
    for n, b in (("B1", b1), ("B2", b2)):
        b_thr = b["successful_ops_per_s"]
        gain = (b_thr / amax - 1) if amax else None
        b_gain_rows.append({"point": n, "gain": (
                                round(gain, 4) if gain is not None else None),
                            "pass": gain is not None and gain >= 0.05})
    gates["b_gain"] = {"pass": all(r["pass"] for r in b_gain_rows),
                       "rows": b_gain_rows}

    p99_rows = []
    a_p99 = max(a1["op_p99_ms"], a2["op_p99_ms"])
    for n, b in (("B1", b1), ("B2", b2)):
        b99 = b["op_p99_ms"]
        rel = (b99 / a_p99 - 1) if a_p99 else 0.0
        abs_ms = b99 - a_p99
        violation = rel > 0.10 and abs_ms > 2.0
        p99_rows.append({"point": n, "a_p99": a_p99, "b_p99": b99,
                         "rel": round(rel, 4), "abs_ms": round(abs_ms, 3),
                         "violation": violation})
    gates["p99_regression"] = {
        "pass": not any(r["violation"] for r in p99_rows), "rows": p99_rows}

    # Missing counters are not zero counters: an absent outcome or health
    # field is absent evidence, so the gate cannot pass.
    clean_rows = []
    for n, r in records.items():
        unx = r.get("outcome_unexpected")
        lnr = r.get("outcome_local_no_request")
        clean_rows.append({
            "point": n, "unexpected": unx, "local_no_request": lnr,
            "pass": unx == 0 and lnr == 0})
    gates["clean_outcomes"] = {
        "pass": all(r["pass"] for r in clean_rows), "rows": clean_rows}

    # Both A baselines are guaranteed present by required_evidence —
    # never compare against a filtered-down single baseline.
    a_wal_max = max(a1["wal_per_success_bytes"],
                    a2["wal_per_success_bytes"])
    wal_rows = []
    for n, b in (("B1", b1), ("B2", b2)):
        bw = b["wal_per_success_bytes"]
        wal_rows.append({"point": n, "wal_per_success": bw,
                         "pass": bw <= a_wal_max * 1.05})
    gates["wal_per_success"] = {"pass": all(r["pass"] for r in wal_rows),
                                "rows": wal_rows}

    health_rows = []
    for n, r in records.items():
        oom = r.get("oom_killed")
        rst = r.get("restart_count")
        scan = r.get("audit_log_scan") or {}
        # A failed log collection is not "no anomalies observed" — the
        # scan must have been collected with zero anomaly markers.
        health_rows.append({
            "point": n, "oom_killed": oom, "restart_count": rst,
            "log_collected": scan.get("collected"),
            "pass": (oom is False and rst == 0
                     and scan.get("collected") is True
                     and scan.get("queue_full") == 0
                     and scan.get("dropped_required") == 0)})
    gates["runtime_health"] = {
        "pass": all(r["pass"] for r in health_rows), "rows": health_rows}
    # DB drain and end-to-end delivery are separate gates — an empty
    # pending set alone is not reconciliation.
    gates["audit_db_drained"] = {"pass": all(
        r["audit_db_drained"] is True for r in records.values())}
    gates["audit_delivery_reconciled"] = {"pass": all(
        r["audit_delivery_reconciled"] is True for r in records.values())}

    all_pass = all(g["pass"] for g in gates.values())
    if invalid:
        verdict = "INVALID"
    elif not gates["a_stability"]["pass"]:
        verdict = "INCONCLUSIVE"
    else:
        verdict = "PASS" if all_pass else "FAIL"
    return {"verdict": verdict, "retain": verdict == "PASS", "gates": gates}


PHASE3_REQUIRED_A = (
    "successful_ops_per_s", "drop_fraction", "op_p99_ms",
    "outcome_expected_rejection", "audit_db_drained",
    "audit_delivery_reconciled")
PHASE3_REQUIRED_B = PHASE3_REQUIRED_A + (
    "window_valid", "outcome_unexpected", "outcome_local_no_request",
    "oom_killed", "restart_count", "audit_log_scan",
    "refresh_invariants", "sidecar_terminal_complete")


def evaluate_phase3_gates(a: dict | None, b: dict | None) -> dict:
    gates: dict = {}

    # Same required-evidence discipline as phase 2: both point records
    # must exist with their required fields before any comparison.
    missing = []
    if a is None:
        missing.append({"point": "A", "field": "<point record>"})
    else:
        missing += _missing_required({"A": a}, ("A",), PHASE3_REQUIRED_A)
    if b is None:
        missing.append({"point": "B", "field": "<point record>"})
    else:
        missing += _missing_required({"B": b}, ("B",), PHASE3_REQUIRED_B)
    gates["required_evidence"] = {"pass": not missing, "missing": missing}
    if missing:
        return {"verdict": "INVALID", "retain": False, "gates": gates}

    a_thr, b_thr = a["successful_ops_per_s"], b["successful_ops_per_s"]
    gates["throughput"] = {
        "pass": bool(a_thr and b_thr and b_thr >= a_thr * 0.98),
        "a": a_thr, "b": b_thr}
    a_drop, b_drop = a["drop_fraction"], b["drop_fraction"]
    gates["drop_fraction"] = {
        "pass": b_drop <= a_drop + 0.001, "a": a_drop, "b": b_drop}
    a99, b99 = a["op_p99_ms"], b["op_p99_ms"]
    rel = (b99 / a99 - 1) if a99 else 0.0
    gates["p99_regression"] = {
        "pass": not (rel > 0.10 and (b99 - a99) > 2.0),
        "a_p99": a99, "b_p99": b99, "rel": round(rel, 4)}
    unx_b = b["outcome_unexpected"]
    lnr_b = b["outcome_local_no_request"]
    rej_a, rej_b = a["outcome_expected_rejection"], b["outcome_expected_rejection"]
    gates["clean_outcomes"] = {"pass":
        unx_b == 0 and lnr_b == 0 and rej_b <= rej_a}
    scan = b.get("audit_log_scan") or {}
    gates["runtime_health"] = {"pass":
        b.get("oom_killed") is False and b.get("restart_count") == 0
        and scan.get("collected") is True
        and scan.get("queue_full") == 0
        and scan.get("dropped_required") == 0}
    inv = b.get("refresh_invariants") or {}
    gates["refresh_invariants"] = {
        "pass": inv.get("max_active_per_scope") is not None
        and inv["max_active_per_scope"] <= 10
        and inv.get("spent_max_per_family") is not None
        and inv["spent_max_per_family"] <= 64
        and inv.get("spent_expired_backlog") == 0,
        "values": inv}
    gates["audit_db_drained"] = {"pass":
        a["audit_db_drained"] is True and b["audit_db_drained"] is True}
    gates["audit_delivery_reconciled"] = {"pass":
        a["audit_delivery_reconciled"] is True
        and b["audit_delivery_reconciled"] is True}
    gates["sidecar_terminal"] = {
        "pass": a.get("sidecar_terminal_complete") is not False
        and b.get("sidecar_terminal_complete") is True}
    all_pass = all(g["pass"] for g in gates.values())
    return {"verdict": "PASS" if all_pass else "FAIL",
            "retain": all_pass, "gates": gates}


# ---------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------

def cmd_env_check() -> None:
    out = RESULTS / "env-check.json"
    ev: dict = {"ts": time.time()}
    ev["nproc"] = os.cpu_count()
    ev["allowed_cpus"] = sorted(
        parse_cpu_list(Path("/sys/fs/cgroup/cpuset.cpus").read_text().strip())
        if Path("/sys/fs/cgroup/cpuset.cpus").exists()
        else parse_cpu_list(
            Path("/proc/self/status").read_text()
            .split("Cpus_allowed_list:")[1].split("\n")[0].strip()))
    ev["smt_groups"] = [sorted(g) for g in smt_groups(set(ev["allowed_cpus"]))]
    ev["plan"] = plan_cpu_sets(set(ev["allowed_cpus"]), ev_smt(ev))
    ev["cgroup_v1"] = {
        "cpuset_cpus": Path(
            "/sys/fs/cgroup/cpuset/cpuset.cpus").read_text().strip()
        if Path("/sys/fs/cgroup/cpuset/cpuset.cpus").exists() else None,
        "cpu_quota": Path(
            "/sys/fs/cgroup/cpu/cpu.cfs_quota_us").read_text().strip()
        if Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").exists() else None,
        "cpu_period": Path(
            "/sys/fs/cgroup/cpu/cpu.cfs_period_us").read_text().strip()
        if Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us").exists() else None,
    }
    ev["docker"] = dc("version", "--format", "{{json .}}", check=False).stdout[:800]
    ev["compose"] = dc("compose", "version", check=False).stdout.strip()
    ev["perf_event_paranoid"] = Path(
        "/proc/sys/kernel/perf_event_paranoid").read_text().strip() \
        if Path("/proc/sys/kernel/perf_event_paranoid").exists() else None
    ev["python"] = sys.version.split()[0]
    ev["images"] = {
        n: dc("inspect", img, "--format", "{{.Id}}", check=False).stdout.strip()
        for n, img in {
            "perf": PERF_IMAGE,
            "receiver": os.environ.get("SIS_RCV_IMAGE", "sis-rcv:latest"),
            "keyset": f"{PROJECT}-keyset",
        }.items()}
    jdump(out, ev)
    print(json.dumps(ev["plan"]))


def ev_smt(ev: dict) -> list[frozenset[int]]:
    return [frozenset(g) for g in ev["smt_groups"]]


def cmd_pinset_build() -> None:
    src = Path(BIN_DIR) / "pinset.c"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(PINSET_C)
    sh(["gcc", "-O2", "-static", "-o", str(Path(BIN_DIR) / "pinset"), str(src)])
    proc = sh(["sha256sum", str(Path(BIN_DIR) / "pinset")])
    print(proc.stdout.strip())


def cmd_up() -> None:
    point = json.loads(os.environ["SIS_POINT"])
    CURRENT_POINT.update(point)
    rec = {"point": point["name"]}
    stack_down()
    rec["stack"] = stack_up(point)
    jdump(RESULTS / "last-up.json", rec)
    print(json.dumps({"healthy": rec["stack"]["healthy"],
                      "depid": rec["stack"].get("deployment_id")}))


def cmd_run() -> None:
    point = json.loads(os.environ["SIS_POINT"])
    rec = run_point(point)
    print(json.dumps({"ok": rec.get("ok"), "error": rec.get("error"),
                      "metrics": rec.get("metrics")}))


def cmd_ledger() -> None:
    run_id = os.environ.get("SIS_RUN_ID", "adhoc")
    phase = os.environ.get("SIS_LEDGER_PHASE", "pre")
    ledger(phase, run_id, RESULTS / "ledger")


def cmd_eval() -> None:
    phase = os.environ.get("SIS_PHASE", "phase2")
    records = {}
    for pj in RESULTS.rglob("point.json"):
        rec = json.loads(pj.read_text())
        name = rec["point"]["name"].upper().replace("-", "")
        if rec.get("metrics"):
            records[name] = rec["metrics"]
    if phase == "phase2":
        needed = {"A1", "A2", "B1", "B2"}
        missing = needed - set(records)
        if missing:
            print(json.dumps({"verdict": "INCOMPLETE", "missing": sorted(missing)}))
            return
        print(json.dumps(evaluate_phase2_gates(
            {k: records[k] for k in needed}), indent=2))
    else:
        a = records.get("MIXEDA")
        b = records.get("MIXEDB")
        if not a or not b:
            print(json.dumps({"verdict": "INCOMPLETE"}))
            return
        print(json.dumps(evaluate_phase3_gates(a, b), indent=2))


def cmd_report() -> None:
    points = {}
    for pj in sorted(RESULTS.rglob("point.json")):
        rec = json.loads(pj.read_text())
        points[rec["point"]["name"]] = {
            "phase": rec["point"].get("phase"),
            "image": rec["point"].get("image"),
            "app_cpus": len(rec["point"].get("app_cpus", [])),
            "ok": rec.get("ok"),
            "metrics": rec.get("metrics"),
            "load_seconds": (rec.get("load") or {}).get("load_seconds"),
            "provenance": {
                "source_sha": (rec.get("provenance") or {}).get("source_sha"),
                "app_image_id": (rec.get("provenance") or {}).get("app_image_id"),
                "binary_sha256": (rec.get("provenance") or {}).get("binary_sha256"),
            },
            "pgss_path_classes": (rec.get("pgss_delta") or {}).get("path_classes"),
            "pin_verified": ((rec.get("stack") or {}).get("pin") or {}).get(
                "app_verified"),
        }
    jdump(RESULTS / "scaling-points.json", {
        "generated_ts": time.time(),
        "budget": budget_state(),
        "points": points,
    })
    print(json.dumps({"points": len(points),
                      "budget": budget_state()["load_seconds_used"]}))


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "env-check"
    RESULTS.mkdir(parents=True, exist_ok=True)
    {
        "env-check": cmd_env_check,
        "pinset-build": cmd_pinset_build,
        "up": cmd_up,
        "run": cmd_run,
        "ledger": cmd_ledger,
        "eval": cmd_eval,
        "report": cmd_report,
    }[cmd]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
