"""Capture public execution metadata only. Never serialize a container environment."""

from pathlib import Path
import hashlib, json, subprocess, sys


def cmd(*argv):
    return subprocess.check_output(argv, text=True).strip()


pg = "oauthbench-pg"
settings = (
    "wal_sync_method",
    "commit_delay",
    "synchronous_commit",
    "fsync",
    "full_page_writes",
    "max_connections",
    "shared_buffers",
    "max_wal_size",
    "checkpoint_timeout",
    "checkpoint_completion_target",
)
meta = {
    "postgres": {
        "id": cmd("docker", "inspect", "-f", "{{.Id}}", pg),
        "started": cmd("docker", "inspect", "-f", "{{.State.StartedAt}}", pg),
        "image": cmd("docker", "inspect", "-f", "{{.Image}}", pg),
        "command": json.loads(
            cmd("docker", "inspect", "-f", "{{json .Config.Cmd}}", pg)
        ),
        "settings": {
            k: cmd(
                "docker",
                "exec",
                "-u",
                "postgres",
                pg,
                "psql",
                "-XAt",
                "-d",
                "postgres",
                "-c",
                f"SHOW {k}",
            )
            for k in settings
        },
    },
    "k6": cmd("docker", "exec", "oauthbench-k6", "k6", "version"),
    "k6_workload_sha256": hashlib.sha256(
        Path("bench/durable-k6.js").read_bytes()
    ).hexdigest(),
    "binaries": {
        k: cmd("sha256sum", f"out/{k}").split()[0]
        for k in (sys.argv[2:] or ["control", "candidate"])
    },
}
assert (
    meta["postgres"]["settings"]["fsync"]
    == meta["postgres"]["settings"]["synchronous_commit"]
    == meta["postgres"]["settings"]["full_page_writes"]
    == "on"
)
assert (
    meta["postgres"]["settings"]["wal_sync_method"] == "fdatasync"
    and meta["postgres"]["settings"]["commit_delay"] == "0"
)
Path(sys.argv[1]).write_text(json.dumps(meta, indent=2) + "\n")
