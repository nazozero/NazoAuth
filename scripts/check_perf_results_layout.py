"""Guard: perf/results/ keeps the canonical layout.

Root of perf/results/ may only contain README.md and directories.
Tracked artifacts must live under data/, environments/, or diagnostics/.
"""
import subprocess
import sys

ALLOWED_DIRS = {"data", "environments", "diagnostics"}
ALLOWED_FILES = {"README.md"}

out = subprocess.run(
    ["git", "ls-files", "perf/results"],
    check=True, capture_output=True, text=True,
).stdout.splitlines()

errors = []
for path in out:
    rel = path.removeprefix("perf/results/")
    top = rel.split("/", 1)[0]
    if "/" not in rel:
        if top not in ALLOWED_FILES:
            errors.append(f"flat tracked file at perf/results root: {path}")
    elif top not in ALLOWED_DIRS and top != ".run":
        errors.append(f"tracked file outside {sorted(ALLOWED_DIRS)}: {path}")

if errors:
    print("perf/results layout violation(s):", *errors, sep="\n  ", file=sys.stderr)
    sys.exit(1)
print(f"perf/results layout OK ({len(out)} tracked files)")
