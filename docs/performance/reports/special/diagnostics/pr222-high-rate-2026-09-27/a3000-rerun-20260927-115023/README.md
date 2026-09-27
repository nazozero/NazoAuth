# A3000 rerun preflight

This checkpoint records only the new-container preflight. No A3000 load has started.

- T0: 2026-09-27 11:50:23 UTC; stop new load at 18:20:23 UTC; delivery by 18:50:23 UTC.
- Runtime-process probe: 64 bindable logical CPU scheduling labels; see `runtime-cpu-plan.json`. Physical topology is out of scope.
- Frozen profile SHA-256 is in `preflight.json`; pool 90, main cap 1600, total VU budget 1973, users 200, vectors 38400, and mixed sidecars remain unchanged. The A3000 point uses 1500 main VUs plus the existing sidecar VUs.
- A source image build started with one compile job. The build log remains in the task container; it does not indicate a completed build.
- The point wrapper was recovered from the pinned taskbook. Its only compatibility patch maps a missing optional pilot memory estimate to disabled estimate gate (0); runtime OOM/CPU/stream/health/audit gates remain enabled.
- The earlier A3000 steady process was lost with its container; it remains `BLOCKED_UNVERIFIED` and supplies no performance result.
- This corrected preflight checkpoint supersedes incomplete commit `b3d70a0578b315fadd3893e6d6ca3478ab6b00be`.