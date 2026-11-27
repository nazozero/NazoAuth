"""Measure one closed batch against the password-login endpoint."""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import monotonic_ns

from api import Api, ApiError


def login(account):
    api = Api("oidc-bench-nazo")
    start = monotonic_ns()
    try:
        api.login(account)
        status = "ok"
    except ApiError as exc:
        status = f"http_{exc.status}"
    except (OSError, RuntimeError) as exc:
        status = type(exc).__name__
    finally:
        api.conn.close()
    return [status, round((monotonic_ns() - start) / 1e6, 3)]


accounts = json.loads(Path("/tmp/nazo.json").read_bytes())["users"][:32]
assert len(accounts) == 32
with ThreadPoolExecutor(max_workers=8) as workers:
    start = monotonic_ns()
    results = list(workers.map(login, accounts))
print(json.dumps({"ms": (monotonic_ns() - start) / 1e6, "operations": results}))
