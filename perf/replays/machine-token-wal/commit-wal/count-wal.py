"""Reconcile audit heap insert records with committed XIDs in the window."""

import json, os, re, sys
from collections import Counter
from pathlib import Path

rel, path, *client_relation = sys.argv[1:]
inserts, commits = Counter(), set()
locks, aborts = set(), set()
for line in sys.stdin:
    rm = line.split("len (rec/tot)", 1)[0].removeprefix("rmgr:").strip()
    if rm not in {"Heap", "Heap2", "Transaction"}:
        continue
    xid = re.search(r"\btx:\s*(\d+)", line)
    if not xid:
        raise ValueError(line[:90])
    xid = int(xid[1])
    if rm == "Transaction":
        if re.search(r"desc: COMMIT(?:\s|$)", line):
            commits.add(xid)
        elif client_relation and re.search(r"desc: ABORT(?:\s|$)", line):
            aborts.add(xid)
    elif client_relation and f"rel {client_relation[0]} " in line and re.search(r"desc: LOCK(?:\s|$)", line):
        locks.add(xid)
    elif f"rel {rel} " in line and re.search(r"desc: INSERT(?:\+INIT)?\s", line):
        inserts[xid] += 1
    elif f"rel {rel} " in line and "MULTI_INSERT" in line:
        raise ValueError("unexpected bulk insert in single issuance benchmark")
p = Path(path)
doc = json.loads(p.read_text())
doc["wal_committed_audit_rows"] = sum(n for x, n in inserts.items() if x in commits)
doc["wal_uncommitted_audit_inserts"] = sum(
    n for x, n in inserts.items() if x not in commits
)
expected_rows = {"required": doc["whole_success"], "off": 0}[
    os.environ.get("BENCH_ISSUANCE_AUDIT", "required")
]
assert doc.get("expected_audit_rows", expected_rows) == expected_rows
doc["expected_audit_rows"] = expected_rows
doc["audit_count_difference"] = doc["durable_token_issued"] - expected_rows
if client_relation:
    doc["client_lock_xids"] = {"committed": len(locks & commits), "aborted": len(locks & aborts),
                               "unresolved": len(locks - commits - aborts)}
p.write_text(json.dumps(doc, indent=2) + "\n")
if (
    doc["wal_uncommitted_audit_inserts"]
    or doc["wal_committed_audit_rows"] != expected_rows
    or doc["wal_committed_audit_rows"] != doc["durable_token_issued"]
):
    raise SystemExit(
        f"WAL/HTTP/adapter discrepancy: {doc['wal_committed_audit_rows']}/{doc['whole_success']}/{doc['durable_token_issued']}"
    )
