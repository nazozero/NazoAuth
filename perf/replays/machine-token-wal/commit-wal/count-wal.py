"""Reconcile audit heap insert records with committed XIDs in the window."""

import json, re, sys
from collections import Counter
from pathlib import Path

rel, path = sys.argv[1:]
inserts, commits = Counter(), set()
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
p.write_text(json.dumps(doc, indent=2) + "\n")
if (
    doc["wal_uncommitted_audit_inserts"]
    or doc["wal_committed_audit_rows"] != doc["whole_success"]
    or doc["wal_committed_audit_rows"] != doc["durable_token_issued"]
):
    raise SystemExit(
        f"WAL/HTTP/adapter discrepancy: {doc['wal_committed_audit_rows']}/{doc['whole_success']}/{doc['durable_token_issued']}"
    )
