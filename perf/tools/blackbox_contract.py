"""Evidence available from blackbox traffic, task processes and the database."""
CONTRACT = "blackbox-db-v1"
INTERNAL_GATES = ("queue_dropped_zero", "pending_zero_post_drain", "enqueued_eq_persisted")

def unavailable_dimension(field):
    return {"field": field, "delta": None, "status": "UNAVAILABLE",
            "reason": "application performance collection removed"}

def audit_queue_unverified():
    return {"collected": False, "status": "UNVERIFIED", "contract": CONTRACT,
            "reason": "blackbox and database evidence cannot establish in-process best-effort queue state",
            "enqueued": None, "persisted": None, "dropped": None, "pending_in_process": None}

def unverified_gates():
    return {name: {"status": "UNVERIFIED", "value": None,
                   "reason": "in-process best-effort queue collection removed"}
            for name in INTERNAL_GATES}

def require_external_point(point):
    if point.get("collection_contract") != CONTRACT:
        raise ValueError("point must explicitly declare the blackbox-db-v1 evidence contract")
    if point.get("residency_observer"):
        raise ValueError("application pool residency collection is retired")
