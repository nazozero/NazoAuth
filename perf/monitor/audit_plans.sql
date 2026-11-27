-- PostgreSQL 18. EXPLAIN without ANALYZE does not execute either query.
-- Same projections and predicates as the fresh claim and decision reclamation functions.
EXPLAIN (FORMAT JSON)
SELECT event.event_id, NULL::bigint, event.event_type::text,
       event.event_category::text, event.payload::text, event.occurred_at,
       NULL::bytea, NULL::bytea
FROM public.security_audit_events AS event
WHERE event.exported_at IS NULL
ORDER BY event.occurred_at, event.event_id
LIMIT 256;

EXPLAIN (FORMAT JSON)
SELECT event.event_id
FROM public.security_audit_events AS event
WHERE event.event_type = 'authorization_decision_committed'
  AND event.exported_at IS NOT NULL
  AND event.business_retain_until <= CURRENT_TIMESTAMP
ORDER BY event.business_retain_until, event.event_id
LIMIT 256 FOR UPDATE SKIP LOCKED;
