-- The approval transaction commits this UUID with its Required audit event.
-- Acknowledging delivery may reclaim the event, never the business receipt.
ALTER TABLE public.client_access_requests
    DROP CONSTRAINT client_access_requests_required_approval_event_id_fkey;
DROP INDEX public.ix_access_request_required_approval_event;
DROP FUNCTION public.nazo_access_request_required_approval_matches(uuid,uuid,uuid,uuid,text,text);
COMMENT ON COLUMN public.client_access_requests.required_approval_event_id IS
    'Required approval commit marker and external audit correlation; retained with the approval after audit delivery reclaims the event.';
