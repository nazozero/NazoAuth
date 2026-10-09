DROP FUNCTION public.nazo_access_request_required_approval_matches(uuid,uuid,uuid,uuid,text,text);
DROP INDEX public.ix_access_request_required_approval_event;
ALTER TABLE public.client_access_requests DROP COLUMN required_approval_event_id;
