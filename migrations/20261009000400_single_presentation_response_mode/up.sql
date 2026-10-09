-- A retained request is the response-mode authority. Never choose between
-- inconsistent historical copies: fail migration before removing information.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM openid4vp_transactions
             WHERE response_mode IS DISTINCT FROM request ->> 'response_mode') THEN
    RAISE EXCEPTION 'presentation response mode disagrees with retained request';
  END IF;
END $$;
ALTER TABLE openid4vp_transactions DROP COLUMN response_mode;
ALTER TABLE openid4vp_transactions ADD CONSTRAINT ck_openid4vp_request_response_mode
  CHECK (COALESCE(request ->> 'response_mode' IN ('direct_post', 'direct_post.jwt'), FALSE));
