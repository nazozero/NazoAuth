ALTER TABLE openid4vp_transactions ADD COLUMN response_mode VARCHAR(32);
UPDATE openid4vp_transactions SET response_mode = request ->> 'response_mode';
ALTER TABLE openid4vp_transactions ALTER COLUMN response_mode SET NOT NULL;
ALTER TABLE openid4vp_transactions ADD CONSTRAINT ck_openid4vp_response_mode
  CHECK (response_mode IN ('direct_post', 'direct_post.jwt'));
ALTER TABLE openid4vp_transactions DROP CONSTRAINT ck_openid4vp_request_response_mode;
