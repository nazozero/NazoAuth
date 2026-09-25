// Subject-token lifecycle for cap_* scenarios.
//
// A VU's subject access token (subjectAt) must track the token the real
// OAuth client would hold: a successful refresh response carries a fresh
// access_token, so the subject token is updated in place instead of
// ageing into a needless full authorization-code re-bootstrap at the
// 240s guardrail. The three low-cardinality counters below let a report
// separate fixture-establishment (initial_mint), refresh-driven renewal
// (refresh_update) and full auth-code re-bootstrap (expired_reauth).
//
// Pure state transitions are kept importable so subject_state_test.js
// can drive them under real k6 without any HTTP dependency.
import { Counter } from 'k6/metrics';

export const SUBJECT_KINDS = [
  'initial_mint',
  'refresh_update',
  'expired_reauth',
];

export const subjectCounters = {
  initial_mint: new Counter('cap_subject_initial_mint'),
  refresh_update: new Counter('cap_subject_refresh_update'),
  expired_reauth: new Counter('cap_subject_expired_reauth'),
};

// Classify a capMintSubjectTokens invocation BEFORE it mutates state:
//   initial_mint    no subjectAt exists — first establishment
//   expired_reauth  subjectAt exists but aged past maxAgeMs, or a forced
//                   re-bootstrap (lost refresh family) — both walk the
//                   full authorization-code flow, which is the load this
//                   counter exists to expose
//   fresh           subjectAt usable — caller must skip the mint
export function classifyMint(state, nowMs, maxAgeMs) {
  if (!state.subjectAt) {
    return 'initial_mint';
  }
  if (nowMs - (state.subjectAtMintedAt || 0) >= maxAgeMs) {
    return 'expired_reauth';
  }
  return 'fresh';
}

// Adopt the access_token of a successful refresh response as the
// subject's current resource token. Returns true only when the state
// actually changed — a refresh response without access_token must never
// fabricate or retimestamp subjectAt.
export function adoptSubjectAccessToken(state, accessToken, nowMs) {
  if (!accessToken) {
    return false;
  }
  state.subjectAt = accessToken;
  state.subjectAtMintedAt = nowMs;
  return true;
}
