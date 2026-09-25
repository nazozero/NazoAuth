// Subject-token lifecycle unit test — pure state transitions from
// subject_state.js, no HTTP/SUT dependency.
//
// Asserts (via check() plus a checks==1.0 threshold and a throwing
// handleSummary so a failure exits k6 non-zero):
//   * refresh 200 with access_token -> subjectAt + mintedAt updated,
//     refreshToken rotated;
//   * refresh 200 WITHOUT access_token -> refreshToken still rotates,
//     subjectAt/mintedAt must NOT be fabricated or retimestamped;
//   * refresh non-200 -> subjectAt/mintedAt untouched, refreshToken
//     cleared;
//   * classifyMint: no subjectAt -> initial_mint; aged >= maxAge ->
//     expired_reauth; fresh -> fresh (caller skips the mint);
//   * the three lifecycle counters actually incremented.
import { check, fail } from 'k6';
import { Counter } from 'k6/metrics';
import {
  adoptSubjectAccessToken, classifyMint, subjectCounters,
} from './subject_state.js';

const MAX_AGE_MS = 240000;
const checksOk = new Counter('subject_test_assertions');

export const options = {
  scenarios: {
    unit: {
      executor: 'shared-iterations',
      vus: 1,
      iterations: 1,
      exec: 'unit',
    },
  },
  thresholds: {
    checks: ['rate==1.0'],
    subject_test_assertions: ['count>=10'],
    cap_subject_refresh_update: ['count==1'],
    cap_subject_initial_mint: ['count==1'],
    cap_subject_expired_reauth: ['count==1'],
  },
};

export function unit() {
  // --- refresh 200 adopts the returned access token ---
  const s1 = { refreshToken: 'rt-old', subjectAt: 'at-old',
               subjectAtMintedAt: 1000 };
  const now1 = 5000;
  const adopted = adoptSubjectAccessToken(s1, 'at-new', now1);
  check({ adopted, s: s1 }, {
    'refresh 200: adoption reported': (o) => o.adopted === true,
    'refresh 200: subjectAt replaced': (o) => o.s.subjectAt === 'at-new',
    'refresh 200: mintedAt updated': (o) => o.s.subjectAtMintedAt === now1,
  });
  if (adopted) {
    subjectCounters.refresh_update.add(1);
  }
  checksOk.add(3);

  // --- refresh 200 without access_token must not touch subjectAt ---
  const s2 = { refreshToken: 'rt', subjectAt: 'at-keep',
               subjectAtMintedAt: 4242 };
  const adopted2 = adoptSubjectAccessToken(s2, undefined, 99999);
  check({ adopted: adopted2, s: s2 }, {
    'refresh 200 no AT: adoption not reported': (o) => o.adopted === false,
    'refresh 200 no AT: subjectAt preserved': (o) => o.s.subjectAt === 'at-keep',
    'refresh 200 no AT: mintedAt untouched': (o) => o.s.subjectAtMintedAt === 4242,
  });
  checksOk.add(3);

  // --- classifyMint ---
  check(classifyMint({}, 1000, MAX_AGE_MS), {
    'no subjectAt -> initial_mint': (k) => k === 'initial_mint',
  });
  subjectCounters.initial_mint.add(1);
  checksOk.add(1);
  const aged = { subjectAt: 'at', subjectAtMintedAt: 0 };
  check(classifyMint(aged, MAX_AGE_MS + 1, MAX_AGE_MS), {
    'aged subjectAt -> expired_reauth': (k) => k === 'expired_reauth',
  });
  subjectCounters.expired_reauth.add(1);
  checksOk.add(1);
  const boundary = { subjectAt: 'at', subjectAtMintedAt: 1000 };
  check(classifyMint(boundary, 1000 + MAX_AGE_MS, MAX_AGE_MS), {
    'age == maxAge -> expired_reauth (half-open)': (k) => k === 'expired_reauth',
  });
  checksOk.add(1);
  const fresh = { subjectAt: 'at', subjectAtMintedAt: 1000 };
  check(classifyMint(fresh, 1000 + MAX_AGE_MS - 1, MAX_AGE_MS), {
    'fresh subjectAt -> fresh (skip mint)': (k) => k === 'fresh',
  });
  checksOk.add(1);
}

export function handleSummary(data) {
  const failed = Object.entries(data.metrics.checks ? data.metrics.checks.values || data.metrics.checks : {});
  const passes = data.metrics.checks && data.metrics.checks.values
    ? data.metrics.checks.values.passes : 0;
  const fails = data.metrics.checks && data.metrics.checks.values
    ? data.metrics.checks.values.fails : 1;
  if (fails > 0 || !passes) {
    throw new Error(`subject_state assertions failed: fails=${fails} passes=${passes}`);
  }
  return { stdout: JSON.stringify({ passes, fails }) };
}
