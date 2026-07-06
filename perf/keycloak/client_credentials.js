import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = (__ENV.BASE_URL || 'http://keycloak:8080').replace(/\/$/, '');
const realm = __ENV.KEYCLOAK_REALM || 'perf';
const clientId = __ENV.KEYCLOAK_CLIENT_ID || 'perf-client-credentials';
const clientSecret = __ENV.KEYCLOAK_CLIENT_SECRET || 'perf-client-secret';
const duration = __ENV.PERF_DURATION || '2m';
const rate = Number(__ENV.PERF_RATE || '100');
const preAllocatedVus = Number(__ENV.PERF_PRE_ALLOCATED_VUS || '512');
const maxVus = Number(__ENV.PERF_MAX_VUS || '512');

export const options = {
  summaryTrendStats: ['min', 'avg', 'med', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    keycloak_client_credentials: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: preAllocatedVus,
      maxVUs,
      gracefulStop: '2m',
      exec: 'clientCredentials',
    },
  },
  thresholds: {
    checks: ['rate>0.99'],
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(99)<5000'],
    'http_req_duration{step:token_client_credentials}': ['p(99)<5000'],
    'http_req_failed{step:token_client_credentials}': ['rate<0.01'],
  },
};

export function clientCredentials() {
  const response = http.post(
    `${BASE_URL}/realms/${realm}/protocol/openid-connect/token`,
    {
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret,
    },
    {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      tags: { step: 'token_client_credentials', grant_type: 'client_credentials' },
    },
  );

  check(response, {
    'client_credentials status is 200': (r) => r.status === 200,
    'client_credentials access token returned': (r) => Boolean(r.json('access_token')),
  });
}
