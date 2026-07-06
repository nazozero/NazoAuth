import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = (__ENV.BASE_URL || 'http://localhost:8080').replace(/\/$/, '');
const TOKEN_PATH = __ENV.TOKEN_PATH || '/oauth2/token';
const clientId = __ENV.OAUTH_CLIENT_ID || 'perf-client-credentials';
const clientSecret = __ENV.OAUTH_CLIENT_SECRET || 'perf-client-secret';
const scope = __ENV.OAUTH_SCOPE || 'profile';
const duration = __ENV.PERF_DURATION || '2m';
const rate = Number(__ENV.PERF_RATE || '100');
const preAllocatedVus = Number(__ENV.PERF_PRE_ALLOCATED_VUS || '512');
const maxVus = Number(__ENV.PERF_MAX_VUS || '512');

export const options = {
  summaryTrendStats: ['min', 'avg', 'med', 'p(50)', 'p(90)', 'p(95)', 'p(99)', 'max'],
  scenarios: {
    oauth_client_credentials: {
      executor: 'constant-arrival-rate',
      rate,
      timeUnit: '1s',
      duration,
      preAllocatedVUs: preAllocatedVus,
      maxVUs: maxVus,
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
    `${BASE_URL}${TOKEN_PATH}`,
    {
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret,
      scope,
    },
    {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      tags: { step: 'token_client_credentials', grant_type: 'client_credentials' },
    },
  );

  check(response, {
    'client_credentials status is 200': (r) => r.status === 200,
    'client_credentials access token returned': (r) => {
      if (r.status !== 200 || !r.body) {
        return false;
      }
      try {
        return Boolean(r.json('access_token'));
      } catch (_) {
        return false;
      }
    },
  });
}
