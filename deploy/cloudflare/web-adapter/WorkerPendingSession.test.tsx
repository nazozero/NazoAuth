import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { AuthProvider } from '../auth/AuthContext';
import { useAuth } from '../auth/useAuth';
import { clearSessionHint, hasSessionHint } from '../auth/sessionHint';
import { apiFetch } from '../lib/api';

vi.mock('../lib/api', async original => ({ ...await original<typeof import('../lib/api')>(), apiFetch: vi.fn() }));

it('never promotes the pending-MFA profile projection into an authenticated account', async () => {
  clearSessionHint();
  vi.mocked(apiFetch).mockResolvedValue({ id: 'user', email: 'person@example.test', mfa_required: true });
  const { result } = renderHook(useAuth, { wrapper: AuthProvider });
  let refreshed: unknown;
  await act(async () => { refreshed = await result.current.refreshSession(); });
  expect(refreshed).toBeNull(); expect(result.current.user).toBeNull();
  expect(result.current.sessionChecked).toBe(true); expect(result.current.loading).toBe(false);
  expect(hasSessionHint()).toBe(false);
});
