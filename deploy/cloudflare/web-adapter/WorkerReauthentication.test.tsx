import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { AuthProvider } from '../auth/AuthContext';
import { clearSessionHint, hasSessionHint, markSessionHint } from '../auth/sessionHint';
import { ApiError, apiFetch } from '../lib/api';
import RequireAuth from './RequireAuth';
import RequireGuest from './RequireGuest';
import WorkerSecurity from './WorkerSecurity';
import Auth from '../pages/Auth';

vi.mock('../i18n', () => ({ useI18n: () => ({ locale: 'en', t: (key: string) => key }) }));
vi.mock('../lib/api', async original => ({ ...await original<typeof import('../lib/api')>(), apiFetch: vi.fn() }));
const api = vi.mocked(apiFetch);
const account = { id: 'user', email: 'person@example.test', role: 'user', admin_level: 0,
  authorized_app_count: 0, mfa_enabled: false };

function Location() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname + location.search + location.hash}</output>;
}

async function requireReauthentication(logout: () => Promise<unknown>) {
  vi.stubGlobal('PublicKeyCredential', class { static parseCreationOptionsFromJSON(value: unknown) { return value; } });
  Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create: vi.fn() } });
  api.mockImplementation(async path => {
    if (path === '/auth/me') return account;
    if (path === '/auth/me/passkeys') return { passkeys: [] };
    if (path === '/auth/logout') return logout();
    throw new ApiError('Recent authentication required', 403, { error: 'reauthentication_required' });
  });
  markSessionHint();
  render(<MemoryRouter basename="/ui" initialEntries={['/ui/profile?tab=security#passkeys']}>
    <AuthProvider><Location /><Routes>
      <Route path="/profile" element={<RequireAuth><WorkerSecurity /></RequireAuth>} />
      <Route path="/auth" element={<RequireGuest><p>Login form</p></RequireGuest>} />
    </Routes></AuthProvider>
  </MemoryRouter>);
  await screen.findByText('No passkeys added yet.');
  await userEvent.click(screen.getByRole('button', { name: 'Add passkey' }));
  await screen.findByRole('button', { name: 'Sign in again' });
  await userEvent.click(screen.getByRole('button', { name: 'Sign in again' }));
}

describe('Worker recent-authentication recovery', () => {
  beforeEach(() => { api.mockReset(); clearSessionHint(); vi.stubEnv('BASE_URL', '/ui/'); });
  afterEach(() => { cleanup(); clearSessionHint(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

  it('waits for logout before opening login and preserves the return path, query and fragment', async () => {
    let finish!: (value: unknown) => void;
    const response = new Promise(resolve => { finish = resolve; });
    await requireReauthentication(() => response);
    expect(screen.getByTestId('location')).toHaveTextContent('/profile?tab=security#passkeys');
    expect(screen.queryByText('Login form')).not.toBeInTheDocument();
    expect(hasSessionHint()).toBe(true);
    await act(async () => { finish({ success: true }); });
    await screen.findByText('Login form');
    expect(screen.getByTestId('location')).toHaveTextContent('/auth?next=%2Fprofile%3Ftab%3Dsecurity%23passkeys');
    expect(hasSessionHint()).toBe(false);
    expect(api.mock.calls.filter(([path]) => path === '/auth/logout')).toHaveLength(1);
  });

  it('keeps the current account and reports a failed logout without entering login', async () => {
    await requireReauthentication(async () => {
      throw new ApiError('Logout is temporarily unavailable', 503, null);
    });
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Logout is temporarily unavailable'));
    expect(screen.getByTestId('location')).toHaveTextContent('/profile?tab=security#passkeys');
    expect(screen.queryByText('Login form')).not.toBeInTheDocument();
    expect(hasSessionHint()).toBe(true);
  });
});

describe('OIDC fresh authentication', () => {
  beforeEach(() => { api.mockReset(); clearSessionHint(); vi.stubEnv('BASE_URL', '/ui/'); });
  afterEach(() => { cleanup(); clearSessionHint(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

  async function challenge(parameter: string, options: { mfa?: Promise<{ success: boolean }>; refreshFails?: boolean } = {}) {
    const replace = vi.fn();
    const original = window;
    vi.spyOn(original, 'scrollTo').mockImplementation(() => {});
    vi.stubGlobal('window', new Proxy(original, { get: (target, key) => key === 'location'
      ? { origin: original.location.origin, replace }
      : Reflect.get(target, key, target) }));
    let authenticated = false;
    api.mockImplementation(async path => {
      if (path === '/auth/login' || path === '/auth/passkey/finish') {
        authenticated = true;
        return { mfa_required: Boolean(options.mfa) };
      }
      if (path === '/auth/me') {
        if (authenticated && options.refreshFails) throw new ApiError('Account temporarily unavailable', 503, null);
        return { ...account, mfa_required: false };
      }
      if (path === '/auth/passkey/begin') return { ceremony_id: 'ceremony', publicKey: {} };
      if (path === '/auth/mfa/verify') return options.mfa;
      return {};
    });
    const next = `/authorize?client_id=client&${parameter}&_nazo_reauth_nonce=server-nonce`;
    markSessionHint();
    render(<MemoryRouter basename="/ui" initialEntries={['/ui/auth?next=' + encodeURIComponent(next)]}>
      <AuthProvider><RequireGuest><Auth /></RequireGuest></AuthProvider>
    </MemoryRouter>);
    await screen.findByRole('button', { name: 'auth.button.signIn' });
    expect(replace).not.toHaveBeenCalled();
    return { replace, next, user: userEvent.setup() };
  }

  async function password(user: ReturnType<typeof userEvent.setup>) {
    await user.type(screen.getByLabelText('auth.placeholder.email'), 'person@example.test');
    await user.type(screen.getByLabelText('auth.placeholder.password'), 'fixture password');
    await user.click(screen.getByRole('button', { name: 'auth.button.signIn' }));
  }

  it('keeps an existing session on the prompt=login form until a new password login completes', async () => {
    const { replace, next, user } = await challenge('prompt=login');
    await password(user);
    await waitFor(() => expect(replace).toHaveBeenCalledExactlyOnceWith(next));
    expect(api.mock.calls.filter(([path]) => path === '/auth/login')).toHaveLength(1);
  });

  it('returns max_age=0 to the server only after a fresh Passkey login completes', async () => {
    vi.stubGlobal('PublicKeyCredential', class { static parseRequestOptionsFromJSON(value: unknown) { return value; } });
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn().mockResolvedValue({ toJSON: () => ({ id: 'fixture-passkey' }) }) } });
    const { replace, next, user } = await challenge('max_age=0');
    await user.type(screen.getByLabelText('Sign in with a passkey'), 'person@example.test');
    await user.click(screen.getByRole('button', { name: 'Use passkey' }));
    await waitFor(() => expect(replace).toHaveBeenCalledExactlyOnceWith(next));
    expect(api.mock.calls.some(([path]) => path === '/auth/passkey/finish')).toBe(true);
  });

  it('waits for fresh MFA verification before returning the authorization nonce', async () => {
    let finish!: (value: { success: boolean }) => void;
    const mfa = new Promise<{ success: boolean }>(resolve => { finish = resolve; });
    const { replace, next, user } = await challenge('prompt=login', { mfa });
    await password(user);
    await user.type(await screen.findByLabelText('Authenticator or backup code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Verify and continue' }));
    expect(replace).not.toHaveBeenCalled();
    await act(async () => { finish({ success: true }); });
    await waitFor(() => expect(replace).toHaveBeenCalledExactlyOnceWith(next));
  });

  it('keeps the form and reports failed account confirmation after credential verification', async () => {
    const { replace, user } = await challenge('prompt=login', { refreshFails: true });
    await password(user);
    await waitFor(() => expect(screen.getByText('auth.error.login')).toBeVisible());
    expect(screen.getByRole('button', { name: 'auth.button.signIn' })).toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
  });
});
