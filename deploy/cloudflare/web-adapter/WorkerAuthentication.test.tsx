import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import Auth from '../pages/Auth';
import WorkerMfaChallenge from './WorkerMfaChallenge';
import { apiFetch } from '../lib/api';

const auth = vi.hoisted(() => ({ refreshSession: vi.fn(), setUser: vi.fn(), logout: vi.fn() }));
vi.mock('../auth/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../i18n', () => ({ useI18n: () => ({ locale: 'en', t: (key: string) => key }) }));
vi.mock('../lib/api', async original => ({ ...await original<typeof import('../lib/api')>(), apiFetch: vi.fn() }));
const api = vi.mocked(apiFetch);

function page() {
  return render(<MemoryRouter initialEntries={['/auth']}><Routes>
    <Route path="/auth" element={<Auth />} /><Route path="/profile" element={<p>Authenticated profile</p>} />
  </Routes></MemoryRouter>);
}
async function password() {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText('auth.placeholder.email'), 'person@example.test');
  await user.type(screen.getByLabelText('auth.placeholder.password'), 'fixture password');
  await user.click(screen.getByRole('button', { name: 'auth.button.signIn' }));
  return user;
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }

describe('Worker login MFA transport', () => {
  beforeEach(() => {
    api.mockReset(); auth.refreshSession.mockReset(); auth.setUser.mockReset(); auth.logout.mockReset();
    auth.refreshSession.mockResolvedValue({ id: 'user', email: 'person@example.test' });
    auth.logout.mockResolvedValue(undefined);
    api.mockImplementation(async path => path === '/auth/me' ? { mfa_required: false }
      : path === '/auth/login' ? { mfa_required: true } : { success: true });
  });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

  it('keeps password login pending until the shared MFA endpoint succeeds', async () => {
    const verification = deferred<{ success: boolean }>();
    api.mockImplementation(async path => path === '/auth/me' ? { mfa_required: false }
      : path === '/auth/login' ? { mfa_required: true } : verification.promise);
    page(); const user = await password();
    await screen.findByRole('heading', { name: 'Complete two-factor verification' });
    expect(auth.refreshSession).not.toHaveBeenCalled();
    expect(auth.setUser).toHaveBeenCalledWith(null);
    await user.type(screen.getByLabelText('Authenticator or backup code'), '123456');
    await user.click(screen.getByLabelText('Remember this device'));
    await user.click(screen.getByRole('button', { name: 'Verify and continue' }));
    expect(screen.queryByText('Authenticated profile')).not.toBeInTheDocument();
    const request = api.mock.calls.find(([path]) => path === '/auth/mfa/verify')?.[1];
    expect(request?.method).toBe('POST'); expect(request?.csrf).not.toBe('defer');
    expect(JSON.parse(String(request?.body))).toEqual({ code: '123456', remember_device: true });
    await act(async () => { verification.resolve({ success: true }); });
    await screen.findByText('Authenticated profile');
    expect(auth.refreshSession).toHaveBeenCalledTimes(1);
  });

  it('preserves the Passkey finish mfa_required result', async () => {
    vi.stubGlobal('PublicKeyCredential', class { static parseRequestOptionsFromJSON(value: unknown) { return value; } });
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { get: vi.fn().mockResolvedValue({ toJSON: () => ({ id: 'fixture-passkey' }) }) } });
    api.mockImplementation(async path => path === '/auth/me' ? { mfa_required: false }
      : path === '/auth/passkey/begin' ? { ceremony_id: 'ceremony', publicKey: {} }
      : { mfa_required: true });
    page(); const user = userEvent.setup();
    await user.type(screen.getByLabelText('Sign in with a passkey'), 'person@example.test');
    await user.click(screen.getByRole('button', { name: 'Use passkey' }));
    await screen.findByRole('heading', { name: 'Complete two-factor verification' });
    expect(auth.refreshSession).not.toHaveBeenCalled();
    expect(api.mock.calls.some(([path]) => path === '/auth/passkey/finish')).toBe(true);
  });

  it('completes ordinary login only after the account refresh succeeds', async () => {
    api.mockResolvedValue({ mfa_required: false });
    page(); await password();
    await screen.findByText('Authenticated profile');
    expect(auth.refreshSession).toHaveBeenCalledTimes(1);
  });

  it('keeps an invalid MFA code on the challenge screen without authenticating', async () => {
    api.mockImplementation(async path => {
      if (path === '/auth/me') return { mfa_required: false };
      if (path === '/auth/login') return { mfa_required: true };
      throw new Error('Invalid code');
    });
    page(); const user = await password();
    await user.type(await screen.findByLabelText('Authenticator or backup code'), 'wrong-code');
    await user.click(screen.getByRole('button', { name: 'Verify and continue' }));
    await screen.findByRole('alert');
    expect(screen.getByLabelText('Authenticator or backup code')).toHaveValue('');
    expect(auth.refreshSession).not.toHaveBeenCalled();
    expect(screen.queryByText('Authenticated profile')).not.toBeInTheDocument();
  });

  it('resumes a pending session after reload and cancels it through logout', async () => {
    api.mockResolvedValue({ mfa_required: true });
    page();
    await screen.findByRole('heading', { name: 'Complete two-factor verification' });
    await userEvent.click(screen.getByRole('button', { name: 'Cancel and sign in again' }));
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Complete two-factor verification' })).not.toBeInTheDocument());
    expect(auth.logout).toHaveBeenCalledTimes(1);
    expect(auth.refreshSession).not.toHaveBeenCalled();
  });

  it('aborts the challenge request on unmount and ignores its late response', async () => {
    const response = deferred<{ success: boolean }>();
    api.mockReturnValue(response.promise);
    const verified = vi.fn();
    const view = render(<WorkerMfaChallenge onVerified={verified} onCancel={vi.fn()} />);
    await userEvent.type(screen.getByLabelText('Authenticator or backup code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify and continue' }));
    const signal = api.mock.calls[0][1]?.signal;
    view.unmount(); expect(signal?.aborted).toBe(true);
    await act(async () => { response.resolve({ success: true }); });
    expect(verified).not.toHaveBeenCalled();
  });
});
