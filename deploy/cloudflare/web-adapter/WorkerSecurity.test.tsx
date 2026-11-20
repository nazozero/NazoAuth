import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import WorkerSecurity from './WorkerSecurity';
import { apiFetch } from '../lib/api';

const auth = vi.hoisted(() => ({ user: { mfa_enabled: false }, refreshSession: vi.fn() }));
vi.mock('../auth/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../i18n', () => ({ useI18n: () => ({ locale: 'en' }) }));
vi.mock('../lib/api', async original => ({ ...await original<typeof import('../lib/api')>(), apiFetch: vi.fn() }));
const api = vi.mocked(apiFetch);

describe('Worker account security transport', () => {
  beforeEach(() => { api.mockReset(); auth.user = { mfa_enabled: false }; auth.refreshSession.mockReset(); });
  afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

  it('registers through WebAuthn and removes only the explicitly confirmed passkey', async () => {
    vi.stubGlobal('PublicKeyCredential', class { static parseCreationOptionsFromJSON(value: unknown) { return value; } });
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: { create: vi.fn().mockResolvedValue({ toJSON: () => ({ id: 'fixture-passkey' }) }) } });
    let stored = false;
    api.mockImplementation(async (path, init) => {
      if (path === '/auth/me/passkeys') return { passkeys: stored ? [{ id: 'record-id', label: 'Phone', created_at: '2026-01-01T00:00:00Z' }] : [] };
      if (path === '/auth/me/passkeys/registration/begin') return { ceremony_id: 'ceremony', publicKey: {} };
      if (path === '/auth/me/passkeys/registration/finish') { stored = true; return {}; }
      if (path === '/auth/me/passkeys/record-id' && init?.method === 'DELETE') { stored = false; return null; }
      throw new Error(`Unexpected endpoint: ${path}`);
    });
    render(<MemoryRouter><WorkerSecurity /></MemoryRouter>);
    await screen.findByText('No passkeys added yet.');
    await userEvent.type(screen.getByLabelText('Passkey name (optional)'), 'Phone');
    await userEvent.click(screen.getByRole('button', { name: 'Add passkey' }));
    await screen.findByText('Phone');
    const finish = api.mock.calls.find(([path]) => path === '/auth/me/passkeys/registration/finish')?.[1];
    expect(finish?.method).toBe('POST'); expect(finish?.csrf).not.toBe('defer');
    expect(JSON.parse(String(finish?.body))).toEqual({ ceremony_id: 'ceremony', response: { id: 'fixture-passkey' } });
    await userEvent.click(screen.getByRole('button', { name: 'Remove Phone' }));
    expect(api.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);
    await userEvent.click(screen.getByRole('button', { name: 'Confirm removal' }));
    await screen.findByText('No passkeys added yet.');
  });

  it('shows setup and one-time backup codes only after successful shared endpoint responses', async () => {
    api.mockImplementation(async path => {
      if (path === '/auth/me/passkeys') return { passkeys: [] };
      if (path === '/auth/me/mfa/totp/begin') return { secret_base32: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/fixture', digits: 6, period: 30 };
      if (path === '/auth/me/mfa/totp/confirm') return { mfa_enabled: true, backup_codes: ['ABCD-EFGH', 'IJKL-MNOP'] };
      throw new Error(`Unexpected endpoint: ${path}`);
    });
    auth.refreshSession.mockImplementation(async () => { auth.user = { mfa_enabled: true }; return auth.user; });
    render(<MemoryRouter><WorkerSecurity /></MemoryRouter>);
    await userEvent.click(screen.getByRole('button', { name: 'Set up authenticator' }));
    await screen.findByLabelText('Authenticator setup key');
    expect(screen.queryByLabelText('Backup codes')).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Enter the 6-digit authenticator code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm and enable' }));
    await screen.findByText('ABCD-EFGH');
    expect(screen.queryByLabelText('Authenticator setup key')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'I saved them. Hide codes.' }));
    expect(screen.queryByText('ABCD-EFGH')).not.toBeInTheDocument();
    expect(auth.refreshSession).toHaveBeenCalledTimes(1);
  });
});
