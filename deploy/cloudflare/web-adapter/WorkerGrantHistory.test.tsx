import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { apiFetch } from '../lib/api';
import Profile from '../pages/Profile';
import GrantsPanel from '../pages/admin/GrantsPanel';

const state = vi.hoisted(() => ({ locale: 'en' }));
const auth = vi.hoisted(() => ({
  user: { id: 'user', email: 'person@example.test', display_name: null, avatar_url: null, role: 'user', admin_level: 0, authorized_app_count: 1 },
  setUser: vi.fn(), logout: vi.fn(),
}));
vi.mock('../i18n', () => ({ useI18n: () => ({ locale: state.locale, t: (key: string) => key }) }));
vi.mock('../auth/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../lib/api', async original => ({ ...await original<typeof import('../lib/api')>(), apiFetch: vi.fn() }));
const api = vi.mocked(apiFetch);
const grant = {
  user_id: 'user', email: 'person@example.test', client_id: 'client', client_name: 'Existing application',
  last_authorized_at: null, authorization_count: null, last_scopes: ['openid'],
};

describe('Worker authorization history', () => {
  beforeEach(() => {
    api.mockReset(); state.locale = 'en';
    api.mockImplementation(async path => {
      if (path === '/auth/me/avatar/uploads') return { upload_mode: 'multipart' };
      if (path === '/auth/me/applications' || path.startsWith('/admin/grants?')) {
        return { total: 1, page: 1, page_size: 20, items: [grant] };
      }
      throw new Error(`Unexpected endpoint: ${path}`);
    });
  });
  afterEach(cleanup);

  it('shows unknown application history without inventing a date or count', async () => {
    render(<MemoryRouter initialEntries={['/profile?tab=apps']}><Profile /></MemoryRouter>);
    await screen.findByText('Existing application');
    expect(screen.getAllByText(/History unavailable/)).toHaveLength(2);
    expect(screen.queryByText(/1970/)).not.toBeInTheDocument();
    expect(screen.queryByText('profile.emptyApps')).not.toBeInTheDocument();
  });

  it('keeps authorized-app read failure distinct from an empty application list', async () => {
    api.mockImplementation(async path => {
      if (path === '/auth/me/avatar/uploads') return { upload_mode: 'multipart' };
      throw new Error('Application history is temporarily unavailable.');
    });
    render(<MemoryRouter initialEntries={['/profile?tab=apps']}><Profile /></MemoryRouter>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Application history is temporarily unavailable.');
    expect(screen.queryByText('profile.emptyApps')).not.toBeInTheDocument();
  });

  it('shows unknown administrator grant history in the selected language', async () => {
    state.locale = 'zh-CN';
    render(<GrantsPanel />);
    await screen.findByText('Existing application');
    expect(screen.getByText(/历史未记录/)).toBeInTheDocument();
    expect(screen.queryByText(/1970/)).not.toBeInTheDocument();
  });

  it('does not show no-grants after the administrator list fails to load', async () => {
    api.mockRejectedValue(new Error('Grant history is temporarily unavailable.'));
    render(<GrantsPanel />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Grant history is temporarily unavailable.');
    expect(screen.queryByText('admin.ui.noGrantsFound')).not.toBeInTheDocument();
  });
});
