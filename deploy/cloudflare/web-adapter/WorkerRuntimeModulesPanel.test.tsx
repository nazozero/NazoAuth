import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { apiFetch } from '../lib/api';
import WorkerRuntimeModulesPanel from './WorkerRuntimeModulesPanel';
import type { RuntimeModuleStatus } from '../pages/admin/runtimeModuleTypes';

vi.mock('../i18n', () => ({ useI18n: () => ({ locale: 'en', t: (key: string) => key }) }));
vi.mock('../lib/api', async original => ({ ...await original<typeof import('../lib/api')>(), apiFetch: vi.fn() }));
const api = vi.mocked(apiFetch);

function fixture(enabled: boolean): RuntimeModuleStatus {
  return {
    module_id: 'ciba', description: 'Client Initiated Backchannel Authentication',
    desired_state: enabled ? 'enabled' : 'disabled', resolved_enabled: enabled,
    actual_state: enabled ? 'enabled' : 'disabled', revision: enabled ? 1 : 2,
    applied_revision: null, transition_revision: null, dependencies: ['request_objects'],
    dependents: [], allowed_actions: enabled ? ['disable'] : ['enable'],
    disable_policy: 'drain_stored_transactions:300s', drain_deadline: null,
    failure_code: null, updated_at: '2026-01-01T00:00:00Z',
  };
}

describe('Worker deployment module view', () => {
  beforeEach(() => { api.mockReset(); });
  afterEach(cleanup);

  it('shows and refreshes deployed state without offering changes or requesting unavailable events', async () => {
    let enabled = true;
    api.mockImplementation(async (path, init) => {
      if (path !== '/admin/runtime-modules' || init?.method !== 'GET') {
        throw new Error(`Unexpected module operation: ${path}`);
      }
      return { items: [fixture(enabled)] };
    });
    render(<WorkerRuntimeModulesPanel />);
    const heading = await screen.findByRole('heading', { name: 'Client Initiated Backchannel Authentication' });
    const card = within(heading.closest('article')!);
    expect(card.getAllByText('enabled')).not.toHaveLength(0);
    expect(screen.getByText('Modules are managed through deployment configuration. Update the configuration and deploy to apply changes.')).toBeInTheDocument();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    expect(screen.getAllByRole('button')).toHaveLength(1);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();

    enabled = false;
    await userEvent.click(screen.getByRole('button', { name: 'Refresh runtime state' }));
    await card.findAllByText('disabled');
    expect(card.queryByText('enabled')).not.toBeInTheDocument();
    expect(api).toHaveBeenCalledTimes(2);
    for (const [path, init] of api.mock.calls) {
      expect(path).toBe('/admin/runtime-modules');
      expect(init?.method).toBe('GET');
    }
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
