import { useCallback, useEffect, useRef, useState } from 'react';
import { useI18n } from '../i18n';
import { apiFetch } from '../lib/api';
import type { RuntimeModuleListResponse, RuntimeModuleStatus } from '../pages/admin/runtimeModuleTypes';
import { actualStateLabel, moduleDomain } from '../pages/admin/runtimeModuleView';

export default function WorkerRuntimeModulesPanel() {
  const { t, locale } = useI18n();
  const zh = locale === 'zh-CN';
  const [modules, setModules] = useState<RuntimeModuleStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const request = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setRefreshing(true);
    setError('');
    try {
      const response = await apiFetch<RuntimeModuleListResponse>('/admin/runtime-modules', {
        method: 'GET', signal: controller.signal,
      });
      if (!controller.signal.aborted) setModules(response.items);
    } catch (caught) {
      if (!controller.signal.aborted) {
        setError(caught instanceof Error ? caught.message : 'Could not refresh runtime modules.');
      }
    } finally {
      if (!controller.signal.aborted) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
    return () => request.current?.abort();
  }, [refresh]);

  return (
    <section className="admin-card runtime-modules-panel" aria-labelledby="runtime-modules-title">
      <header className="admin-card-head">
        <div>
          <h2 id="runtime-modules-title">{t('admin.ui.runtimeModules')}</h2>
          <p>{zh
            ? '此部署通过部署配置管理模块；更改配置并部署后生效。'
            : 'Modules are managed through deployment configuration. Update the configuration and deploy to apply changes.'}</p>
        </div>
        <button type="button" className="btn-secondary" disabled={refreshing}
          onClick={() => void refresh()}>
          {refreshing ? (zh ? '刷新中…' : 'Refreshing…') : (zh ? '刷新模块状态' : 'Refresh runtime state')}
        </button>
      </header>
      {error && <p className="admin-feedback error" role="alert">{error}</p>}
      {loading ? <p>{t('admin.ui.loadingRuntimeModules')}</p> : (
        <div className="runtime-module-grid">
          {modules.map(module => (
            <article className="admin-card runtime-module-card" key={module.module_id}>
              <header><h3>{module.description}</h3><code>{module.module_id}</code></header>
              <dl className="admin-readonly-grid">
                <div><dt>{t('admin.ui.domainOwner')}</dt><dd>{moduleDomain(module.module_id)}</dd></div>
                <div><dt>{t('admin.ui.desired')}</dt><dd>{module.desired_state}</dd></div>
                <div><dt>{t('admin.ui.resolvedInheritedValue')}</dt><dd>{module.resolved_enabled ? 'enabled' : 'disabled'}</dd></div>
                <div><dt>{t('admin.ui.actual')}</dt><dd>{actualStateLabel(module.actual_state)}</dd></div>
                <div><dt>{t('admin.ui.revision')}</dt><dd>{module.revision}</dd></div>
                <div><dt>{t('admin.ui.failure')}</dt><dd>{module.failure_code ?? '—'}</dd></div>
              </dl>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
