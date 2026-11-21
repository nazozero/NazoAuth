import { cpSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const adapters = dirname(fileURLToPath(import.meta.url));

function replaceOnce(source, before, after, contract) {
  if (source.split(before).length !== 2) throw new Error(`NazoAuthWeb adapter contract changed: ${contract}`);
  return source.replace(before, after);
}

// Only the pinned build checkout is patched. The upstream application remains
// independently versioned; an unexpected source change fails the build.
export function applyWorkerOverlay(work) {
  for (const name of ['WorkerPasskey.tsx', 'WorkerMfaChallenge.tsx', 'WorkerSecurity.tsx', 'WorkerSecurity.css',
    'WorkerAuthentication.test.tsx', 'WorkerPendingSession.test.tsx', 'WorkerSecurity.test.tsx',
    'WorkerGrantHistory.test.tsx']) {
    cpSync(resolve(adapters, name), resolve(work, 'src/components', name));
  }
  const authPath = resolve(work, 'src/pages/Auth.tsx');
  let auth = readFileSync(authPath, 'utf8');
  const authPatch = (before, after, name) => { auth = replaceOnce(auth, before, after, name); };
  authPatch('useEffect, useMemo, useState, type FormEvent', 'useEffect, useMemo, useRef, useState, type FormEvent', 'auth hooks');
  authPatch("import './Auth.css';", "import WorkerPasskey, { type WorkerLoginResult } from '../components/WorkerPasskey';\nimport WorkerMfaChallenge from '../components/WorkerMfaChallenge';\nimport '../components/WorkerSecurity.css';\nimport './Auth.css';", 'auth components');
  authPatch('const { refreshSession } = useAuth();', 'const { refreshSession, setUser, logout } = useAuth();', 'auth context');
  authPatch("const [authState, setAuthState] = useState<AuthState>('login');", `const [authState, setAuthState] = useState<AuthState>('login');
  const [mfaPending, setMfaPending] = useState(false);
  const pendingCheck = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    pendingCheck.current = controller;
    void apiFetch<{ mfa_required?: boolean }>('/auth/me', { signal: controller.signal }).then(result => {
      if (!controller.signal.aborted && result.mfa_required === true) {
        setUser(null);
        setMfaPending(true);
      }
    }).catch(() => { /* Anonymous sign-in does not require an existing session. */ });
    return () => controller.abort();
  }, [setUser]);`, 'pending session probe');
  authPatch('  const performAction = async (action: AuthAction) => {', `  const completeLogin = async (result: WorkerLoginResult) => {
    pendingCheck.current?.abort();
    setPassword('');
    if (typeof result.mfa_required !== 'boolean') throw new Error(t('auth.error.login'));
    if (result.mfa_required) {
      setUser(null);
      setMfaPending(true);
      return;
    }
    const account = await refreshSession();
    if (!account) throw new Error(t('auth.error.login'));
  };

  const performAction = async (action: AuthAction) => {
    if (action === 'login') pendingCheck.current?.abort();`, 'login completion');
  authPatch('      await apiFetch<{ session_id: string; expires_in: number }>(', '      const result = await apiFetch<WorkerLoginResult>(', 'password result');
  authPatch(`      await refreshSession();
      if (nextAfterLogin) {
        window.location.href = nextAfterLogin;
        return;
      }
      setSuccessMsg(t('auth.success.signedIn'));
      navigate('/profile', { replace: true });`, '      await completeLogin(result);', 'password MFA dispatch');
  authPatch('            <div className="auth-form-wrapper">', `            {mfaPending ? (
              <WorkerMfaChallenge onVerified={() => completeLogin({ mfa_required: false })}
                onCancel={async () => { await logout(); setMfaPending(false); }} />
            ) : authState === 'login' && (
              <WorkerPasskey onSignedIn={completeLogin} disabled={submitting}
                onBusyChange={busy => { if (busy) pendingCheck.current?.abort(); setSubmitting(busy); }} />
            )}
            <div className="auth-form-wrapper" hidden={mfaPending} style={mfaPending ? { display: 'none' } : undefined}>`, 'auth MFA view');
  authPatch('<div className="auth-footer">', '<div className="auth-footer" hidden={mfaPending} style={mfaPending ? { display: \'none\' } : undefined}>', 'auth MFA footer');
  writeFileSync(authPath, auth);

  // The guest guard owns navigation for both new and existing sessions. Web
  // routes go through the router basename; /authorize is a Worker endpoint.
  const guestPath = resolve(work, 'src/components/RequireGuest.tsx');
  let guest = readFileSync(guestPath, 'utf8');
  guest = replaceOnce(guest, '  const location = useLocation();', `  const location = useLocation();
  const next = resolveSafeNextFromSearch(location.search);
  const nextPath = next?.split(/[?#]/, 1)[0];
  const authorizationNext = nextPath === '/authorize' ? next : null;
  useEffect(() => {
    if (user && !loading && authorizationNext) window.location.replace(authorizationNext);
  }, [user, loading, authorizationNext]);`, 'authorization endpoint return');
  guest = replaceOnce(guest, `    const next = resolveSafeNextFromSearch(location.search);
    return <Navigate to={next ?? '/profile'} replace />;`, `    if (authorizationNext) return null;
    const base = import.meta.env.BASE_URL.replace(/\\/$/, '');
    const hasBase = nextPath === base || nextPath?.startsWith(base + '/');
    const relative = hasBase ? next!.slice(base.length) : next;
    const target = relative?.startsWith('/') ? relative : '/' + (relative ?? '');
    const targetPath = target.split(/[?#]/, 1)[0].replace(/\\/+$/, '').toLowerCase();
    const returnTo = next && !target.startsWith('//') && targetPath !== '/auth' ? target : '/profile';
    return <Navigate to={returnTo} replace />;`, 'basename-aware Web return');
  writeFileSync(guestPath, guest);

  const contextPath = resolve(work, 'src/auth/AuthContext.tsx');
  let context = readFileSync(contextPath, 'utf8');
  context = replaceOnce(context, '        setUserState(me);', `        if (me.mfa_required === true) {
          setUserState(null);
          clearSessionHint();
          setSessionChecked(true);
          return null;
        }
        setUserState(me);`, 'pending MFA cannot become an authenticated user');
  writeFileSync(contextPath, context);

  const typesPath = resolve(work, 'src/types/auth.ts');
  let types = readFileSync(typesPath, 'utf8');
  types = replaceOnce(types, 'export interface AuthUser {', 'export interface AuthUser {\n  mfa_enabled?: boolean;\n  mfa_required?: boolean;', 'account MFA fields');
  for (const name of ['AuthorizedApp', 'AdminGrantItem']) {
    const start = types.indexOf(`export interface ${name} {`);
    const end = types.indexOf('\n}', start);
    if (start < 0 || end < 0) throw new Error(`NazoAuthWeb adapter contract changed: ${name} history fields`);
    const original = types.slice(start, end);
    let replacement = replaceOnce(original, 'last_authorized_at: string;', 'last_authorized_at: string | null;', `${name} last authorization`);
    replacement = replaceOnce(replacement, 'authorization_count: number;', 'authorization_count: number | null;', `${name} authorization count`);
    types = replaceOnce(types, original, replacement, `${name} history contract`);
  }
  writeFileSync(typesPath, types);

  const profilePath = resolve(work, 'src/pages/Profile.tsx');
  let profile = readFileSync(profilePath, 'utf8');
  profile = replaceOnce(profile, "import './Profile.css';", "import WorkerSecurity from '../components/WorkerSecurity';\nimport './Profile.css';", 'profile security component');
  profile = replaceOnce(profile, `              </form>
            </motion.section>
          )}

          {activeTab === 'apps'`, `              </form>
              <WorkerSecurity />
            </motion.section>
          )}

          {activeTab === 'apps'`, 'profile security placement');
  profile = replaceOnce(profile, '  const { t } = useI18n();', `  const { t, locale } = useI18n();
  const historyUnavailable = locale === 'zh-CN' ? '历史未记录' : 'History unavailable';`, 'profile history language');
  profile = replaceOnce(profile, '  const [loadingApps, setLoadingApps] = useState(false);', `  const [loadingApps, setLoadingApps] = useState(false);
  const [appsErrorMsg, setAppsErrorMsg] = useState('');`, 'authorized-app read error state');
  profile = replaceOnce(profile, `    const setError = activeTab === 'apps' ? setProfileErrorMsg : setRequestErrorMsg;
    setLoading(true);`, `    const setError = activeTab === 'apps' ? setAppsErrorMsg : setRequestErrorMsg;
    setError('');
    setLoading(true);`, 'authorized-app read error owner');
  profile = replaceOnce(profile, '                ) : apps.length === 0 ? (', `                ) : appsErrorMsg ? (
                  <motion.div key="apps-error" className="profile-feedback error" role="alert">
                    {appsErrorMsg}
                  </motion.div>
                ) : apps.length === 0 ? (`, 'authorized-app failure is not an empty list');
  profile = replaceOnce(profile, "{item.authorization_count} {t('account.ui.times')}", "{item.authorization_count === null ? historyUnavailable : <>{item.authorization_count} {t('account.ui.times')}</>}", 'authorized-app unknown count');
  profile = replaceOnce(profile, '{formatDateTime(item.last_authorized_at)}', '{item.last_authorized_at === null ? historyUnavailable : formatDateTime(item.last_authorized_at)}', 'authorized-app unknown time');
  writeFileSync(profilePath, profile);

  const grantsPath = resolve(work, 'src/pages/admin/GrantsPanel.tsx');
  let grants = readFileSync(grantsPath, 'utf8');
  grants = replaceOnce(grants, '  const { t } = useI18n();', `  const { t, locale } = useI18n();
  const historyUnavailable = locale === 'zh-CN' ? '历史未记录' : 'History unavailable';`, 'admin grant history language');
  grants = replaceOnce(grants, '  const [loading, setLoading] = useState(true);', `  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);`, 'admin grant read error state');
  grants = replaceOnce(grants, '      setLoading(true);', `      setLoading(true);
      setLoadError(false);
      setFeedback(current => current?.error ? null : current);`, 'admin grant reload resets read failure');
  grants = replaceOnce(grants, `        if (controller.signal.aborted) return;
        setFeedback({`, `        if (controller.signal.aborted) return;
        setLoadError(true);
        setFeedback({`, 'admin grant read failure owner');
  grants = replaceOnce(grants, '      ) : items.length === 0 ? (', '      ) : loadError ? null : items.length === 0 ? (', 'admin grant failure is not an empty list');
  grants = replaceOnce(grants, `                    {new Date(item.last_authorized_at).toLocaleString('zh-CN', {
                      hour12: false,
                    })}`, `                    {item.last_authorized_at === null ? historyUnavailable : new Date(item.last_authorized_at).toLocaleString(locale, {
                      hour12: false,
                    })}`, 'admin grant unknown time');
  writeFileSync(grantsPath, grants);

  // Keep the Web application's existing CAS, MFA, review and polling workflow.
  // Actual state is instance-scoped in the shared lifecycle on both hosts.
  const modulesPath = resolve(work, 'src/pages/admin/RuntimeModulesPanel.tsx');
  let modules = replaceOnce(readFileSync(modulesPath, 'utf8'),
    '  const { t } = useI18n();', '  const { t, locale } = useI18n();',
    'runtime module locale');
  modules = replaceOnce(modules,
    "              'admin.ui.desiredIntentAndObservedRuntimeStateAreShownSeparately'\n            )}\n          </p>",
    "              'admin.ui.desiredIntentAndObservedRuntimeStateAreShownSeparately'\n            )}\n          </p>\n          <p>{locale === 'zh-CN'\n            ? '运行状态来自处理本次请求的实例。停用期间，新请求停止接入，已有事务按排空期限完成。'\n            : 'Runtime state belongs to the instance handling this request. Disabling stops new admissions while existing transactions finish within their drain window.'}</p>",
    'instance-scoped runtime status');
  writeFileSync(modulesPath, modules);

  const homePath = resolve(work, 'src/pages/Home.tsx');
  let home = readFileSync(homePath, 'utf8');
  home = replaceOnce(home,
    '核心通过独立接口连接持久存储与短期状态实现。一个部署可承载多个租户与域名，各自拥有明确的 issuer、账户和安全边界。',
    '当前 Cloudflare Workers 部署运行一个 issuer 和租户，账户、应用及协议服务均归属此安全边界。管理员可在已部署的能力范围内管理模块启停。',
    'Worker single-issuer deployment description (Chinese)');
  home = replaceOnce(home,
    'Independent interfaces connect the core to persistence and transient-state implementations. One deployment can serve multiple tenants and domains, each with its own issuer, accounts, and security boundary.',
    'This Cloudflare Workers deployment serves one issuer and tenant. Accounts, applications, and protocol services share that security boundary. Administrators can manage runtime modules within the deployed capabilities.',
    'Worker single-issuer deployment description (English)');
  home = replaceOnce(home,
    `<span>Docker</span>
            <span>Podman</span>
            <span>{zh ? '主机部署' : 'Host runtime'}</span>`,
    `<span>Cloudflare Workers</span>
            <span>D1</span>
            <span>{zh ? '单 issuer' : 'One issuer'}</span>`,
    'Worker deployment runtime labels');
  writeFileSync(homePath, home);
}
