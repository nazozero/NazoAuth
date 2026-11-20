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
    'WorkerRuntimeModulesPanel.tsx', 'WorkerRuntimeModulesPanel.test.tsx']) {
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
    if (nextAfterLogin) window.location.assign(nextAfterLogin);
    else navigate('/profile', { replace: true });
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
  writeFileSync(profilePath, profile);

  const adminPath = resolve(work, 'src/pages/admin/AdminPage.tsx');
  const admin = replaceOnce(readFileSync(adminPath, 'utf8'),
    "import RuntimeModulesPanel from './RuntimeModulesPanel';",
    "import RuntimeModulesPanel from '../../components/WorkerRuntimeModulesPanel';",
    'deployment-managed module view');
  writeFileSync(adminPath, admin);
}
