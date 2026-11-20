import { useEffect, useRef, useState } from 'react';
import { Fingerprint } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useI18n } from '../i18n';

type Begin = { ceremony_id: string; publicKey: PublicKeyCredentialRequestOptionsJSON };
export type WorkerLoginResult = { mfa_required: boolean };

// This is a browser transport adapter. The existing server endpoints own the
// ceremony, origin/RP binding, signature verification and session creation.
export default function WorkerPasskey({ onSignedIn, disabled = false, onBusyChange }: {
  onSignedIn: (result: WorkerLoginResult) => Promise<void>;
  disabled?: boolean;
  onBusyChange?: (busy: boolean) => void;
}) {
  const { locale } = useI18n();
  const zh = locale === 'zh-CN';
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const pending = useRef<AbortController | null>(null);
  useEffect(() => () => pending.current?.abort(), []);

  const signIn = async () => {
    if (pending.current || disabled) return;
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    onBusyChange?.(true);
    setMessage('');
    try {
      if (!window.PublicKeyCredential || !navigator.credentials ||
          typeof PublicKeyCredential.parseRequestOptionsFromJSON !== 'function') {
        throw new Error(zh ? '请使用支持 Passkey 的新版浏览器。' : 'Use a current browser with passkey support.');
      }
      const normalized = email.trim();
      if (!normalized) throw new Error(zh ? '请输入账号邮箱。' : 'Enter your account email.');
      const post = <T,>(path: string, value: unknown) => apiFetch<T>(path, {
        method: 'POST', csrf: 'defer', signal: controller.signal,
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value),
      });
      const begin = await post<Begin>('/auth/passkey/begin', { email: normalized });
      const credential = await navigator.credentials.get({
        publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(begin.publicKey),
        signal: controller.signal,
      }) as PublicKeyCredential | null;
      if (!credential) throw new Error(zh ? '没有选择 Passkey。' : 'No passkey was selected.');
      const result = await post<WorkerLoginResult>('/auth/passkey/finish', { ceremony_id: begin.ceremony_id, response: credential.toJSON() });
      if (typeof result?.mfa_required !== 'boolean') throw new Error(zh ? '登录响应无效，请重试。' : 'Invalid sign-in response. Try again.');
      if (!controller.signal.aborted) await onSignedIn(result);
    } catch (error) {
      if (!controller.signal.aborted) setMessage(error instanceof Error ? error.message : (zh ? '登录失败。' : 'Sign-in failed.'));
    } finally {
      if (pending.current === controller) pending.current = null;
      onBusyChange?.(false);
      if (!controller.signal.aborted) setBusy(false);
    }
  };
  return (
    <section aria-label="Passkey" style={{ marginBottom: 24 }}>
      <label className="auth-input-label" htmlFor="nazo-passkey-email">{zh ? '使用 Passkey 登录' : 'Sign in with a passkey'}</label>
      <input id="nazo-passkey-email" type="email" autoComplete="username webauthn" className="glass-input"
        placeholder={zh ? '账号邮箱' : 'Account email'} value={email} disabled={busy || disabled}
        onChange={event => setEmail(event.target.value)} />
      <button type="button" className="btn-primary w-full mt-4" disabled={busy || disabled} onClick={() => void signIn()}>
        <Fingerprint size={18} /><span>{busy ? (zh ? '请在设备上确认…' : 'Confirm on your device…') : (zh ? '使用 Passkey' : 'Use passkey')}</span>
      </button>
      {message && <p className="auth-alert error" role="alert">{message}</p>}
    </section>
  );
}
