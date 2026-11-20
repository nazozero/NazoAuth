import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ShieldCheck } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useI18n } from '../i18n';

// A pending session becomes authenticated only after the shared MFA endpoint
// accepts the code and rotates the cookies. Codes stay in component memory.
export default function WorkerMfaChallenge({ onVerified, onCancel }: {
  onVerified: () => Promise<void>;
  onCancel: () => Promise<void>;
}) {
  const { locale } = useI18n();
  const zh = locale === 'zh-CN';
  const [code, setCode] = useState('');
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const pending = useRef<AbortController | null>(null);
  useEffect(() => () => pending.current?.abort(), []);

  const verify = async (event: FormEvent) => {
    event.preventDefault();
    if (pending.current || !code.trim()) return;
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setMessage('');
    const candidate = code.trim();
    setCode('');
    try {
      const result = await apiFetch<{ success: boolean }>('/auth/mfa/verify', {
        method: 'POST', signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: candidate, remember_device: remember }),
      });
      if (result?.success !== true) throw new Error(zh ? '验证未完成，请重试。' : 'Verification did not complete. Try again.');
      if (!controller.signal.aborted) await onVerified();
    } catch (error) {
      if (!controller.signal.aborted) setMessage(error instanceof Error ? error.message : (zh ? '验证码验证失败。' : 'Verification failed.'));
    } finally {
      if (pending.current === controller) pending.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  };
  const cancel = async () => {
    if (pending.current || busy) return;
    setBusy(true);
    setMessage('');
    try { await onCancel(); }
    catch (error) { setMessage(error instanceof Error ? error.message : (zh ? '无法退出，请重试。' : 'Could not cancel. Try again.')); }
    finally { setBusy(false); }
  };
  return (
    <section aria-labelledby="worker-mfa-title" className="worker-mfa-challenge">
      <h3 id="worker-mfa-title"><ShieldCheck size={20} /> {zh ? '完成双重验证' : 'Complete two-factor verification'}</h3>
      <p className="auth-help-text">{zh ? '输入验证器中的验证码，也可以使用一枚备用码。' : 'Enter a code from your authenticator, or use a backup code.'}</p>
      <form className="auth-form" onSubmit={event => void verify(event)}>
        <label className="auth-input-label" htmlFor="worker-mfa-code">{zh ? '验证码或备用码' : 'Authenticator or backup code'}</label>
        <input id="worker-mfa-code" className="glass-input" type="text" autoComplete="one-time-code"
          autoCapitalize="none" spellCheck={false} maxLength={128} required autoFocus disabled={busy}
          value={code} onChange={event => setCode(event.target.value)} />
        <label style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <input type="checkbox" checked={remember} disabled={busy} onChange={event => setRemember(event.target.checked)} />
          <span>{zh ? '记住此设备' : 'Remember this device'}</span>
        </label>
        <button className="btn-primary w-full" type="submit" disabled={busy || !code.trim()}>
          {busy ? (zh ? '正在验证…' : 'Verifying…') : (zh ? '验证并继续' : 'Verify and continue')}
        </button>
        <button className="btn-secondary w-full" type="button" disabled={busy} onClick={() => void cancel()}>
          {zh ? '取消并重新登录' : 'Cancel and sign in again'}
        </button>
      </form>
      {message && <p className="auth-alert error" role="alert">{message}</p>}
    </section>
  );
}
