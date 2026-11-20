import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { Fingerprint, ShieldCheck, Trash2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/useAuth';
import { useI18n } from '../i18n';
import { ApiError, apiFetch } from '../lib/api';
import './WorkerSecurity.css';

type Passkey = { id: string; label: string; created_at: string; last_used_at?: string | null };
type Enrollment = { secret_base32: string; otpauth_uri: string; period: number; digits: number };
type MfaResult = { mfa_enabled?: boolean; backup_codes?: string[]; success?: boolean };

export default function WorkerSecurity() {
  const { user, refreshSession } = useAuth();
  const { locale } = useI18n();
  const navigate = useNavigate();
  const zh = locale === 'zh-CN';
  const [passkeys, setPasskeys] = useState<Passkey[] | null>(null);
  const [label, setLabel] = useState('');
  const [removing, setRemoving] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState('');
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [reauthentication, setReauthentication] = useState(false);
  const pending = useRef<AbortController | null>(null);
  const enabled = user?.mfa_enabled === true;

  const loadPasskeys = useCallback(async (signal: AbortSignal) => {
    const result = await apiFetch<{ passkeys: Passkey[] }>('/auth/me/passkeys', { signal });
    if (!Array.isArray(result?.passkeys)) throw new Error('Invalid passkey list response.');
    if (!signal.aborted) setPasskeys(result.passkeys);
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    void loadPasskeys(controller.signal).catch(error => {
      if (!controller.signal.aborted) setError(error instanceof Error ? error.message : 'Could not load passkeys.');
    });
    return () => { controller.abort(); pending.current?.abort(); };
  }, [loadPasskeys]);

  const run = async (action: (signal: AbortSignal) => Promise<void>) => {
    if (pending.current) return;
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true); setMessage(''); setError(''); setReauthentication(false);
    try { await action(controller.signal); }
    catch (error) {
      if (!controller.signal.aborted) {
        const needsLogin = error instanceof ApiError && error.payload && !Array.isArray(error.payload)
          && error.payload.error === 'reauthentication_required';
        setReauthentication(Boolean(needsLogin));
        setError(needsLogin
          ? (zh ? '请重新登录，或先完成下方的双重验证，再重试此操作。' : 'Sign in again, or confirm a fresh authenticator code below, then retry.')
          : error instanceof Error ? error.message : (zh ? '操作失败，请重试。' : 'The request failed. Try again.'));
      }
    } finally {
      if (pending.current === controller) pending.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  };
  const post = <T,>(path: string, signal: AbortSignal, value?: unknown) => apiFetch<T>(path, {
    method: 'POST', signal,
    ...(value === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(value) }),
  });

  const addPasskey = (event: FormEvent) => {
    event.preventDefault();
    void run(async signal => {
      if (!window.PublicKeyCredential || !navigator.credentials || typeof PublicKeyCredential.parseCreationOptionsFromJSON !== 'function') {
        throw new Error(zh ? '请使用支持 Passkey 的新版浏览器。' : 'Use a current browser with passkey support.');
      }
      const begin = await post<{ ceremony_id: string; publicKey: PublicKeyCredentialCreationOptionsJSON }>(
        '/auth/me/passkeys/registration/begin', signal, { label: label.trim() || null });
      const credential = await navigator.credentials.create({
        publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(begin.publicKey), signal,
      }) as PublicKeyCredential | null;
      if (!credential) throw new Error(zh ? '未创建 Passkey。' : 'No passkey was created.');
      await post('/auth/me/passkeys/registration/finish', signal, { ceremony_id: begin.ceremony_id, response: credential.toJSON() });
      if (signal.aborted) return;
      setLabel(''); setMessage(zh ? 'Passkey 已添加。' : 'Passkey added.');
      await loadPasskeys(signal);
    });
  };
  const removePasskey = (id: string) => void run(async signal => {
    await apiFetch(`/auth/me/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE', signal });
    if (signal.aborted) return;
    setRemoving(null); setMessage(zh ? 'Passkey 已移除。' : 'Passkey removed.');
    await loadPasskeys(signal);
  });
  const beginTotp = () => void run(async signal => {
    const result = await post<Enrollment>('/auth/me/mfa/totp/begin', signal);
    if (typeof result?.secret_base32 !== 'string' || typeof result.otpauth_uri !== 'string') throw new Error('Invalid authenticator setup response.');
    if (!signal.aborted) { setEnrollment(result); setCode(''); setCodes(null); }
  });
  const mfaAction = (action: 'confirm' | 'step-up' | 'regenerate' | 'disable') => {
    if (!code.trim()) return;
    const candidate = code.trim();
    setCode('');
    void run(async signal => {
      const path = action === 'confirm' ? '/auth/me/mfa/totp/confirm'
        : action === 'regenerate' ? '/auth/me/mfa/backup-codes/regenerate' : `/auth/me/mfa/${action}`;
      const result = await post<MfaResult>(path, signal, { code: candidate });
      if (signal.aborted) return;
      if (action === 'confirm' || action === 'regenerate') {
        if (!Array.isArray(result.backup_codes) || !result.backup_codes.every(code => typeof code === 'string')) throw new Error('Invalid backup code response.');
        setCodes(result.backup_codes); setEnrollment(null);
      }
      if (action === 'disable') { setCodes(null); setEnrollment(null); setConfirmDisable(false); }
      setMessage(action === 'disable' ? (zh ? '双重验证已关闭。' : 'Two-factor authentication turned off.')
        : action === 'step-up' ? (zh ? '近期身份验证已确认，请重试需要验证的操作。' : 'Recent authentication confirmed. Retry the protected action.')
        : action === 'regenerate' ? (zh ? '已生成新的备用码，旧码已失效。' : 'New backup codes are ready. The previous codes no longer work.')
        : (zh ? '双重验证已启用。请保存备用码。' : 'Two-factor authentication enabled. Save your backup codes.'));
      await refreshSession();
    });
  };
  const reauthenticate = () => navigate(`/auth?next=${encodeURIComponent(window.location.pathname + window.location.search)}`);

  return (
    <div className="worker-security" aria-label={zh ? '账户安全' : 'Account security'}>
      {error && <p className="profile-alert error" role="alert">{error}</p>}
      {message && <p className="profile-alert success" role="status">{message}</p>}
      {reauthentication && <button type="button" className="btn-secondary" onClick={reauthenticate}>{zh ? '重新登录' : 'Sign in again'}</button>}
      <section className="worker-security-section" aria-labelledby="worker-passkeys-title">
        <h3 id="worker-passkeys-title"><Fingerprint size={20} /> Passkeys</h3>
        <p className="profile-form-hint">{zh ? '使用设备上的指纹、面容或安全密钥登录。添加和删除需要近期身份验证。' : 'Sign in with a fingerprint, face, or security key. Adding or removing a passkey requires recent authentication.'}</p>
        {passkeys === null ? <p className="profile-form-hint">{zh ? '正在加载 Passkey…' : 'Loading passkeys…'}</p>
          : passkeys.length === 0 ? <p className="profile-form-hint">{zh ? '尚未添加 Passkey。' : 'No passkeys added yet.'}</p>
          : <ul className="worker-passkey-list">{passkeys.map(item => <li key={item.id}>
            <div><strong>{item.label || 'Passkey'}</strong><small>{item.last_used_at
              ? `${zh ? '上次使用：' : 'Last used: '}${new Date(item.last_used_at).toLocaleString()}`
              : (zh ? '尚未用于登录' : 'Not used to sign in yet')}</small></div>
            <button type="button" className="btn-secondary" disabled={busy} aria-label={`${zh ? '移除' : 'Remove'} ${item.label || 'Passkey'}`} onClick={() => setRemoving(item.id)}><Trash2 size={16} />{zh ? '移除' : 'Remove'}</button>
            {removing === item.id && <div className="worker-confirmation">
              <p className="profile-form-hint">{zh ? '移除此 Passkey？请确认你仍有其他可用的登录方式。' : 'Remove this passkey? Make sure you have another way to sign in.'}</p>
              <div className="worker-security-actions"><button type="button" className="btn-primary" disabled={busy} onClick={() => removePasskey(item.id)}>{zh ? '确认移除' : 'Confirm removal'}</button>
                <button type="button" className="btn-secondary" disabled={busy} onClick={() => setRemoving(null)}>{zh ? '取消' : 'Cancel'}</button></div>
            </div>}
          </li>)}</ul>}
        <form className="profile-form" onSubmit={addPasskey}>
          <label htmlFor="worker-passkey-label">{zh ? 'Passkey 名称（可选）' : 'Passkey name (optional)'}</label>
          <input id="worker-passkey-label" value={label} maxLength={128} disabled={busy} placeholder={zh ? '例如：我的手机' : 'For example, my phone'} onChange={event => setLabel(event.target.value)} />
          <div className="worker-security-actions"><button type="submit" className="btn-primary" disabled={busy}><Fingerprint size={16} />{busy ? (zh ? '请稍候…' : 'Please wait…') : (zh ? '添加 Passkey' : 'Add passkey')}</button></div>
        </form>
      </section>
      <section className="worker-security-section" aria-labelledby="worker-totp-title">
        <h3 id="worker-totp-title"><ShieldCheck size={20} />{zh ? '双重验证' : 'Two-factor authentication'}</h3>
        <p className="profile-form-hint">{enabled ? (zh ? '已启用验证器验证码。备用码可在无法使用验证器时登录，每枚只能使用一次。' : 'Authenticator codes are enabled. Each backup code can be used once if you lose access to your authenticator.')
          : (zh ? '添加验证器后，登录还需输入一次性验证码。' : 'Add an authenticator to require a one-time code when signing in.')}</p>
        {!enabled && !enrollment && <div className="worker-security-actions"><button type="button" className="btn-primary" disabled={busy} onClick={beginTotp}>{zh ? '设置验证器' : 'Set up authenticator'}</button></div>}
        {enrollment && <div className="profile-form">
          <p className="profile-form-hint">{zh ? `在验证器中手动添加此密钥，使用 ${enrollment.digits} 位数字、${enrollment.period} 秒间隔。` : `Add this setup key to your authenticator using ${enrollment.digits} digits and a ${enrollment.period}-second interval.`}</p>
          <code className="worker-secret" aria-label={zh ? '验证器设置密钥' : 'Authenticator setup key'}>{enrollment.secret_base32}</code>
          {enrollment.otpauth_uri.startsWith('otpauth://totp/') && <a href={enrollment.otpauth_uri}>{zh ? '在验证器中打开' : 'Open in authenticator'}</a>}
          <label htmlFor="worker-totp-confirm">{zh ? '输入验证器的 6 位验证码' : 'Enter the 6-digit authenticator code'}</label>
          <input id="worker-totp-confirm" autoComplete="one-time-code" inputMode="numeric" maxLength={6} value={code} disabled={busy} onChange={event => setCode(event.target.value)} />
          <div className="worker-security-actions"><button type="button" className="btn-primary" disabled={busy || !/^[0-9]{6}$/.test(code.trim())} onClick={() => mfaAction('confirm')}>{zh ? '确认并启用' : 'Confirm and enable'}</button>
            <button type="button" className="btn-secondary" disabled={busy} onClick={() => { setEnrollment(null); setCode(''); }}>{zh ? '取消设置' : 'Cancel setup'}</button></div>
        </div>}
        {enabled && <div className="profile-form">
          <label htmlFor="worker-totp-current">{zh ? '当前验证码或备用码' : 'Current authenticator or backup code'}</label>
          <input id="worker-totp-current" autoComplete="one-time-code" autoCapitalize="none" spellCheck={false} maxLength={128} value={code} disabled={busy} onChange={event => setCode(event.target.value)} />
          <div className="worker-security-actions"><button type="button" className="btn-secondary" disabled={busy || !code.trim()} onClick={() => mfaAction('step-up')}>{zh ? '确认近期身份验证' : 'Confirm recent authentication'}</button>
            <button type="button" className="btn-secondary" disabled={busy || !code.trim()} onClick={() => mfaAction('regenerate')}>{zh ? '重新生成备用码' : 'Replace backup codes'}</button>
            <button type="button" className="btn-secondary" disabled={busy || !code.trim()} onClick={() => setConfirmDisable(true)}>{zh ? '关闭双重验证' : 'Turn off two-factor authentication'}</button></div>
          {confirmDisable && <div className="worker-confirmation"><p>{zh ? '确认关闭此账户的双重验证？' : 'Turn off two-factor authentication for this account?'}</p>
            <div className="worker-security-actions"><button type="button" className="btn-primary" disabled={busy || !code.trim()} onClick={() => mfaAction('disable')}>{zh ? '确认关闭' : 'Confirm turn off'}</button>
              <button type="button" className="btn-secondary" disabled={busy} onClick={() => setConfirmDisable(false)}>{zh ? '取消' : 'Cancel'}</button></div></div>}
        </div>}
        {codes && <div className="worker-backup-codes" aria-label={zh ? '备用码' : 'Backup codes'}>
          <strong>{zh ? '请现在保存这些备用码' : 'Save these backup codes now'}</strong>
          <p className="profile-form-hint">{zh ? '离开本页后不会再次显示，请保存在安全的地方。' : 'They will not be shown again after you leave this page. Keep them somewhere safe.'}</p>
          <ul>{codes.map(item => <li key={item}><code>{item}</code></li>)}</ul>
          <button type="button" className="btn-secondary" onClick={() => setCodes(null)}>{zh ? '我已保存，隐藏备用码' : 'I saved them. Hide codes.'}</button>
        </div>}
      </section>
    </div>
  );
}
