// An explicit acceptance authenticator for an isolated operator-provisioned
// account. The service still verifies TOTP/backup proofs and rotates sessions.
import { createHmac } from 'node:crypto';

const ensure = (value, reason) => { if (!value) throw new Error('Acceptance ' + reason); };
export function totp(base32, step = Math.floor(Date.now() / 30_000)) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const bytes = [];
  for (const character of base32.replace(/=+$/, '').toUpperCase()) {
    const digit = alphabet.indexOf(character);
    ensure(digit >= 0, 'TOTP seed is malformed');
    value = (value << 5) | digit; bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((value >> bits) & 255); }
  }
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac('sha1', Buffer.from(bytes)).update(counter).digest();
  const offset = digest.at(-1) & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

export async function publicMfa({ issuer, input, request, postJson, json, step }) {
  let session = { cookie: '', csrf: '' };
  const cookies = new Map();
  let seed, backups = [], enabled = false;
  const update = response => {
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';')[0];
      const separator = pair.indexOf('=');
      cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
    const body = json(response);
    session = { cookie: [...cookies].map(([name,value]) => name + '=' + value).join('; '),
      csrf: body.csrf_token || cookies.get('__Host-nazo_oauth_csrf') || session.csrf };
    return body;
  };
  const headers = () => ({ cookie: session.cookie, 'x-csrf-token': session.csrf });
  const action = (path, body) => postJson(path, body, headers());
  const login = () => postJson('/auth/login', { email: input.administrator.email, password: input.administrator.password }, { cookie: session.cookie });
  await step('password_login_totp_enrollment_and_backup_codes', async () => {
    const loginResult = update(await login());
    ensure(!loginResult.mfa_required, 'fresh isolated administrator unexpectedly requires MFA');
    const pending = json(await action('/auth/me/mfa/totp/begin', {}));
    seed = pending.secret_base32;
    ensure(typeof seed === 'string' && pending.digits === 6 && pending.period === 30, 'TOTP enrollment parameters differ');
    ensure((await action('/auth/me/mfa/totp/confirm', { code: 'invalid' })).status === 400, 'invalid TOTP confirmation accepted');
    const confirmed = update(await action('/auth/me/mfa/totp/confirm', { code: totp(seed) }));
    enabled = confirmed.mfa_enabled === true;
    backups = confirmed.backup_codes || [];
    ensure(enabled && backups.length === 10 && new Set(backups).size === 10, 'MFA enrollment did not return distinct backup codes');
    ensure(json(await request('/auth/me', { headers: headers() })).mfa_enabled === true, 'MFA enablement was not persisted');
  });
  if (enabled) {
    await step('pending_mfa_backup_consumption_and_remembered_device', async () => {
      const pending = update(await login());
      ensure(pending.mfa_required === true, 'password login bypassed the configured second factor');
      const profile = json(await request('/auth/me', { headers: headers() }));
      ensure(profile.mfa_required === true, 'pending session was projected as an authenticated account');
      ensure((await request('/admin/users', { headers: headers() })).status !== 200, 'pending session reached an admin operation');
      ensure((await action('/auth/mfa/verify', { code: 'invalid' })).status === 400, 'invalid MFA challenge accepted');
      update(await action('/auth/mfa/verify', { code: backups[0], remember_device: true }));
      ensure(json(await request('/auth/me', { headers: headers() })).mfa_required === false, 'MFA did not complete the session');
      ensure((await action('/auth/me/mfa/step-up', { code: backups[0] })).status === 400, 'backup code replay accepted');
      const remembered = update(await login());
      ensure(remembered.mfa_required === false, 'remembered MFA proof did not survive password login');
      // Remembered devices are not interactive recent MFA for admin mutation.
      update(await action('/auth/me/mfa/step-up', { code: backups[1] }));
      ensure((await request('/admin/users', { headers: headers() })).status === 200, 'confirmed administrator could not read users');
    });
  }
  return {
    get session() { return session; },
    async cleanup() {
      if (enabled) await step('mfa_backup_regeneration_and_disable', async () => {
        const regenerated = update(await action('/auth/me/mfa/backup-codes/regenerate', { code: backups[2] }));
        ensure(regenerated.backup_codes?.length === 10, 'backup regeneration failed');
        ensure((await action('/auth/me/mfa/step-up', { code: backups[3] })).status === 400, 'retired backup code remained usable');
        backups = regenerated.backup_codes;
        update(await action('/auth/me/mfa/disable', { code: backups[0] }));
        enabled = false;
        ensure(json(await request('/auth/me', { headers: headers() })).mfa_enabled === false, 'MFA disablement did not persist');
        ensure((await action('/auth/logout', {})).status === 200, 'administrator session cleanup failed');
      });
    },
  };
}
