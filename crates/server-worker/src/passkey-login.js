'use strict';
const emailInput = document.getElementById('email');
const button = document.getElementById('login');
const status = document.getElementById('status');

function decode(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = atob(base64);
  return Uint8Array.from(bytes, character => character.charCodeAt(0));
}
function requestOptions(value) {
  if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function') {
    return PublicKeyCredential.parseRequestOptionsFromJSON(value);
  }
  return {
    ...value,
    challenge: decode(value.challenge),
    allowCredentials: (value.allowCredentials || []).map(item => ({
      ...item, id: decode(item.id),
    })),
  };
}
async function send(path, data) {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) throw new Error('认证失败：' + response.status);
  return response.json();
}
function returnPath() {
  const parameters = new URLSearchParams(location.search);
  const value = parameters.get('return_to') || parameters.get('next');
  if (!value?.startsWith('/') || value.startsWith('//')) return null;
  const target = new URL(value, location.origin);
  if (target.origin !== location.origin || !['/authorize', '/device'].includes(target.pathname)) return null;
  return target.pathname + target.search;
}
button.addEventListener('click', async () => {
  button.disabled = true;
  status.textContent = '正在准备 Passkey…';
  try {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      throw new Error('当前浏览器不支持 Passkey');
    }
    const email = emailInput.value.trim();
    if (!email) throw new Error('请输入账号邮箱');
    const started = await send('/auth/passkey/begin', { email });
    status.textContent = '请在设备上确认 Passkey…';
    const assertion = await navigator.credentials.get({
      publicKey: requestOptions(started.publicKey),
    });
    if (!assertion) throw new Error('没有选择 Passkey');
    await send('/auth/passkey/finish', {
      ceremony_id: started.ceremony_id,
      response: assertion.toJSON(),
    });
    const next = returnPath();
    if (next) {
      location.replace(next);
      return;
    }
    status.textContent = '已登录。';
  } catch (error) {
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
