'use strict';
const ticketInput = document.getElementById('ticket');
const button = document.getElementById('enroll');
const status = document.getElementById('status');
let csrf = null;

function decode(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = atob(base64);
  return Uint8Array.from(bytes, character => character.charCodeAt(0));
}

function creationOptions(value) {
  if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function') {
    return PublicKeyCredential.parseCreationOptionsFromJSON(value);
  }
  return {
    ...value,
    challenge: decode(value.challenge),
    user: { ...value.user, id: decode(value.user.id) },
    excludeCredentials: (value.excludeCredentials || []).map(item => ({
      ...item, id: decode(item.id),
    })),
  };
}

async function send(path, data, headers = {}) {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { ...headers, ...(data ? { 'content-type': 'application/json' } : {}) },
    ...(data ? { body: JSON.stringify(data) } : {}),
  });
  if (!response.ok) throw new Error('请求未通过：' + response.status);
  return response.json();
}

button.addEventListener('click', async () => {
  button.disabled = true;
  status.textContent = '正在验证初始化凭据…';
  try {
    if (!navigator.credentials || !window.PublicKeyCredential) {
      throw new Error('当前浏览器不支持 Passkey');
    }
    if (!csrf) {
      const token = ticketInput.value.trim();
      ticketInput.value = '';
      if (!token) throw new Error('请输入初始化凭据');
      const result = await send('/auth/setup/claim', null, {
        Authorization: 'Bearer ' + token,
      });
      csrf = result.csrf_token;
    }
    status.textContent = '请按浏览器提示创建 Passkey…';
    const begin = await send('/auth/me/passkeys/registration/begin', {
      label: '初始设备',
    }, { 'x-csrf-token': csrf });
    const publicKey = creationOptions(begin.publicKey);
    const created = await navigator.credentials.create({ publicKey });
    if (!created) throw new Error('设备未创建 Passkey');
    await send('/auth/me/passkeys/registration/finish', {
      ceremony_id: begin.ceremony_id,
      response: created.toJSON(),
    }, { 'x-csrf-token': csrf });
    csrf = null;
    status.textContent = '绑定成功。请用 Passkey 正常登录，并尽快添加一枚备用 Passkey。';
  } catch (error) {
    status.textContent = error.message + '。若初始化已验证，可在本页重试创建。';
  } finally {
    button.disabled = false;
  }
});
