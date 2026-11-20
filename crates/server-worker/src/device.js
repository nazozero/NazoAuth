'use strict';

const lookup = document.getElementById('lookup');
const codeInput = document.getElementById('user-code');
const lookupButton = document.getElementById('lookup-button');
const status = document.getElementById('status');
const details = document.getElementById('details');
const approve = document.getElementById('approve');
const deny = document.getElementById('deny');
const requestOptions = { credentials: 'same-origin', cache: 'no-store', redirect: 'error' };
let prepared = null;

function busy(value) {
  codeInput.disabled = value;
  lookupButton.disabled = value;
  approve.disabled = value || !prepared;
  deny.disabled = value || !prepared;
}

function devicePath(code) {
  return '/device?' + new URLSearchParams({ user_code: code });
}

function login(code) {
  location.replace('/auth/passkey?' + new URLSearchParams({ return_to: devicePath(code) }));
}

function list(id, values) {
  const element = document.getElementById(id);
  element.replaceChildren();
  for (const value of values) {
    const item = document.createElement('li');
    item.textContent = value;
    element.append(item);
  }
}

async function showRequest(code) {
  prepared = null;
  details.hidden = true;
  code = code.trim();
  codeInput.value = code;
  busy(true);
  try {
    if (!code) throw new Error('请输入设备上显示的用户码。');
    history.replaceState(null, '', devicePath(code));
    status.textContent = '正在读取设备授权请求…';
    const response = await fetch('/device/verification?' + new URLSearchParams({ user_code: code }), requestOptions);
    if (!response.ok) throw new Error('无法读取设备授权请求，请稍后重试。');
    const verification = await response.json();
    if (!verification.request) throw new Error('用户码无效、已过期或已经处理。请从设备重新发起登录。');

    // The shared CSRF endpoint requires a fully authenticated, active session.
    // Enrollment and expired sessions return 401; a token is never anonymous.
    const session = await fetch('/auth/csrf', requestOptions);
    if (session.status === 401) {
      login(code);
      return;
    }
    if (!session.ok) throw new Error('无法确认登录会话，请稍后重试。');
    const { csrf_token: csrf } = await session.json();
    if (typeof csrf !== 'string' || !csrf) throw new Error('登录会话已失效，请刷新页面后重试。');

    const request = verification.request;
    document.getElementById('client').textContent = request.client_name;
    document.getElementById('client-id').textContent = request.client_id;
    document.getElementById('confirmation-code').textContent = code;
    list('permissions', [
      ...request.scopes,
      ...request.authorization_details.map(detail => JSON.stringify(detail)),
    ]);
    list('resources', request.resource_indicators || []);
    const expiry = document.getElementById('expires');
    expiry.dateTime = request.expires_at;
    expiry.textContent = new Date(request.expires_at).toLocaleString();
    prepared = { code, csrf };
    details.hidden = false;
    status.textContent = '请核对请求，然后选择允许或拒绝。';
  } catch (error) {
    status.textContent = error.message;
  } finally {
    busy(false);
  }
}

async function decide(decision) {
  if (!prepared || approve.disabled) return;
  const { code, csrf } = prepared;
  busy(true);
  status.textContent = '正在提交你的选择…';
  try {
    const response = await fetch('/device/decision', {
      ...requestOptions,
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ user_code: code, decision, csrf_token: csrf }),
    });
    if (response.status === 401) {
      login(code);
      return;
    }
    if (!response.ok) {
      if (response.status === 400 || response.status === 403) {
        prepared = null;
        details.hidden = true;
        throw new Error('请求或登录会话已失效。请重新查看用户码后再试。');
      }
      throw new Error('暂时无法提交选择，请稍后重试。');
    }
    prepared = null;
    details.hidden = true;
    lookup.hidden = true;
    history.replaceState(null, '', '/device');
    status.textContent = decision === 'approve'
      ? '已允许此设备。请返回设备继续登录，你可以关闭此页面。'
      : '已拒绝此设备的授权请求。你可以关闭此页面。';
  } catch (error) {
    status.textContent = error.message;
  } finally {
    busy(false);
  }
}

lookup.addEventListener('submit', event => {
  event.preventDefault();
  return showRequest(codeInput.value);
});
approve.addEventListener('click', () => decide('approve'));
deny.addEventListener('click', () => decide('deny'));
const initialCode = new URLSearchParams(location.search).get('user_code');
if (initialCode) showRequest(initialCode);
