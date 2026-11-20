'use strict';

async function showConsent() {
  const status = document.getElementById('status');
  try {
    const requestId = new URLSearchParams(location.search).get('request_id');
    if (!requestId) throw new Error('缺少授权请求编号');
    const query = new URLSearchParams({ request_id: requestId });
    const response = await fetch('/authorize/consent?' + query, {
      credentials: 'same-origin', cache: 'no-store',
    });
    if (!response.ok) throw new Error('无法读取授权请求，请从应用重新发起。');
    const consent = await response.json();
    if (!consent.csrf_token || consent.request_id !== requestId) {
      throw new Error('授权会话已失效，请从应用重新发起。');
    }
    document.getElementById('client').textContent = consent.client_name;
    document.getElementById('redirect').textContent = consent.redirect_uri;
    const permissions = document.getElementById('permissions');
    for (const value of new Set([
      ...consent.scopes, ...consent.userinfo_claims, ...consent.id_token_claims,
      ...consent.authorization_details.map(detail => JSON.stringify(detail)),
    ])) {
      const item = document.createElement('li');
      item.textContent = value;
      permissions.append(item);
    }
    const form = document.querySelector('form');
    form.elements.request_id.value = consent.request_id;
    form.elements.csrf_token.value = consent.csrf_token;
    status.hidden = true;
    document.getElementById('details').hidden = false;
  } catch (error) {
    status.textContent = error.message;
  }
}

showConsent();
