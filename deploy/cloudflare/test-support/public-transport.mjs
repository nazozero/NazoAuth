// Only the explicit public acceptance client uses native TLS. Production
// Workers observe certificates exclusively from Cloudflare's trusted metadata.
import https from 'node:https';

export function publicTransport(input, ordinaryFetch = fetch) {
  const issuer = new URL(input.issuer).origin;
  const agent = input.mtls ? new https.Agent({
    cert: input.mtls.certificate_pem, key: input.mtls.private_key_pem,
    keepAlive: true, maxSockets: 8,
  }) : undefined;
  const send = (url, init = {}) => {
    const { nazo_mtls, ...options } = init;
    if (!nazo_mtls) return ordinaryFetch(url, options);
    if (!agent || new URL(url).origin !== issuer || new URL(url).protocol !== 'https:') {
      throw new Error('Acceptance mTLS transport requires its configured HTTPS issuer and certificate');
    }
    return new Promise((resolve, reject) => {
      const request = https.request(url, { agent, method: options.method || 'GET',
        headers: Object.fromEntries(new Headers(options.headers)), signal: options.signal,
      }, response => {
        const chunks = [];
        let length = 0;
        response.on('data', chunk => {
          length += chunk.length;
          if (length > 2 * 1024 * 1024) { response.destroy(new Error('Acceptance response exceeded its limit')); return; }
          chunks.push(chunk);
        });
        response.on('error', reject);
        response.on('end', () => {
          const headers = new Headers();
          for (let i = 0; i < response.rawHeaders.length; i += 2) headers.append(response.rawHeaders[i], response.rawHeaders[i + 1]);
          const status = response.statusCode;
          resolve(new Response([204,205,304].includes(status) || options.method === 'HEAD' ? null : Buffer.concat(chunks), { status, headers }));
        });
      });
      request.on('error', reject);
      if (options.body != null) request.write(typeof options.body === 'string' || Buffer.isBuffer(options.body)
        ? options.body : options.body.toString());
      request.end();
    });
  };
  return { fetch: send, close: () => agent?.destroy() };
}
