// Loaded only by the integration suite's in-memory module manifest. Calls the
// production WASM handler in one isolate with changed deployment bindings.
import Worker from './worker/shim.mjs';

export default {
  async fetch(request, env, context) {
    const invoke = (bindings) => new Worker(context, bindings).fetch(request);
    const clock = request.headers.get('x-nazo-test-clock-ms');
    if (clock !== null) {
      const SystemDate = Date;
      globalThis.Date = new Proxy(SystemDate, {
        construct: (target, args) => Reflect.construct(target, args.length ? args : [Number(clock)]),
        get: (target, key) => key === 'now' ? () => Number(clock) : Reflect.get(target, key),
      });
      try {
        return await invoke({ ...env, NAZO_VERSION: { id: clock } });
      } finally {
        globalThis.Date = SystemDate;
      }
    }
    switch (request.headers.get('x-nazo-test-binding')) {
      case 'key':
        return invoke({ ...env, NAZO_SIGNING_KEY: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' });
      case 'database':
        return invoke({ ...env, NAZO_DB: env.NAZO_EMPTY_DB });
      case 'version':
        return invoke({ ...env, NAZO_VERSION: { id: 'updated-version' } });
      case 'warm-version':
        return invoke({ ...env, NAZO_VERSION: { id: 'warm-version' } });
      case 'without-avatar-bucket':
        return invoke({ ...env, NAZO_AVATARS: undefined });
      case 'passkey-profile': {
        const configuration = JSON.parse(env.NAZO_CONFIG);
        configuration.passkey_only = true;
        return invoke({ ...env, NAZO_CONFIG: JSON.stringify(configuration) });
      }
      case 'without-device': {
        const configuration = JSON.parse(env.NAZO_CONFIG);
        configuration.modules = configuration.modules.filter(module => module !== 'device_authorization');
        return invoke({ ...env, NAZO_CONFIG: JSON.stringify(configuration) });
      }
      case 'configuration': {
        const configuration = JSON.parse(env.NAZO_CONFIG);
        configuration.issuer = configuration.issuer.replace('127.0.0.1', 'localhost');
        return invoke({ ...env, NAZO_CONFIG: JSON.stringify(configuration) });
      }
      default:
        return invoke(env);
    }
  },
};
