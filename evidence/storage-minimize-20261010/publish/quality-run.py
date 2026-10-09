from pathlib import Path
import subprocess,json,time
E=Path('/workspace/evidence/storage-minimize-20261010');O=E/'round2';O.mkdir(exist_ok=True);env=json.loads((E/'fixture-env.json').read_text())
tests=[('migration','cargo test --locked --all-features -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables'),('mfa','cargo test --locked --all-features -p nazo-postgres --test identity_repositories -- --nocapture'),('schema','cargo test --locked --all-features -p nazo-postgres --test schema_cleanup -- --nocapture'),('host-mfa','cargo test --locked --all-features -p nazoauth --lib http::profile::mfa -- --nocapture'),('static','python3 scripts/verify_static_contracts.py --check'),('persistence-boundary','python3 scripts/check_persistence_dependency_graph.py'),('crypto-boundary','python3 scripts/check_crypto_boundary.py'),('fmt','cargo fmt --check'),('clippy','cargo clippy --workspace --all-targets --all-features --locked --keep-going -- -D warnings'),('workspace','cargo test --workspace --all-features --locked --no-fail-fast -- --nocapture'),('release','cargo build --release --locked -p nazoauth --bin nazoauth')]
for name,command in tests:
 cmd=['docker','exec']
 for k,v in env.items():cmd+=['-e',k+'='+v]
 cmd+=['-w','/src','nazoauth-perf-runner-20261009',*command.split()]
 start=time.monotonic()
 with (O/(name+'.log')).open('w') as out:r=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
 result={'command':command,'exit':r.returncode,'seconds':time.monotonic()-start};(O/(name+'-exit.json')).write_text(json.dumps(result));print(name,json.dumps(result),flush=True)
 if r.returncode:break
