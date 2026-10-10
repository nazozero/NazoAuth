from pathlib import Path
import subprocess,json,time,sys
R=Path('/workspace');E=R/'evidence/pr238-closure-20261010';O=E/'quality';O.mkdir(exist_ok=False)
env=json.loads((R/'evidence/storage-minimize-20261010/fixture-env.json').read_text())
for name in ['nazo-storage-pg-20261010','nazo-storage-vk-20261010','nazo-storage-s3-20261010']:
 info=json.loads(subprocess.check_output(['docker','inspect',name]))[0]
 assert info['Config']['Labels'].get('task.owner')=='storage-minimize-20261010'
 subprocess.run(['docker','start',name],check=True,stdout=subprocess.DEVNULL)
commands=[('format','cargo fmt'),('static','python3 scripts/verify_static_contracts.py --check'),('persistence-boundary','python3 scripts/check_persistence_dependency_graph.py'),('crypto-boundary','python3 scripts/check_crypto_boundary.py'),('migration','cargo test --locked --all-features -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables'),('schema','cargo test --locked --all-features -p nazo-postgres --test schema_cleanup -- --nocapture'),('revocation-unit','cargo test --locked --all-features -p nazo-postgres --lib repositories::access_token_revocation -- --nocapture'),('revocation','cargo test --locked --all-features -p nazo-postgres --test access_token_retention -- --nocapture'),('controller','cargo test --locked --all-features -p nazo-postgres --test controller_registry --test controller_recovery -- --nocapture'),('audit-ledger','cargo test --locked --all-features -p nazo-postgres --test audit_ledger -- --nocapture'),('host-audit','cargo test --locked --all-features -p nazoauth --lib adapters::audit -- --nocapture'),('mtls','cargo test --locked --all-features -p nazo-oauth-server --lib security::mtls -- --nocapture'),('fmt','cargo fmt --check'),('clippy','cargo clippy --workspace --all-targets --all-features --locked --keep-going -- -D warnings'),('workspace','cargo test --workspace --all-features --locked --no-fail-fast -- --nocapture'),('release','cargo build --release --locked -p nazoauth --bin nazoauth')]
for name,command in commands:
 cmd=['docker','exec']
 for k,v in env.items():cmd+=['-e',k+'='+v]
 cmd+=['-w','/src','nazoauth-perf-runner-20261009',*command.split()]
 start=time.monotonic()
 with (O/(name+'.log')).open('w') as out:r=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
 result={'command':command,'exit':r.returncode,'seconds':time.monotonic()-start};(O/(name+'-exit.json')).write_text(json.dumps(result));print(name,json.dumps(result),flush=True)
 if r.returncode:sys.exit(r.returncode)
