from pathlib import Path
import subprocess,shutil,json,time
p=Path('/src');e=p/'evidence/pr230-performance-repair-20261009'
assert not subprocess.check_output(['git','diff','--name-only'],cwd=p,text=True).strip()
src=(e/'diagnostic-read.rs').read_text();needle='impl ObservedConnection {';assert needle in src;src=src.replace(needle,needle+'\n    pub(super) fn set_phase(&mut self, phase: &str) { self.phase = phase.to_owned(); }',1)
f=p/'crates/persistence-postgres/src/pool/diagnostic.rs';f.parent.mkdir(exist_ok=True);f.write_text(src)
f=p/'crates/persistence-postgres/src/pool.rs';s=f.read_text();s=s.replace('pub type DbConnection = Object<AsyncPgConnection>;','mod diagnostic;\npub(crate) use diagnostic::profile;\npub type DbConnection = diagnostic::ObservedConnection;')
s=s.replace('read<T, F>(&self, query: F)','read<T, F>(&self, phase: &\'static str, query: F)')
s=s.replace('let mut guard = DiscardOnDrop(Some(get_conn(&pool).await?));','let mut connection = get_conn(&pool).await?;\n                connection.set_phase(&format!("{phase}:connection"));\n                let mut guard = DiscardOnDrop(Some(connection));',1)
s=s.replace('let result = query(guard.connection()).await;','let result = profile(phase, query(guard.connection())).await;',1)
a=s.index('pub async fn get_conn(');b=s.index('/// Performs a real database round trip',a)
s=s[:a]+'''#[track_caller]
pub fn get_conn(pool: &DbPool) -> impl std::future::Future<Output = anyhow::Result<DbConnection>> + Send + '_ {
    let location = std::panic::Location::caller();
    let phase = format!("{}:{}", location.file(), location.line());
    async move {
        static SAMPLES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        if SAMPLES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 1024 == 0 {
            let q = pool.status();
            eprintln!("POOLSTATUS {}", serde_json::json!({"ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64(), "phase":phase,"size":q.size,"max_size":q.max_size,"available":q.available,"waiting":q.waiting}));
        }
        let started = std::time::Instant::now();
        let connection = pool.get().await?;
        Ok(diagnostic::ObservedConnection::new(connection, started.elapsed().as_micros() as u64, phase))
    }
}

'''+s[b:];f.write_text(s)
for name,phase in [('authorization_flow.rs','authorization_task'),('token_issuance.rs','issuance_task')]:
 f=p/'crates/persistence-postgres/src/repositories'/name;s=f.read_text();s=s.replace('operation.spawn_on(\n                async move {','operation.spawn_on(\n                crate::pool::profile("'+phase+'", async move {',1);s=s.replace('                },\n                &self.pool.runtime,','                }),\n                &self.pool.runtime,',1);f.write_text(s)
for filename, methods in [('clients/query.rs',['by_client_id','by_id','authentication_snapshot','client_secret_digest_matches']),('users.rs',['public_account_by_id','principal_by_tenant_id','active_subject_claims_by_tenant_id'])]:
 f=p/'crates/persistence-postgres/src/repositories'/filename;s=f.read_text()
 for method in methods:
  a=s.index('    pub async fn '+method+'(');b=s.index('{\n',a)+2;c=s.index('\n    }',b);body=s[b:c];assert '.read(move |connection|' in body;phase=('client_' if filename.startswith('clients') else 'user_')+method;body=body.replace('.read(move |connection|','.read("'+phase+'", move |connection|',1);s=s[:b]+body+s[c:]
 f.write_text(s)
subprocess.run(['cargo','fmt'],cwd=p,check=True)
(e/'diagnostic-read-after.patch').write_bytes(subprocess.check_output(['git','diff'],cwd=p));(e/'diagnostic-read-after.rs').write_bytes((p/'crates/persistence-postgres/src/pool/diagnostic.rs').read_bytes())
cmd=['cargo','build','--release','--locked','-p','nazoauth'];t=time.monotonic()
with (e/'diagnostic-read-after-build.log').open('w') as f:r=subprocess.run(cmd,cwd=p,stdout=f,stderr=subprocess.STDOUT)
row=dict(command=cmd,exit=r.returncode,seconds=time.monotonic()-t);(e/'diagnostic-read-after-build-exit.json').write_text(json.dumps(row));print(row);print((e/'diagnostic-read-after-build.log').read_text()[-3000:]);assert r.returncode==0
shutil.copy2(p/'target/release/nazoauth',e/'diagnostic-read-after-nazoauth')

