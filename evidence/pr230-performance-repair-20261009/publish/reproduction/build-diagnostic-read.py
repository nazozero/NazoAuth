from pathlib import Path
import subprocess,base64,time,json,shutil
p=Path('/src'); e=p/'evidence/pr230-performance-repair-20261009'
src=(p/'evidence/pr230-performance-20261009/publish/diagnostic-after.rs').read_text()
src=src.replace('begin_us:u64 }', 'begin_us:u64, steps:Vec<(u64,u64)> }')
src=src.replace('q.queries+=1;match', 'let idx=q.queries;q.steps.push((idx,us));q.queries+=1;match')
src=src.replace('  record(self.phase.clone(),', '  if let Some(q)=q.as_ref(){for (idx,us) in &q.steps {record(format!("{}:sql{}",self.phase,idx),|r|{r.n+=1;r.sql_us+=us;});}}\n  record(self.phase.clone(),')
(p/'crates/persistence-postgres/src/pool/diagnostic.rs').parent.mkdir(exist_ok=True)
(p/'crates/persistence-postgres/src/pool/diagnostic.rs').write_text(src)
f=p/'crates/persistence-postgres/src/pool.rs';s=f.read_text();s=s.replace('pub type DbConnection = Object<AsyncPgConnection>;','mod diagnostic;\npub(crate) use diagnostic::profile;\npub type DbConnection = diagnostic::ObservedConnection;')
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
for filename, methods in [
 ('clients/query.rs', ['by_client_id','by_id','authentication_snapshot','client_secret_digest_matches']),
 ('users.rs', ['principal_by_id','principal_by_tenant_id','active_subject_claims_by_tenant_id'])
]:
 f=p/'crates/persistence-postgres/src/repositories'/filename;s=f.read_text()
 for method in methods:
  a=s.index('    pub async fn '+method+'(');b=s.index('{\n',a)+2;c=s.index('\n    }',b)
  body=s[b:c];sep=body.index('?;\n')+3
  phase=('client_' if filename.startswith('clients') else 'user_')+method+'_query'
  body=body[:sep]+'        crate::pool::profile("'+phase+'", async {\n'+body[sep:]+'\n        }).await\n'
  s=s[:b]+body+s[c:]
 f.write_text(s)
subprocess.run(['cargo','fmt'],cwd=p,check=True)
(e/'diagnostic-read.patch').write_bytes(subprocess.check_output(['git','diff'],cwd=p))
(e/'diagnostic-read.rs').write_text(src)
cmd=['cargo','build','--release','--locked','-p','nazoauth'];t=time.monotonic()
with (e/'diagnostic-read-build.log').open('w') as f:r=subprocess.run(cmd,cwd=p,stdout=f,stderr=subprocess.STDOUT)
print(dict(command=cmd,exit=r.returncode,seconds=time.monotonic()-t));print((e/'diagnostic-read-build.log').read_text()[-6000:]);assert r.returncode==0
shutil.copy2('/src/target/release/nazoauth',e/'diagnostic-read-nazoauth')



