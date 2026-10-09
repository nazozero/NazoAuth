from pathlib import Path
import subprocess,json,hashlib
R=Path('/workspace');E=R/'evidence/model-consolidation-20261009';a='ef89417c9377ea765878b24d7b034a189638dee3';b=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip();f='crates/persistence-postgres/src/repositories/tokens.rs'
def body(sha):
 s=subprocess.check_output(['git','show',sha+':'+f],cwd=R,text=True);i=s.index('async fn refresh_family_id_for_digest(');return s[i:s.index('#[derive',i)]
x=body(a);y=body(b);assert x==y
migration='migrations/20260926000100_refresh_state_minimal/up.sql';mx=subprocess.check_output(['git','show',a+':'+migration],cwd=R);my=(R/migration).read_bytes();assert mx==my
r={'historical_sha':a,'candidate_sha':b,'lookup_identical':True,'lookup_sha256':hashlib.sha256(x.encode()).hexdigest(),'unique_index_migration_identical':True,'migration':migration,'index_constraint':'UNIQUE (tenant_id, current_token_blake3)','finding':'The measured lookup wall-time increase is real, but its SQL, holder/tenant predicates and unique index did not change. Plans and I/O timing were not captured for these formal points; no causal attribution to shared CPU or model changes is established.'};(E/'revoke-code-review.json').write_text(json.dumps(r,indent=2));print(r)
