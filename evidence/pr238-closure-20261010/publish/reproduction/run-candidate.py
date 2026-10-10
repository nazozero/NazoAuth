from pathlib import Path
import io,tarfile,subprocess,json,hashlib,time,sys
R=Path('/workspace');C=R/'evidence/pr238-closure-20261010';O=R/'evidence/pr238-reverify-20261009';E=C/'candidate-load';E.mkdir(exist_ok=False)
assert json.loads((C/'quality/release-exit.json').read_text())['exit']==0
# The full suite marks this real PG/Valkey FAPI case ignored by default;
# execute it explicitly with the same provisioned fixtures before formal load.
command='cargo test --locked --all-features -p nazoauth --lib par_fapi2_rejects_shared_secret_client_auth_after_authentication -- --ignored --nocapture'
fixture_env=json.loads((R/'evidence/storage-minimize-20261010/fixture-env.json').read_text())
cmd=['docker','exec']
for k,v in fixture_env.items():cmd+=['-e',k+'='+v]
cmd+=['-w','/src','nazoauth-perf-runner-20261009',*command.split()]
start=time.monotonic()
with (C/'quality/fapi-explicit.log').open('w') as out:r=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
(C/'quality/fapi-explicit-exit.json').write_text(json.dumps({'command':command,'exit':r.returncode,'seconds':time.monotonic()-start}))
assert r.returncode==0,'explicit FAPI regression failed'
# Quality fixtures are separate from the point's databases. Stop only this
# task's completed fixtures before formal load, so their maintenance cannot overlap.
for name in ['nazo-storage-pg-20261010','nazo-storage-vk-20261010','nazo-storage-s3-20261010']:
 info=json.loads(subprocess.check_output(['docker','inspect',name]))[0]
 assert info['Config']['Labels'].get('task.owner')=='storage-minimize-20261010'
 subprocess.run(['docker','stop',name],check=True,stdout=subprocess.DEVNULL)
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()
assert sha==json.loads((C/'candidate-source.json').read_text())['source_sha']
assert not subprocess.check_output(['git','diff','HEAD','--','crates','migrations','perf','Cargo.toml','Cargo.lock'],cwd=R)
subprocess.run(['docker','cp','nazoauth-perf-runner-20261009:/src/target/release/nazoauth',str(C/'nazoauth')],check=True)
files={'nazoauth':(C/'nazoauth').read_bytes(),'source-sha':(sha+'\n').encode(),'env.yaml':(R/'perf/env.yaml').read_bytes()}
files['Dockerfile']=('FROM nazoauth-reverify-runtime:20261009\nLABEL org.opencontainers.image.revision="'+sha+'"\nCOPY --chmod=0755 nazoauth /usr/local/bin/nazoauth\nCOPY source-sha /etc/nazoauth-source-sha\nCOPY env.yaml /app/.env.yaml\nUSER 10001:10001\nCMD ["nazoauth","server"]\n').encode()
data=io.BytesIO()
with tarfile.open(fileobj=data,mode='w') as t:
 for name,value in files.items():
  info=tarfile.TarInfo(name);info.size=len(value);t.addfile(info,io.BytesIO(value))
with (C/'candidate-image.log').open('wb') as out:r=subprocess.run(['docker','build','-t','nazoauth-closure-app:20261010','-'],input=data.getvalue(),stdout=out,stderr=subprocess.STDOUT)
assert r.returncode==0
images=json.loads((O/'build.json').read_text())['images'];images['app']=subprocess.check_output(['docker','image','inspect','nazoauth-closure-app:20261010','--format','{{.Id}}'],text=True).strip();binary=hashlib.sha256(files['nazoauth']).hexdigest()
(E/'build.json').write_text(json.dumps({'source_sha':sha,'binary_sha256':binary,'images':images},indent=2))
for name in ['diagnostic_controller.py','observer.sql']:(E/name).write_bytes((O/name).read_bytes())
# Observe the table changed by this revision as well as the existing retention series.
sql=(E/'observer.sql').read_text()
sql=sql.replace(" 'issuance_counts',", " 'revocations',(SELECT jsonb_build_object('total',count(*),'eligible',count(*) FILTER(WHERE expires_at<=now()),'retained',count(*) FILTER(WHERE expires_at>now())) FROM access_token_revocations),\n 'issuance_counts',")
sql=sql.replace("'oauth_token_issuances')) t)", "'oauth_token_issuances','access_token_revocations')) t)")
(E/'observer.sql').write_text(sql)
s=(O/'point-observer-cycle.py').read_text().replace('/src/evidence/pr238-reverify-20261009','/src/evidence/pr238-closure-20261010/candidate-load')
# A cohort selected before load: every decision up to 120s after load launch.
# Continue full original load after this cohort expires; no manual cleanup.
s=s.replace("row=snapshot();row['observer_elapsed_s']", """row=snapshot()
    if COHORT_CUTOFF is not None:
     target=ctl.E/'target-cohort.json';old=json.loads(target.read_text()) if target.exists() else None
     last=row['target_decisions']['last_business_retain_until']
     previous=old['target_decisions']['last_business_retain_until'] if old else None
     if old is None or (last and (previous is None or last>previous)):ctl.save(target,row)
    row['observer_elapsed_s']""")
s=s.replace("ctl.save(ctl.E/'load-boundary.json',{'load_start':time.time(),'point':point['name']})", "started=time.time();COHORT_CUTOFF=started+120\n ctl.save(ctl.E/'cohort-definition.json',{'defined_at':started,'occurred_at_lte':COHORT_CUTOFF,'rule':'all decisions created before load launch + 120s; original retention, full load continues'})\n ctl.save(ctl.E/'load-boundary.json',{'load_start':started,'point':point['name']})")
s=s.replace("COHORT_CUTOFF=time.time();ctl.save(ctl.E/'load-ended.json',{'load_return':COHORT_CUTOFF});ctl.save(ctl.E/'target-cohort.json',snapshot())", "ctl.save(ctl.E/'load-ended.json',{'load_return':time.time()});ctl.save(ctl.E/'cohort-at-stop.json',snapshot())")
# If a point has never contained an observed decision, its deadline is undefined.
# Never skip an actual cohort with an observed retention deadline.
s=s.replace("row=snapshot();ctl.save(ctl.E/'storage-after-validation.json',row)", "row=snapshot();ctl.save(ctl.E/'storage-after-validation.json',row)\n if sys.argv[1]=='REV360' and not row['target_decisions']['count'] and not json.loads((ctl.E/'target-cohort.json').read_text())['target_decisions']['last_business_retain_until']:\n  row['cohort_not_applicable']=True;row['full_cycle_after_target_deadline']=None\n  ctl.save(ctl.E/'natural-final.json',row);return r")
(E/'point-observer-cycle.py').write_text(s)
for key in ['MIX300','REV360']:
 D=E/key;(D/'requests').mkdir(parents=True)
 p=json.loads((O/key/'requests'/f'{key}.json').read_text());old=json.loads(json.dumps(p))
 for path,digest in p['harness_file_sha256'].items():assert hashlib.sha256((R/path).read_bytes()).hexdigest()==digest,path
 p.update(name='pr238-closure-final-'+key.lower()+'-20261010',source_sha=sha,source_modified=False,image=images['app'],expected_binary_sha256=binary,status='FINAL_CANDIDATE_ORIGINAL_GATE',replicate=6)
 changes={k:{'before':old.get(k),'after':p.get(k)} for k in set(old)|set(p) if old.get(k)!=p.get(k)}
 assert set(changes)<={'name','source_sha','source_modified','image','expected_binary_sha256','status','replicate'}
 (D/'request-delta.json').write_text(json.dumps(changes,indent=2))
 target=D/'requests'/f'{key}.json';target.write_text(json.dumps(p,indent=2))
 m=json.loads((O/key/'requests/manifest.json').read_text());m.update(project=p['name'],source_sha=sha,app_image=images['app'],post_observe_s=0)
 m['requests']={key:{'path':str(target).replace('/workspace/','/src/'),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}}
 (D/'requests/manifest.json').write_text(json.dumps(m,indent=2))
 for action in ['setup',key]:
  cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/candidate-load/'+key,'-w','/src','nazoauth-reverify-controller-20261009','python','/src/evidence/pr238-closure-20261010/candidate-load/point-observer-cycle.py',action]
  start=time.monotonic();utc=time.time()
  with (E/(key+'-'+action+'.log')).open('w') as out:r=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
  record={'action':action,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start,'start_ts':utc,'end_ts':time.time()}
  with (E/'commands.jsonl').open('a') as out:out.write(json.dumps(record)+'\n')
  print(json.dumps(record),flush=True)
  if action=='setup' and r.returncode:sys.exit(r.returncode)
  if r.returncode not in [0,2,3]:sys.exit(r.returncode)
