from pathlib import Path
import hashlib,json,subprocess,time
R=Path('/workspace');O=R/'evidence/pr238-reverify-20261009';E=R/'evidence/pr238-mixed-retest-20261009';key='MIX300'
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()=='7fec5ac1513e4c421ee9c1d89d058a1174eea375'
assert not subprocess.check_output(['git','diff','e8242c44','HEAD','--','crates','migrations','Cargo.toml','Cargo.lock','perf'],cwd=R)
E.mkdir(exist_ok=False)
for name in ['build.json','diagnostic_controller.py','observer.sql']:(E/name).write_bytes((O/name).read_bytes())
(E/'point-observer-cycle.py').write_text((O/'point-observer-cycle.py').read_text().replace('/src/evidence/pr238-reverify-20261009','/src/evidence/pr238-mixed-retest-20261009'))
D=E/key;(D/'requests').mkdir(parents=True)
p=json.loads((O/key/'requests'/f'{key}.json').read_text());original=json.loads(json.dumps(p))
p.update(name='pr238-mixed-retest-20261009',replicate=3,status='USER_REQUESTED_IDENTICAL_MIXED_RETEST')
for path,digest in p['harness_file_sha256'].items():assert hashlib.sha256((R/path).read_bytes()).hexdigest()==digest,path
assert hashlib.sha256((O/'nazoauth').read_bytes()).hexdigest()==p['expected_binary_sha256']
changes={k:{'before':original.get(k),'after':p.get(k)} for k in set(original)|set(p) if original.get(k)!=p.get(k)}
assert set(changes)=={'name','replicate','status'}
(D/'request-delta.json').write_text(json.dumps(changes,indent=2))
target=D/'requests'/f'{key}.json';target.write_text(json.dumps(p,indent=2))
m=json.loads((O/key/'requests/manifest.json').read_text());m['project']=p['name'];m['requests']={key:{'path':str(target).replace('/workspace/','/src/'),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}}
(D/'requests/manifest.json').write_text(json.dumps(m,indent=2))
(E/'provenance.json').write_text(json.dumps({'checkout_head':'7fec5ac1513e4c421ee9c1d89d058a1174eea375','tested_source':p['source_sha'],'binary_sha256':p['expected_binary_sha256'],'only_request_changes':changes,'previous_evidence':str(O)},indent=2))
for action in ['setup',key]:
 cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE=/src/evidence/pr238-mixed-retest-20261009/'+key,'-w','/src','nazoauth-reverify-controller-20261009','python','/src/evidence/pr238-mixed-retest-20261009/point-observer-cycle.py',action]
 start=time.monotonic();utc=time.time()
 with (E/(key+'-'+action+'.log')).open('w') as out:r=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
 record={'action':action,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start,'start_ts':utc,'end_ts':time.time()}
 with (E/'commands.jsonl').open('a') as out:out.write(json.dumps(record)+'\n')
 print(json.dumps(record),flush=True)
 if action=='setup' and r.returncode:raise SystemExit(r.returncode)
 if r.returncode not in [0,2,3]:raise SystemExit(r.returncode)
