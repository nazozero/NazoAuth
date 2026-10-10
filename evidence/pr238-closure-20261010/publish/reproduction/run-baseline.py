from pathlib import Path
import hashlib,json,subprocess,time
R=Path('/workspace');O=R/'evidence/pr238-reverify-20261009';E=R/'evidence/pr238-closure-20261010';key='MIX300'
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()
assert head=='34402ffea83c574a6c3805ca91ab82e511ba74f8'
subprocess.run(['git','diff','--exit-code','088afcd5',head,'--','crates','migrations','Cargo.toml','Cargo.lock','perf'],cwd=R,check=True)
E.mkdir(exist_ok=False)
build=json.loads((R/'evidence/storage-minimize-20261010/build.json').read_text())
for name in ['diagnostic_controller.py','observer.sql']:(E/name).write_bytes((O/name).read_bytes())
(E/'point-observer-cycle.py').write_text((O/'point-observer-cycle.py').read_text().replace('/src/evidence/pr238-reverify-20261009','/src/evidence/pr238-closure-20261010'))
D=E/key;(D/'requests').mkdir(parents=True)
p=json.loads((O/key/'requests'/f'{key}.json').read_text());original=json.loads(json.dumps(p))
p.update(name='pr238-closure-mix300-20261010',replicate=5,status='ORIGINAL_300S_FAILURE_CLOSURE',source_sha=build['source_sha'],image=build['images']['app'],expected_binary_sha256=build['binary_sha256'])
for path,digest in p['harness_file_sha256'].items():assert hashlib.sha256((R/path).read_bytes()).hexdigest()==digest,path
changes={k:{'before':original.get(k),'after':p.get(k)} for k in set(original)|set(p) if original.get(k)!=p.get(k)}
assert set(changes)<= {'name','replicate','status','source_sha','image','expected_binary_sha256'}
(D/'request-delta.json').write_text(json.dumps(changes,indent=2))
target=D/'requests'/f'{key}.json';target.write_text(json.dumps(p,indent=2))
m=json.loads((O/key/'requests/manifest.json').read_text());m.update(project=p['name'],source_sha=p['source_sha'],app_image=p['image'],post_observe_s=0)
m['requests']={key:{'path':str(target).replace('/workspace/','/src/'),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}}
(D/'requests/manifest.json').write_text(json.dumps(m,indent=2))
(E/'provenance.json').write_text(json.dumps({'checkout_head':head,'tested_source':p['source_sha'],'binary_sha256':p['expected_binary_sha256'],'only_request_changes':changes,'previous_evidence':str(O)},indent=2))
for action in ['setup',key]:
 cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/'+key,'-w','/src','nazoauth-reverify-controller-20261009','python','/src/evidence/pr238-closure-20261010/point-observer-cycle.py',action]
 start=time.monotonic();utc=time.time()
 with (E/(action+'.log')).open('w') as out:r=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
 record={'action':action,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start,'start_ts':utc,'end_ts':time.time()}
 with (E/'commands.jsonl').open('a') as out:out.write(json.dumps(record)+'\n')
 print(json.dumps(record),flush=True)
 if action=='setup' and r.returncode:raise SystemExit(r.returncode)
 if r.returncode not in [0,2,3]:raise SystemExit(r.returncode)
