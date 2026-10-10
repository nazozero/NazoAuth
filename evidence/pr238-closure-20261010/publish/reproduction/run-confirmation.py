from pathlib import Path
import json,subprocess,hashlib,time,sys
R=Path('/workspace');C=R/'evidence/pr238-closure-20261010';O=R/'evidence/pr238-reverify-20261009'
plan={'defined_at':time.time(),'reason':'B1 FAPI P95 109ms fails original 100ms gate; metadata latency rose and recovered in matching time buckets, without app single-thread saturation. One predeclared full-window A2/B2 control; retain all results, no threshold or workload change.','order':['control-A2','confirm-B2'],'key':'MIX300','repeat_count_each':1,'source_A':json.loads((C/'build.json').read_text())['source_sha'],'source_B':json.loads((C/'candidate-load/build.json').read_text())['source_sha']}
(C/'confirmation-plan.json').write_text(json.dumps(plan,indent=2));print(json.dumps(plan),flush=True)
# Serialize with the already running revoked-token point; no concurrent load.
for _ in range(240):
 f=C/'candidate-load/commands.jsonl';rows=[json.loads(s) for s in f.read_text().splitlines()] if f.exists() else []
 if any(r['action']=='REV360' for r in rows):break
 time.sleep(5)
else:raise SystemExit('Existing point has not ended; no new load launched')
for label,buildfile in [('control-A2',C/'build.json'),('confirm-B2',C/'candidate-load/build.json')]:
 E=C/label;E.mkdir(exist_ok=False);build=json.loads(buildfile.read_text());(E/'build.json').write_text(json.dumps(build,indent=2))
 for name in ['diagnostic_controller.py','observer.sql','point-observer-cycle.py']:
  s=(C/'candidate-load'/name).read_text().replace('/src/evidence/pr238-closure-20261010/candidate-load','/src/evidence/pr238-closure-20261010/'+label)
  (E/name).write_text(s)
 key='MIX300';D=E/key;(D/'requests').mkdir(parents=True)
 p=json.loads((O/key/'requests'/f'{key}.json').read_text());old=json.loads(json.dumps(p))
 for path,digest in p['harness_file_sha256'].items():assert hashlib.sha256((R/path).read_bytes()).hexdigest()==digest,path
 p.update(name='pr238-closure-'+label.lower()+'-20261010',source_sha=build['source_sha'],source_modified=False,image=build['images']['app'],expected_binary_sha256=build['binary_sha256'],status='PREDECLARED_A2_B2_ORIGINAL_GATE',replicate=7 if label=='control-A2' else 8)
 changes={k:{'before':old.get(k),'after':p.get(k)} for k in old.keys()|p.keys() if old.get(k)!=p.get(k)};assert set(changes)<={'name','source_sha','source_modified','image','expected_binary_sha256','status','replicate'}
 (D/'request-delta.json').write_text(json.dumps(changes,indent=2));target=D/'requests'/f'{key}.json';target.write_text(json.dumps(p,indent=2))
 m=json.loads((O/key/'requests/manifest.json').read_text());m.update(project=p['name'],source_sha=p['source_sha'],app_image=p['image'],post_observe_s=0);m['requests']={key:{'path':str(target).replace('/workspace/','/src/'),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}};(D/'requests/manifest.json').write_text(json.dumps(m,indent=2))
 for action in ['setup',key]:
  cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/'+label+'/'+key,'-w','/src','nazoauth-reverify-controller-20261009','python','/src/evidence/pr238-closure-20261010/'+label+'/point-observer-cycle.py',action]
  start=time.monotonic();utc=time.time()
  with (E/(key+'-'+action+'.log')).open('w') as out:r=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
  record={'action':action,'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start,'start_ts':utc,'end_ts':time.time()}
  with (E/'commands.jsonl').open('a') as out:out.write(json.dumps(record)+'\n')
  print(label,json.dumps(record),flush=True)
  if (action=='setup' and r.returncode) or r.returncode not in [0,2,3]:sys.exit(r.returncode)
