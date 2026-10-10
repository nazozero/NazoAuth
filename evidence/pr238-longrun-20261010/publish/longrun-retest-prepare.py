from pathlib import Path
import json,hashlib,ast,time
E=Path('/workspace/evidence/pr238-longrun-20261010')
changes=[]
for key in ['REFRESH10','FAPI10','COLD10']:
 D=E/key;assert not (D/'load-boundary.json').exists()
 p=D/'requests'/f'{key}.json';q=json.loads(p.read_text());before=q['effective_seconds'];q.update(effective_seconds=300,duration=str(300+q['warmup_ms']//1000)+'s');p.write_text(json.dumps(q,indent=2))
 m=json.loads((D/'requests/manifest.json').read_text());m['requests'][key]['sha256']=hashlib.sha256(p.read_bytes()).hexdigest();(D/'requests/manifest.json').write_text(json.dumps(m,indent=2));changes.append({'key':key,'before_s':before,'after_s':300})
for old,key in [('AUTH10','AUTH1R2'),('MIX30','MIX1R2')]:
 D=E/key;D.mkdir();(D/'requests').mkdir();q=json.loads((E/old/'requests'/f'{old}.json').read_text());q.update(name='pr238-long-'+key.lower()+'-20261010',request_key=key,effective_seconds=60,duration=str(60+q['warmup_ms']//1000)+'s',status='PREDECLARED_ENVIRONMENT_RETEST')
 print('sidecars',q.get('sidecars'))
 for side in q.get('sidecars',[]):
  if isinstance(side,dict):side['duration']='150s'
 p=D/'requests'/f'{key}.json';p.write_text(json.dumps(q,indent=2));m=json.loads((E/old/'requests/manifest.json').read_text());m.update(project=q['name'],point_timeout_s=570,point_budget_s=600,requests={key:{'path':str(p).replace('/workspace/','/src/'),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}});(D/'requests/manifest.json').write_text(json.dumps(m,indent=2))
 for f in ['diagnostic_controller.py','observer.sql','point-observer-cycle.py']:
  s=(E/old/f).read_text().replace('/pr238-longrun-20261010/'+old,'/pr238-longrun-20261010/'+key);(D/f).write_text(s)
  if f.endswith('.py'):ast.parse(s)
(E/'environment-retest-plan.json').write_text(json.dumps({'ts':time.time(),'user_requested':True,'new_points':['AUTH1R2','MIX1R2'],'formal_seconds':60,'reason':'Repeat anomalies after observing lower steadier one-minute UI load; preserve prior failures; short retest is not long-run stability proof','unstarted_window_changes':changes,'gates_rates_vus_ttls_unchanged':True},indent=2))
