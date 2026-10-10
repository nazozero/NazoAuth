from pathlib import Path
import json,math,collections
C=Path('/workspace/evidence/pr238-closure-20261010');reports=[]
for label,P in [('A',C/'MIX300'),('B1',C/'candidate-load/MIX300')]:
 result=json.loads(next(P.rglob('short-result.json')).read_text());main=result['metrics']['measure']['window_start_s'];chains={}
 def q(h,bounds,p):
  count=0
  if not h['n']:return None
  for i,n in enumerate(h['b']):
   count+=n
   if count>=math.ceil(h['n']*p):return [bounds[i-1] if i else 0,bounds[i] if i<len(bounds) else None]
 for name in ['load','fapi','meta','refresh']:
  f=next(f for f in P.rglob('*.series.json') if f.parent.name==name);x=json.loads(f.read_text());bins={}
  for ts,r in x['bins'].items():
   k=math.floor((float(ts)-math.floor(main))/30)*30;h=r['cap_iter_ms']
   if not h['n']:continue
   b=bins.setdefault(k,{'n':0,'b':[0]*len(h['b'])});b['n']+=h['n'];b['b']=[u+v for u,v in zip(b['b'],h['b'])]
  chains[name]=[{'offset':k,'n':h['n'],'p95':q(h,x['hist_bounds_ms'],.95),'p99':q(h,x['hist_bounds_ms'],.99)} for k,h in sorted(bins.items())]
 proc=[json.loads(s) for s in next(P.rglob('proc-detail.jsonl')).read_text().splitlines()];proc=[r for r in proc if 'ts' in r];cpu=[]
 for a,b in zip(proc,proc[1:]):
  dt=b['ts']-a['ts'];at={t['tid']:t['jif'] for t in a.get('app',{}).get('pid1_threads',[])}
  cores=[(t['jif']-at[t['tid']])/100/dt for t in b.get('app',{}).get('pid1_threads',[]) if t['tid'] in at]
  if cores:cpu.append({'offset':round(b['ts']-main,1),'app_cores':round((b['app']['total_jif']-a['app']['total_jif'])/100/dt,3),'max_thread_cores':round(max(cores),3)})
 roles=[json.loads(s) for s in (P/'pg-roles.jsonl').read_text().splitlines()];active=[]
 for r in roles:
  app=[a for a in r.get('activity') or [] if a.get('usename')=='nazoauth_perf_runtime'];active.append({'offset':round(r['ts']-main,1),'active_connections':sum(a['n'] for a in app if a['state']!='idle'),'oldest_active_xact_s':max((a['oldest_xact_s'] or 0 for a in app),default=0),'waits':{str(a['wait_event']):a['n'] for a in app if a['state']!='idle'}})
 out={'label':label,'chains':chains,'app_cpu_series':cpu,'runtime_role_activity':active};reports.append(out)
 print(label,'FAPI',chains['fapi']);print(label,'META',chains['meta']);print(label,'max thread',max(c['max_thread_cores'] for c in cpu),'max oldest xact',max(c['oldest_active_xact_s'] for c in active))
(C/'fapi-diagnostic.json').write_text(json.dumps(reports,indent=2))
