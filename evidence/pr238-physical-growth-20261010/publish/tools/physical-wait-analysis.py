from pathlib import Path
import json,collections,statistics
E=Path('/workspace/evidence/pr238-physical-growth-20261010')
for key in ['AUTH_DIAG','AUTH_B30']:
 D=E/key;a=json.loads((D/'analysis.json').read_text());r=a['result'];print(key,'queue',r.get('queue'),'cost',r.get('cost'))
 res=json.loads((D/'resource-analysis.json').read_text());print('cpu', {k:round(v['time_weighted_mean_cores'],3) for k,v in res['whole_window']['cpu'].items()})
 rows=[json.loads(x) for x in (D/'pg-roles.jsonl').read_text().splitlines()];base=a['lanes']['load']['measure']['window_start_s'];end=a['lanes']['load']['measure']['window_end_s'];rows=[r for r in rows if base<=r['ts']<=end]
 for lo,hi in [(0,600),(600,1200),(1200,1800)]:
  rr=[r for r in rows if lo<=r['ts']-base<hi]
  if not rr:continue
  groups=collections.defaultdict(list)
  for r in rr:
   for v in r.get('activity') or []:
    k=(v['usename'],v.get('application_name'),v['state'],v['wait_event_type'],v['wait_event']);groups[k].append(v)
  print('window',lo,hi,'samples',len(rr))
  for k,vv in sorted(groups.items(),key=lambda kv:sum(v['n'] for v in kv[1]),reverse=True)[:12]: print(k,'mean_sessions',round(sum(v['n'] for v in vv)/len(rr),2),'max_xact_s',max(v['oldest_xact_s'] or 0 for v in vv))
 paths=list(D.glob('results/*/*/proc-detail.jsonl'))
 if paths:
  first=json.loads(paths[0].read_text().splitlines()[0]);print('process fields',{k:list(v) if isinstance(v,dict) else type(v).__name__ for k,v in first.items()})
