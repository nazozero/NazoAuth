from pathlib import Path
import json,csv,sys,collections
E=Path('/workspace/evidence/pr238-physical-growth-20261010')
for key in sys.argv[1:]:
 D=E/key;rows=[json.loads(x) for x in (D/'storage.jsonl').read_text().splitlines()];rows=[r for r in rows if 'pending' in r];base=json.loads((D/'load-boundary.json').read_text())['load_start'];out=[]
 for a,b in zip(rows,rows[1:]):
  dt=b['ts']-a['ts'];out.append({'offset_s':b['ts']-base,'ts':b['ts'],'interval_s':dt,'pending':b['pending'],'oldest_pending_s':b['oldest_pending_s'],'acked_events_s':(b['anchor']-a['anchor'])/dt,'persisted_events_s':(b['anchor']+b['pending']-a['anchor']-a['pending'])/dt})
 with (D/'export-throughput.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(out[0]));w.writeheader();w.writerows(out)
 for lo in range(0,1800,120):
  rr=[r for r in out if lo<=r['offset_s']<lo+120]
  if rr:print(key,lo,{'pending_first_last':[rr[0]['pending'],rr[-1]['pending']],'peak_age_s':max(r['oldest_pending_s'] for r in rr),'acked_events_s':round(sum(r['acked_events_s']*r['interval_s'] for r in rr)/sum(r['interval_s'] for r in rr),2),'persisted_events_s':round(sum(r['persisted_events_s']*r['interval_s'] for r in rr)/sum(r['interval_s'] for r in rr),2)})
