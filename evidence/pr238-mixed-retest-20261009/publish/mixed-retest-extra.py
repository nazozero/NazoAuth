from pathlib import Path
import json,collections
E=Path('/workspace/evidence/pr238-mixed-retest-20261009');P=E/'MIX300'
s=json.loads((E/'summary.json').read_text())[0];start=s['measure']['window_start_s'];end=s['measure']['window_end_s']
for path in P.rglob('*.series.json'):
 if path.parent.name not in ['load','refresh']:continue
 x=json.loads(path.read_text());print('SERIES',path.parent.name,list(x['bins'].items())[:1])
rows=[json.loads(l) for l in (P/'pg-roles.jsonl').read_text().splitlines()];out=[]
for lo,hi in [(0,120),(120,300)]:
 observations=[]
 for r in rows:
  if start+lo<=r['ts']<min(end,start+hi):
   a=[z for z in r['activity'] or [] if z['usename']=='nazoauth_perf_runtime'];observations.append({'ts':r['ts'],'wal_wait_connections':sum(z['n'] for z in a if z['wait_event'] in ['WalSync','WALWrite']),'oldest_tx_s':max([z['oldest_xact_s'] or 0 for z in a],default=0)})
 out.append({'from_s':lo,'to_s':hi,'samples':observations})
(E/'pg-wait-observations.json').write_text(json.dumps(out,indent=2));print('PG',out)
