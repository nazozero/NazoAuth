from pathlib import Path
import json,csv,sys
E=Path('/workspace/evidence/pr238-physical-growth-20261010')
for key in sys.argv[1:]:
 d=E/key;p=d/'storage.jsonl'
 rows=[json.loads(x) for x in p.read_text().splitlines()]
 rr=[r for r in rows if 'wal_disk_bytes' in r]
 if not rr:continue
 base=json.loads((d/'load-boundary.json').read_text())['load_start']
 series=[]
 for r in rr:
  s={'ts':r['ts'],'offset_s':r['ts']-base,'wal_disk_bytes':r['wal_disk_bytes'],'db_bytes':r.get('db_bytes'),'pending':r.get('pending')}
  s.update({'checkpoint_'+k:v for k,v in (r.get('checkpoint_stats') or {}).items()})
  series.append(s)
 fields=list(dict.fromkeys(k for r in series for k in r))
 with (d/'wal-disk-series.csv').open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(series)
 out={'key':key,'samples':len(series),'first':series[0],'last':series[-1],'min_bytes':min(r['wal_disk_bytes'] for r in rr),'max_bytes':max(r['wal_disk_bytes'] for r in rr),'limitations':'pg_ls_waldir allocation, not cumulative WAL generation. No manual checkpoint/vacuum. Short capacity windows may end before a scheduled checkpoint. settings and terminal probes are separate actual observations.'}
 (d/'wal-disk-analysis.json').write_text(json.dumps(out,indent=2));print(json.dumps(out))