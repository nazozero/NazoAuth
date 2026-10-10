from pathlib import Path
import json,math
E=Path('/workspace/evidence/pr238-mixed-retest-20261009');P=E/'MIX300';s=json.loads((E/'summary.json').read_text())[0]
f=next(p for p in P.rglob('*.series.json') if p.parent.name=='refresh');x=json.loads(f.read_text());m=s['sidecar_gates']['refresh']['metrics']['measure'];bins={}
for sec,v in x['bins'].items():
 if not v['dropped']:continue
 offset=math.floor((float(sec)-math.floor(m['window_start_s']))/30)*30
 bins[offset]=bins.get(offset,0)+v['dropped']
r={'window':m,'drop_buckets_30s_including_pre_window':bins,'note':'Timestamp buckets include pre-window drops and boundary seconds; exact acceptance uses measure cohort.'};(E/'refresh-drops.json').write_text(json.dumps(r,indent=2));print(json.dumps(r))
