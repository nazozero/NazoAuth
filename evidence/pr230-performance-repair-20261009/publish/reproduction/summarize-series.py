from pathlib import Path
import json
E=Path('/src/evidence/pr230-performance-repair-20261009');rows=[]
for key in ['BREAD','AREAD','BREAD2','BREAD03','BREAD04','BREAD10']:
 r=json.loads((E/key/'time-analysis.json').read_text());rows.append({'key':key,'buckets':[{'offset_s':x['completion_offset_s'],'samples':x['complete_samples'],'p99_interval_ms':x['p99_interval_ms'],'max_ms':x['max_ms']} for x in r['latency'] if 0<=x['completion_offset_s']<60],'storage':r['storage'],'boundary':r['boundary']})
(E/'time-series-summary.json').write_text(json.dumps(rows,indent=2));print(json.dumps(rows,indent=2))
