from pathlib import Path
import json
D=Path('/workspace/evidence/pr238-physical-growth-20261010/AUTH_B30')
x=[json.loads(s) for s in (D/'storage.jsonl').read_text().splitlines()];rows=[r for r in x if 'physical_detail' in r];base=json.loads((D/'load-boundary.json').read_text())['load_start'];a=next(r for r in rows if r['ts']-base>=600);b=rows[-1]
print('window',a['ts']-base,b['ts']-base)
for k,v in sorted(b['physical_detail']['indexes'].items(),key=lambda kv:kv[1]['index_size'],reverse=True)[:15]:
 old=a['physical_detail']['indexes'][k]
 print(k,round(v['index_size']/1048576,2),'deltaMiB',round((v['index_size']-old['index_size'])/1048576,2),'leaf_density',v['avg_leaf_density'],'deleted_pages',v['deleted_pages'])
