from pathlib import Path
import json,statistics
OLD=Path('/workspace/evidence/pr238-longrun-20261010');E=Path('/workspace/evidence/pr238-physical-growth-20261010')
out=[]
for key in ['AUTH10','REVOKE20','CC10','MTLS10','MIX30','REFRESH10','FAPI10','COLD10','INTROSPECT10','PAR10','NATIVE6R2']:
 D=OLD/key;a=json.loads((D/'analysis.json').read_text());m=a['lanes']['load']['measure'];start=m['window_start_s'];end=m['window_end_s']
 rows=[json.loads(x) for x in (D/'storage.jsonl').read_text().splitlines()]
 rows=[r for r in rows if 'db_bytes' in r and start<=r['ts']<=end]
 tail=rows[len(rows)//2:];parts=[tail[len(tail)*i//3:len(tail)*(i+1)//3] for i in range(3)]
 tables={}
 for t in tail[-1]['tables']:
  name=t['relname'];series=[[next(x for x in r['tables'] if x['relname']==name) for r in part] for part in parts]
  tables[name]={field:[round(statistics.median(x[field] for x in s)/1048576,2) if field.endswith('_bytes') else statistics.median(x[field] for x in s) for s in series] for field in ['table_bytes','index_bytes','n_tup_ins','n_tup_del','n_dead_tup','autovacuum_count']}
 item={'key':key,'tail_window_seconds':[tail[0]['ts']-start,tail[-1]['ts']-start],'db_mib':[round(statistics.median(r['db_bytes'] for r in part)/1048576,2) for part in parts],'tables':tables};out.append(item)
 print(key,item['db_mib'],{name:{k:v for k,v in t.items() if k in ['table_bytes','index_bytes']} for name,t in tables.items() if t['table_bytes'][-1]+t['index_bytes'][-1]>5})
(E/'historical-physical-growth.json').write_text(json.dumps(out,indent=2))
