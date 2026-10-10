from pathlib import Path
import json,sys
E=Path('/workspace/evidence/pr238-physical-growth-20261010')
for key in sys.argv[1:]:
 d=E/key;rows=[json.loads(x) for x in (d/'storage.jsonl').read_text().splitlines()];rows=[r for r in rows if 'db_bytes' in r];base=json.loads((d/'load-boundary.json').read_text())['load_start'];stop=json.loads((d/'load-ended.json').read_text())['load_return'] if (d/'load-ended.json').exists() else rows[-1]['ts']
 active=[r for r in rows if base<=r['ts']<=stop];a,b=active[0],active[-1]
 residual=lambda r:r['db_bytes']-sum(t['table_bytes']+t['index_bytes'] for t in r['tables'])
 out={'key':key,'from_ts':a['ts'],'to_ts':b['ts'],'db_delta_bytes':b['db_bytes']-a['db_bytes'],'observed_relation_delta_bytes':{},'other_database_bytes_first_last':[residual(a),residual(b)],'other_database_bytes_min_max':[min(map(residual,active)),max(map(residual,active))],'terminal_other_database_bytes':residual(rows[-1]),'note':'Seven hot relations include heap/TOAST/FSM/VM via pg_table_size and their indexes. Residual includes other relations, catalogs and allocation overhead. Values are physical allocations, not necessary live domain bytes.'}
 for t in b['tables']:
  old=next(x for x in a['tables'] if x['relname']==t['relname']);out['observed_relation_delta_bytes'][t['relname']]={f:t[f]-old[f] for f in ['table_bytes','index_bytes']}
 (d/'physical-decomposition.json').write_text(json.dumps(out,indent=2));print(json.dumps(out))