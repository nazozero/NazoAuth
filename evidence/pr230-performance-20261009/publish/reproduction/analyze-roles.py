import pathlib,json,re,collections
p=pathlib.Path('/src/evidence/pr230-performance-20261009')
for key in ['D1','D2','D3']:
 s=(p/key/'pg-roles.jsonl').read_text();dec=json.JSONDecoder();rows=[]
 while s.strip():
  s=s.lstrip();row,i=dec.raw_decode(s);rows.append(row);s=s[i:]
 roles=collections.defaultdict(collections.Counter)
 for row in rows:
  for a in row.get('activity') or []:roles[a['usename']][str((a['state'],a['wait_event_type'],a['wait_event']))]+=a['n']
 result={'sample_count':len(rows),'role_state_wait_observations':{k:dict(v) for k,v in roles.items()},'boundary':'counts are summed connection observations, not elapsed wait measurements; exporter/observer are separate'}
 (p/key/'pg-role-analysis.json').write_text(json.dumps(result,indent=2))
print('role analyses written')
