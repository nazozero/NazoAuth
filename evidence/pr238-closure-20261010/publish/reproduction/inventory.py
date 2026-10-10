import sys,json,re,subprocess,collections,hashlib
from pathlib import Path
R=Path('/workspace');E=R/'evidence/pr238-closure-20261010';sys.path.insert(0,str(R/'scripts'))
import data_model_inventory as inv
models,errors,n=inv.source_inventory(R)
old=json.loads((R/'evidence/model-consolidation-20261009/publish/models.json').read_text())['models']; old={m['id']:m for m in old}
new={m['id']:m for m in models}
delta=[{'id':k,'before':old.get(k),'after':new.get(k)} for k in old.keys()|new.keys() if old.get(k,{}).get('fields')!=new.get(k,{}).get('fields')]
files={str(p.relative_to(R)):p.read_text() for p in R.glob('crates/*/src/**/*.rs')}
refs=collections.defaultdict(list)
for path,s in files.items():
 for num,line in enumerate(s.splitlines(),1):
  for token in set(re.findall(r'\b[A-Za-z_]\w*\b',line)):refs[token].append([path,num,line.strip()[:180]])
(E/'models.json').write_text(json.dumps({'source_files':n,'models':models,'errors':errors,'fields':sum(len(m['fields']) for m in models)},indent=2))
(E/'model-delta.json').write_text(json.dumps(delta,indent=2))
print('TOTAL',n,len(models),sum(len(m['fields']) for m in models),errors)
print('DELTA',json.dumps(delta))
candidates=[]
for m in models:
 if m['kind']!='struct':continue
 p=m['id'].split('::')[0];name=m['id'].split('::')[-1];s=files[p]
 if '/schema.rs' in p:continue
 for f in m['fields']:
  token=f['name'];r=refs[token]
  if token.isdigit():continue
  if len(r)<=4:candidates.append({'model':m['id'],'field':f,'refs':r})
(E/'low-reference-candidates.json').write_text(json.dumps(candidates,indent=2))
print('CANDIDATES',len(candidates))
for c in candidates:print(c['model'],c['field'],c['refs'])
