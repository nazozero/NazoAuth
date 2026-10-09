from pathlib import Path
import json,hashlib
p=Path('/workspace');e=p/'evidence/pr230-performance-repair-20261009'
for key,origin,arm in [('AREAD','R16','A'),('BREAD2','BREAD','B')]:
 out=e/key;(out/'requests').mkdir(parents=True,exist_ok=True);r=json.loads((e/origin/'requests'/f'{origin}.json').read_text());m=json.loads((e/origin/'requests/manifest.json').read_text());r.update(name='r230-repair-'+key.lower()+'-20261009',request_key=key,arm=arm,diagnostic_only=False);r.pop('diagnostic_purpose',None);f=out/'requests'/f'{key}.json';f.write_text(json.dumps(r,indent=2));m.update(project=r['name'],diagnostic_only=False,requests={key:{'path':str(f).replace('/workspace','/src',1),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}});(out/'requests/manifest.json').write_text(json.dumps(m,indent=2));print(key,r['source_sha'],r['rate'],r['pre_vus'])
