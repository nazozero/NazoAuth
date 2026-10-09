from pathlib import Path
import json,hashlib
p=Path('/workspace/evidence/pr230-bottleneck-20261009')
for key,size in [('Q32',32),('Q64',64)]:
 d=p/key;(d/'requests').mkdir(parents=True,exist_ok=True);r=json.loads((p/'B06R2/requests/B06R2.json').read_text());m=json.loads((p/'B06R2/requests/manifest.json').read_text());r.update(name='r230-bottleneck-'+key.lower()+'-20261009',request_key=key,diagnostic_only=True,pool_connections=size,diagnostic_purpose='single-variable pool size; not original-configuration acceptance');r['app_env_overrides']['DATABASE_MAX_CONNECTIONS']=str(size);f=d/'requests'/f'{key}.json';f.write_text(json.dumps(r,indent=2));m.update(project=r['name'],decision_follow=False,diagnostic_only=True,requests={key:{'path':str(f).replace('/workspace','/src',1),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}});(d/'requests/manifest.json').write_text(json.dumps(m,indent=2));print(key,r['source_sha'],r['rate'],r['pre_vus'],size)
