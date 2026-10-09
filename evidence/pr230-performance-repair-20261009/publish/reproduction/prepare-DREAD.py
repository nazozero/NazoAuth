from pathlib import Path
import json,hashlib
p=Path('/workspace');e=p/'evidence/pr230-performance-repair-20261009';key='DREAD';out=e/key;(out/'requests').mkdir(parents=True,exist_ok=True)
a=json.loads((e/'image-diagnostic-read.json').read_text());r=json.loads((e/'R16/requests/R16.json').read_text());m=json.loads((e/'R16/requests/manifest.json').read_text());r.update(name='r230-repair-dread-20261009',request_key=key,image=a['image'],expected_binary_sha256=a['binary_sha256'],diagnostic_purpose='connection holding and borrower query wake-to-poll; no scheduling changes',diagnostic_only=True);f=out/'requests'/f'{key}.json';f.write_text(json.dumps(r,indent=2));m.update(project=r['name'],app_image=a['image'],requests={key:{'path':str(f).replace('/workspace','/src',1),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}});(out/'requests/manifest.json').write_text(json.dumps(m,indent=2))
print(key,r['rate'],r['pre_vus'])
