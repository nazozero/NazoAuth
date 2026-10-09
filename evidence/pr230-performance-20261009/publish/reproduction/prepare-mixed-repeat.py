from pathlib import Path
import json,hashlib
E=Path('/src/evidence/pr230-performance-20261009')
s=(E/'point-wrapper.py').read_text();hook='''
original_pin=ctl.sis.pin_container
def pin_with_evidence(container,cpus):
 for attempt in range(3):
  result=original_pin(container,cpus)
  with (ctl.E/'pin-attempts.jsonl').open('a') as f:f.write(json.dumps({'ts':time.time(),'attempt':attempt+1,'result':result})+'\\n')
  if result['verified']:return result
  time.sleep(.25)
 return result
ctl.sis.pin_container=pin_with_evidence
'''
s=s.replace('original_audit=ctl.sis.audit_pair_up',hook+'\noriginal_audit=ctl.sis.audit_pair_up');(E/'point-wrapper-retry.py').write_text(s)
for oldkey in ['A03','B03','B04','A04']:
 key=oldkey+'R';old=E/oldkey;new=E/key;(new/'requests').mkdir(parents=True,exist_ok=True)
 r=json.loads((old/'requests'/f'{oldkey}.json').read_text());r.update(name=f'pr230-perf-{key.lower()}-20261009',request_key=key,replicate=2);f=new/'requests'/f'{key}.json';f.write_text(json.dumps(r,indent=2));m=json.loads((old/'requests/manifest.json').read_text());m.update(project=r['name'],requests={key:{'path':str(f),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}},repeat_reason='Initial load process affinity setup failed; preserve attempts and retry pinning up to three times; all original full affinity and common window gates remain');(new/'requests/manifest.json').write_text(json.dumps(m,indent=2))
print('prepared four scoped repeats; no production source edits')
