from pathlib import Path
import subprocess,io,tarfile,hashlib,json
R=Path('/workspace');E=R/'evidence/model-consolidation-20261009';old=R/'evidence/pr230-performance-repair-20261009'
source=(E/'final-source-sha.txt').read_text().strip();assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()==source
for n in ['final-fmt','final-clippy','final-workspace','final-explicit-fapi','final-release']:
 assert json.loads((E/(n+'-exit.json')).read_text())['exit']==0,n
binary=(E/'final-nazoauth').read_bytes();files={'nazoauth':binary,'source-sha':source.encode(),'env.yaml':(R/'perf/env.yaml').read_bytes()}
files['Dockerfile']=('FROM nazoauth-perf-runtime-base:20261009\nLABEL org.opencontainers.image.revision="'+source+'"\nCOPY --chmod=0755 nazoauth /usr/local/bin/nazoauth\nCOPY source-sha /etc/nazoauth-source-sha\nCOPY env.yaml /app/.env.yaml\nUSER 10001:10001\nCMD ["nazoauth", "server"]\n').encode()
data=io.BytesIO()
with tarfile.open(fileobj=data,mode='w') as t:
 for k,b in files.items():i=tarfile.TarInfo(k);i.size=len(b);t.addfile(i,io.BytesIO(b))
tag='nazoauth-perf-model-final:20261009'
with (E/'image-final.log').open('w') as f:r=subprocess.run(['docker','build','-t',tag,'-'],input=data.getvalue(),stdout=f,stderr=subprocess.STDOUT)
assert r.returncode==0
image=subprocess.check_output(['docker','image','inspect',tag,'--format','{{.Id}}'],text=True).strip()
row={'image':image,'source_sha':source,'binary_sha256':hashlib.sha256(binary).hexdigest(),'diagnostic_patch':False};(E/'image-final.json').write_text(json.dumps(row));print(row)
tree=subprocess.check_output(['git','rev-parse',source+'^{tree}'],cwd=R,text=True).strip()
for key,prior in [('MODEL02','BREAD2'),('MODEL10','BREAD10'),('MODEL03','BREAD03'),('MODEL04','BREAD04')]:
 out=E/key;(out/'requests').mkdir(parents=True,exist_ok=True);r=json.loads((old/prior/'requests'/f'{prior}.json').read_text());m=json.loads((old/prior/'requests/manifest.json').read_text())
 r.update(name='r230-model-'+key.lower()+'-20261009',request_key=key,arm='B',source_sha=source,source_tree=tree,image=image,expected_binary_sha256=row['binary_sha256'],diagnostic_only=False)
 f=out/'requests'/f'{key}.json';f.write_text(json.dumps(r,indent=2));m.update(project=r['name'],source_sha=source,app_image=image,requests={key:{'path':str(f).replace('/workspace','/src',1),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}},repeat_reason='Final model consolidation changed authorization payloads and refresh representation; affected original four capacity points only.')
 (out/'requests/manifest.json').write_text(json.dumps(m,indent=2));print(key,r['rate'],r['pre_vus'],r['duration'],r['app_env_overrides']['AUDIT_ANCHOR_MODE'],m.get('decision_follow'))
# Unit fixture is no longer being used, and must not contend with measurements.
subprocess.run(['docker','stop','nazoauth-perf-unit-pg-20261009'],check=True,capture_output=True)
