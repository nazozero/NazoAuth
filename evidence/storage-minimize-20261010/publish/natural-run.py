from pathlib import Path
import io,tarfile,subprocess,json,hashlib,time
R=Path('/workspace');E=R/'evidence/storage-minimize-20261010';O=R/'evidence/pr238-reverify-20261009';P=E/'natural-mixed';P.mkdir(exist_ok=False)
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()
assert not subprocess.check_output(['git','diff','HEAD','--','crates','migrations','perf','Cargo.toml','Cargo.lock'],cwd=R)
subprocess.run(['docker','cp','nazoauth-perf-runner-20261009:/src/target/release/nazoauth',str(E/'nazoauth')],check=True)
def build(text,files):
 data=io.BytesIO()
 with tarfile.open(fileobj=data,mode='w') as t:
  for name,value in [('Dockerfile',text.encode()),*files.items()]:
   info=tarfile.TarInfo(name);info.size=len(value);t.addfile(info,io.BytesIO(value))
 with (E/'app-image.log').open('wb') as out:r=subprocess.run(['docker','build','-t','nazoauth-storage-app:20261010','-'],input=data.getvalue(),stdout=out,stderr=subprocess.STDOUT)
 assert r.returncode==0
build('FROM nazoauth-reverify-runtime:20261009\nLABEL org.opencontainers.image.revision="'+sha+'"\nCOPY --chmod=0755 nazoauth /usr/local/bin/nazoauth\nCOPY source-sha /etc/nazoauth-source-sha\nCOPY env.yaml /app/.env.yaml\nUSER 10001:10001\nCMD ["nazoauth","server"]\n',{'nazoauth':(E/'nazoauth').read_bytes(),'source-sha':(sha+'\n').encode(),'env.yaml':(R/'perf/env.yaml').read_bytes()})
oldbuild=json.loads((O/'build.json').read_text());images=oldbuild['images'];images['app']=subprocess.check_output(['docker','image','inspect','nazoauth-storage-app:20261010','--format','{{.Id}}'],text=True).strip()
binary=hashlib.sha256((E/'nazoauth').read_bytes()).hexdigest();(E/'build.json').write_text(json.dumps({'source_sha':sha,'binary_sha256':binary,'images':images},indent=2))
(P/'diagnostic_controller.py').write_bytes((O/'diagnostic_controller.py').read_bytes())
(P/'observer.sql').write_bytes((O/'observer.sql').read_bytes())
s=(O/'point-observer-cycle.py').read_text().replace('/src/evidence/pr238-reverify-20261009','/src/evidence/storage-minimize-20261010/natural-mixed')
(P/'point-observer-cycle.py').write_text(s)
D=P/'MIX60';(D/'requests').mkdir(parents=True)
p=json.loads((O/'MIX300/requests/MIX300.json').read_text());old=json.loads(json.dumps(p))
for path,digest in p['harness_file_sha256'].items():assert hashlib.sha256((R/path).read_bytes()).hexdigest()==digest,path
p.update(name='pr238-natural-mix60-20261010',source_sha=sha,source_modified=False,image=images['app'],expected_binary_sha256=binary,status='TARGETED_NATURAL_RECLAMATION_WITH_ORIGINAL_LOAD',duration='120s',effective_seconds=60,replicate=4)
for sidecar in p['sidecars']:sidecar['duration']='150s'
for k in ['scenario','rate','warmup_ms','pre_vus','max_vus','user_count','gate','app_env_overrides','durability','stream_evidence','stream_workers']:assert p[k]==old[k],k
for a,b in zip(p['sidecars'],old['sidecars']):assert {k:v for k,v in a.items() if k!='duration'}=={k:v for k,v in b.items() if k!='duration'}
(D/'request-delta.json').write_text(json.dumps({k:{'before':old.get(k),'after':p.get(k)} for k in set(old)|set(p) if old.get(k)!=p.get(k)},indent=2))
target=D/'requests/MIX60.json';target.write_text(json.dumps(p,indent=2))
m=json.loads((O/'MIX300/requests/manifest.json').read_text());m.update(project=p['name'],source_sha=sha,app_image=images['app'],post_observe_s=0,requests={'MIX60':{'path':str(target).replace('/workspace/','/src/'),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}})
(D/'requests/manifest.json').write_text(json.dumps(m,indent=2))
for action in ['setup','MIX60']:
 cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE=/src/evidence/storage-minimize-20261010/natural-mixed/MIX60','-w','/src','nazoauth-reverify-controller-20261009','python','/src/evidence/storage-minimize-20261010/natural-mixed/point-observer-cycle.py',action]
 start=time.monotonic()
 with (P/(action+'.log')).open('w') as out:r=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
 record={'command':cmd,'exit':r.returncode,'seconds':time.monotonic()-start}
 with (P/'commands.jsonl').open('a') as out:out.write(json.dumps(record)+'\n')
 print(action,json.dumps(record),flush=True)
 if action=='setup' and r.returncode:raise SystemExit(r.returncode)
