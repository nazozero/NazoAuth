import pathlib,subprocess,io,tarfile,hashlib,json
p=pathlib.Path('/workspace');e=p/'evidence/pr230-performance-repair-20261009'
source=(e/'read-source-sha.txt').read_text().strip()
for name in ['read']:
 binary=(e/(name+'-nazoauth')).read_bytes();files={'nazoauth':binary,'source-sha':source.encode(),'env.yaml':(p/'perf/env.yaml').read_bytes()}
 files['Dockerfile']=('FROM nazoauth-perf-runtime-base:20261009\nLABEL org.opencontainers.image.revision="'+source+'"\nCOPY --chmod=0755 nazoauth /usr/local/bin/nazoauth\nCOPY source-sha /etc/nazoauth-source-sha\nCOPY env.yaml /app/.env.yaml\nUSER 10001:10001\nCMD ["nazoauth", "server"]\n').encode()
 data=io.BytesIO()
 with tarfile.open(fileobj=data,mode='w') as t:
  for k,b in files.items():i=tarfile.TarInfo(k);i.size=len(b);t.addfile(i,io.BytesIO(b))
 with (e/('image-'+name+'.log')).open('w') as f:r=subprocess.run(['docker','build','-t','nazoauth-perf-'+name+':20261009','-'],input=data.getvalue(),stdout=f,stderr=subprocess.STDOUT)
 assert r.returncode==0
 row={'image':subprocess.check_output(['docker','image','inspect','nazoauth-perf-'+name+':20261009','--format','{{.Id}}'],text=True).strip(),'source_sha':source,'binary_sha256':hashlib.sha256(binary).hexdigest(),'diagnostic_patch':name=='diagnostic'}
 (e/('image-'+name+'.json')).write_text(json.dumps(row));print(name,row)


