from pathlib import Path
import concurrent.futures, hashlib, io, json, subprocess, tarfile, time
R=Path('/workspace'); E=R/'evidence/pr238-reverify-20261009'; E.mkdir(exist_ok=True)
SHA='e8242c44aab842e1828b471413905f74b4132325'
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()==SHA
def run(key,cmd,data=None):
    started=time.monotonic()
    with (E/(key+'.log')).open('wb') as out:
        result=subprocess.run(cmd,cwd=R,input=data,stdout=out,stderr=subprocess.STDOUT)
    row={'command':cmd,'exit':result.returncode,'seconds':time.monotonic()-started}
    (E/(key+'-exit.json')).write_text(json.dumps(row));print(key,row['exit'],flush=True)
    if result.returncode:raise RuntimeError(key+' failed')
def dockerfile(key,text,files=None):
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w') as t:
        for name,value in [('Dockerfile',text.encode()),*(files or {}).items()]:
            member=tarfile.TarInfo(name);member.size=len(value);t.addfile(member,io.BytesIO(value))
    run('image-'+key,['docker','build','-t','nazoauth-reverify-'+key+':20261009','-'],data.getvalue())
def binaries():
    run('release',['docker','exec','-e','CARGO_TARGET_DIR=/src/target','nazoauth-perf-runner-20261009','cargo','build','--release','--locked','-p','nazoauth'])
    run('receiver',['docker','exec','-e','CARGO_TARGET_DIR=/src/target','nazoauth-perf-runner-20261009','cargo','build','--release','--locked','--manifest-path','perf/audit-anchor-receiver/Cargo.toml'])
    for name in ['nazoauth','nazo-audit-anchor-receiver']:
        run('copy-'+name,['docker','cp','nazoauth-perf-runner-20261009:/src/target/release/'+name,str(E/name)])
def images():
    for name,path in [('load','perf/runner/Containerfile'),('keyset','perf/keyset/Containerfile')]:
        run('image-'+name,['docker','build','-f',path,'-t','nazoauth-reverify-'+name+':20261009','.'])
    s=(R/'Containerfile').read_text();a=s.index('FROM docker.io/library/debian:');b=s.index('FROM runtime-base AS runtime',a)
    dockerfile('runtime',s[a:b])
    dockerfile('controller','FROM nazoauth-reverify-load:20261009\nRUN apk add --no-cache gcc musl-dev git docker-cli-compose\n')
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    tasks=[executor.submit(binaries),executor.submit(images)]
    for task in tasks:task.result()
dockerfile('app','FROM nazoauth-reverify-runtime:20261009\nLABEL org.opencontainers.image.revision="'+SHA+'"\nCOPY --chmod=0755 nazoauth /usr/local/bin/nazoauth\nCOPY source-sha /etc/nazoauth-source-sha\nCOPY env.yaml /app/.env.yaml\nUSER 10001:10001\nCMD ["nazoauth", "server"]\n',{'nazoauth':(E/'nazoauth').read_bytes(),'source-sha':(SHA+'\n').encode(),'env.yaml':(R/'perf/env.yaml').read_bytes()})
dockerfile('receiver','FROM nazoauth-reverify-runtime:20261009\nCOPY --chmod=0755 receiver /usr/local/bin/nazo-audit-anchor-receiver\nENTRYPOINT ["nazo-audit-anchor-receiver"]\n',{'receiver':(E/'nazo-audit-anchor-receiver').read_bytes()})
run('controller-up',['docker','run','-d','--name','nazoauth-reverify-controller-20261009','--workdir','/src','-v','/workspace:/src','-v','/var/run/docker.sock:/var/run/docker.sock','--entrypoint','sh','nazoauth-reverify-controller:20261009','-c','sleep infinity'])
info={'source_sha':SHA,'binary_sha256':hashlib.sha256((E/'nazoauth').read_bytes()).hexdigest(),'images':{}}
for key in ['app','receiver','keyset','load','controller']:
    info['images'][key]=subprocess.check_output(['docker','image','inspect','nazoauth-reverify-'+key+':20261009','--format','{{.Id}}'],text=True).strip()
(E/'build.json').write_text(json.dumps(info,indent=2));print('BUILD_READY',flush=True)
