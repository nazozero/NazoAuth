from pathlib import Path
import subprocess,time,json
p=Path('/src');e=p/'evidence/pr230-performance-repair-20261009';e.mkdir(exist_ok=True)
cmd=['cargo','build','--release','--locked','-p','nazoauth'];t=time.monotonic()
with (e/'read-build.log').open('w') as f:r=subprocess.run(cmd,cwd=p,stdout=f,stderr=subprocess.STDOUT)
print(dict(command=cmd,exit=r.returncode,seconds=time.monotonic()-t));assert r.returncode==0
import shutil,hashlib
shutil.copy2('/src/target/release/nazoauth',e/'read-nazoauth')
print('binary_sha256',hashlib.file_digest((e/'read-nazoauth').open('rb'),'sha256').hexdigest())


