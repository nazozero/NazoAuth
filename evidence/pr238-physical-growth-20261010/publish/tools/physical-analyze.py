from pathlib import Path
import subprocess,json,time,sys
E=Path('/workspace/evidence/pr238-physical-growth-20261010');T=E/'tools';T.mkdir(exist_ok=True)
for name in ['longrun-analyze','longrun-resource-analysis','longrun-inflight']:
 s=Path('/tmp/'+name+'.py').read_text().replace('/workspace/evidence/pr238-longrun-20261010',str(E))
 script=T/(name.replace('longrun-','')+'.py');script.write_text(s)
 cmd=['python3',str(script),*sys.argv[1:]];start=time.time()
 r=subprocess.run(cmd,capture_output=True,text=True)
 label=name+'-'+'-'.join(sys.argv[1:]);(T/(label+'.log')).write_text(r.stdout+r.stderr)
 (T/(label+'-exit.json')).write_text(json.dumps({'command':cmd,'exit':r.returncode,'start':start,'end':time.time()},indent=2))
 print(name,r.returncode,r.stdout[-1800:],r.stderr[-400:]);assert r.returncode==0
