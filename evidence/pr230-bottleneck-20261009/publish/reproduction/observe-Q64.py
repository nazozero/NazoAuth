from pathlib import Path
import subprocess,time,json
p=Path('/workspace/evidence/pr230-bottleneck-20261009/Q64');name='r230-bottleneck-q64-20261009-nazoauth-1'
deadline=time.monotonic()+100
log=p.parent/'Q64-Q64.log'
while time.monotonic()<deadline:
 if log.exists() and 'collector-preflight' in log.read_text():break
 time.sleep(1)
else:raise RuntimeError('Q64 load preflight not observed')
time.sleep(16)
cmd=['docker','exec',name,'sh','-c','for f in /proc/1/task/*/schedstat; do printf "%s " "$f"; cat "$f"; done']
with (p/'app-thread-schedstat.jsonl').open('w') as f:
 for i in range(6):
  r=subprocess.run(cmd,capture_output=True,text=True);row={'ts':time.time(),'exit':r.returncode,'threads':{}}
  for l in r.stdout.splitlines():
   a=l.split()
   if len(a)==4:row['threads'][a[0].split('/')[-2]]=list(map(int,a[1:]))
  f.write(json.dumps(row)+'\n');f.flush()
  if r.returncode:break
  time.sleep(5)
print('captured application thread scheduler counters inside its container')

