import hashlib,json,os,subprocess,time
from pathlib import Path
root=Path('/workspace/perf-results/failed-point-retest-20260929T104036Z')
done=set()
while time.time()<1790681736:
    if (root/'manifest.json').exists():
        m=json.loads((root/'manifest.json').read_text())
        env={**os.environ,'SIS_RESULTS':str(root),'SIS_PROJECT':m['project'],'SIS_PERF_IMAGE':m['runner_image']}
        for spec in sorted(root.glob('request-*.json')):
            if spec.name in done: continue
            p=json.loads(spec.read_text()); d=root/p['phase']/p['name']
            names=['load']+[s['name'] for s in p.get('sidecars',[])]
            if all((d/n/'latest.json').exists() for n in names):
                subprocess.run(['python3','/tmp/pr222-post-measurement.py',str(spec)],env=env,timeout=45)
                done.add(spec.name)
                print(json.dumps({'captured':spec.name,'ts':time.time()}),flush=True)
    if (root/'cleanup.json').exists(): break
    time.sleep(0.5)
