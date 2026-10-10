from pathlib import Path
import json,subprocess,time
R=Path('/workspace');E=R/'evidence/pr238-reverify-20261009'
assert (E/'build.json').exists()
for key in ['REV360','MIX300']:
    for action in ['setup',key]:
        cmd=['docker','exec','-e','SIS_WORKSPACE=/src','-e','SIS_CNB_EVIDENCE=/src/evidence/pr238-reverify-20261009/'+key,'-w','/src','nazoauth-reverify-controller-20261009','python','/src/evidence/pr238-reverify-20261009/point-observer-cycle.py',action]
        start=time.monotonic()
        with (E/(key+'-'+action+'.log')).open('w') as out:
            proc=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT)
        record={'key':key,'action':action,'command':cmd,'exit':proc.returncode,'seconds':time.monotonic()-start}
        with (E/'commands.jsonl').open('a') as out:out.write(json.dumps(record)+'\n')
        print(record,flush=True)
        if action=='setup' and proc.returncode:raise SystemExit(proc.returncode)
        if action!='setup' and proc.returncode not in [0,2,3]:raise SystemExit(proc.returncode)
        if action!='setup':
            # Preserve first cleanup result; remove only this test project's own
            # stopped leftovers before starting the next isolated point.
            project=json.loads((E/key/'requests/manifest.json').read_text())['project']
            ids=subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project='+project],text=True).split()
            removed=[]
            for cid in ids:
                d=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0]
                assert d['Config']['Labels']['com.docker.compose.project']==project
                assert not d['State']['Running'],'Do not hide an unfinished running test'
                subprocess.run(['docker','rm',cid],check=True,capture_output=True)
                removed.append(cid)
            (E/key/'cleanup-followup.json').write_text(json.dumps({'removed_stopped_owned_containers':removed}))
