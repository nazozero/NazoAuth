from pathlib import Path
import subprocess,json,time
E=Path('/workspace/evidence/pr238-physical-growth-20261010');D=E/'CC_RETEST';assert (D/'execution.json').exists(),'Do not overlap final load/observation'
assert json.loads(next(D.glob('results/*/*/task-cleanup.json')).read_text())['containers_remaining']==[]
owner='pr238-physical-quality-20261010';pg=owner+'-pg';vk=owner+'-vk';records=[]
def call(cmd):
 start=time.time();r=subprocess.run(cmd,capture_output=True,text=True);rec={'command':cmd,'exit':r.returncode,'start':start,'end':time.time()};records.append(rec)
 if r.returncode:raise RuntimeError('Owned fixture command failed: '+str(cmd))
 return r.stdout
for name in [pg,vk]:
 meta=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]
 assert meta['Config']['Labels'].get('diag.owner')==owner
 assert not meta['State']['Running']
net=json.loads(subprocess.check_output(['docker','network','inspect',owner],text=True))[0];assert net['Labels'].get('diag.owner')==owner
call(['docker','start',pg])
for _ in range(30):
 if subprocess.run(['docker','exec',pg,'pg_isready','-U','postgres','-d','oauth'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
 time.sleep(1)
else:raise RuntimeError('quality PG readiness')
call(['docker','cp','/tmp/physical-index-probe.sql',pg+':/tmp/physical-index-probe.sql'])
call(['python3','/tmp/physical-quality-command.py','index-key-probe-final','docker','exec',pg,'psql','-X','-U','postgres','-d','oauth','-v','ON_ERROR_STOP=1','-f','/tmp/physical-index-probe.sql'])
call(['docker','stop',pg])
call(['docker','rm','-v',pg,vk])
call(['docker','network','disconnect',owner,'nazoauth-long-builder-20261010'])
call(['docker','network','rm',owner])
for name in ['/tmp/physical-quality.env','/tmp/physical-quality-postgres.env']:Path(name).unlink()
(E/'quality'/'fixture-finalization.json').write_text(json.dumps({'owner':owner,'records':records,'private_test_env_removed':True},indent=2));print(json.dumps({'commands':len(records),'exit':0}))