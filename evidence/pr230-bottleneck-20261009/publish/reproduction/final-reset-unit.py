import subprocess,time,json
from pathlib import Path
p=Path('/workspace/evidence/pr230-bottleneck-20261009');rows=[]
for cmd in [['docker','start','nazoauth-perf-unit-pg-20261009']]:
 r=subprocess.run(cmd,capture_output=True,text=True);assert not r.returncode,(r.stdout,r.stderr);rows.append({'command':cmd,'exit':r.returncode})
for _ in range(30):
 r=subprocess.run(['docker','exec','nazoauth-perf-unit-pg-20261009','pg_isready','-U','postgres'],capture_output=True,text=True)
 if not r.returncode:break
 time.sleep(.5)
assert r.returncode==0
for db in ['oauth','nazo_audit_test']:
 for sql in ['DROP DATABASE IF EXISTS '+db+' WITH (FORCE)','CREATE DATABASE '+db]:
  cmd=['docker','exec','nazoauth-perf-unit-pg-20261009','psql','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres','-c',sql];r=subprocess.run(cmd,capture_output=True,text=True);rows.append({'command':cmd,'exit':r.returncode});assert not r.returncode,(r.stdout,r.stderr)
(p/'final-unit-fixture-reset.json').write_text(json.dumps(rows,indent=2));print('Reset only the two isolated unit fixture databases; no performance database mutation')
