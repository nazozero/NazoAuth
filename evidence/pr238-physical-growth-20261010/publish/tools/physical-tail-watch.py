from pathlib import Path
import json,subprocess,time,sys
E=Path('/workspace/evidence/pr238-physical-growth-20261010');D=E/sys.argv[1]
p=json.loads((D/'requests'/(sys.argv[1]+'.json')).read_text());pg=p['name']+'-postgres-1'
deadline=time.monotonic()+p['phase_budget_seconds']
while not (D/'load-ended.json').exists():
 if time.monotonic()>deadline:raise RuntimeError('no load completion within point budget')
 if (D/'execution.json').exists():raise RuntimeError('point ended before workload')
 time.sleep(2)
sql="SELECT json_build_object('ts',extract(epoch from clock_timestamp()),'issuance_count',count(*),'last_retain_until',max(retain_until),'last_retain_epoch',extract(epoch from max(retain_until)),'last_decision_retain_until',(SELECT max(business_retain_until) FROM security_audit_events WHERE event_type='authorization_decision_committed')) FROM oauth_token_issuances"
r=subprocess.run(['docker','exec',pg,'psql','-X','-A','-t','-U','postgres','-d','oauth','-v','ON_ERROR_STOP=1','-c',sql],capture_output=True,text=True)
assert r.returncode==0,r.stderr
row=json.loads(r.stdout);(D/'last-receipt-cohort.json').write_text(json.dumps(row,indent=2));print(json.dumps(row))
