from pathlib import Path
import json,hashlib
p=Path('/workspace/evidence/pr230-performance-repair-20261009/BREAD2/requests');assert not (p.parent/'followed-instance.json').exists()
f=p/'BREAD2.json';r=json.loads(f.read_text());r['app_env_overrides']['RUST_LOG']='warn,nazoauth::jobs::security_state=debug';f.write_text(json.dumps(r,indent=2));f2=p/'manifest.json';m=json.loads(f2.read_text());m['decision_follow']=True;m['decision_observe_budget_s']=540;m['requests']['BREAD2']['sha256']=hashlib.sha256(f.read_bytes()).hexdigest();f2.write_text(json.dumps(m,indent=2));print('BREAD2 will follow final application and unchanged retention through natural cleanup, bounded at 540 seconds')
