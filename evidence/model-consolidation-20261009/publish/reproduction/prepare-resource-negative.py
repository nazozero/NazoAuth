from pathlib import Path
import subprocess,json,time,os
R=Path('/workspace');E=R/'evidence/model-consolidation-20261009'
commit='b1ad9bf3ce2dd952aedbae46e74b79be1f956a3b'
for f in ['crates/resource-server/tests/unit/lib.rs','crates/resource-server/tests/unit/lib/access_token_profile.rs']:
 s=subprocess.check_output(['git','show',commit+':'+f],cwd=R,text=True)
 if f.endswith('access_token_profile.rs'):
  s=s.replace('let mut missing = claims(now);','let mut missing = claims(now);\n    missing["token_use"] = json!("access");')
  s=s.replace('claims["iat"] = invalid;','claims["token_use"] = json!("access");\n        claims["iat"] = invalid;')
  s=s.replace('fractional["iat"] =', 'fractional["token_use"] = json!("access");\n    fractional["iat"] =')
 (R/f).write_text(s)
cmd=['docker','exec','-w','/src','nazoauth-perf-runner-20261009','cargo','test','-p','nazo-resource-server','--lib','access_token_profile','--locked']
t=time.monotonic()
with (E/'resource-profile-negative.log').open('w') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
(E/'resource-profile-negative-exit.json').write_text(json.dumps(dict(command=cmd,exit=r.returncode,seconds=time.monotonic()-t)))
print(r.returncode);print((E/'resource-profile-negative.log').read_text()[-7000:])
