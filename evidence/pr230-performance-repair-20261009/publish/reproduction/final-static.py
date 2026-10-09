from pathlib import Path
import subprocess,json,time
p=Path('/workspace');e=p/'evidence/pr230-performance-repair-20261009'
assert not subprocess.check_output(['git','diff','--name-only'],cwd=p,text=True).strip()
commands=[['python','scripts/verify_static_contracts.py','--check'],['python','scripts/check_persistence_dependency_graph.py'],['python','scripts/check_crypto_boundary.py'],['python','-m','unittest','discover','-s','scripts','-p','test_crypto_boundary.py'],['python','scripts/check_perf_results_layout.py']]
for i,cmd in enumerate(commands):
 actual=['docker','exec','-e','PATH=/tmp/nazo-quality-bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin','-w','/src','nazoauth-perf-controller-20261009']+cmd;t=time.monotonic();r=subprocess.run(actual,capture_output=True,text=True);(e/f'final-static-{i}.log').write_text(r.stdout+r.stderr);row={'command':actual,'exit':r.returncode,'seconds':time.monotonic()-t};(e/f'final-static-{i}-exit.json').write_text(json.dumps(row));print(row);print((r.stdout+r.stderr)[-2000:]);assert not r.returncode

