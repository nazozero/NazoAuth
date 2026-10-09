from pathlib import Path
import subprocess,json,time
R=Path('/workspace');E=R/'evidence/model-consolidation-20261009'
commands=[['python','scripts/verify_static_contracts.py','--check'],['python','scripts/check_persistence_dependency_graph.py'],['python','scripts/check_crypto_boundary.py'],['python','-m','unittest','discover','-s','scripts','-p','test_crypto_boundary.py'],['python','scripts/check_perf_results_layout.py'],['python','-m','unittest','discover','-s','scripts','-p','test_data_model_inventory.py']]
for i,cmd in enumerate(commands):
 actual=['docker','exec','-e','PATH=/tmp/nazo-quality-bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin','-w','/src','nazoauth-perf-controller-20261009']+cmd;t=time.monotonic();r=subprocess.run(actual,capture_output=True,text=True);(E/f'final-static-{i}.log').write_text(r.stdout+r.stderr);row={'command':actual,'exit':r.returncode,'seconds':time.monotonic()-t};(E/f'final-static-{i}-exit.json').write_text(json.dumps(row));print(row);print((r.stdout+r.stderr)[-1600:]);assert not r.returncode
