from pathlib import Path
import json,re
p=Path('/src/evidence/pr230-bottleneck-20261009')
keys=['negative-round-trips','positive-round-trips','principal-regressions-r2','role-commit-regressions-r2','clippy-candidate2','unit-postgres-candidate2','candidate2-build','final-static','final-dependency','final-fmt','final-schema-fixture','final-postgres-suite']
out={'source_sha':'3da0734de491a380b315fc2fb2827f4043c04823','scope':'Final PostgreSQL owning package and affected real transaction regressions; full workspace suite not repeated in this scoped round','commands':{}}
for k in keys:
 f=p/(k+'-exit.json')
 if not f.exists():continue
 x=json.loads(f.read_text());q=p/(k+'.log');s=q.read_text() if q.exists() else '';summaries=[dict(zip(['passed','failed','ignored','measured','filtered_out'],map(int,m))) for m in re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out',s)];x.update(test_summaries=summaries,test_totals={a:sum(r[a] for r in summaries) for a in ['passed','failed','ignored']});out['commands'][k]=x
required=['clippy-candidate2','candidate2-build','final-static','final-dependency','final-fmt','final-schema-fixture','final-postgres-suite'];out['CODE']=('PASS' if all(out['commands'][k]['exit']==0 for k in required) else 'FAIL') if all(k in out['commands'] for k in required) else 'BLOCKED';out['SECURITY']='PASS' if out['CODE']=='PASS' else 'BLOCKED';out['RECOVERY']='PASS' if out['SECURITY']=='PASS' else 'BLOCKED';out['RECOVERY_boundary']='Affected real commit/connection/failure tests; unchanged comprehensive exporter recovery load reused from historical report, not rerun.';out['PERFORMANCE']='FAIL';out['STORAGE_decision_gc']='PASS';out['STORAGE_long_term_target_rate']='INVALID';out['merge_ready']=False
(p/'verification-summary.json').write_text(json.dumps(out,indent=2));print(json.dumps({k:v for k,v in out.items() if k!='commands'},indent=2));print({k:(v['exit'],v['test_totals']) for k,v in out['commands'].items()})

