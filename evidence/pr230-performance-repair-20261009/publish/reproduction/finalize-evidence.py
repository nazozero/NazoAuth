from pathlib import Path
import subprocess,json,re,hashlib,datetime
E=Path('/src/evidence/pr230-performance-repair-20261009');p=Path('/src')
source='ef89417c9377ea765878b24d7b034a189638dee3'
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=p,text=True).strip()==source
assert not subprocess.check_output(['git','diff','--name-only'],cwd=p,text=True).strip()
names=['positive-read-ownership','read-clippy','read-affected-tests','read-integration','final-fmt','final-schema','final-workspace','final-explicit-fapi']+['final-static-'+str(n) for n in range(5)]
checks=[]
for name in names:
 r=json.loads((E/(name+'-exit.json')).read_text());assert r['exit']==0,(name,r)
 log=(E/(name+'.log')).read_text(errors='replace')
 counts=[tuple(map(int,m)) for m in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',log)]
 r.update(name=name,test_result_counts={'passed':sum(x[0] for x in counts),'failed':sum(x[1] for x in counts),'ignored':sum(x[2] for x in counts),'result_groups':len(counts)})
 if name=='final-static-3':
  m=re.search(r'Ran (\d+) tests',log);assert m and '\nOK\n' in log;r['test_result_counts'].update(passed=int(m[1]),result_groups=1)
 if name=='final-explicit-fapi':assert r['test_result_counts']['passed']==1
 if name in ['positive-read-ownership','read-affected-tests','read-integration','final-schema','final-workspace']:assert r['test_result_counts']['passed']>0,name
 checks.append(r)
negative=json.loads((E/'negative-read-ownership-exit.json').read_text());assert negative['exit']==101
assert 'completed database read still holds the sole pool connection' in (E/'negative-read-ownership.log').read_text()
metrics=json.loads((E/'acceptance-metrics.json').read_text());by={r['key']:r for r in metrics}
for k in ['BREAD','BREAD2','BREAD03','BREAD04','BREAD10']:
 r=by[k];assert r['source_sha']==source and r['verdict']=='PASS' and not r['diagnostic_only']
 assert r['unfinished']==0 and all(r['health'].values()) and all(r['audit']['checks'].values())
gc=json.loads((E/'BREAD2/decision-natural-reclamation.json').read_text())
assert gc['status']=='PASS' and gc['same_final_instance'] and gc['cohort_size']==gc['natural_delete_total']==60001
summary={'source_sha':source,'CODE':'PASS','SECURITY':'PASS','RECOVERY':'PASS','PERFORMANCE':'PASS','STORAGE':'PASS','scope':'This targeted round: final-source full workspace and affected real database regressions; four original capacity points; natural decision cohort reclamation. No claim of indefinite disk boundedness or long-term target-load plateau. Historical severe slowdown exclusive attribution remains unproven. Unchanged complete recovery fault loads use historical evidence. CI separate after publication.','checks':checks,'negative_behavior':negative,'natural_reclamation':gc,'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
(E/'verification-summary.json').write_text(json.dumps(summary,indent=2))
src={'source_sha':source,'baseline_sha':'5005b39182f42c53537ed45ce21a72db7db92af5','baseline_underlying_source':'3da0734de491a380b315fc2fb2827f4043c04823','candidate_binary_sha256':'1511cd33e1f3ea8586fce9e29109e8107048e9e9ef5b8b114155fbe60f873fd7','baseline_binary_sha256':'7b199250bb8fb82f8fee2b084d465081b9ddd8532c703f8216a2776ebebaa35d','tracked_tree_clean':True,'diagnostic_overlay_removed':True}
(E/'final-source.json').write_text(json.dumps(src,indent=2))
print(json.dumps({'checks':checks,'source':src},indent=2))
