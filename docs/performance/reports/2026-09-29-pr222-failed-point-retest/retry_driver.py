"""Repair only controller evidence-finalization timeout; rerun INVALID attempts."""
import json,os,sys,time
from pathlib import Path
root=Path('/workspace');sys.path.insert(0,str(root/'perf/tools'));import short_baseline as sb
out=root/'perf-results/failed-point-retest-20260929T104036Z'
started=sb.started_epoch('2026-09-29T10:40:36Z');sb.COMMAND_DEADLINE=started+3300
while not (out/'cleanup.json').exists() and time.time()<sb.COMMAND_DEADLINE-300:time.sleep(5)
if not (out/'cleanup.json').exists():raise SystemExit('Original task exceeded load budget')
time.sleep(1)
m=json.loads((out/'manifest.json').read_text());summ=json.loads((out/'summary.json').read_text())
env={**os.environ,'SIS_WORKSPACE':str(root),'SIS_RESULTS':str(out),'SIS_BIN':str(out/'bin'),'SIS_PROJECT':m['project'],'SIS_PERF_IMAGE':m['runner_image'],'SIS_SOURCE_SHA':m['source_sha'],'SIS_APP_SHA':m['source_sha'],'SIS_LOAD_BUDGET_S':'2700'}
attempts=[]
for i,row in enumerate(list(summ['points'])):
    if row['verdict']!='INVALID':continue
    original=json.loads((out/f'request-{i}.json').read_text());window=original['effective_seconds']
    budget=sb.point_budget(window,original['scenario']=='cap_mixed')+60
    if time.time()+budget>sb.COMMAND_DEADLINE:break
    pt={**original,'name':f'retry{i}-'+str(int(time.time()))}
    pt.pop('deployment_id',None)
    # Fresh request recipes; worker mutates its private copy, not this frozen file.
    spec=out/f'request-retry-{i}.json';sb.save(spec,pt)
    print(json.dumps({'event':'RETRY_START','index':i,'name':pt['name'],'timeout_s':budget,'original_verdict':row['verdict'],'time':time.time()}),flush=True)
    rc=sb.bounded_child([sys.executable,str(root/'perf/tools/short_baseline.py'),'--worker',str(spec)],env,out/f'retry-{i}.log',budget)
    result=out/pt['phase']/pt['name']/'short-result.json'
    attempts.append({'original_attempt':row,'retry_request':spec.name,'timeout_repair':'original full worker budget +60s for residency/evidence finalization; formal windows and original gates unchanged'})
    if rc==0 and result.exists():
        sb.bounded_child([sys.executable,'/tmp/pr222-post-measurement.py',str(spec)],env,out/f'retry-post-{i}.log',45)
        summ['points'][i]=json.loads(result.read_text())
    else:summ['points'][i]={**row,'name':pt['name'],'exit_code':rc}
    print(json.dumps({'event':'RETRY_END','index':i,'verdict':summ['points'][i]['verdict'],'time':time.time()}),flush=True)
summ['attempts_preserved']=attempts
valid=len(summ['points'])==4 and all(r['verdict'] in ('PASS','FAIL') for r in summ['points'])
summ['status']='COMPLETE' if valid else 'INCOMPLETE'
summ['acceptance_status']=('PASS' if all(r['verdict']=='PASS' for r in summ['points']) else 'FAIL') if valid else 'INVALID'
summ['missing_valid_cases']=[r['name'] for r in summ['points'] if r['verdict']=='INVALID']
summ['elapsed_seconds']=round(time.time()-started,1)
sb.save(out/'summary-before-timeout-repair.json',json.loads((out/'summary.json').read_text()))
sb.save(out/'summary.json',summ)
sb.COMMAND_DEADLINE=started+3540
sb.save(out/'retry-cleanup.json',sb.own_cleanup(m['project']))
sb.save(out/'retry-finished.json',{'ts':time.time(),'status':summ['status']})
