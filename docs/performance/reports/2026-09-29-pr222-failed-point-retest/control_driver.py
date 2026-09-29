"""Optional single-factor diagnostic: code warmup 15->60s, original FAIL retained."""
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
root=Path('/workspace'); sys.path.insert(0,str(root/'perf/tools'));import short_baseline as sb
out=root/'perf-results/failed-point-retest-20260929T104036Z'
started=sb.started_epoch('2026-09-29T10:40:36Z');sb.COMMAND_DEADLINE=started+3300
while not (out/'retry-finished.json').exists() and time.time()<sb.COMMAND_DEADLINE-240:time.sleep(5)
if not (out/'retry-finished.json').exists():raise SystemExit('Mandatory original four points did not finish')
summary=json.loads((out/'summary.json').read_text())
if summary['status']!='COMPLETE':raise SystemExit('Mandatory four-point measurement incomplete; control skipped')
m=json.loads((out/'manifest.json').read_text())
env={**os.environ,'SIS_WORKSPACE':str(root),'SIS_RESULTS':str(out),'SIS_BIN':str(out/'bin'),'SIS_PROJECT':m['project'],'SIS_PERF_IMAGE':m['runner_image'],'SIS_SOURCE_SHA':m['source_sha'],'SIS_APP_SHA':m['source_sha'],'SIS_LOAD_BUDGET_S':'2700'}
pt=sb.make_point(m,'multi','cap_authorization_code',800,60,4)
pt['name']='c0-warmup60-'+str(int(time.time()));pt.update(warmup_ms=60000,duration='120s',residency_observer={'interval_s':0.25,'runtime_role':'nazoauth_perf_runtime'})
pt['control']={'factor':'authorization-code warmup_seconds','original':15,'control':60,'hypothesis':'Cold planner/statistics transient: original code failure recovers around first autoanalyze. No DB parameter or safety changes. Longer warmup also advances family/receipt population; cannot isolate generic-plan causality by itself.'}
path=out/'request-control-0.json';sb.save(path,pt)
print(json.dumps({'event':'CONTROL_START','name':pt['name'],'time':time.time()}),flush=True)
rc=sb.bounded_child([sys.executable,str(root/'perf/tools/short_baseline.py'),'--worker',str(path)],env,out/'control-0.log',min(240,sb.COMMAND_DEADLINE-time.time()))
result=out/'multi'/pt['name']/'short-result.json'
if rc==0 and result.exists():
    sb.bounded_child([sys.executable,'/tmp/pr222-post-measurement.py',str(path)],env,out/'control-post.log',45)
    row=json.loads(result.read_text())
else:row={'name':pt['name'],'verdict':'INVALID','exit_code':rc}
sb.save(out/'control-summary.json',{'scope':'One optional diagnostic control; excluded from four-point acceptance','driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'original_task_started_at':'2026-09-29T10:40:36Z','control':pt['control'],'point':row})
sb.COMMAND_DEADLINE=started+3540
sb.save(out/'control-cleanup.json',sb.own_cleanup(m['project']))
print(json.dumps({'event':'CONTROL_END','verdict':row['verdict'],'time':time.time()}),flush=True)
