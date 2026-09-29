#!/usr/bin/env python3
"""PR222 failed-point retest only; reuse existing preparation, worker and gates."""
import argparse, hashlib, json, os, sys, time
from pathlib import Path
ROOT=Path('/workspace')
sys.path.insert(0,str(ROOT/'perf/tools'))
import short_baseline as sb
parser=argparse.ArgumentParser()
parser.add_argument('--started-at',required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--cpu-budget',type=float,default=None)
args=parser.parse_args()
started=sb.started_epoch(args.started_at)
cutoff=started+3300
sb.COMMAND_DEADLINE=cutoff
out=args.output.resolve()
out.mkdir(parents=True,exist_ok=False)
os.chmod(out,0o700)
manifest={}; rows=[]; error=None
queue=[('multi','cap_authorization_code',800,60),('single','cap_mixed',400,60),('multi','cap_mixed',1600,60),('multi','cap_mixed',800,570)]
def publish():
    covered=len(rows)==4 and all(r['verdict'] in ('PASS','FAIL') for r in rows)
    summary={'schema_version':1,'scope':'失败点补测; four original failed points only; five original PASS points not rerun','status':'COMPLETE' if covered else 'INCOMPLETE','acceptance_status':('PASS' if all(r['verdict']=='PASS' for r in rows) else 'FAIL') if covered else 'INVALID','source_sha':manifest.get('source_sha'),'harness_sha':manifest.get('harness_sha'),'task_started_at':args.started_at,'elapsed_seconds':round(time.time()-started,1),'points':rows,'missing_valid_cases':[list(q) for i,q in enumerate(queue) if i>=len(rows) or rows[i]['verdict']=='INVALID'],'error_kind':error}
    sb.save(out/'summary.json',summary)
    return summary
try:
    manifest=sb.prepare(argparse.Namespace(app_image='nazoauth-perf-nazoauth',runner_image='nazoauth-perf-perf',cpu_budget=args.cpu_budget),out)
    manifest.update(task_started_at=args.started_at,load_cutoff_at='2026-09-29T11:35:36Z',delivery_deadline_at='2026-09-29T11:40:36Z',scope='失败点补测',driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),production_inputs_equal_previous=not sb.command(['git','diff','3b6d8d3cfe35f79a3ab896d53a3aa76c443e7599',manifest['harness_sha'],'--',*sb.APP_INPUTS]),cpu_budget_basis='This deployment .cnb.yml runner.cpus=64; actual CPU IDs from current process and runner probe intersection.')
    sb.save(out/'manifest.json',manifest)
    env={**os.environ,'SIS_WORKSPACE':str(ROOT),'SIS_RESULTS':str(out),'SIS_BIN':str(out/'bin'),'SIS_PROJECT':manifest['project'],'SIS_PERF_IMAGE':manifest['runner_image'],'SIS_SOURCE_SHA':manifest['source_sha'],'SIS_APP_SHA':manifest['source_sha'],'SIS_LOAD_BUDGET_S':'2700'}
    if len(manifest['cpus']['multi'])<2: raise RuntimeError('multicore unavailable')
    for i,(mode,scenario,rate,window) in enumerate(queue):
        left=cutoff-time.time()
        budget=sb.point_budget(window,scenario=='cap_mixed')
        if left<budget: break
        point=sb.make_point(manifest,mode,scenario,rate,window,i)
        # These are diagnostic-only observers, never production parameter changes.
        point['residency_observer']={'interval_s':0.25,'runtime_role':'nazoauth_perf_runtime'}
        spec=out/f'request-{i}.json'; sb.save(spec,point)
        print(json.dumps({'event':'START','index':i,'name':point['name'],'time':time.time(),'configuration':{'app_cpus':len(point['app_cpus']),'postgres_cpus':len(point['postgres_cpus']),'generator_cpus':len(point['infra_cpus']),'vus':point['max_vus'],'users':point['user_count'],'pool':point['app_env_overrides']}}),flush=True)
        rc=sb.bounded_child([sys.executable,str(ROOT/'perf/tools/short_baseline.py'),'--worker',str(spec)],env,out/f'point-{i}.log',min(left,budget))
        result=out/mode/point['name']/'short-result.json'
        if rc==0 and result.exists(): row=json.loads(result.read_text())
        else:
            row={'name':point['name'],'mode':mode,'scenario':scenario,'rate':rate,'window_seconds':window,'verdict':'INVALID','confirmation':point['confirmation'],'exit_code':rc}
            sb.own_cleanup(manifest['project'])
        rows.append(row); publish()
        print(json.dumps({'event':'END','index':i,'time':time.time(),'verdict':row['verdict']}),flush=True)
except BaseException as exc:
    error=type(exc).__name__; publish(); raise
finally:
    sb.COMMAND_DEADLINE=started+3540
    if manifest.get('project'): sb.save(out/'cleanup.json',sb.own_cleanup(manifest['project']))
    summary=publish()
    print(json.dumps({'event':'FINISHED','status':summary['status'],'acceptance':summary['acceptance_status']}),flush=True)
