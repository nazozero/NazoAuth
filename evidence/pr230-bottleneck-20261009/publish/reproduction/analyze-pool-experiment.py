from pathlib import Path
import json,collections,statistics
p=Path('/src/evidence/pr230-bottleneck-20261009');out={}
for key in ['Q32','Q64']:
 q=p/key;x=json.loads(next(q.rglob('short-result.json')).read_text());w=x['metrics']['measure'];raw=[json.loads(s) for s in (q/'pg-roles.jsonl').read_text().splitlines()];rows=[r for r in raw if w['window_start_s']<=r['ts']<=w['window_end_s']];counts=[];states=collections.Counter();errors=0
 for r in rows:
  if 'activity' not in r:errors+=1;continue
  pool=[a for a in (r['activity'] or []) if a.get('usename')=='nazoauth_perf_runtime'];counts.append(sum(a['n'] for a in pool))
  for a in pool:states[str((a.get('state'),a.get('wait_event_type'),a.get('wait_event')))]+=a['n']
 sched=[json.loads(s) for s in (q/'app-thread-schedstat.jsonl').read_text().splitlines()];a,b=sched[0],sched[-1];deltas=[]
 for tid,v in b['threads'].items():
  if tid in a['threads']:deltas.append([i-j for i,j in zip(v,a['threads'][tid])])
 summary={'diagnostic_only':True,'pool_connections':json.loads((q/'requests'/f'{key}.json').read_text())['pool_connections'],'runtime_role_samples':len(counts),'observer_errors':errors,'runtime_connections_min':min(counts),'runtime_connections_max':max(counts),'runtime_connections_mean':statistics.mean(counts),'runtime_role_state_sample_counts':dict(states),'app_scheduler':{'start':a['ts'],'end':b['ts'],'elapsed_s':b['ts']-a['ts'],'total_run_s':sum(v[0] for v in deltas)/1e9,'total_thread_runqueue_s':sum(v[1] for v in deltas)/1e9},'success_ops_s':x['metrics']['rate_for_gate'],'latency_ms':x['metrics']['complete_operation_latency_ms'],'drop_fraction':w['measure_drop_fraction'],'verdict':x['verdict'],'health':x.get('health')};out[key]=summary;(q/'pool-experiment-analysis.json').write_text(json.dumps(summary,indent=2))
(p/'pool-experiment-analysis.json').write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
