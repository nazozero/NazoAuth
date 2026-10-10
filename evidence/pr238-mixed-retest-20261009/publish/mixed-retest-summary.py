from pathlib import Path
import json
R=Path('/workspace/evidence');E=R/'pr238-mixed-retest-20261009';O=R/'pr238-reverify-20261009'
rows=[]
for key in ['MIX300']:
    path=E/key/'investigation-analysis.json'
    if not path.exists():continue
    x=json.loads(path.read_text());old=json.loads((O/key/'investigation-analysis.json').read_text())
    measures=x['measure'];start=measures['window_start_s']-x['request']['warmup_ms']/1000;end=measures['window_end_s']
    db=[json.loads(l) for l in (E/key/'storage.jsonl').read_text().splitlines()]
    active=[r for r in db if 'db_bytes' in r and start<=r['ts']<=end]
    errors=[r for r in db if 'error' in r]
    final=x['natural_final'];storage_errors_before_final=[r for r in errors if r['ts']<=final['ts']]
    load_start=json.loads((E/key/'load-boundary.json').read_text())['load_start']
    vk=[v for v in x['valkey'] if start<=load_start+v['offset_s']<=end]
    row={'key':key,'verdict':x['verdict'],'ops_s':x['ops_s'],'latency_ms':x['latency_ms'],'measure':measures,'unexpected':x['unexpected_errors'],'expected_invalid_grant':x['expected_invalid_grant'],'sidecar_gates':x['sidecar_gates'],'audit':x['audit'],'wal_per_success':x['wal_per_success'],'cpu_cores':x['cpu_cores'],'db_initial_mib':active[0]['db_bytes']/2**20,'db_peak_mib':max(r['db_bytes'] for r in active)/2**20,'db_last_active_mib':active[-1]['db_bytes']/2**20,'db_final_mib':final['db_bytes']/2**20,'valkey_peak_mib':max(v['info']['used_memory'] for v in vk)/2**20,'pending_peak':max(r['pending'] for r in active),'oldest_pending_peak_s':max(r['oldest_pending_s'] for r in active),'decision_eligible_peak':max(r['decision_eligible'] for r in active),'decision_eligible_age_peak_s':max(r['decision_oldest_due_s'] for r in active),'natural_target':final['target_decisions'],'full_cycle':final['full_cycle_after_target_deadline'],'retained_issuances':final['issuance_counts'],'storage_errors_before_final':storage_errors_before_final,'teardown_observer_errors':len(errors)-len(storage_errors_before_final),'latency_30s':x['latency_30s'],'prior_same_candidate':{k:old[k] for k in ['verdict','ops_s','latency_ms','sidecar_gates','wal_per_success','cpu_cores']}}
    row['storage_verdict']='PASS' if final['target_decisions']['count']==0 and row['full_cycle'] and not storage_errors_before_final else 'INVALID'
    rows.append(row)
(E/'summary.json').write_text(json.dumps(rows,indent=2))
for row in rows:print(json.dumps({k:v for k,v in row.items() if k not in ['audit','latency_30s','prior_same_candidate','measure']}))

