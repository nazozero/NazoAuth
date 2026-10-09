from pathlib import Path
import json,time
E=Path('/workspace/evidence/pr238-reverify-20261009')
for key in ['REV360','MIX300']:
    P=E/key
    row={'point':key}
    for filename in ['load-boundary.json','load-ended.json','natural-final.json']:
        path=P/filename
        if path.exists():
            data=json.loads(path.read_text())
            if filename=='load-boundary.json':row['elapsed_since_load_start_s']=round(time.time()-data['load_start'],1)
            elif filename=='load-ended.json':row['load_finished']=True
            else:row['natural_final']={'target':data.get('target_decisions'),'full_cycle':data.get('full_cycle_after_target_deadline')}
    path=P/'storage.jsonl'
    if path.exists():
        samples=[]
        for line in path.read_text().splitlines():
            try:samples.append(json.loads(line))
            except ValueError:pass
        if samples:row['latest_storage']={k:samples[-1].get(k) for k in ['ts','db_bytes','pending','oldest_pending_s','decision_eligible','decision_retained','target_decisions']}
        row['storage_samples']=len(samples)
    for result in P.rglob('short-result.json'):
        data=json.loads(result.read_text());row['verdict']=data.get('verdict');row['metrics']=data.get('metrics',{}).get('complete_operation_latency_ms');row['error']=data.get('error_kind')
    print(json.dumps(row),flush=True)
