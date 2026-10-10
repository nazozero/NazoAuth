from pathlib import Path
import json,csv,math,statistics,sys
E=Path('/workspace/evidence/pr238-longrun-20261010')
def read(p):return json.loads(p.read_text())
def lines(p):
    if not p.exists():return []
    out=[]
    for line in p.read_text().splitlines():
        try:out.append(json.loads(line))
        except ValueError:pass
    return out
def interval(h,bounds,q):
    if not h['n']:return None
    total=0
    for i,n in enumerate(h['b']):
        total+=n
        if total>=math.ceil(h['n']*q):return [bounds[i-1] if i else 0,bounds[i] if i<len(bounds) else None]
def windows(series,measure,size):
    bounds=series['hist_bounds_ms'];buckets={};origin=math.floor(measure['window_start_s'])
    for second,row in series['bins'].items():
        offset=math.floor((float(second)-origin)/size)*size
        h=row['cap_iter_ms'];z=buckets.setdefault(offset,{'n':0,'b':[0]*(len(bounds)+1),'sum':0,'max':0,'begun':0,'success':0,'expected_rejection':0,'other_outcomes':0,'dropped':0,'max_vus':0})
        if h['n']:
            assert sum(h['b'])==h['n'];z['n']+=h['n'];z['sum']+=h['sum'];z['max']=max(z['max'],h['max']);z['b']=[a+b for a,b in zip(z['b'],h['b'])]
        z['begun']+=row.get('begins',{}).get('measure',0)
        if origin<=float(second)<math.ceil(measure['window_end_s']):z['dropped']+=row.get('dropped',0)
        z['max_vus']=max(z['max_vus'],row.get('vus',0))
        for name,count in row.get('ends',{}).items():
            if not name.startswith('measure|'):continue
            outcome=name.split('|')[-1];z[outcome if outcome in ['success','expected_rejection'] else 'other_outcomes']+=count
    assert sum(z['n'] for z in buckets.values())==measure['measure_completed_exact']
    results=[]
    for offset,z in sorted(buckets.items()):
        if not z['n'] and not z['begun']:continue
        complete=offset>=0 and origin+offset+size<=math.floor(measure['window_end_s'])
        results.append({'offset_s':offset,'full_bucket':complete,'completed':z['n'],'begun':z['begun'],'success':z['success'],'expected_rejection':z['expected_rejection'],'other_outcomes':z['other_outcomes'],'dropped_approx_boundary':z['dropped'],'success_ops_s':z['success']/size if complete else None,'p50_interval_ms':interval(z,bounds,.5),'p95_interval_ms':interval(z,bounds,.95),'p99_interval_ms':interval(z,bounds,.99),'mean_ms':z['sum']/z['n'] if z['n'] else None,'max_ms':z['max'],'max_active_vus':z['max_vus']})
    return results
def describe(values):
    if not values:return None
    return {'min':min(values),'median':statistics.median(values),'max':max(values),'first':values[0],'last':values[-1]}
def phase(rows,start,end,access):
    out=[]
    for i in range(3):
        lo=start+(end-start)*i/3;hi=start+(end-start)*(i+1)/3
        selected=[r for r in rows if lo<=r['ts']<hi]
        out.append({'start':lo,'end':hi,'samples':len(selected),'values':{k:describe([fn(r) for r in selected]) for k,fn in access.items()}})
    return out
summaries=[]
for key in sys.argv[1:] or ['MIX60','REVOKE20','INTROSPECT10','MTLS10','PAR10','NATIVE10','REQUIRED15','MIX60R2','AUTH12']:
    D=E/key;paths=list(D.glob('results/*/*/short-result.json'))
    if not paths:continue
    result=read(paths[0]);rq=read(D/'requests'/f'{key}.json');out={'key':key,'source':rq['source_sha'],'request':rq,'capacity_verdict':result.get('verdict'),'result':result}
    if not result.get('metrics',{}).get('measure'):
        out['status']='INVALID_NO_MEASUREMENT';(D/'analysis.json').write_text(json.dumps(out,indent=2));summaries.append(out);continue
    if not (D/'natural-final.json').exists():continue
    base=paths[0].parent;lanes={'load':result['metrics']}
    lanes.update({k:v['metrics'] for k,v in result['metrics'].get('sidecar_gates',{}).items()})
    lane_results={}
    for name,metrics in lanes.items():
        measured=metrics['measure'];files=list((base/name).glob('*.series.json'));assert len(files)==1,(key,name,files)
        series=read(files[0]);one=windows(series,measured,60);five=windows(series,measured,300)
        lane_results[name]={'rate':metrics['rate_for_gate'],'latency_ms':metrics['complete_operation_latency_ms'],'measure':measured,'window_seconds':metrics['window_seconds'],'unexpected_errors':metrics.get('unexpected_errors'),'subject_lifecycle':metrics.get('subject_lifecycle'),'minute':one,'five_minute':five,'all_complete_minute_mean_ms':describe([x['mean_ms'] for x in one if x['full_bucket']]),'histogram_note':'Quantiles are bounds from full-operation histograms; completion-time buckets use floor(second), so edge buckets and drop attribution have at most one-second boundary ambiguity. Overall cohort counts remain exact.'}
        with (D/(name+'-latency-minute.csv')).open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(one[0]));writer.writeheader();writer.writerows(one)
    out['lanes']=lane_results
    storage=lines(D/'storage.jsonl');errors=[r for r in storage if 'error' in r];storage=[r for r in storage if 'db_bytes' in r]
    for name in ['storage-terminal.json','storage-after-validation.json','natural-final.json']:
        if (D/name).exists():storage.append(read(D/name))
    storage+=lines(D/'natural-tail.jsonl');storage.sort(key=lambda x:x['ts'])
    beginning=read(D/'load-boundary.json')['load_start'];ending=read(D/'load-ended.json')['load_return'];during=[r for r in storage if beginning<=r['ts']<=ending]
    out['load_start']=beginning;out['load_return']=ending;out['natural_final']=read(D/'natural-final.json');out['observed_cohort']=read(D/'target-cohort.json')
    out['observer_errors_during_load']=[r for r in errors if r['ts']<=ending];out['observer_errors_after_load']=[r for r in errors if r['ts']>ending]
    access={'pending':lambda r:r['pending'],'oldest_pending_s':lambda r:r['oldest_pending_s'],'db_bytes':lambda r:r['db_bytes'],'decision_eligible':lambda r:r['decision_eligible'],'decision_retained':lambda r:r['decision_retained'],'decision_oldest_due_s':lambda r:r['decision_oldest_due_s'],'family_live':lambda r:r['family_live'],'spent_retained':lambda r:r['spent_retained'],'issuance_total':lambda r:r['issuance_counts']['total'],'issuance_eligible':lambda r:r['issuance_counts']['eligible'],'issuance_oldest_due_s':lambda r:r['issuance_counts']['oldest_due_s']}
    out['storage_during_load']={k:describe([fn(r) for r in during]) for k,fn in access.items()}
    measure=result['metrics']['measure'];mature=measure['window_start_s']+360
    out['storage_mature_thirds']=phase(during,mature,measure['window_end_s'],access) if mature<measure['window_end_s'] else []
    out['storage_whole_thirds']=phase(during,measure['window_start_s'],measure['window_end_s'],access)
    out['observer_peak_seconds']=max(r.get('observer_elapsed_s',0) for r in during)
    with (D/'storage-series.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['ts','offset_s',*access.keys()]);writer.writeheader()
        for r in storage:writer.writerow({'ts':r['ts'],'offset_s':r['ts']-beginning,**{k:fn(r) for k,fn in access.items()}})
    out['valkey']=lines(D/'valkey-series.jsonl')
    (D/'analysis.json').write_text(json.dumps(out,indent=2));summaries.append(out)
    print(json.dumps({'key':key,'capacity':out['capacity_verdict'],'lanes':{k:{n:v[n] for n in ['rate','latency_ms','unexpected_errors']} for k,v in lane_results.items()},'pending':out['storage_during_load']['pending'],'age':out['storage_during_load']['oldest_pending_s'],'natural_count':out['natural_final']['target_decisions']['count'],'cycle':out['natural_final']['full_cycle_after_target_deadline']}),flush=True)
(E/'analysis-index.json').write_text(json.dumps([{'key':x['key'],'status':x.get('status','MEASURED'),'capacity_verdict':x['capacity_verdict'],'path':str(E/x['key']/'analysis.json')} for x in summaries],indent=2))
