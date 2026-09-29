"""Offline diagnostic projection; no acceptance logic and no secret fields."""
import argparse,collections,gzip,hashlib,json,math,re
from pathlib import Path
from datetime import datetime, timezone
p=argparse.ArgumentParser(); p.add_argument('point',type=Path); p.add_argument('output',type=Path); a=p.parse_args()
def load(f): return json.loads(f.read_text()) if f.exists() else {}
def jsonl(f):
    if f.exists():
        with f.open() as h:
            for l in h:
                if l.strip(): yield json.loads(l)
def quant(v):
    v=sorted(v)
    def q(t):
        if not v:return None
        z=(len(v)-1)*t; k=int(z); return v[k]+(v[min(k+1,len(v)-1)]-v[k])*(z-k)
    return {'n':len(v),'p50':q(.5),'p95':q(.95),'p99':q(.99),'max':max(v) if v else None}
rec=load(a.point/'point.json'); m=rec.get('metrics',{}); start=m.get('window_start_ms',0)/1000; end=m.get('window_end_ms',0)/1000
result={'point':a.point.name,'main_formal_start_utc':datetime.fromtimestamp(start,timezone.utc).isoformat() if start else None,'main_formal_start_epoch':start,'main_formal_end_epoch':end,'scope':'Diagnostic only. Original worker verdict is authoritative. Whole-scenario HTTP step distributions include warmup; formal sampled HTTP latencies are forensic, not exact full-population quantiles.','loads':{},'pgss':{},'residency':{},'resources':{}}
timeline=collections.defaultdict(dict); source_hashes={}
for folder in ['load','argon2','meta','fapi','refresh']:
    d=a.point/folder
    if not d.exists(): continue
    latest=load(d/'latest.json'); native=latest[0] if isinstance(latest,list) and latest else {}
    kk=native.get('k6',{}); measure=kk.get('measure',{}); contract=measure.get('measurement_contract',{})
    fs=contract.get('window_start_ms',start*1000)/1000; fe=contract.get('window_end_ms',end*1000)/1000
    entry={'scenario':native.get('scenario'),'whole_scenario_steps':native.get('steps',[]),'formal_measure':measure,'stream_evidence':native.get('measurement_evidence'),'k6_exit_code':native.get('k6_exit_code'),'formal_window_epoch':[fs,fe],'forensic':{}}
    series_file=next(d.glob('*.series.json'),None)
    if series_file:
        series=load(series_file)
        for sec,b in series.get('bins',{}).items():
            timeline[sec][folder]={k:b.get(k) for k in ['begins','ends','dropped','iterations','vus','vus_max','cap_iter_ms','cap_measure_ms','http_req_duration','http_reqs','http_req_failed']}
    stats=next(d.glob('*.analyzer-stats.json'),None)
    entry['analyzer_stats']=load(stats) if stats else {}
    diag=next(d.glob('*.diag.jsonl.gz'),None)
    step_values=collections.defaultdict(list); stage_second=collections.defaultdict(lambda:collections.defaultdict(lambda:{'n':0,'max_ms':0,'tails_ge500':0}))
    iter_values=[]; vu_ids=set()
    if diag:
        with gzip.open(diag,'rt') as h:
            for line in h:
                x=json.loads(line); dat=x.get('data',{}); metric=x.get('metric'); tags=dat.get('tags') or {}
                ts=datetime.fromisoformat(dat['time'].replace('Z','+00:00')).timestamp() if dat.get('time') else None
                if ts is None: continue
                # cap_iter_ms is emitted for measure-entry cohort only;
                # include completions after formal end, as the native gate does.
                if metric=='cap_iter_ms':
                    iter_values.append(dat.get('value',0))
                    continue
                if not fs<=ts<fe: continue
                val=dat.get('value',0)
                if tags.get('vu') is not None:vu_ids.add(str(tags['vu']))
                if metric=='http_req_duration':
                    step=tags.get('step','unknown'); step_values[step].append(val)
                    z=stage_second[str(int(ts))][step]; z['n']+=1;z['max_ms']=max(z['max_ms'],val);z['tails_ge500']+=int(val>=500)
        entry['forensic']={'sampled_formal_steps_ms':{k:quant(v) for k,v in step_values.items()},'sampled_formal_iteration_ms':quant(iter_values),'tail_ge500_count_retained':sum(v>=500 for v in iter_values),'observed_vu_ids_count':len(vu_ids),'tail_completeness':'UNAVAILABLE if diag_overflow; otherwise all emitted >=500ms samples retained by existing analyzer','diag_overflow':entry['analyzer_stats'].get('diag_overflow')}
        for sec,stages in stage_second.items(): timeline[sec].setdefault(folder,{})['sampled_http_steps']=dict(stages)
    log=d/'run.log'
    if log.exists():
        # Only known safe scheduling/version lines; never error payload bodies.
        entry['scheduling_messages']=[l.strip() for l in log.read_text(errors='replace').splitlines() if re.search(r'insufficient VUs|reached.*VUs|dropped iterations|PERF_USER_COUNT=|seeded [0-9]+ perf users',l,re.I)]
    result['loads'][folder]=entry
pre=load(a.point/'pgss-pre.json'); post=load(a.point/'pgss-post.json'); extra=load(a.point/'post-measurement-diagnostics.json')
def identity(r):return tuple(r.get(k) for k in ('dbid','userid','toplevel','queryid'))
before={identity(r):r for r in pre.get('statements',[])}
full={identity(r):r for r in extra.get('pgss_full',{}).get('statements',[]) or []}
rows=[]
for r in post.get('statements',[]):
    b=before.get(identity(r)); reset_ok=bool(pre.get('stats_reset')) and pre.get('stats_reset')==post.get('stats_reset')
    same=reset_ok and b is not None and b.get('stats_since')==r.get('stats_since')
    row={k:r.get(k) for k in ('dbid','datname','userid','rolname','toplevel','queryid','stats_since','q')}
    if identity(r) in full:row['q']=full[identity(r)]['q']
    row['baseline_present']=b is not None;row['delta_valid']=same
    row['basis']='pre_post_same_identity_same_stats_since' if same else 'post_snapshot_since_reset_observation; missing baseline not filled with zero'
    row['post']={k:r.get(k) for k in ('calls','total_exec_time','rows','wal_records','wal_fpi','wal_bytes','shared_blks_dirtied','shared_blks_written')}
    row['pre']={k:b.get(k) for k in row['post']} if b else None
    if same: row['delta']={k:float(r[k])-float(b[k]) for k in row['post'] if r.get(k) is not None and b.get(k) is not None}
    rows.append(row)
result['pgss']={'pre_metadata':{k:pre.get(k) for k in ('ts','stats_reset','dealloc')},'post_metadata':{k:post.get(k) for k in ('ts','stats_reset','dealloc')},'rows':rows,'population':extra.get('family_population'),'seed_population':extra.get('seed_population'),'relation_stats':extra.get('relation_stats'),'post_capture_collected':extra.get('collected'),'warning':'Top-level and nested reported separately; never sum them. Snapshot interval includes seed, warmup and drain. SQL exec time is not CPU time.'}
samples=[r for r in jsonl(a.point/'residency.jsonl') if r.get('kind')=='sample' and start<=r.get('ts',0)<end]
events=collections.Counter(); qids=collections.Counter(); pools=[]; locks=[]; missing=0
for row in samples:
    if row.get('pool'): pools.append(row['pool'])
    for b in row.get('backends',[]):
        events[(b.get('state'),b.get('wet'),b.get('we'))]+=1
        if b.get('state')=='active':qids[(str(b.get('qid')),b.get('wet'),b.get('we'))]+=1
    if row.get('app_err') or row.get('pg_err'):missing+=1
    if row.get('lock_blocks'):locks.append({'ts':row['ts'],'blocks':row['lock_blocks']})
    sec=str(int(row['ts'])); timeline[sec].setdefault('residency',[]).append({'ts':row['ts'],'pool':row.get('pool'),'wait_events':dict(collections.Counter(str(b.get('wet'))+'/'+str(b.get('we')) for b in row.get('backends',[]) if b.get('state')=='active'))})
result['residency']={'samples':len(samples),'error_samples':missing,'pool_connections':quant([x['con'] for x in pools if isinstance(x.get('con'),(int,float))]),'pool_checked_out':quant([x['con']-x['idle'] for x in pools if isinstance(x.get('con'),(int,float)) and isinstance(x.get('idle'),(int,float))]),'pool_waiting':quant([x['waiting'] for x in pools if isinstance(x.get('waiting'),(int,float))]),'events_backend_samples':[{'state':k[0],'wait_type':k[1],'wait_event':k[2],'backend_samples':v} for k,v in events.most_common()],'active_query_backend_samples':[{'queryid':k[0],'wait_type':k[1],'wait_event':k[2],'backend_samples':v} for k,v in qids.most_common()],'lock_block_samples':locks[:100],'lock_block_sample_count':len(locks),'role_checks':[r for r in jsonl(a.point/'residency.jsonl') if r.get('kind')=='role_check'],'sampling_limit':'250ms snapshots are occupancy observations, not exhaustive individual request durations. Absence of sampled locks does not prove zero locks.'}
proc=list(jsonl(a.point/'proc-detail.jsonl')); hz=next((r.get('clk_tck',100) for r in proc if r.get('kind')=='meta'),100)
proc=[r for r in proc if start<=r.get('ts',0)<end]
targets=sorted({k for r in proc for k,v in r.items() if isinstance(v,dict)})
for target in targets:
    rr=[(r['ts'],r[target]) for r in proc if target in r and isinstance(r[target],dict)]
    rss=[v['rss_kb']/1024 for _,v in rr if isinstance(v.get('rss_kb'),(int,float))]
    ds=[(t1-t0,(v1['total_jif']-v0['total_jif'])/hz) for (t0,v0),(t1,v1) in zip(rr,rr[1:]) if t1>t0 and 'total_jif' in v0 and 'total_jif' in v1]
    result['resources'][target]={'samples':len(rr),'process_cpu_cores_mean':sum(x[1] for x in ds)/sum(x[0] for x in ds) if ds and all(x[1]>=0 for x in ds) else None,'process_rss_mib_mean':sum(rss)/len(rss) if rss else None,'process_rss_mib_peak':max(rss) if rss else None}
for r in proc:
    timeline[str(int(r['ts']))]['process_snapshot']={k:{z:v.get(z) for z in ('total_jif','rss_kb','cpus_allowed','threads')} for k,v in r.items() if isinstance(v,dict)}
for r in jsonl(a.point/'soak-metrics.jsonl'):
    if start-60<=r.get('ts',0)<=end+60:
        timeline[str(int(r['ts']))]['soak']={k:r.get(k) for k in ('ts','pool','wal_bytes','wal_io','pg_waits','audit_queue')}
for f in a.point.rglob('*'):
    if f.is_file() and f.name in ('pgss-pre.json','pgss-post.json','post-measurement-diagnostics.json','residency.jsonl','soak-metrics.jsonl','proc-detail.jsonl','point.json','latest.json'):
        with f.open('rb') as h:source_hashes[str(f.relative_to(a.point))]=hashlib.file_digest(h,'sha256').hexdigest()
result['source_files_sha256']=source_hashes
a.output.mkdir(parents=True,exist_ok=True)
(a.output/'diagnostics.json').write_text(json.dumps(result,indent=2)+'\n')
with (a.output/'timeline.jsonl').open('w') as h:
    for sec,data in sorted(timeline.items(),key=lambda x:int(x[0])): h.write(json.dumps({'epoch_second':int(sec),'relative_to_main_formal_start_s':round(int(sec)-start,3),**data})+'\n')
print(json.dumps({'point':a.point.name,'loads':{k:{'steps':v['whole_scenario_steps'],'tail':v['forensic'].get('sampled_formal_iteration_ms'),'overflow':v['forensic'].get('diag_overflow')} for k,v in result['loads'].items()},'waits':result['residency']['events_backend_samples'][:8]}))
