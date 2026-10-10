from pathlib import Path
import json,sys,statistics,csv
E=Path('/workspace/evidence/pr238-physical-growth-20261010')
def rows(p):
    if not p.exists():return []
    return [json.loads(s) for s in p.read_text().splitlines() if s.strip()]
def desc(v):
    return dict(first=v[0],last=v[-1],median=statistics.median(v),max=max(v),min=min(v)) if v else None
for key in sys.argv[1:]:
    D=E/key;a=json.loads((D/'analysis.json').read_text())
    if 'lanes' not in a:continue
    b=next(D.glob('results/*/*/short-result.json')).parent
    m=a['lanes']['load']['measure'];start=m['window_start_s'];end=m['window_end_s']
    soak=[r for r in rows(b/'soak-metrics.jsonl') if start<=r.get('ts',0)<=end]
    proc=[r for r in rows(b/'proc-detail.jsonl') if 'ts' in r]
    cpu=[]
    for x,y in zip(proc,proc[1:]):
        if not start<=y['ts']<=end:continue
        z={'ts':y['ts'],'offset_s':y['ts']-start};dt=y['ts']-x['ts'];z['interval_s']=dt
        for svc in ['app','postgres','valkey','audit-worker','audit-receiver']:
            if svc not in x or svc not in y:continue
            if 'total_jif' not in x[svc] or 'total_jif' not in y[svc]:continue
            delta=y[svc]['total_jif']-x[svc]['total_jif']
            z[svc+'_cores']=delta/100/dt if delta>=0 else None
            z[svc+'_rss_kb']=y[svc].get('rss_kb')
        cpu.append(z)
    with (D/'resource-cpu.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=sorted(set().union(*(r.keys() for r in cpu))));w.writeheader();w.writerows(cpu)
    thirds=[]
    for i in range(3):
        lo=start+360+(end-start-360)*i/3;hi=start+360+(end-start-360)*(i+1)/3
        ss=[r for r in soak if lo<=r['ts']<hi];cc=[r for r in cpu if lo<=r['ts']<hi]
        rel={}
        for name in sorted(set().union(*(r.get('rel_bytes',{}).keys() for r in ss))):
            rel[name]={k:desc([r['rel_bytes'][name][k] for r in ss if name in r.get('rel_bytes',{}) and k in r['rel_bytes'][name]]) for k in ['total','heap','idx','dead','autovac','ins','del']}
        thirds.append({'start':lo,'end':hi,'tables':rel,'valkey':{k:desc([r['vk'][k] for r in ss if 'vk' in r and k in r['vk']]) for k in ['mem','keys','exp','cmd']},'cpu':{svc:desc([r[svc+'_cores'] for r in cc if r.get(svc+'_cores') is not None]) for svc in ['app','postgres','valkey','audit-worker','audit-receiver']},'old_transactions':{k:max([r.get('xact',{}).get(k,0) for r in ss],default=0) for k in ['oldest_xact_age_s','xacts_over_60s','xacts_over_300s']}})
    # Cumulative WAL uses nearest in-window collector samples: explicitly preserve endpoints.
    wal={'first':{'ts':soak[0]['ts'],'wal_bytes':soak[0]['wal_bytes']},'last':{'ts':soak[-1]['ts'],'wal_bytes':soak[-1]['wal_bytes']}} if soak else None
    if wal:wal['delta_bytes']=wal['last']['wal_bytes']-wal['first']['wal_bytes']
    out={'key':key,'window_start':start,'window_end':end,'wal_sample_window':wal,'mature_thirds':thirds,'cpu_note':'Owned service process jiffy deltas / elapsed seconds; terminated PG backend jiffies are not retained, so negative deltas are omitted. Shared cgroup counters are deliberately not treated as per-service CPU. No host metrics were probed.'}
    out['whole_window']={'cpu':{svc:{'time_weighted_mean_cores':sum(r[svc+'_cores']*r['interval_s'] for r in cpu if r.get(svc+'_cores') is not None)/sum(r['interval_s'] for r in cpu if r.get(svc+'_cores') is not None),'sample_summary':desc([r[svc+'_cores'] for r in cpu if r.get(svc+'_cores') is not None])} for svc in ['app','postgres','valkey','audit-worker','audit-receiver'] if any(r.get(svc+'_cores') is not None for r in cpu)},'valkey':{k:desc([r['vk'][k] for r in soak if 'vk' in r and k in r['vk']]) for k in ['mem','keys','exp','cmd']}}
    (D/'resource-analysis.json').write_text(json.dumps(out,indent=2))
    print(json.dumps({'key':key,'wal':wal,'mature_valkey':[r['valkey']['mem'] for r in thirds],'mature_cpu_app':[r['cpu']['app'] for r in thirds]}))

