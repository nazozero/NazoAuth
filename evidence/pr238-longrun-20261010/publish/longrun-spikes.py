from pathlib import Path
import json,sys,math
E=Path('/workspace/evidence/pr238-longrun-20261010')
def rows(p):return [json.loads(s) for s in p.read_text().splitlines() if s.strip()]
for key in sys.argv[1:]:
    D=E/key;a=json.loads((D/'analysis.json').read_text());b=next(D.glob('results/*/*/short-result.json')).parent
    start=a['lanes']['load']['measure']['window_start_s'];series=json.loads(next((b/'load').glob('*.series.json')).read_text())
    bad=[]
    for sec,r in series['bins'].items():
        if r['cap_iter_ms']['n'] and (r.get('dropped',0)>0 or r['cap_iter_ms']['max']>1000):
            h=r['cap_iter_ms'];bad.append({'ts':int(sec),'offset':int(sec)-start,'n':h['n'],'mean_ms':h['sum']/h['n'],'max_ms':h['max'],'drop':r.get('dropped',0),'vus':r.get('vus',0)})
    soak=[r for r in rows(b/'soak-metrics.jsonl') if 'ts' in r]
    roles=rows(D/'pg-roles.jsonl');storage=rows(D/'storage.jsonl')
    out=[]
    for r in sorted(bad,key=lambda x:x['drop'],reverse=True)[:20]:
        near=min(soak,key=lambda x:abs(x['ts']-r['ts']));role=min(roles,key=lambda x:abs(x['ts']-r['ts']));st=min(storage,key=lambda x:abs(x['ts']-r['ts']))
        out.append({'load':r,'db':{k:near.get(k) for k in ['ts','pg','xact','checkpoints','runtime_role_activity','pg_waits']},'role_sample':role,'storage_sample':{k:st.get(k) for k in ['ts','pending','oldest_pending_s','observer_elapsed_s']}})
    (D/'spike-correlation.json').write_text(json.dumps({'key':key,'note':'Coincidence is not causation. PG collector is about 2 seconds; role/storage samples about 10 seconds. Highest drop seconds first; no external host load attribution.','spike_seconds':len(bad),'evidence':out},indent=2))
    print(json.dumps({'key':key,'spike_seconds':len(bad),'top':out[:3]}))
