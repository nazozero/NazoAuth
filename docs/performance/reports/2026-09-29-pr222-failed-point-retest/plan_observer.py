"""Read-only fresh generic-plan snapshots; never actual cached-plan claims."""
import hashlib,json,subprocess,time
from pathlib import Path
root=Path('/workspace/perf-results/failed-point-retest-20260929T104036Z')
m=json.loads((root/'manifest.json').read_text());project=m['project']
q=next(r['q'] for r in json.loads((root/'multi/s0-multi-1790679003/post-measurement-diagnostics.json').read_text())['pgss_full']['statements'] if r['queryid']==3059364362978693673 and r['rolname']=='nazoauth_perf_runtime' and r['toplevel'])
captured=set()
until=time.time()+1800
while time.time()<until:
    for spec in [root/'request-3.json',root/'request-control-0.json']:
        if not spec.exists():continue
        pt=json.loads(spec.read_text());d=root/pt['phase']/pt['name']; marker=d/'load/k6-started.json'
        if not marker.exists():continue
        first=min(marker.stat().st_mtime,time.time());elapsed=time.time()-first
        bucket=0 if elapsed<30 else 1 if elapsed<75 else 2
        key=(pt['name'],bucket)
        if key in captured:continue
        row={'ts':time.time(),'point':pt['name'],'k6_started_marker_mtime':first,'bucket':bucket,'scope':'Fresh observer-session generic plan, same runtime permissions. Not actual application connection cached plan. No statement execution or planner settings changed.','collector_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'queryid':3059364362978693673}
        try:
            proc=subprocess.run(['docker','exec',project+'-postgres-1','psql','-U','postgres','-d','oauth','-qAt','-c','SET ROLE nazoauth_perf_runtime; EXPLAIN (GENERIC_PLAN TRUE,FORMAT JSON) '+q],capture_output=True,text=True,timeout=10,check=True)
            row['plan']=json.loads(proc.stdout)
            stat=subprocess.run(['docker','exec',project+'-postgres-1','psql','-U','postgres','-d','oauth','-qAt','-c',"SELECT json_build_object('rel',(SELECT row_to_json(t) FROM (SELECT n_live_tup,n_dead_tup,last_autoanalyze,last_autovacuum,seq_scan,idx_scan FROM pg_stat_user_tables WHERE relname='oauth_refresh_families') t),'catalog',(SELECT row_to_json(t) FROM (SELECT reltuples,relpages FROM pg_class WHERE oid='oauth_refresh_families'::regclass) t))"],capture_output=True,text=True,timeout=10,check=True)
            row['relation']=json.loads(stat.stdout)
        except Exception as e:row['error_kind']=type(e).__name__
        with (root/'fresh-plan-observations.jsonl').open('a') as h:h.write(json.dumps(row)+'\n')
        captured.add(key)
    if (root/'control-cleanup.json').exists():break
    time.sleep(5)
