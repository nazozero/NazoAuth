from pathlib import Path
import json,time
D=Path('/workspace/evidence/pr238-physical-growth-20261010/CC_RETEST');p=D/'observer.sql';s=p.read_text();assert 'wal_disk_bytes' not in s
s=s.replace('SELECT base.value::jsonb',"SELECT jsonb_build_object('wal_disk_bytes',(SELECT sum(size) FROM pg_ls_waldir()),'checkpoint_stats',(SELECT row_to_json(s) FROM pg_stat_checkpointer s)) || base.value::jsonb",1);p.write_text(s)
(D/'observation-delta.json').write_text(json.dumps({'ts':time.time(),'change':'Add WAL directory total/checkpoint counters to existing SQL sampler before the retest. Original 4000/s load, 992 VUs, exporter batch 256, safety configuration and capacity thresholds are unchanged.','reason':'Separate cumulative WAL generation from actual retained file allocation; initial CC_B15 late probe missed its cleaned-up database.'},indent=2))
print('CC_RETEST WAL observation prepared without running workload')
