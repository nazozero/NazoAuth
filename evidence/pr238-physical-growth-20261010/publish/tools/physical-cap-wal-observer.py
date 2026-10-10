from pathlib import Path
import json,time
E=Path('/workspace/evidence/pr238-physical-growth-20261010')
for key in ['AUTH_A_CAP','AUTH_CAP']:
 D=E/key;p=D/'observer.sql';s=p.read_text();assert 'wal_disk_bytes' not in s
 s=s.replace('SELECT base.value::jsonb',"SELECT jsonb_build_object('wal_disk_bytes',(SELECT sum(size) FROM pg_ls_waldir()),'checkpoint_stats',(SELECT row_to_json(s) FROM pg_stat_checkpointer s)) || base.value::jsonb",1);p.write_text(s)
 (D/'observation-delta.json').write_text(json.dumps({'ts':time.time(),'change':'Add read-only WAL directory total and checkpoint counters to the existing single SQL observation; identical in both clean-capacity arms. No extra physical heap/index scans.','reason':'pg_database_size excludes WAL; cumulative WAL generation is not retained WAL disk occupancy.'},indent=2))
print('Added identical low-overhead WAL observations to A/B, before setup or load')
