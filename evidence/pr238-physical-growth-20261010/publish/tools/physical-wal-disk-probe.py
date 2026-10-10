from pathlib import Path
import json,subprocess,time,sys
E=Path('/workspace/evidence/pr238-physical-growth-20261010');D=E/sys.argv[1];p=json.loads((D/'requests'/(sys.argv[1]+'.json')).read_text())
sql="SELECT json_build_object('ts',extract(epoch FROM clock_timestamp()),'database_bytes',pg_database_size(current_database()),'wal_disk_bytes',(SELECT sum(size) FROM pg_ls_waldir()),'replication_slots',(SELECT count(*) FROM pg_replication_slots),'checkpointer',(SELECT row_to_json(s) FROM pg_stat_checkpointer s),'settings',(SELECT json_object_agg(name,setting) FROM pg_settings WHERE name IN ('max_wal_size','min_wal_size','checkpoint_timeout','archive_mode','wal_keep_size')));"
cmd=['docker','exec',p['name']+'-postgres-1','psql','-X','-A','-t','-U','postgres','-d','oauth','-v','ON_ERROR_STOP=1','-c',sql];start=time.time();r=subprocess.run(cmd,capture_output=True,text=True)
result={'command':cmd,'exit':r.returncode,'start':start,'end':time.time(),'sample':json.loads(r.stdout) if r.returncode==0 else None,'error':r.stderr if r.returncode else None};(D/'wal-disk-terminal.json').write_text(json.dumps(result,indent=2));print(json.dumps(result));sys.exit(r.returncode)
