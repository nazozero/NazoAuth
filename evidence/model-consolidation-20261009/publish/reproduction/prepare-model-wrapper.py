from pathlib import Path
R=Path('/workspace');E=R/'evidence/model-consolidation-20261009';s=(R/'evidence/pr230-performance-repair-20261009/point-wrapper-retry.py').read_text()
needle=' # Collect the exact final instance, after drain/observation, in addition to live following.'
sql="SELECT json_build_object('columns',(SELECT json_agg(s) FROM (SELECT table_name AS table,column_name AS field,udt_name AS type,is_nullable AS nullable,column_default AS default FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position) s),'constraints',(SELECT json_agg(s) FROM (SELECT rel.relname AS table,con.conname AS name,pg_get_constraintdef(con.oid) AS definition FROM pg_constraint con JOIN pg_class rel ON rel.oid=con.conrelid JOIN pg_namespace ns ON ns.oid=rel.relnamespace WHERE ns.nspname='public' ORDER BY 1,2) s));"
s=s.replace(needle,' # Metadata-only catalog read occurs after load/drain; it does not enter the timed workload.\n ctl.save(ctl.E/\'postgres-catalog.json\',json.loads(ctl.sis.psql('+repr(sql)+')))\n'+needle)
assert s.count('Metadata-only catalog read')==1
(E/'point-wrapper-model.py').write_text(s);print('prepared wrapper')
