from pathlib import Path
import subprocess,json,re,hashlib
R=Path('/workspace');C=R/'evidence/pr238-closure-20261010'
q="""SELECT json_agg(s ORDER BY s.table_name) FROM (
 SELECT c.relname AS table_name,
 (SELECT json_agg(json_build_object('name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull) ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns,
 (SELECT json_agg(json_build_object('name',x.conname,'definition',pg_get_constraintdef(x.oid)) ORDER BY x.conname) FROM pg_constraint x WHERE x.conrelid=c.oid) AS constraints,
 (SELECT json_agg(indexdef ORDER BY indexname) FROM pg_indexes WHERE schemaname='public' AND tablename=c.relname) AS indexes
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r') s;"""
cmd=['docker','exec','-i','nazo-storage-pg-20261010','psql','-X','-qAt','-U','postgres','-d','oauth_final','-v','ON_ERROR_STOP=1']
p=subprocess.run(cmd,input=q,text=True,capture_output=True,check=True)
tables=json.loads(p.stdout);doc=(R/'docs/project/state-storage-lifecycle.md').read_text();missing=[t['table_name'] for t in tables if '`'+t['table_name']+'`' not in doc]
(C/'postgres-catalog.json').write_text(json.dumps(tables,indent=2));(C/'postgres-catalog.sql').write_text(q)
meta={'source_sha':subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip(),'command':cmd,'exit':p.returncode,'table_count':len(tables),'column_count':sum(len(t['columns']) for t in tables),'unclassified_tables':missing}
(C/'catalog-coverage.json').write_text(json.dumps(meta,indent=2));assert not missing,missing
models=json.loads((C/'models.json').read_text());prov=json.loads((C/'review-provenance.json').read_text());changed={f['path'] for f in prov['file_comparison'] if f['changed']}
delta={d['id'] for d in json.loads((C/'model-delta.json').read_text())}
ledger=[]
for m in models['models']:
 path=m['id'].split('::')[0]
 ledger.append({'model':m['id'],'kind':m['kind'],'members':m['fields'],'source_sha256':hashlib.sha256((R/path).read_bytes()).hexdigest(),'baseline_review':'evidence/model-consolidation-20261009/publish/model-review.md','review_basis':'current changed-file and call-chain review' if path in changed else 'unchanged production file: prior responsibility-group review retained','model_shape_changed':m['id'] in delta})
(C/'model-review-ledger.json').write_text(json.dumps({'source_sha':meta['source_sha'],'note':'Declaration and provenance ledger; member names and textual hits are navigation, not type-resolved reachability or proof by field count. Detailed current decisions in MODEL-REVIEW.md and docs/project/state-model-review.md.','models':ledger},indent=2))
print(json.dumps(meta));print('models',len(ledger),'members',models['fields'],'parse_errors',models['errors'])
