import pathlib,json,gzip,hashlib,shutil,collections
E=pathlib.Path('/src/evidence/pr230-performance-20261009');P=E/'publish';P.mkdir(exist_ok=True)
index=[]
def put(src,rel=None):
 rel=rel or src.relative_to(E);dst=P/rel;dst.parent.mkdir(parents=True,exist_ok=True);data=src.read_bytes()
 if len(data)>200000 and src.suffix not in ['.gz']:
  dst=dst.with_name(dst.name+'.gz');dst.write_bytes(gzip.compress(data,compresslevel=6,mtime=0))
 else:dst.write_bytes(data)
 index.append({'source':str(src.relative_to(E)),'published':str(dst.relative_to(P)),'source_bytes':len(data),'source_sha256':hashlib.sha256(data).hexdigest(),'published_bytes':dst.stat().st_size,'published_sha256':hashlib.sha256(dst.read_bytes()).hexdigest()})
rootnames=['final-source.json','chain-review.json','round-analysis.json','postgres-suite-reconciled.json','formal-commands.jsonl','diagnostic.patch','diagnostic.rs','diagnostic-after.patch','diagnostic-after.rs','point-wrapper.py','point-wrapper-retry.py','storage-observer.sql','allowed-application-container-cpus.json','unit-pg-final-checkpoints.log','unit-pg-stop.json','source-push.json']
for pattern in ['image-*.json','*-exit.json']:rootnames.extend(f.name for f in E.glob(pattern))
for stem in ['cache-before','cache-after','cache-negative-all','cache-regressions','postgres-suite','audit-fixture-completion','commit-boundaries-fixture-completion','clippy','fmt-check','static-contracts','dependency-boundary','candidate-build']:
 rootnames.append(stem+'.log')
for name in sorted(set(rootnames)):
 if (E/name).exists():put(E/name)
keys=['D1','D2','D3','A06','B06','B10','A10','A03','B03','B04','A04','A06R','A03R','B03R','B04R','A04R']
for f in (E/'reproduction').glob('*.py'):put(f)
for key in keys:
 d=E/key
 if not d.exists():continue
 for f in d.glob('*'):
  if f.is_file() and f.suffix in ['.json','.jsonl','.csv','.log']:put(f)
 for f in (d/'requests').glob('*.json'):put(f)
 for f in E.glob(key+'-*.log'):put(f)
 for f in (d/'results').rglob('*'):
  if not f.is_file():continue
  if f.name=='audit-journal.jsonl':
   index.append({'source':str(f.relative_to(E)),'source_bytes':f.stat().st_size,'source_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'published':None,'reason':'raw signed payload journal kept in isolated evidence; publish count/hash/checkpoint reconciliation'});continue
  if f.name.endswith('.diag.jsonl.gz'):
   dest=P/f.relative_to(E);dest=dest.with_name(dest.name.replace('.diag.','.capacity-raw.'));dest.parent.mkdir(parents=True,exist_ok=True);n=kept=0;tags=collections.Counter()
   with gzip.open(f,'rt') as inp,dest.open('wb') as out,gzip.GzipFile(fileobj=out,mode='wb',mtime=0) as z:
    for line in inp:
     n+=1
     if not any(marker in line for marker in ['"metric":"cap_','"metric": "cap_','"metric":"dropped_iterations"','"metric": "dropped_iterations"','"metric":"iterations"','"metric": "iterations"','"metric":"vus"','"metric": "vus"','"metric":"vus_max"','"metric": "vus_max"']):continue
     r=json.loads(line);metric=r.get('metric','')
     if metric.startswith('cap_') or metric in ['dropped_iterations','iterations','vus','vus_max']:
      z.write(line.encode());kept+=1
      for tag in (r.get('data') or {}).get('tags',{}):tags[tag]+=1
   index.append({'source':str(f.relative_to(E)),'published':str(dest.relative_to(P)),'source_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'source_bytes':f.stat().st_size,'source_lines':n,'kept_lines':kept,'kept_tag_keys':sorted(tags),'published_bytes':dest.stat().st_size,'published_sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'filter':'cap_* and dropped_iterations/iterations/vus/vus_max; original retained lines unmodified; HTTP metrics omitted'});continue
  if f.name.startswith('task-container-states'):continue
  if f.suffix in ['.json','.jsonl','.txt','.k6log'] and f.name not in ['budget.json']:put(f)
(P/'artifact-index.json').write_text(json.dumps(index,indent=2))
print(json.dumps({'files':len(index),'bytes':sum(f.stat().st_size for f in P.rglob('*') if f.is_file())}))

