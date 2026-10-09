import pathlib,json,gzip,hashlib,shutil,collections
E=pathlib.Path('/src/evidence/pr230-bottleneck-20261009');P=E/'publish';P.mkdir(exist_ok=True)
index=[]
def put(src,rel=None):
 rel=rel or src.relative_to(E);dst=P/rel;dst.parent.mkdir(parents=True,exist_ok=True);data=src.read_bytes()
 if len(data)>200000 and src.suffix not in ['.gz']:
  dst=dst.with_name(dst.name+'.gz');dst.write_bytes(gzip.compress(data,compresslevel=6,mtime=0))
 else:dst.write_bytes(data)
 index.append({'source':str(src.relative_to(E)),'published':str(dst.relative_to(P)),'source_bytes':len(data),'source_sha256':hashlib.sha256(data).hexdigest(),'published_bytes':dst.stat().st_size,'published_sha256':hashlib.sha256(dst.read_bytes()).hexdigest()})
rootnames=['round-analysis.json','formal-commands.jsonl','diagnostic.patch','diagnostic.rs','diagnostic-B.patch','diagnostic-B.rs','diagnostic-C.patch','diagnostic-C.rs','point-wrapper-retry.py','point-wrapper-450.py','storage-observer.sql','allowed-application-container-cpus.json','source-push.json','final-source.json','chain-review.json','historical-baseline-equivalence.json','final-unit-fixture-reset.json','verification-summary.json','pool-experiment-analysis.json']
for pattern in ['image-*.json','*-exit.json','*.log']:
 rootnames.extend(f.name for f in E.glob(pattern) if not f.name.startswith(tuple(['A06-','A06R-','B06-','B06R-','D0-','D1-','D2-','A06R2-','B06R2-','B10-','B03-','B04-','Q32-','Q64-'])))
for name in sorted(set(rootnames)):
 if (E/name).exists():put(E/name)
keys=['D0','D1','D2','A06','A06R','B06','B06R','B10','B03','B04','Q32','Q64']
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





