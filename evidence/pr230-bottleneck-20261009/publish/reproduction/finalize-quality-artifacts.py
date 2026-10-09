from pathlib import Path
import json,gzip,hashlib
E=Path('/src/evidence/pr230-bottleneck-20261009');P=E/'publish';index=json.loads((P/'artifact-index.json').read_text());sources=['final-postgres-suite-exit.json','final-postgres-suite.log','verification-summary.json','historical-baseline-equivalence.json','execution-time.json']
sources.extend(str(f.relative_to(E)) for f in (E/'reproduction').glob('*.py'))
for name in sources:
 src=E/name;assert src.exists(),name;data=src.read_bytes();rel=Path(name+'.gz' if len(data)>200000 else name);dst=P/rel
 for item in index:
  if item['source']==name and item.get('published') and item['published']!=str(rel):
   old=P/item['published'];assert old.resolve().is_relative_to(P.resolve());old.unlink(missing_ok=True)
 dst.write_bytes(gzip.compress(data,compresslevel=6,mtime=0) if rel.suffix=='.gz' else data);index=[r for r in index if r['source']!=name];index.append({'source':name,'published':str(rel),'source_bytes':len(data),'source_sha256':hashlib.sha256(data).hexdigest(),'published_bytes':dst.stat().st_size,'published_sha256':hashlib.sha256(dst.read_bytes()).hexdigest()})
(P/'artifact-index.json').write_text(json.dumps(index,indent=2));print('Final completed quality evidence and index refreshed')



