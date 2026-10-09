from pathlib import Path
import json,gzip,re,hashlib,urllib.parse
E=Path('/src/evidence/pr230-bottleneck-20261009');P=E/'publish';secrets=set()
for v in json.loads((E/'unit-env.json').read_text()).values():
 if isinstance(v,str) and '://' in v:
  pwd=urllib.parse.urlsplit(v).password
  if pwd and len(pwd)>8:secrets.add(urllib.parse.unquote(pwd).encode())
for f in E.glob('*/environment*.y*ml'):
 for m in re.finditer(rb'postgres(?:ql)?://[^\s:@]+:([^@\s]+)@',f.read_bytes()):secrets.add(m.group(1))
hits=[];files=list(P.rglob('*'))
for f in files:
 if not f.is_file():continue
 b=gzip.decompress(f.read_bytes()) if f.suffix=='.gz' else f.read_bytes()
 if any(v in b for v in secrets) or re.search(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',b) or re.search(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})',b):hits.append(str(f.relative_to(P)))
assert not hits,{'credential_pattern_paths':hits}
index=json.loads((P/'artifact-index.json').read_text())
for x in index:
 if x.get('published'):
  f=P/x['published'];assert hashlib.sha256(f.read_bytes()).hexdigest()==x['published_sha256'],x['published']
print({'published_files':sum(x.is_file() for x in files),'size_bytes':sum(x.stat().st_size for x in files if x.is_file()),'max_file_bytes':max(x.stat().st_size for x in files if x.is_file()),'artifact_hashes_verified':True,'credential_patterns_found':0})
