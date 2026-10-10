from pathlib import Path
import sys,json,subprocess,hashlib,collections
R=Path('/workspace');E=R/'evidence/pr238-closure-20261010';sys.path.insert(0,str(R/'scripts'));import data_model_inventory as inv
old=json.loads((R/'evidence/model-consolidation-20261009/publish/models.json').read_text());reported={m['id']:m['fields'] for m in old['models']}
base={};files=[]
for line in subprocess.check_output(['git','ls-tree','-r','--name-only','4b4fdc33','crates'],cwd=R,text=True).splitlines():
 if '/src/' not in line or not line.endswith('.rs'):continue
 text=subprocess.check_output(['git','show','4b4fdc33:'+line],cwd=R,text=True)
 for m in inv.rust_models(text,line):base[m['id']]=m['fields']
 current=(R/line).read_bytes();basehash=hashlib.sha256(text.encode()).hexdigest()
 files.append({'path':line,'baseline_sha256':basehash,'candidate_sha256':hashlib.sha256(current).hexdigest(),'changed':current!=text.encode()})
missing=[k for k in base.keys()|reported.keys() if base.get(k)!=reported.get(k)]
result={'baseline':'4b4fdc33','prior_report':'evidence/model-consolidation-20261009/publish/model-review.md','prior_report_model_count':len(reported),'squashed_baseline_model_count':len(base),'inventory_mismatches':missing,'file_comparison':files}
(E/'review-provenance.json').write_text(json.dumps(result,indent=2))
print('prior reported inventory vs merged baseline mismatches',len(missing),missing[:20])
print('changed production files',sum(f['changed'] for f in files))
