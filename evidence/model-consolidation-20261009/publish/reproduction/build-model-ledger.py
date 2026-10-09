from pathlib import Path
import sys,json,re,collections,subprocess,hashlib
R=Path('/workspace');E=R/'evidence/model-consolidation-20261009';P=E/'publish';P.mkdir(exist_ok=True)
sys.path.insert(0,str(R/'scripts'));import data_model_inventory as inv
models,errors,files=inv.source_inventory(R);assert not errors,errors
receiver=[]
for p in sorted((R/'perf/audit-anchor-receiver/src').glob('*.rs')):receiver+=inv.rust_models(p.read_text(),p.relative_to(R).as_posix())
generated=[]
for name in ['UserId','TenantId','RealmId','OrganizationId']:
 generated.append({'id':'crates/identity/src/tenancy.rs::'+name,'kind':'macro-generated-struct','fields':[{'name':'0','type':'Uuid'}],'owner':'identity_id! nonnil identity boundary'})
out={'source_files':files,'declarations':len(models),'members':sum(len(m['fields']) for m in models),'parse_errors':errors,'models':models,'generated_models':generated,'receiver_models':receiver,'note':'Inventory and lexical references are navigation, not proof of semantic correctness. See model-review.md and execution evidence.'}
(P/'models.json').write_text(json.dumps(out,indent=2,ensure_ascii=False))
terms=set()
for m in models+receiver:
 terms.add(m['id'].split('::')[-1].split('#')[0])
 for f in m['fields']:
  name=f['name'].split('.')[-1]
  if name.isidentifier():terms.add(name)
refs=collections.defaultdict(list)
paths=subprocess.check_output(['git','ls-files','crates','perf/audit-anchor-receiver/src'],cwd=R,text=True).splitlines()
for path in paths:
 if '/tests/' in path or not path.endswith(('.rs','.sql','.lua')) or not (R/path).exists():continue
 for line,s in enumerate((R/path).read_text().splitlines(),1):
  for term in set(re.findall(r'\b[A-Za-z_]\w*\b',s))&terms:refs[term].append([path,line])
(P/'member-reference-index.json').write_text(json.dumps({'qualification':'Lexical cross references, including field declarations and SQL/Lua/string consumers; not type-resolved or a consumer count.','references':refs},separators=(',',':')))
baseline=json.loads((E/'declarations.json').read_text())
old={(m['id'],f['name']):f['type'] for m in baseline['models'] for f in m['fields']};new={(m['id'],f['name']):f['type'] for m in models for f in m['fields']}
delta={'baseline_declarations':len(baseline['models']),'baseline_members':len(old),'removed':[{'model':m,'field':f,'type':old[(m,f)]} for m,f in old.keys()-new.keys()],'added':[{'model':m,'field':f,'type':new[(m,f)]} for m,f in new.keys()-old.keys()],'changed':[{'model':m,'field':f,'before':old[(m,f)],'after':new[(m,f)]} for m,f in old.keys()&new.keys() if old[(m,f)]!=new[(m,f)]]}
for key in ['removed','added','changed']:delta[key].sort(key=lambda x:(x['model'],x['field']))
(P/'model-delta.json').write_text(json.dumps(delta,indent=2))
print(json.dumps({k:v for k,v in out.items() if k not in ['models','generated_models','receiver_models']},ensure_ascii=False));print('generated',len(generated),'receiver',len(receiver),'delta', {k:len(delta[k]) for k in ['removed','added','changed']})
