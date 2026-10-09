from pathlib import Path
import json,collections
p=Path('/src/evidence/pr230-performance-20261009/D1');r=json.loads(next(p.rglob('short-result.json')).read_text());w=r['metrics']['measure'];lo=w['window_start_s'];hi=w['window_end_s'];tot={};slices={}
for line in (p/'application-ledger-maintenance-final.log').read_text().splitlines():
 if 'POOLLEDGER ' not in line:continue
 row=json.loads(line.split('POOLLEDGER ',1)[1]);ts=row['ts']
 if not lo<=ts<hi:continue
 for dest in [tot,slices.setdefault(str(int((ts-lo)//10)*10),{})]:
  a=dest.setdefault(row['phase'],collections.Counter());a.update({k:v for k,v in row.items() if isinstance(v,(int,float)) and k!='ts'})
def table(rows):
 out=[]
 for phase,q in rows.items():
  n=q['n'];sample=q['samples'];out.append({'phase':phase,'n':n,'acquire_ms':q['acquire_us']/n/1000,'hold_ms':q['hold_us']/n/1000,'queries_per_sample':q['queries']/sample if sample else None,'sample_hold_ms':q['sample_hold_us']/sample/1000 if sample else None,'sql_ms':q['sql_us']/sample/1000 if sample else None,'commit_ms':q['commit_us']/sample/1000 if sample else None,'begin_ms':q['begin_us']/sample/1000 if sample else None,'poll_ms':q['poll_us']/n/1000,'ready_ms':q['ready_us']/n/1000,'elapsed_ms':q['elapsed_us']/n/1000})
 return out
result={'complete_ops':w['measure_completed_exact'],'phase':table(tot),'slices':{k:table(v) for k,v in slices.items()},'boundary':'second buckets fully included by start timestamp; per-phase aggregates not request-identical samples; poll wall includes preemption; ready wait overlaps query elapsed'}
(p/'ledger-analysis.json').write_text(json.dumps(result,indent=2));print(json.dumps(result['phase'],indent=2));print('SLICES TOKEN',[(k,[v for v in x if 'token_issuance' in v['phase'] or v['phase']=='issuance_task']) for k,x in result['slices'].items()])
