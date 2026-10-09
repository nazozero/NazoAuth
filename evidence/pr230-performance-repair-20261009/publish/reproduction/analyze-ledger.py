from pathlib import Path
import json,collections,math
import os
p=Path('/workspace/evidence/pr230-performance-repair-20261009')/os.environ.get('LEDGER_POINT','DREAD');r=json.loads(next(p.glob('**/short-result.json')).read_text());a=r['metrics']['measure']['window_start_s'];b=r['metrics']['measure']['window_end_s'];tot=collections.defaultdict(collections.Counter)
for l in (p/'application-ledger-maintenance.log').read_text().splitlines():
 if 'POOLLEDGER ' not in l:continue
 d=json.loads(l.split('POOLLEDGER ',1)[1]);t=d.pop('ts');phase=d.pop('phase')
 if math.ceil(a)<=t<math.floor(b):tot[phase].update(d)
reference=max(1,sum(v['n'] for k,v in tot.items() if 'repositories/token_issuance.rs:' in k and ':sql' not in k))
rows=[]
for k,v in tot.items():
 if ':sql' in k:continue
 n=max(1,v['n']);sm=max(1,v['samples']);row={'phase':k,'n':v['n'],'borrows_per_observed_issuance':v['n']/reference if v['hold_us'] else None,'acquire_ms':v['acquire_us']/n/1000,'hold_ms':v['hold_us']/n/1000,'sample_n':v['samples'],'hold_ms_sample':v['sample_hold_us']/sm/1000,'sql_ms_sample':v['sql_us']/sm/1000,'begin_ms_sample':v['begin_us']/sm/1000,'other_hold_ms_sample':(v['sample_hold_us']-v['sql_us']-v['commit_us']-v['begin_us'])/sm/1000,'commit_ms_sample':v['commit_us']/sm/1000,'query_count_sample':v['queries']/sm,'ready_ms':v['ready_us']/n/1000,'poll_ms':v['poll_us']/n/1000,'elapsed_ms':v['elapsed_us']/n/1000};
 if not v['samples']:
  for field in ['hold_ms_sample','sql_ms_sample','begin_ms_sample','other_hold_ms_sample','commit_ms_sample','query_count_sample']:row[field]=None
 if not v['hold_us']:
  row['acquire_ms']=None;row['hold_ms']=None
 rows.append(row);print(row)
(p/'ledger-summary-formal.json').write_text(json.dumps({'source':'sampled ledger complete seconds in formal window','window':[a,b],'selected_complete_seconds':[math.ceil(a),math.floor(b)],'reference_issuance_borrows':reference,'rows':rows},indent=2))





