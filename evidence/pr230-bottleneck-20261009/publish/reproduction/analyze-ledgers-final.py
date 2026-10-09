from pathlib import Path
import json,collections
p=Path('/src/evidence/pr230-bottleneck-20261009')
for key in ['D0','D1','D2']:
 d=p/key;fs=list(d.rglob('short-result.json'))
 if not fs:continue
 x=json.loads(fs[0].read_text());w=x['metrics']['measure'];lo=w['window_start_s'];hi=w['window_end_s'];tot={};status=[]
 for line in (d/'application-ledger-maintenance-final.log').read_text().splitlines():
  if 'POOLSTATUS ' in line:
   r=json.loads(line.split('POOLSTATUS ',1)[1]);
   if lo<=r['ts']<hi:status.append(r)
  if 'POOLLEDGER ' not in line:continue
  r=json.loads(line.split('POOLLEDGER ',1)[1]);
  if not lo<=r['ts']<hi:continue
  q=tot.setdefault(r['phase'],collections.Counter());q.update({k:v for k,v in r.items() if isinstance(v,(int,float)) and k!='ts'})
 rows=[]
 for phase,q in tot.items():
  n=max(q['n'],1);sample=q['samples'];den=sample if sample else n
  rows.append(dict(phase=phase,n=q['n'],samples=sample,borrow_per_complete=q['n']/w['measure_completed_exact'] if q['hold_us'] else None,acquire_ms=q['acquire_us']/n/1000,hold_ms=q['hold_us']/n/1000,driver_calls=q['queries']/sample if sample else None,sample_hold_ms=q['sample_hold_us']/sample/1000 if sample else None,sql_ms=q['sql_us']/den/1000,commit_ms=q['commit_us']/den/1000,begin_ms=q['begin_us']/den/1000,ready_ms=q['ready_us']/n/1000,poll_ms=q['poll_us']/n/1000))
 result=dict(key=key,window=w,phases=rows,pool_status=status,boundary='Timestamp-second aggregate approximation; sampled query cohorts. SQL await includes server, wire, driver and task wait. Task ready time overlaps SQL await; poll wall includes OS preemption. Driver calls are not TCP packet or precise wire round-trip counts.')
 (d/'final-ledger-analysis.json').write_text(json.dumps(result,indent=2));print(key,[{k:v for k,v in r.items() if k in ['phase','borrow_per_complete','acquire_ms','hold_ms','driver_calls','sql_ms','commit_ms','ready_ms','poll_ms']} for r in rows if ':sql' not in r['phase'] and ('issuance' in r['phase'] or 'authorization' in r['phase'])]);
 if status:print('POOL',collections.Counter((r['size'],r['max_size'],r['available']) for r in status), 'max_waiting',max(r['waiting'] for r in status))

