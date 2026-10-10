from pathlib import Path
import json,sys,statistics,csv,re,datetime
E=Path('/workspace/evidence/pr238-physical-growth-20261010')
def load(p): return json.loads(p.read_text())
for key in sys.argv[1:]:
 D=E/key
 rows=[json.loads(x) for x in (D/'storage.jsonl').read_text().splitlines()]
 base=load(D/'load-boundary.json')['load_start']
 end=load(D/'load-ended.json')['load_return'] if (D/'load-ended.json').exists() else rows[-1]['ts']
 valid=[r for r in rows if 'db_bytes' in r]
 physical=[r for r in rows if 'physical_detail' in r]
 out={'key':key,'load_start':base,'load_end':end,'errors':[r for r in rows if 'error' in r],'windows':[]}
 for lo,hi in [(0,360),(360,600),(600,900),(900,1200),(1200,1500),(1500,1800),(1800,2400)]:
  rr=[r for r in valid if lo<=r['ts']-base<hi]
  if not rr:continue
  out['windows'].append({'offset_s':[lo,hi],'samples':len(rr),'db_mib_median':round(statistics.median(r['db_bytes'] for r in rr)/1048576,3),'retained_receipts':[min(r['issuance_counts']['retained'] for r in rr),max(r['issuance_counts']['retained'] for r in rr)],'eligible_receipts_max':max(r['issuance_counts']['eligible'] for r in rr),'oldest_due_s_max':max(r['issuance_counts']['oldest_due_s'] for r in rr),'pending_max':max(r['pending'] for r in rr),'pending_age_s_max':max(r['oldest_pending_s'] for r in rr),'tables':{t['relname']:{f:round(statistics.median(next(t for t in r['tables'] if t['relname']==name)[f] for r in rr)/1048576,3) for f in ['table_bytes','index_bytes']} for t in rr[-1]['tables'] for name in [t['relname']]}})
 series=[]
 for r in physical:
  for name,t in r['physical_detail']['relations'].items():
   series.append({'offset_s':round(r['ts']-base,3),'ts':r['ts'],'relation':name,**t})
 if series:
  with (D/'physical-pages.csv').open('w',newline='') as f:
   w=csv.DictWriter(f,fieldnames=list(series[0]));w.writeheader();w.writerows(series)
 idx=[]
 for r in physical:
  for name,t in r['physical_detail']['indexes'].items():idx.append({'offset_s':round(r['ts']-base,3),'ts':r['ts'],'index':name,**t})
 if idx:
  with (D/'physical-indexes.csv').open('w',newline='') as f:
   w=csv.DictWriter(f,fieldnames=list(idx[0]));w.writeheader();w.writerows(idx)
 if (D/'last-receipt-cohort.json').exists() and (D/'natural-final.json').exists():
  cohort=load(D/'last-receipt-cohort.json');deadline=cohort['last_retain_epoch'];final=load(D/'natural-final.json');cycles=[]
  for line in (D/'maintenance.log').read_text().splitlines():
   line=re.sub(r'\x1b\[[0-9;]*m','',line)
   if 'cycle completed' not in line:continue
   ts=datetime.datetime.fromisoformat(line.split()[0].replace('Z','+00:00')).timestamp();m=re.search(r'elapsed_ms=(\d+)',line)
   if m and deadline is not None and ts-int(m[1])/1000>=deadline:cycles.append(line)
  out['receipt_natural_end']={'cohort':cohort,'final_ts':final['ts'],'final_counts':final['issuance_counts'],'cycles_started_after_last_retention':cycles,'proven':bool(cycles) and final['issuance_counts']['total']==0}
 out['last_physical']={'offset_s':physical[-1]['ts']-base,**physical[-1]['physical_detail']} if physical else None
 (D/'physical-analysis.json').write_text(json.dumps(out,indent=2))
 print(key, 'windows', [{k:v for k,v in x.items() if k!='tables'} for x in out['windows']]);print('natural_receipts',out.get('receipt_natural_end'))
 if (D/'analysis.json').exists():
  a=load(D/'analysis.json');print('analysis_top_keys',list(a));print('lanes',{k:{f:v.get(f) for f in ['status','measure']} for k,v in a.get('lanes',{}).items()})
