from pathlib import Path
import json,csv,math,re
import sys
E=Path(sys.argv[1])
POINTS=sys.argv[2:]
reports=[]
for key in POINTS:
 P=E/key; f=list(P.rglob('short-result.json'))
 if not f: print(key,'not yet finished');continue
 x=json.loads(f[0].read_text());m=x['metrics'];rq=json.loads((P/'requests'/f'{key}.json').read_text());w=m.get('measure',{})
 if not w:print(key,'INVALID',m);continue
 db=[json.loads(s) for s in (P/'storage.jsonl').read_text().splitlines()];errors=[r for r in db if 'error' in r];db=[r for r in db if 'db_bytes' in r]
 terminal=json.loads((P/'storage-terminal.json').read_text());db.append(terminal)
 if (P/'natural-tail.jsonl').exists():db.extend(json.loads(s) for s in (P/'natural-tail.jsonl').read_text().splitlines())
 if (P/'natural-final.json').exists():db.append(json.loads((P/'natural-final.json').read_text()))
 db.sort(key=lambda r:r['ts'])
 if (P/'storage-after-validation.json').exists():db.append(json.loads((P/'storage-after-validation.json').read_text()))
 db.sort(key=lambda r:r['ts'])
 vk=[json.loads(s) for s in (P/'valkey-series.jsonl').read_text().splitlines()];vkt=json.loads((P/'valkey-terminal.json').read_text());vkt['ts']=json.loads((P/'post-ended.json').read_text())['ts'];vk.append(vkt)
 full=json.loads(next(p for p in P.rglob('*.series.json') if p.parent.name=='load').read_text());bounds=full['hist_bounds_ms'];bins={}
 for second,v in full['bins'].items():
  h=v['cap_iter_ms']
  if not h['n']:continue
  offset=int((float(second)-math.floor(w['window_start_s']))//30)*30
  z=bins.setdefault(offset,{'n':0,'b':[0]*len(h['b']),'max':0});z['n']+=h['n'];z['b']=[a+b for a,b in zip(z['b'],h['b'])];z['max']=max(z['max'],h['max'])
 assert sum(z['n'] for z in bins.values())==w['measure_completed_exact']
 def interval(h,q):
  seen=0
  for i,n in enumerate(h['b']):
   seen+=n
   if seen>=math.ceil(h['n']*q):return [bounds[i-1] if i else 0,bounds[i] if i<len(bounds) else None]
 latency=[dict(offset_s=k,completed=v['n'],p95_interval_ms=interval(v,.95),p99_interval_ms=interval(v,.99),max_ms=v['max']) for k,v in sorted(bins.items())]
 keys=['ts','db_bytes','pending','oldest_pending_s','decision_eligible','decision_retained','decision_oldest_due_s','family_eligible','family_live','family_oldest_due_s','contract_orphan','spent_eligible','spent_retained','anchor']
 with (P/'storage-series.csv').open('w',newline='') as f:
  wr=csv.DictWriter(f,fieldnames=keys+['issuances','issuances_eligible','issuances_oldest_due_s','revocations','revocations_eligible','revocations_retained']);wr.writeheader()
  for r in db:wr.writerow(dict({k:r.get(k) for k in keys},issuances=r['issuance_counts']['total'],issuances_eligible=r['issuance_counts']['eligible'],issuances_oldest_due_s=r['issuance_counts']['oldest_due_s'],revocations=r.get('revocations',{}).get('total'),revocations_eligible=r.get('revocations',{}).get('eligible'),revocations_retained=r.get('revocations',{}).get('retained')))
 rows=[]
 start=json.loads((P/'load-boundary.json').read_text())['load_start']
 for r in db:
  rows.append({'offset_s':round(r['ts']-start,1),'db_mib':round(r['db_bytes']/2**20,2),'pending':r['pending'],'oldest_pending_s':r['oldest_pending_s'],'decision_eligible':r['decision_eligible'],'decision_retained':r['decision_retained'],'decision_oldest_due_s':r['decision_oldest_due_s'],'family_eligible':r['family_eligible'],'contract_orphan':r['contract_orphan'],'issuances':r['issuance_counts'],'decision_bytes':r['decision_bytes'],'decision_retention':r['decision_retention'],'revocations':r.get('revocations')})
 out={'key':key,'frozen_source':rq['source_sha'],'request':rq,'source_manifest':json.loads((E/'build.json').read_text()),'natural_final':json.loads((P/'natural-final.json').read_text()),'verdict':x['verdict'],'measure':w,'ops_s':m['rate_for_gate'],'latency_ms':m['complete_operation_latency_ms'],'unexpected_errors':m.get('unexpected_errors'),'expected_invalid_grant':m.get('expected_invalid_grant'),'classified_errors':m.get('classified_errors'),'sidecar_gates':m.get('sidecar_gates'),'health':x['health'],'audit':x['audit'],'maintenance':x['maintenance'],'forensic_diag':m.get('forensic_diag'), 'post_validation':json.loads((P/'storage-after-validation.json').read_text()) if (P/'storage-after-validation.json').exists() else None,'wal_per_success':x['cost']['wal_per_success_bytes'],'cpu_cores':x['component_cpu_cores'],'latency_30s':latency,'storage':rows,'storage_errors':errors,'valkey':[{'offset_s':round(v['ts']-start,1),'keys':v['census_exact'],'info':v['info'],'sample_memory':v['mem_bytes_sampled'],'sample_n':v['mem_sample_n']} for v in vk],'terminal_table_sizes':terminal['tables'],'observer_peak_s':max(r.get('observer_elapsed_s',0) for r in db),'elapsed_s':x['elapsed_s'],'cleanup':x.get('cleanup')}
 out['storage_error_classification'] = {'during_observation': [r for r in errors if r['ts'] <= out['natural_final']['ts']], 'after_natural_final': [r for r in errors if r['ts'] > out['natural_final']['ts']]}
 (P/'investigation-analysis.json').write_text(json.dumps(out,indent=2));reports.append(out)
 print(json.dumps({k:out[k] for k in ['key','verdict','ops_s','latency_ms','unexpected_errors','expected_invalid_grant','sidecar_gates','storage_errors','elapsed_s','wal_per_success','cpu_cores','natural_final']},default=str))
(E/'analysis.json').write_text(json.dumps(reports,indent=2))





