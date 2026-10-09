import pathlib,json,csv,gzip,datetime,math,collections
E=pathlib.Path('/src/evidence/pr230-performance-20261009')
def records(path):
 s=path.read_text();d=json.JSONDecoder()
 while s.strip():
  s=s.lstrip();x,i=d.raw_decode(s);yield x;s=s[i:]
def quantile(v,q):
 if not v:return None
 v=sorted(v);t=(len(v)-1)*q;i=int(t);j=min(i+1,len(v)-1);return round(v[i]+(v[j]-v[i])*(t-i),3)
rows=[]
for key in ['D1','D2','D3','A06','B06','B10','A10','A03','B03','B04','A04','A06R','A03R','B03R','B04R','A04R']:
 p=E/key;fs=list(p.rglob('short-result.json'))
 if not fs:continue
 x=json.loads(fs[0].read_text());m=x['metrics'];
 if 'measure' not in m:
  rows.append({'key':key,'verdict':x['verdict'],'invalid_reason':m.get('reason'),'point_error':json.loads(next(p.rglob('point.json')).read_text()).get('error')});continue
 w=m['measure'];rq=json.loads((p/'requests'/f'{key}.json').read_text());outcomes=w['measure_outcomes'];n=w['measure_started_exact'];success=outcomes.get('success',0)
 row={'key':key,'source_sha':rq['source_sha'],'diagnostic_only':rq.get('diagnostic_only',False),'scenario':rq['scenario'],'app_cpus':len(rq['app_cpus']),'rate':rq['rate'],'vus':rq['pre_vus'],'users':rq['user_count'],'sidecars':rq.get('sidecars',[]),'verdict':x['verdict'],'success_ops_s':m['rate_for_gate'],'latency_ms':m['complete_operation_latency_ms'],'started':n,'successful':success,'completed':w['measure_completed_exact'],'unfinished':n-w['measure_completed_exact'],'success_fraction_of_started':success/n if n else None,'planned_success_fraction':success/w['rational_planned_arrivals'],'dropped':w['measure_dropped_exact'],'drop_fraction':w['measure_drop_fraction'],'outcomes':outcomes,'classified_errors':m.get('classified_errors'),'expected_invalid_grant':m.get('expected_invalid_grant'),'unexpected_errors':m.get('unexpected_errors'),'sidecar_gates':m.get('sidecar_gates',{}),'all_load_common_window':m.get('all_load_common_window',{}),'main_verdict':m.get('main_verdict'),'health':x['health'],'wal_bytes_per_success':x['cost']['wal_per_success_bytes'],'cpu_cores':x['component_cpu_cores'],'window':w,'elapsed_s':x['elapsed_s'],'audit':x['audit'],'maintenance':x['maintenance']}
 series=list(records(p/'storage.jsonl'))
 with (p/'storage-series.csv').open('w',newline='') as f:
  keys=['ts','db_bytes','pending','oldest_pending_s','decision_eligible','decision_retained','family_eligible','family_live','contract_orphan','spent_eligible','spent_retained','anchor'];writer=csv.DictWriter(f,fieldnames=keys);writer.writeheader();writer.writerows({k:r.get(k) for k in keys} for r in series)
 row['storage_sampling']={'start':series[0]['ts'],'end':series[-1]['ts'],'db_first':series[0]['db_bytes'],'db_last':series[-1]['db_bytes'],'db_peak':max(r['db_bytes'] for r in series),'pending_peak':max(r['pending'] for r in series),'oldest_pending_peak_s':max(r['oldest_pending_s'] for r in series)}
 full=json.loads(next(f for f in p.rglob('*.series.json') if f.parent.name=='load').read_text());bounds=full['hist_bounds_ms'];buckets={}
 for second,v in full['bins'].items():
  h=v['cap_iter_ms']
  if not h['n']:continue
  offset=int((float(second)-w['window_start_s'])//10)*10
  z=buckets.setdefault(offset,{'n':0,'b':[0]*len(h['b']),'max':0})
  z['n']+=h['n'];z['b']=[u+v for u,v in zip(z['b'],h['b'])];z['max']=max(z['max'],h['max'])
 assert sum(z['n'] for z in buckets.values())==w['measure_completed_exact'],(key,'full histogram cohort mismatch')
 def interval(h,q):
  target=math.ceil(h['n']*q);seen=0
  for i,n in enumerate(h['b']):
   seen+=n
   if seen>=target:return [bounds[i-1] if i else 0,bounds[i] if i<len(bounds) else None]
 timeline=[{'completion_offset_s':offset,'complete_samples':z['n'],'p50_interval_ms':interval(z,.5),'p95_interval_ms':interval(z,.95),'p99_interval_ms':interval(z,.99),'max_ms':z['max'],'histogram':z['b']} for offset,z in sorted(buckets.items())]
 row['histogram_bounds_ms']=bounds
 row['latency_time_buckets']=timeline;row['bucket_boundary']='Full stream cap_iter_ms histograms, grouped by completion-time 10-second buckets (one-second input resolution); quantiles are bucket intervals [lower,upper), not exact values. All formal cohort completions reconcile. Sampled diagnostic raw points cannot estimate unbiased quantiles. Formal whole-window exact gates and exact drops remain the harness result; per-second drop series retained separately. Finite VUs and drops can flatten latency.'
 (p/'time-analysis.json').write_text(json.dumps({'latency':timeline,'storage':row['storage_sampling'],'boundary':row['bucket_boundary']},indent=2));rows.append(row)
(E/'round-analysis.json').write_text(json.dumps(rows,indent=2));print(json.dumps([{k:r.get(k) for k in ['key','verdict','success_ops_s','latency_ms','dropped','wal_bytes_per_success','cpu_cores']} for r in rows],indent=2))



