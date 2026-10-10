from pathlib import Path
import json,sys,csv,math
E=Path('/workspace/evidence/pr238-longrun-20261010')
for key in sys.argv[1:]:
 D=E/key;p=D/'analysis.json'
 if not p.exists():continue
 a=json.loads(p.read_text())
 if not a.get('lanes'):continue
 base=next(D.glob('results/*/*/short-result.json')).parent;out={}
 for lane,info in a['lanes'].items():
  s=json.loads(next((base/lane).glob('*.series.json')).read_text());net=0;peak=0;minutes=[];current=None;row=None;begun=0;ended=0;origin=math.floor(info['measure']['window_start_s'])
  for t,r in sorted(s['bins'].items(),key=lambda x:float(x[0])):
   b=r.get('begins',{}).get('measure',0);e=sum(v for k,v in r.get('ends',{}).items() if k.startswith('measure|'))
   if not begun and not b:continue
   begun+=b;ended+=e;net+=b-e;peak=max(peak,net);minute=math.floor((float(t)-origin)/60)
   if current!=minute:
    if row:minutes.append(row)
    row={'minute':minute,'second_end_inflight_min':net,'second_end_inflight_max':net,'last_second_end_inflight':net};current=minute
   row['second_end_inflight_min']=min(row['second_end_inflight_min'],net);row['second_end_inflight_max']=max(row['second_end_inflight_max'],net);row['last_second_end_inflight']=net
  if row:minutes.append(row)
  assert begun==info['measure']['measure_started_exact'],(key,lane,'begun',begun,info['measure']['measure_started_exact'])
  assert ended==info['measure']['measure_completed_exact'],(key,lane,'ended',ended,info['measure']['measure_completed_exact'])
  out[lane]={'formal_begun':begun,'formal_completed':ended,'final_unfinished':net,'max_second_end_inflight':peak,'minutes':minutes,'note':'Net cumulative formal begins minus ends at one-second aggregate boundaries. This is application-operation concurrency, not K6 allocated VUs. Subsecond peaks are not observed.'}
  with (D/(lane+'-inflight-minute.csv')).open('w',newline='') as f:
   w=csv.DictWriter(f,fieldnames=list(minutes[0]));w.writeheader();w.writerows(minutes)
 (D/'inflight-analysis.json').write_text(json.dumps(out,indent=2));print(json.dumps({'key':key,'load':{k:v for k,v in out['load'].items() if k!='minutes'}}))