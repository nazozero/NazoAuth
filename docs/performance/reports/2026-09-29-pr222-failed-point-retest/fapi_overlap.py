"""Temporal overlap evidence, no causal assertion and no payload/tag identifiers."""
import gzip,json,sys
from pathlib import Path
from datetime import datetime
root=Path(sys.argv[1]); dest=Path(sys.argv[2])
def points(folder,metric,step=None):
    f=next((root/folder).glob('*.diag.jsonl.gz'),None)
    if not f:return []
    result=[]
    with gzip.open(f,'rt') as h:
        for line in h:
            x=json.loads(line);d=x.get('data',{});tags=d.get('tags') or {}
            if x.get('metric')!=metric or (step and tags.get('step')!=step):continue
            ts=datetime.fromisoformat(d['time'].replace('Z','+00:00')).timestamp();ms=d['value']
            result.append((ts-ms/1000,ts,ms))
    return result
fapi=points('fapi','cap_iter_ms');logins=points('argon2','http_req_duration','login')
groups={'overlaps_cold_login':[],'does_not_overlap_retained_login':[]}; slow=[]
for start,end,ms in fapi:
    overlaps=[(a,b,c) for a,b,c in logins if a<end and b>start]
    group='overlaps_cold_login' if overlaps else 'does_not_overlap_retained_login';groups[group].append(ms)
    if ms>100:slow.append({'fapi_entry_epoch':start,'fapi_completion_epoch':end,'full_operation_ms':ms,'retained_login_overlap_count':len(overlaps),'overlap_seconds':sum(max(0,min(end,b)-max(start,a)) for a,b,_ in overlaps)})
def q(v,t):
    v=sorted(v)
    if not v:return None
    n=(len(v)-1)*t;i=int(n);return v[i]+(v[min(i+1,len(v)-1)]-v[i])*(n-i)
result={'point':root.name,'fapi_retained_operations':len(fapi),'retained_cold_login_requests':len(logins),'groups':{k:{'count':len(v),'over_100ms':sum(x>100 for x in v),'p50_ms':q(v,.5),'p95_ms':q(v,.95),'max_ms':max(v) if v else None} for k,v in groups.items()},'slow_fapi_operations':slow,'scope':'Retained cap_iter_ms measurement-entry cohort; cold login interval approximated by HTTP completion minus request duration. Correlation only. Check forensic sample count and overflow against authoritative cohort; missing retained login is not proof of no login.'}
dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('slow_fapi_operations',)}))
