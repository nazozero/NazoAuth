from pathlib import Path
import json,sys,csv
E=Path('/workspace/evidence/pr238-physical-growth-20261010')
cols=['oid','relation','heap_main','heap_aux','indexes','toast','total','live_est','dead_est','ins','upd','hot_upd','del','vac','autovac','component_check']
for key in sys.argv[1:]:
 d=E/key;rr={}
 for phase in ['pre','post']:
  p=next(d.glob('results/*/*/ledger-'+phase+'.txt'),None)
  if p is None:continue
  allowed={'META','RELATION_BYTES','INDEX_DETAIL','ROW_COUNTS','REFRESH_MODEL','EXPIRED_BACKLOG','AUDIT','WAL','BGWRITER','CHECKPOINTER','DB_TOTAL','DONE'}
  lines=[l for l in p.read_text().splitlines() if l.split('|')[0] in allowed]
  (d/('physical-ledger-'+phase+'.txt')).write_text('\n'.join(lines)+'\n')
  rows=[]
  for line in lines:
   vals=line.split('|')
   if vals[0]=='RELATION_BYTES':
    r=dict(zip(cols,vals[1:]));r={k:(int(v) if k!='relation' else v) for k,v in r.items()};assert r['total']==r['component_check'];rows.append(r)
  rr[phase]={r['relation']:r for r in rows}
 if set(rr)!= {'pre','post'}:continue
 delta=[]
 for name,b in rr['post'].items():
  a=rr['pre'][name];delta.append({'relation':name,'pre_bytes':a['total'],'post_bytes':b['total'],'delta_bytes':b['total']-a['total'],'post_heap_bytes':b['heap_main'],'post_index_bytes':b['indexes'],'post_live_est':b['live_est'],'post_dead_est':b['dead_est'],'delta_updates':b['upd']-a['upd'],'delta_autovac':b['autovac']-a['autovac']})
 delta.sort(key=lambda r:r['delta_bytes'],reverse=True)
 (d/'all-relation-deltas.json').write_text(json.dumps(delta,indent=2))
 print(key,'other_growth',[r for r in delta if r['delta_bytes']>0 and not any(s in r['relation'] for s in ['oauth_refresh_','oauth_token_issuances','security_audit_events','security_audit_chain_entries'])])