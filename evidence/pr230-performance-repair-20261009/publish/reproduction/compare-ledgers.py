from pathlib import Path
import json,collections,re
E=Path('/src/evidence/pr230-performance-repair-20261009');result={}
def weighted(rows,field):
 weight='sample_n' if field.endswith('_sample') else 'n'
 valid=[r for r in rows if r.get(field) is not None and r.get(weight,0)>0]
 return sum(r[field]*r[weight] for r in valid)/sum(r[weight] for r in valid) if valid else None
stages=[('client reads',5,'repositories/clients/base.rs:',lambda k:k.startswith('client_') and k.endswith(':connection')),('public account',2,'repositories/users.rs:68',lambda k:k=='user_public_account_by_id:connection'),('subject snapshot',1,'repositories/users.rs:114',lambda k:k=='user_active_subject_claims_by_tenant_id:connection'),('audit preflight',1,'repositories/audit_ledger.rs:',lambda k:'repositories/audit_ledger.rs:' in k),('decision commit',1,'repositories/authorization_flow.rs:',lambda k:'repositories/authorization_flow.rs:' in k),('token issuance',1,'repositories/token_issuance.rs:',lambda k:'repositories/token_issuance.rs:' in k)]
for key in ['DREAD','DREADA2','DREADB']:
 ledger=json.loads((E/key/'ledger-summary-formal.json').read_text());rows=ledger['rows'];by_stage=[]
 for name,count,old,new in stages:
  selected=[r for r in rows if (new(r['phase']) if key=='DREADB' else old in r['phase']) and r.get('hold_ms') is not None]
  by_stage.append({'stage':name,'logical_borrows_per_operation':count,'observed_borrows':sum(r['n'] for r in selected),**{field:weighted(selected,field) for field in ['acquire_ms','hold_ms','hold_ms_sample','sql_ms_sample','begin_ms_sample','commit_ms_sample','other_hold_ms_sample','query_count_sample']}})
 roles=collections.defaultdict(collections.Counter);samples=0;a,b=ledger['window'];statuses=[]
 for line in (E/key/'pg-roles.jsonl').read_text().splitlines():
  x=json.loads(line)
  if not a<=x.get('ts',0)<=b:continue
  samples+=1
  for q in x.get('activity') or []:
   role=q['usename'] or 'background';roles[role][str((q['state'],q['wait_event_type'],q['wait_event']))]+=q['n']
 for line in (E/key/'application-ledger-maintenance.log').read_text().splitlines():
  if 'POOLSTATUS ' not in line:continue
  x=json.loads(line.split('POOLSTATUS ',1)[1])
  if a<=x['ts']<=b:statuses.append(x)
 pool={'observations':len(statuses),'minimum_available':min((x['available'] for x in statuses),default=None),'maximum_waiting':max((x['waiting'] for x in statuses),default=None),'mean_waiting_observation':sum(x['waiting'] for x in statuses)/len(statuses) if statuses else None}
 result[key]={'selected_seconds':ledger['selected_complete_seconds'],'reference_issuance_borrows':ledger['reference_issuance_borrows'],'stages':by_stage,'profiled_scheduling':[r for r in rows if r.get('hold_ms') is None],'role_samples':samples,'role_mean_connection_observations':{k:{s:n/samples for s,n in v.items()} for k,v in roles.items()},'pool_observations':pool}
result['boundary']='SQL/BEGIN/COMMIT are client-observed elapsed time, not backend CPU; matched sampled hold minus those times is application/other hold residual. Wake-to-poll and poll time are separate profiles, not additive to SQL wall time. Profiles do not observe delay before a driver wake or before the first task poll. A public-account future was not separately profiled. Connection counts cover complete one-second buckets and are not per-request traces. Runtime/exporter/postgres observation/background roles remain separate; ClientRead alone is not pool occupancy. DREAD was an earlier busy window, not a simultaneous causal control; DREADA2 and DREADB form the later pair.'
(E/'ledger-comparison.json').write_text(json.dumps(result,indent=2));print(json.dumps({k:{'pool':v['pool_observations'],'stages':v['stages']} for k,v in result.items() if isinstance(v,dict)},indent=2))
