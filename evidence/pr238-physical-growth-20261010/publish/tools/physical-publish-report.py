from pathlib import Path
import json,csv,hashlib,shutil,re,datetime
E=Path('/workspace/evidence/pr238-physical-growth-20261010');P=E/'publish';P.mkdir(exist_ok=True)
keys=['AUTH_DIAG','AUTH_B','AUTH_B30','CC_B15','AUTH_A_CAP','AUTH_CAP','AUTH_A_CAP2','CC_RETEST']
def read(p):return json.loads(p.read_text())
def table(headers,rows):return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |']+['| '+' | '.join(map(str,r))+' |' for r in rows])
# Explicit evidence allowlist, never environment overrides, token material, raw requests or forensic traces.
files=['execute.log','setup.log','execution.json','checkout-execution.json','source-equivalence.json','observation-delta.json','wal-disk-terminal.json','wal-disk-analysis.json','wal-disk-series.csv','setup-exit.json','export-throughput.csv','analysis.json','resource-analysis.json','resource-cpu.csv','inflight-analysis.json','load-inflight-minute.csv','load-latency-minute.csv','physical-analysis.json','physical-decomposition.json','physical-ledger-pre.txt','physical-ledger-post.txt','all-relation-deltas.json','physical-pages.csv','physical-indexes.csv','storage-series.csv','storage.jsonl','pg-roles.jsonl','valkey-series.jsonl','maintenance.log','load-boundary.json','load-ended.json','cohort-definition.json','target-cohort.json','cohort-at-stop.json','post-start.json','post-ended.json','storage-terminal.json','storage-after-validation.json','valkey-terminal.json','indexes-terminal.json','natural-final.json','natural-tail.jsonl','last-receipt-cohort.json','holder-footprint.json','vacuum-config.json','ui-release.json','ui-gate-passed.json','ui-observations.jsonl','followed-instance.json','copy-policy-evidence.json']
copied=[]
def cp(src,dst):
 if not src.exists():return
 dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst);copied.append(str(dst.relative_to(P)))
capacity=[];states=[];costs=[];storage=[];commands=[];details=[]
for key in keys:
 D=E/key;assert (D/'execution.json').exists(),key+' not complete'
 for name in files:cp(D/name,P/key/name)
 cp(D/'requests'/f'{key}.json',P/key/'request.json')
 for name in ['observer.sql','point-observer-cycle.py','diagnostic_controller.py']:cp(D/name,P/key/'tools'/name)
 ex=read(D/'execution.json');commands.append({'key':key,**ex})
 if (D/'checkout-execution.json').exists():
  commands.extend({'key':key+'/checkout',**x} for x in read(D/'checkout-execution.json')['records'])
 for extra in ['wal-disk-terminal.json','setup-exit.json']:
  if (D/extra).exists():commands.append({'key':key+'/'+extra,**read(D/extra)})
 for result in D.glob('results/*/*/short-result.json'):
  base=result.parent
  for name in ['short-result.json','task-cleanup.json','task-finalization.json','task-container-states-before-cleanup.json','provenance.json','service-affinity.json','generator-affinity.json','soak-metrics.jsonl','proc-detail.jsonl','wal-pre.json','wal-post.json','vkledger-pre.json','vkledger-post.json','task-audit-preflight.json','task-collector-preflight.json']:
   cp(base/name,P/key/'raw'/name)
  for f in base.glob('*/*.series.json'):cp(f,P/key/'raw'/f.parent.name/f.name)
 if not (D/'analysis.json').exists():continue
 a=read(D/'analysis.json');details.append({'key':key,'verdict':a['capacity_verdict'],'result':a['result']})
 if 'lanes' not in a:
  capacity.append([key,'INVALID_NO_MEASUREMENT','—','—','—','—','—','—','—','—']);continue
 lane=a['lanes']['load'];m=lane['measure'];lat=lane['latency_ms'];out=m['measure_outcomes']
 capacity.append([key,a['capacity_verdict'],lane['window_seconds'],lane['rate'],'/'.join(str(lat[x]) for x in ['p50','p95','p99']),m['measure_dropped_exact'],out.get('expected_rejection',0),sum(v for k,v in out.items() if k not in ['success','expected_rejection']),m['measure_started_exact']-m['measure_completed_exact'],ex['exit']])
 f=a['natural_final'];states.append([key,f['pending'],f['target_decisions']['count'],f.get('full_cycle_after_target_deadline'),f['issuance_counts']['total'],f['family_live'],f['family_eligible'],f['contract_orphan']])
 res=read(D/'resource-analysis.json');cpu=res['whole_window']['cpu'];wal=res['wal_sample_window'];costs.append([key,round(cpu.get('app',{}).get('time_weighted_mean_cores',0),3),round(cpu.get('postgres',{}).get('time_weighted_mean_cores',0),3),a['result'].get('cost',{}).get('wal_per_success_bytes'),wal['delta_bytes'] if wal else '—'])
 if (D/'physical-analysis.json').exists():
  pa=read(D/'physical-analysis.json')
  for w in pa['windows']:
   t=w['tables'];storage.append([key,str(w['offset_s']),w['db_mib_median'],t['oauth_token_issuances']['table_bytes'],t['oauth_token_issuances']['index_bytes'],t['security_audit_events']['table_bytes'],t['security_audit_events']['index_bytes'],str(w['retained_receipts']),w['oldest_due_s_max']])
for name in ['build.json','historical-physical-growth.json','plan.json','wait-analysis.log'] : cp(E/name,P/name)
for f in (E/'quality').glob('*'):
 if f.suffix in ['.log','.json'] and f.name!='fixture.json':cp(f,P/'quality'/f.name)
for f in (E/'tools').glob('*'):
 if f.suffix in ['.py','.log','.json']:cp(f,P/'tools'/f.name)
for name in ['physical-candidate-prepare.py','physical-growth-execute.py','physical-analyze.py','physical-page-analysis.py','physical-tail-watch.py','physical-historical-growth.py','physical-index-probe.sql','physical-holder.sql','physical-authority.sql','physical-wait-analysis.py','physical-index-trend.py','physical-baseline-cap-prepare.py','physical-capacity-pair-arm.py','physical-baseline-cap2-prepare.py','physical-export-trend.py','physical-wal-disk-probe.py','physical-cap-wal-observer.py','physical-cc-wal-observer.py','physical-wal-analysis.py','physical-decomposition.py','physical-ledger-analysis.py','physical-final-index-probe.py','physical-publish-report.py']:
 cp(Path('/tmp')/name,P/'tools'/name)
for f in (E/'quality').glob('*-exit.json'):commands.append({'key':'quality/'+f.name,**read(f)})
(P/'commands.json').write_text(json.dumps(commands,indent=2));(P/'details.json').write_text(json.dumps(details,indent=2))
lines=[Path('/tmp/physical-report-findings.md').read_text(),'\n## Actual workload results\n',table(['Point','Capacity verdict','Formal seconds','Successful ops/s','P50/P95/P99 ms','Drop','Expected rejection','Other failed operations','Unfinished','Exit'],capacity),'\nAUTH_DIAG/AUTH_B30/CC_B15/CC_RETEST are storage diagnostics. AUTH_A_CAP/AUTH_A_CAP2/AUTH_CAP use the original normal sampler without the added physical page scans. Capacity verdicts retain all original success and latency thresholds; diagnostic observer cost is not subtracted.\n','## Natural terminal state\n',table(['Point','Pending','Target decisions','Full cycle after target deadline','All receipts','Legal live families','Eligible families','Orphan contracts'],states),'\nAll 180-second capacity arms are shorter than the receipt retention horizon and are not used to prove receipt cleanup. AUTH_B30 covers the final receipt retention deadline and a full natural maintenance cycle; see its last-receipt-cohort.json and physical-analysis.json. N/A decision cycles in client credentials reflect absence of decision rows, not a skipped applicable case.\n','## Physical windows\n',table(['Point','Seconds from load launch','DB MiB median','Receipt table MiB','Receipt indexes MiB','Audit table MiB','Audit indexes MiB','Valid receipt count range','Max expired receipt age s'],storage),'\nThese are allocation and row observations, not equal-work normalized total database savings. Detailed pgstattuple live/dead/free bytes and pgstatindex density/deleted pages are retained in physical-pages.csv and physical-indexes.csv.\n','## CPU and WAL\n',table(['Point','Application average cores','PG average cores','WAL bytes/success from collector','WAL raw endpoint delta bytes'],costs),'\nCPU uses owned service process jiffies, with explicit limitations for terminated PG backends in resource-analysis.json. WAL generation endpoints and full time series are preserved; retained WAL allocation and checkpoint counters are separately in wal-disk-series.csv and wal-disk-analysis.json. No host CPU/disk probes were used.\n','## Commands and integrity\n','Actual command arrays, start/end times and exit codes are in commands.json and per-command exit JSON. Source candidate is the exact image source in build.json. This report commit adds evidence only. SHA256SUMS covers published files; historical reports remain unchanged.\n']
if (E/'final-conclusions.md').exists():lines+=['## Final scoped conclusions\n',(E/'final-conclusions.md').read_text()]
(P/'REPORT.md').write_text('\n'.join(lines))
(P/'copied-evidence-manifest.json').write_text(json.dumps(copied,indent=2))
# A publication guard catches common credential forms; findings must be reviewed, never blindly removed.
findings=[]
for f in P.rglob('*'):
 if not f.is_file() or f.name=='SHA256SUMS':continue
 text=f.read_text(errors='replace')
 for pattern in [r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY',r'gh[pousr]_[A-Za-z0-9]{25,}',r'github_pat_[A-Za-z0-9_]{30,}',r'postgres(?:ql)?://[^\s\"]+:[^\s\"]+@',r'Authorization: Bearer [A-Za-z0-9._-]{20,}']:
  if re.search(pattern,text):findings.append({'path':str(f.relative_to(P)),'pattern':pattern})
assert not findings,findings
(P/'SHA256SUMS').write_text('\n'.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+str(f.relative_to(P)) for f in sorted(P.rglob('*')) if f.is_file() and f.name!='SHA256SUMS')+'\n')
print(json.dumps({'files':len(list(P.rglob('*'))),'bytes':sum(f.stat().st_size for f in P.rglob('*') if f.is_file()),'report':str(P/'REPORT.md')}))
