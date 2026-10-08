import pathlib,sys,os,json,time,signal,subprocess
sys.path.insert(0,'/src/perf/tools')
import cnb_controller as ctl
import hashlib
for leaf,digest in ctl.M.get('instrumentation_sha256',{}).items():
 assert hashlib.sha256((pathlib.Path('/src/evidence/pr230-revision-20261008')/leaf).read_bytes()).hexdigest()==digest,leaf
if sys.argv[1]=='setup':ctl.setup();raise SystemExit(0)
key=sys.argv[1];point=json.loads(pathlib.Path(ctl.M['requests'][key]['path']).read_text());runid=point['name'];out=ctl.E/'results'/point['phase']/runid;out.mkdir(parents=True,exist_ok=True);ctl.sis.CURRENT_POINT=point
signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('fault test deadline')));signal.alarm(550)
captured_logs={}
result={'source_sha':ctl.M['source_sha'],'fixture':'Required, freshness/max_lag 10s, 200 Telemetry reads/s + 1 Required disclosure/s','phases':{'healthy':[0,40],'receiver_http500':[40,90],'recovery':[90,135],'permanent_rejection':[135,185],'recovery_after_operator_unblock':[185,240],'stop_and_drain':[240,400]}}
try:
 ctl.sis.stack_down();initial=ctl.points.stack_up_pinned(point);depid=initial['deployment_id'];result['audit']=ctl.sis.audit_pair_up(runid,depid)
 ctl.sis.psql("INSERT INTO runtime_module_desired_states (tenant_id,module_id,desired_mode,revision,reason) VALUES ('00000000-0000-0000-0000-000000000001','dynamic_client_registration','enabled',1,'isolated revision fault fixture') ON CONFLICT (tenant_id,module_id) DO UPDATE SET desired_mode='enabled',revision=runtime_module_desired_states.revision+1;")
 point['app_env_overrides'].update(AUDIT_ANCHOR_MODE='required',DEPLOYMENT_ID=depid,RUST_LOG='warn,audit.persistence=debug')
 result['stack']=ctl.points.stack_up_pinned(point);result['provenance']=ctl.sis.provenance(point,out)
 appenv=ctl.RAW('inspect',ctl.sis.APP,'--format','{{range .Config.Env}}{{println .}}{{end}}',timeout=10).stdout.splitlines()
 result['app_audit_configuration']={k:v for k,v in (line.split('=',1) for line in appenv if '=' in line) if k in ['AUDIT_ANCHOR_MODE','AUDIT_ANCHOR_FRESHNESS_SECONDS','AUDIT_ANCHOR_MAX_LAG_SECONDS','DATABASE_MAX_CONNECTIONS','RUST_LOG']}
 assert result['app_audit_configuration'].get('AUDIT_ANCHOR_MODE')=='required'
 assert result['stack']['deployment_id']==depid
 ctl.sis.pgss_reset();ctl.sis.pgss_snapshot('pre',out);ctl.sis.ledger('pre',runid,out)
 ctl.sis.start_samplers(runid,str(out));result['sampler_health']=ctl.sis.sampler_health(runid,out);assert result['sampler_health']['ok']
 env=ctl.RAW('inspect','sis-rcv-'+runid,'--format','{{range .Config.Env}}{{println .}}{{end}}',timeout=10).stdout.splitlines();token=next(s.split('=',1)[1] for s in env if s.startswith('ANCHOR_RECEIVER_TOKEN='));ctl.SECRETS.append(token)
 code=pathlib.Path('/src/evidence/pr230-revision-20261008/fault-load-v2.py').read_text();sql=pathlib.Path('/src/evidence/pr230-revision-20261008/storage-observer.sql').read_text()
 name='revision-fault-load-'+runid
 q=ctl.dc('run','-d','--name',name,'--network',ctl.sis.NETWORK,'--label',ctl.sis.SIS_LABEL+'='+ctl.P,'-v',ctl.TLS_VOL+':/run/anchor-tls:ro','-e','PROBE_DCR_TOKEN='+point['app_env_overrides']['DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN'],'-e','PROBE_DEPLOYMENT='+depid,'-e','PROBE_CA=/run/anchor-tls/'+runid+'/receiver.crt','-e','PROBE_RECEIVER=https://sis-rcv-'+runid+':9443','-e','PROBE_RECEIVER_TOKEN='+token,'-e','PROBE_STORAGE_SQL='+sql,'--entrypoint','python',ctl.M['runner_image'],'-u','-c',code,timeout=20)
 ctl.sis._record_extra(q.stdout,name,'fault_load');ctl.sis.pin_container(name,ctl.sis.format_cpu_list(point['infra_cpus']))
 deadline=time.monotonic()+445
 while time.monotonic()<deadline:
  state=json.loads(ctl.RAW('inspect',name,'--format','{{json .State}}',timeout=10).stdout)
  if not state['Running']:break
  time.sleep(2)
 else:raise TimeoutError('fault load exceeded 445 seconds')
 result['load_exit']=state['ExitCode'];raw=ctl.RAW('logs',name,check=False,timeout=20);captured_logs['fault-storage-http.jsonl']=ctl.scrub(raw.stdout);captured_logs['fault-load-stderr.log']=ctl.scrub(raw.stderr);assert state['ExitCode']==0,'fault load failed'
 result['drain']=ctl.sis.audit_drain();result['audit_final']=ctl.points.audit_state_snapshot(runid);ctl.sis.pgss_snapshot('post',out);ctl.sis.ledger('post',runid,out)
except BaseException as error:result['error']=ctl.scrub(type(error).__name__+': '+str(error))
finally:
 signal.alarm(0)
 for name,label in [(ctl.sis.APP,'app'),('sis-worker-'+runid,'exporter')]:
  q=ctl.RAW('logs',name,check=False,timeout=20);captured_logs[label+'.log']=ctl.scrub(q.stdout+q.stderr)
 try:ctl.sis.stop_samplers(runid)
 except Exception as error:result['sampler_stop_error']=str(error)
 ctl.sync_samplers();ctl.capture(runid,out)
 for leaf,text in captured_logs.items():(out/leaf).write_text(text)
 ctl.save(out/'fault-result.json',result)
 ctl.CLEANING=True;ctl.CLEANUP_DEADLINE=time.monotonic()+45
 try:ctl.sis.stack_down()
 except Exception as error:result['cleanup_error']=str(error)
 ctl.save(out/'fault-result.json',result)
 print(json.dumps({'error':result.get('error'),'load_exit':result.get('load_exit'),'drain':result.get('drain'),'cleanup_error':result.get('cleanup_error')}),flush=True)
raise SystemExit(1 if result.get('error') or result.get('cleanup_error') else 0)
