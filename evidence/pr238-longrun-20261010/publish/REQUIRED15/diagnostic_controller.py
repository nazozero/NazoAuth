#!/usr/bin/env python3
"""CNB Docker-socket controller using named output volumes.

Host-bind runs continue to use single_instance_scaling directly. This entry
copies named-volume output for readiness and once at termination, never on
state/affinity inspection. The supplied manifest binds source and requests.
"""
import pathlib,sys,os,json,hashlib,subprocess,time,datetime,signal,traceback
E=pathlib.Path(os.environ.get('SIS_CNB_EVIDENCE','/evidence'));R=pathlib.Path(os.environ.get('SIS_WORKSPACE','/workspace'))
M=json.loads((E/'requests/manifest.json').read_text());P=M['project']
os.umask(0o077)
os.environ.update(SIS_WORKSPACE=str(R),SIS_RESULTS=str(E/'results'),SIS_BIN=str(E/'bin'),SIS_PROJECT=P,SIS_PERF_IMAGE=M['runner_image'],SIS_SOURCE_SHA=M['source_sha'],COMPOSE_PROJECT_NAME=P)
sys.path.insert(0,str(R/'perf/tools'))
import single_instance_scaling as sis,point_runner as points,short_baseline as sb
from blackbox_contract import CONTRACT
assert M.get('collection_contract') == CONTRACT
points.KEYSET_VOLUME=P+'-keys'
RAW=sis.dc;SECRETS=[];OUTS={};VOLS={};SYNCING=False
INSPECT_SKIPS=[];COPY_OPS=[];COPY_FAILURES=[];TERMINAL_CAPTURED=set();TERMINATION_ERRORS=[]
CLEANING=False;CLEANUP_DEADLINE=None
SCRIPT_VOL=P+'-scripts';TLS_VOL=P+'-audit-tls';PIN_VOL=P+'-pinbin'
def scrub(text):
    for value in sorted(set(SECRETS),key=len,reverse=True):
        if len(value)>7:text=text.replace(value,'[REDACTED]')
    return text
def save(path,value):
    path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(scrub(json.dumps(value,indent=2))+'\n');path.chmod(0o600)
def event(stage,**data):
    item={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stage':stage,**data}
    with (E/'adapter-events.jsonl').open('a') as f:f.write(scrub(json.dumps(item))+'\n')
    print(scrub(json.dumps(item)),flush=True)
def copy_helper(volume,target='/copy'):
    name=P+'-copy-'+hashlib.sha256(volume.encode()).hexdigest()[:7]
    RAW('run','-d','--name',name,'--label','diag.owner='+P,'-v',volume+':'+target,'--entrypoint','sh',M['runner_image'],'-c','tail -f /dev/null',timeout=20)
    return name
def output_volume(source):
    source=str(pathlib.Path(source));key=hashlib.sha256(source.encode()).hexdigest()[:12]
    volume=P+'-out-'+key
    if source not in VOLS:
        RAW('volume','create','--label','diag.owner='+P,volume,timeout=15)
        helper=copy_helper(volume)
        try:
            pathlib.Path(source).mkdir(parents=True,exist_ok=True)
            RAW('cp',source+'/.',helper+':/copy/',timeout=20)
        finally:RAW('rm','-f',helper,check=False,timeout=15)
        VOLS[source]=volume
    return volume
def output_name(value):
    if value in OUTS:return value
    return next((name for name,(_,_,cid) in OUTS.items() if value==cid),None)

def output_state(name,deadline=None):
    """Read the exact registered instance and verify ownership before terminal capture."""
    cid=OUTS[name][2]
    limit=2 if deadline is None else min(2,max(.05,deadline-time.monotonic()))
    fmt='{"id":{{json .Id}},"running":{{json .State.Running}},"labels":{{json .Config.Labels}}}'
    reply=RAW('inspect',cid,'--format',fmt,check=False,timeout=limit)
    if reply.returncode:raise RuntimeError('registered output instance unavailable')
    state=json.loads(reply.stdout)
    if state.get('id')!=cid or (state.get('labels') or {}).get(sis.SIS_LABEL)!=P or not isinstance(state.get('running'),bool):
        raise RuntimeError('registered output instance ownership/state mismatch')
    return state

def finalize_outputs(timeout_s=35):
    """Stop only registered, still-owned instances and take final output before cleanup."""
    deadline=time.monotonic()+timeout_s;errors=[];stopped=[];partial=[]
    for name,(_,_,cid) in list(OUTS.items()):
        if name in TERMINAL_CAPTURED:continue
        try:
            if time.monotonic()>=deadline:raise TimeoutError('output finalization budget exhausted')
            state=output_state(name,deadline)
            confirmed_stopped=not state['running']
            if state['running']:
                stopped.append(name)
                errors.append({'container':name,'reason':'workload still running at finalization'})
                for command,limit in [(('stop','--time','3',cid),5),(('wait',cid),2)]:
                    try:
                        reply=RAW(*command,check=False,timeout=min(limit,max(.05,deadline-time.monotonic())))
                        if reply.returncode:errors.append({'container':name,'reason':command[0]+' failed'})
                        elif command[0]=='wait':confirmed_stopped=True
                    except BaseException as exc:
                        errors.append({'container':name,'reason':command[0]+': '+type(exc).__name__})
            if not confirmed_stopped:
                try:
                    confirmed_stopped=output_state(name,deadline)['running'] is False
                except BaseException as exc:
                    errors.append({'container':name,'reason':'stop confirmation: '+type(exc).__name__})
            if not confirmed_stopped:
                partial.append(name)
                errors.append({'container':name,'reason':'output is partial; termination unconfirmed'})
            sync_one(name,terminal=confirmed_stopped,deadline=deadline)
        except BaseException as exc:
            errors.append({'container':name,'reason':type(exc).__name__+': '+scrub(str(exc))})
    return {'errors':errors,'stopped':stopped,'terminal_captured':sorted(TERMINAL_CAPTURED),
            'partial_captured':partial,'copy_failures':COPY_FAILURES,'budget_seconds':timeout_s}

def sync_one(name,terminal=False,deadline=None):
    global SYNCING
    if SYNCING or name not in OUTS or name in TERMINAL_CAPTURED:return
    source,dest,cid=OUTS[name];SYNCING=True;ts=time.time();started=time.monotonic()
    requested_terminal=terminal;terminal=False;proof=None;copied=False
    try:
        if requested_terminal:
            try:state=output_state(name,deadline)
            except BaseException as exc:
                TERMINATION_ERRORS.append({'container':name,'reason':'terminal confirmation: '+type(exc).__name__})
                raise
            if state['running']:
                TERMINATION_ERRORS.append({'container':name,'reason':'output is partial; termination unconfirmed'})
            else:
                proof={'container_id':cid,'owner':P,'running':False,'checked_at':time.time(),
                       'basis':'owned exact-ID Docker inspect before copy'}
                terminal=True
        limit=30 if deadline is None else max(.05,min(30,deadline-time.monotonic()))
        q=RAW('cp',cid+':'+dest+'/.',source+'/',check=False,timeout=limit)
        if q.returncode:
            COPY_FAILURES.append({'container':name,'exit':q.returncode,'requested_terminal':requested_terminal,'terminal':False})
            raise RuntimeError('required container output copy failed: '+name)
        copied=True
        if terminal:TERMINAL_CAPTURED.add(name)
    finally:
        SYNCING=False
        COPY_OPS.append({'ts_start':ts,'ts_end':time.time(),'elapsed_ms':round((time.monotonic()-started)*1000,4),
                         'container':name,'requested_terminal':requested_terminal,'terminal':terminal and copied,
                         'copy_succeeded':copied,'termination_proof':proof})

def sync_samplers():
    for name in list(OUTS):
        if name.startswith(('sis-sampler-','sis-proc-')):sync_one(name)
def prepare_tls(runid):
    source=R/'perf-results/anchor-tls'/runid
    helper=copy_helper(TLS_VOL)
    try:
        RAW('exec',helper,'mkdir','-p','/copy/'+runid,timeout=15)
        for leaf in ['receiver.crt','receiver.key']:
            RAW('cp',str(source/leaf),helper+':/copy/'+runid+'/'+leaf,timeout=20)
        RAW('exec',helper,'chown','10001:10001','/copy/'+runid+'/receiver.crt',timeout=15)
        RAW('exec',helper,'chmod','600','/copy/'+runid+'/receiver.crt','/copy/'+runid+'/receiver.key',timeout=15)
    finally:RAW('rm','-f',helper,check=False,timeout=15)
    event('tls-volume-ready',run_id=runid,public_ca_owner='10001:10001',private_key_owner='0:0',file_mode='0600')
def dc(*values,check=True,timeout=None):
    args=list(values);run=args and args[0]=='run';compose=args and args[0]=='compose'
    if compose:
        if 'run' in args and args[-1]=='audit-receiver':
            for value in args:
                if str(value).startswith('ANCHOR_RECEIVER_TLS_CERT='):
                    prepare_tls(str(value).split('/')[-2]);break
        at=args.index('-p') if '-p' in args else 1
        args[at:at]=['-f',str(E/'environment.override.yml')]
    replacements={};output=None;name=None;script_mount=False
    if run:
        if '--name' in args:name=args[args.index('--name')+1]
        new=[];i=0
        while i<len(args):
            if args[i]=='-v' and i+1<len(args):
                value=args[i+1];parts=value.split(':');source=parts[0];dest=parts[1] if len(parts)>1 else None;mode=parts[2] if len(parts)>2 else None
                path=pathlib.Path(source)
                if source.startswith(str(R)+'/') and path.is_file():
                    replacements[dest]='/task-tools/'+path.name;script_mount=True;i+=2;continue
                if source.startswith(str(E)+'/') and path.is_dir():
                    volume=output_volume(source);new+=['-v',volume+':'+dest+(':'+mode if mode else '')]
                    if mode!='ro':output=(source,dest)
                    i+=2;continue
            new.append(args[i]);i+=1
        args=new
        for old,target in replacements.items():args=[a.replace(old,target) if isinstance(a,str) else a for a in args]
        if script_mount:args[1:1]=['-v',SCRIPT_VOL+':/task-tools:ro']
    env={};oldenv={};new=[];i=0
    while i<len(args):
        if args[i]=='-e' and i+1<len(args) and '=' in str(args[i+1]):
            key,value=str(args[i+1]).split('=',1);env[key]=value;oldenv[key]=os.environ.get(key)
            if any(word in key for word in ['TOKEN','SIGNING_KEY','PEPPER','SECRET','DATABASE_URL']):SECRETS.append(value)
            new+=['-e',key];i+=2;continue
        new.append(args[i]);i+=1
    args=new
    if args and args[0]=='rm':
        for item in args[1:]:
            target=output_name(item)
            if target and not CLEANING:sync_one(target,terminal=True)
    try:
        os.environ.update(env)
        limit=min(timeout or 90,90)
        if CLEANING and CLEANUP_DEADLINE is not None:limit=min(limit,max(.05,CLEANUP_DEADLINE-time.monotonic()))
        q=RAW(*args,check=False,timeout=limit)
    finally:
        for key,old in oldenv.items():
            if old is None:os.environ.pop(key,None)
            else:os.environ[key]=old
    if check and q.returncode:
        event('task-command-failure',operation=str(args[0]),exit=q.returncode,stderr=scrub(q.stderr[-2600:]))
        raise RuntimeError('task command failed rc='+str(q.returncode)+': '+scrub(q.stderr[-1800:]))
    if run and name and output and q.returncode==0:
        cid=q.stdout.strip()
        if len(cid)!=64 or any(c not in '0123456789abcdef' for c in cid):raise RuntimeError('output container did not return its full instance ID')
        OUTS[name]=(*output,cid)
    # State/affinity inspection needs no output files; copying live output perturbs the workload.
    target=output_name(args[1]) if len(args)>1 else None
    if args and args[0]=='inspect' and target:INSPECT_SKIPS.append({'ts':time.time(),'container':target})
    if args and args[0]=='logs' and target:sync_one(target,terminal=True)
    return q
sis.dc=dc
def receiver_get(run_id,path,token):
    SECRETS.append(token)
    code="import os,json,ssl,sys,urllib.request;ctx=ssl.create_default_context(cafile=sys.argv[2]);req=urllib.request.Request(sys.argv[1],headers={'Authorization':'Bearer '+os.environ['TASK_RECEIVER_TOKEN']});print(urllib.request.urlopen(req,context=ctx,timeout=10).read().decode())"
    q=dc('run','--rm','--network',sis.NETWORK,'--label',sis.SIS_LABEL+'='+P,'-v',TLS_VOL+':/run/anchor-tls:ro','-e','TASK_RECEIVER_TOKEN='+token,'--entrypoint','python',M['runner_image'],'-c',code,'https://sis-rcv-'+run_id+':9443'+path,'/run/anchor-tls/'+run_id+'/receiver.crt',check=False,timeout=20)
    if q.returncode:return {'collected':False,'error':scrub(q.stderr[-300:])}
    try:obj=json.loads(q.stdout)
    except ValueError:return {'collected':False,'error':'non-json response'}
    obj['collected']=True;return obj
points._receiver_get=receiver_get
ORIG_AUDIT=sis.audit_pair_up
def audit(run_id,depid):
    result=ORIG_AUDIT(run_id,depid)
    env=RAW('inspect',result['worker'],'--format','{{range .Config.Env}}{{println .}}{{end}}',timeout=10).stdout.splitlines()
    dburl=next(v.split('=',1)[1] for v in env if v.startswith('AUDIT_ANCHOR_DATABASE_URL='))
    SECRETS.append(dburl)
    code="import os,psycopg,json;c=psycopg.connect(os.environ['TASK_EXPORTER_DB']);row=c.execute('SELECT current_user,current_database()').fetchone();print(json.dumps({'login_ok':True,'user':row[0],'database':row[1]}));c.close()"
    login=dc('run','--rm','--network',sis.NETWORK,'--label',sis.SIS_LABEL+'='+P,'-e','TASK_EXPORTER_DB='+dburl,'--entrypoint','python',M['runner_image'],'-c',code,check=False,timeout=20)
    if login.returncode:raise RuntimeError('exporter real login failed: '+scrub(login.stderr[-300:]))
    login=json.loads(login.stdout);assert login['user']=='nazoauth_perf_exporter'
    state=None
    for _ in range(12):
        state=points.audit_state_snapshot(run_id)
        checkpoint=state.get('receiver_checkpoint',{})
        if checkpoint.get('collected') and checkpoint.get('checkpoint_kind')=='genesis' and checkpoint.get('last_sequence')==0:break
        time.sleep(1)
    else:save(E/'results'/sis.CURRENT_POINT['phase']/run_id/'audit-preflight-failed.json',state);raise RuntimeError('initial genesis checkpoint not established')
    durable={k:sis.psql('SHOW '+k).strip() for k in ['fsync','synchronous_commit','full_page_writes']}
    if not all(v=='on' for v in durable.values()):raise RuntimeError('durability preflight failed')
    pre={'exporter':login,'initial_checkpoint':state,'durability':durable,'expected_pool_max':32}
    save(E/'results'/sis.CURRENT_POINT['phase']/run_id/'task-audit-preflight.json',pre)
    event('audit-preflight-pass',run_id=run_id,exporter_login=True,genesis=True,durability=durable)
    return result
sis.audit_pair_up=audit
ORIG_HEALTH=sis.sampler_health
def health(runid,outdir,**kwargs):
    # Refresh the sampler files before each bounded metadata readiness check.
    ready_deadline=time.monotonic()+float(kwargs.pop('timeout_s',5.0))
    result={'ok':False}
    while time.monotonic()<ready_deadline:
        sync_samplers()
        result=ORIG_HEALTH(runid,outdir,timeout_s=min(.5,max(.05,ready_deadline-time.monotonic())),**kwargs)
        if result['ok']:break
    rows=[]
    for _ in range(10):
        sync_samplers()
        p=outdir/'soak-metrics.jsonl'
        if p.is_file():
            for line in p.read_text().splitlines():
                try:row=json.loads(line)
                except ValueError:continue
                if 'ts' in row:rows.append(row)
        if rows and all(k in rows[-1] for k in ['pg','vk','audit','runtime_role_activity']) and not any(k.endswith('_err') for k in rows[-1]):break
        rows=[];time.sleep(0.5)
    sample_ok=bool(rows) and all(k in rows[-1] for k in ['pg','vk','audit','runtime_role_activity']) and not any(k.endswith('_err') for k in rows[-1])
    result['real_sample_ok']=sample_ok;result['ok']=result['ok'] and sample_ok
    save(outdir/'task-collector-preflight.json',{'health':result,'last_sample':rows[-1] if rows else None})
    event('collector-preflight',run_id=runid,ok=result['ok'],checks=result.get('checks'),real_sample_ok=sample_ok)
    return result
sis.sampler_health=health
ORIG_DRAIN=sis.audit_drain
def drain(*args,**kwargs):
    result=ORIG_DRAIN(*args,**kwargs);sync_samplers();return result
sis.audit_drain=drain
def setup():
    for suffix in ['keys']:
        RAW('volume','create','--label','diag.owner='+P,P+'-'+suffix,timeout=15)
    sis.cmd_pinset_build()
    helper=P+'-input-copy'
    RAW('run','-d','--name',helper,'--label','diag.owner='+P,'-v',PIN_VOL+':/pin','-v',SCRIPT_VOL+':/scripts','--entrypoint','sh',M['runner_image'],'-c','tail -f /dev/null',timeout=15)
    try:
        RAW('cp',str(E/'bin')+'/.',helper+':/pin/',timeout=20)
        RAW('cp',str(R/'perf/tools')+'/.',helper+':/scripts/',timeout=20)
    finally:RAW('rm','-f',helper,check=False,timeout=15)
    override='services:\n  keyset:\n    image: '+M['helpers']['keyset']+'\n  nazoauth:\n    volumes:\n      - '+PIN_VOL+':/pinbin:ro\n  audit-receiver:\n    image: '+M['helpers']['receiver']+'\n    volumes:\n      - '+TLS_VOL+':/run/anchor-tls:ro\n  audit-worker:\n    image: '+M['app_image']+'\n    volumes:\n      - '+TLS_VOL+':/run/anchor-tls:ro\nvolumes:\n  '+PIN_VOL+':\n    external: true\n  '+TLS_VOL+':\n    external: true\n'
    (E/'environment.override.yml').write_text(override)
    allowed=sis.format_cpu_list(M['cpus']['allowed'])
    q=RAW('run','--rm','--label','diag.owner='+P,'-v',PIN_VOL+':/pin:ro','--entrypoint','/pin/pinset',M['runner_image'],allowed,'--all',timeout=20)
    event('task-environment-setup',pinset_sha256=hashlib.sha256((E/'bin/pinset').read_bytes()).hexdigest(),isolated_pinset_output=q.stdout.strip(),scripts_volume=SCRIPT_VOL,pinbin_volume=PIN_VOL,tls_volume=TLS_VOL)
def capture(runid,out,timeout_s=10):
    states={};errors=[];deadline=time.monotonic()+timeout_s
    for name in ['sis-rcv-'+runid,'sis-worker-'+runid,'sis-sampler-'+runid,'sis-proc-'+runid,sis.APP,sis.POSTGRES,sis.VALKEY,sis.MIGRATE]:
        try:q=RAW('inspect',name,check=False,timeout=min(1,max(.05,deadline-time.monotonic())))
        except BaseException as exc:
            errors.append(type(exc).__name__+': '+name);continue
        if q.returncode:continue
        d=json.loads(q.stdout)[0];states[name]={'image':d['Image'],'state':d['State'],'restart_count':d['RestartCount'],'resources':{k:d['HostConfig'].get(k) for k in ['CpusetCpus','NanoCpus','Memory','MemorySwap','PidsLimit']},'public_env':{k:v for k,v in [x.split('=',1) for x in d['Config'].get('Env',[]) if '=' in x] if k in ['DATABASE_MAX_CONNECTIONS','OTEL_ENABLED','K6_JSON_OMIT_UNUSED_HTTP_TIMINGS','RUST_LOG','AUDIT_ANCHOR_MAX_BATCH_SIZE','AUDIT_ANCHOR_POLL_INTERVAL_MS','AUDIT_ANCHOR_MODE','AUDIT_ANCHOR_MAX_LAG_SECONDS']},'mounts':[{'type':x['Type'],'destination':x['Destination'],'rw':x['RW']} for x in d.get('Mounts',[])]}
    save(out/'task-container-states-before-cleanup.json',states)
    if errors:raise RuntimeError("state capture failed: "+", ".join(errors))
def run(key):
    global CLEANING,CLEANUP_DEADLINE
    request=pathlib.Path(M['requests'][key]['path']);raw=request.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==M['requests'][key]['sha256']
    for rel,h in M['harness_file_sha256'].items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==h,rel
    point=json.loads(raw);runid=point['name'];out=E/'results'/point['phase']/runid
    assert not (out/'short-result.json').exists(), 'Preserve completed point evidence'
    out.mkdir(parents=True,exist_ok=True);start=time.monotonic()
    def deadline(signum,frame):raise TimeoutError('task point deadline before cleanup')
    signal.signal(signal.SIGALRM,deadline);signal.signal(signal.SIGTERM,deadline);signal.alarm(M['point_timeout_s'])
    error=None;result={};finalization={}
    try:
        sb.worker(str(request))
        result=json.loads((out/'short-result.json').read_text())
    except BaseException as exc:
        error=type(exc).__name__+': '+scrub(str(exc));event('point-exception',key=key,error=error)
        if (out/'short-result.json').is_file():
            try:result=json.loads((out/'short-result.json').read_text())
            except ValueError:pass
    finally:
        signal.alarm(0)
        finalization=finalize_outputs()
        # A copy failure never skips the independent state capture.
        try:capture(runid,out)
        except BaseException as exc:error=error or type(exc).__name__+': '+scrub(str(exc))
        copy_complete=not COPY_FAILURES and not TERMINATION_ERRORS and not finalization['errors'] and error is None
        result.setdefault('health',{})['collector_copy_complete']=copy_complete
        if not copy_complete:
            original=result.get('verdict','INVALID')
            result['original_verdict']=original
            result['verdict']=original if original in ['FAIL','INVALID'] else 'INVALID'
        save(out/'short-result.json',result)
        save(out/'task-finalization.json',finalization)
        save(E/'copy-policy-evidence.json',{'source_sha':M['source_sha'],
             'policy':'inspect never copies output; required readiness and instance-ID terminal capture',
             'skipped_inspects':INSPECT_SKIPS,'copies':COPY_OPS,'required_copy_failures':COPY_FAILURES,
             'termination_errors':TERMINATION_ERRORS,'terminal_captured':sorted(TERMINAL_CAPTURED),'finalization':finalization})
        event('point-evaluation',key=key,verdict=result.get('verdict','INVALID'),error=error,
              metrics=result.get('metrics'),health=result.get('health'))
        cleanup_start=time.monotonic();CLEANING=True;CLEANUP_DEADLINE=min(start+M['point_budget_s']-15,cleanup_start+45)
        cleanup_error=None
        try:sis.stack_down()
        except BaseException as exc:cleanup_error=type(exc).__name__+': '+scrub(str(exc))
        for volume in set(VOLS.values()):
            try:RAW('volume','rm',volume,check=False,timeout=max(.05,min(15,CLEANUP_DEADLINE-time.monotonic())))
            except BaseException as exc:cleanup_error=cleanup_error or type(exc).__name__
        remaining=[]
        for label in ['com.docker.compose.project='+P,sis.SIS_LABEL+'='+P]:
            try:
                q=RAW('ps','-aq','--filter','label='+label,timeout=max(.05,min(10,CLEANUP_DEADLINE-time.monotonic())))
                remaining+=q.stdout.split()
                if q.returncode:remaining.append('unknown')
            except BaseException:remaining.append('unknown')
        if cleanup_error or remaining:
            result['original_verdict']=result.get('original_verdict',result.get('verdict','INVALID'))
            if result.get('verdict') not in ['FAIL','INVALID']:result['verdict']='INVALID'
            result['health']['collector_copy_complete']=False
            save(out/'short-result.json',result)
        cleanup={'label':M.get('label',P),'key':key,'containers_remaining':remaining,
                 'cleanup_elapsed_s':round(time.monotonic()-cleanup_start,3),'total_elapsed_s':round(time.monotonic()-start,3),
                 'request_sha256_unchanged':hashlib.sha256(request.read_bytes()).hexdigest()==M['requests'][key]['sha256'],
                 'verdict':result.get('verdict','INVALID'),'error':error,'cleanup_error':cleanup_error}
        save(out/'task-cleanup.json',cleanup);event('point-cleanup',**cleanup)
    if cleanup['containers_remaining'] or cleanup['total_elapsed_s']>=M['point_budget_s']:raise SystemExit(3)
    raise SystemExit(0 if result.get('verdict')=='PASS' and error is None else 2)
if __name__=='__main__':
    action=sys.argv[1]
    if action=='setup':setup()
    elif action in M['requests']:run(action)
    else:raise SystemExit('unknown action')
