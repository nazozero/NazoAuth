import ast
import hashlib
import json
import pathlib
import tempfile
import types
import unittest

TOOLS=pathlib.Path(__file__).resolve().parents[1]/'tools'
tree=ast.parse((TOOLS/'cnb_controller.py').read_text())
functions=['dc','health','sync_samplers','sync_one','output_name','finalize_outputs','run']
code=compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in functions],type_ignores=[]),'<cnb-controller>','exec')
sis_tree=ast.parse((TOOLS/'single_instance_scaling.py').read_text())
owned_code=compile(ast.Module(body=[n for n in sis_tree.body if isinstance(n,ast.FunctionDef) and n.name in ['_label_of','_remove_owned_by_name','stop_samplers']],type_ignores=[]),'<existing-sampler-lifecycle>','exec')

class CopyPolicy(unittest.TestCase):
    def setUp(self):
        self.calls=[];self.instances={};self.failed_copies=set()
        self.add_instance('sis-load-own','a'*64)
        self.add_instance('sis-sampler-own','b'*64)
        self.ns={'RAW':self.raw,'OUTS':{name:('/unused','/out',cid) for cid,row in self.instances.items() for name in [row['name']]},
            'INSPECT_SKIPS':[],'SYNCING':False,'TERMINAL_CAPTURED':set(),'COPY_FAILURES':[],'COPY_OPS':[],
            'CLEANING':False,'CLEANUP_DEADLINE':None,'P':'own','sis':types.SimpleNamespace(SIS_LABEL='sis.owner'),
            'os':types.SimpleNamespace(environ={}), 'pathlib':pathlib,'time':__import__('time'),'hashlib':hashlib,
            'signal':types.SimpleNamespace(SIGALRM=1,SIGTERM=2,signal=lambda *a:None,alarm=lambda *a:None),
            'json':json,'SECRETS':[],'E':pathlib.Path('/unused'),'scrub':lambda s:s,
            'event':lambda *a,**k:None,'save':lambda *a,**k:None,'ORIG_HEALTH':lambda *a,**k:{'ok':True}}
        exec(code,self.ns)
        self.owned={'dc':self.ns['dc'],'PROJECT':'own','SIS_LABEL':'sis.owner'};exec(owned_code,self.owned)
    def add_instance(self,name,cid,running=False,owner='own'):
        self.instances[cid]={'id':cid,'name':name,'running':running,'labels':{'sis.owner':owner}}
    def raw(self,*args,**kwargs):
        self.calls.append(('docker',args[0],args[1:]));stdout='';rc=0
        target=next((r for r in self.instances.values() if args[1:2] and args[1] in [r['id'],r['name']]),None)
        if args[0]=='inspect':
            if not target:rc=1
            elif args[-1]=='{{.Id}}':stdout=target['id']
            elif 'index .Config.Labels' in args[-1]:stdout=target['labels']['sis.owner']
            elif args[-1].startswith('{"id":'):stdout=json.dumps(target)
            else:stdout='true' if target['running'] else 'false'
        elif args[0]=='stop':
            cid=args[-1]
            if cid in self.instances:self.instances[cid]['running']=False
        elif args[0]=='wait':stdout='0'
        elif args[0]=='cp':
            cid=args[1].split(':',1)[0]
            rc=1 if cid in self.failed_copies or cid not in self.instances else 0
        elif args[0]=='rm':
            for v in args[1:]:
                row=next((r for r in self.instances.values() if v in [r['id'],r['name']]),None)
                if row:self.instances.pop(row['id'])
        return types.SimpleNamespace(returncode=rc,stdout=stdout+'\n' if stdout else '',stderr='')
    def assertNoCopies(self):
        self.assertFalse(any(c[0]=='docker' and c[1]=='cp' for c in self.calls),self.calls)
    def operations(self):return [c[1] for c in self.calls]
    def test_state_inspection_never_copies(self):
        self.ns['dc']('inspect','sis-load-own','--format','{{.State.Running}}')
        self.assertEqual(len(self.ns['INSPECT_SKIPS']),1);self.assertNoCopies()
    def test_untracked_inspection_never_copies(self):
        self.ns['dc']('inspect','owned-app',check=False);self.assertEqual(self.ns['INSPECT_SKIPS'],[]);self.assertNoCopies()
    def test_no_copy_assertion_detects_actual_docker_cp(self):
        self.raw('cp','a'*64+':/out/.','/unused')
        with self.assertRaises(AssertionError):self.assertNoCopies()
    def test_logs_preserve_capture(self):
        self.ns['dc']('logs','sis-load-own')
        self.assertEqual(self.operations(),['logs','cp']);self.assertIn('sis-load-own',self.ns['TERMINAL_CAPTURED'])
    def test_run_registers_returned_full_instance_id(self):
        cid='d'*64
        self.ns.update(E='/evidence',R='/workspace',output_volume=lambda source:'owned-output',
            pathlib=types.SimpleNamespace(Path=lambda value:types.SimpleNamespace(is_file=lambda:False,is_dir=lambda:True)),
            RAW=lambda *a,**k:types.SimpleNamespace(returncode=0,stdout=cid+'\n',stderr=''))
        self.ns['dc']('run','-d','--name','sis-new-own','-v','/evidence/out:/out','image')
        self.assertEqual(self.ns['OUTS']['sis-new-own'],('/evidence/out','/out',cid))
        self.assertEqual(self.ns['output_name'](cid),'sis-new-own')
    def test_name_removal_copies_before_delete(self):
        self.ns['dc']('rm','-f','sis-load-own');self.assertEqual(self.operations(),['cp','rm'])
    def test_cid_removal_copies_exact_instance_before_delete(self):
        self.ns['dc']('rm','-f','a'*64)
        self.assertEqual(self.operations(),['cp','rm']);self.assertTrue(self.calls[0][2][0].startswith('a'*64+':'))
    def test_existing_stop_samplers_cid_path_retains_final_output(self):
        self.add_instance('sis-proc-own','c'*64,running=True)
        self.instances['b'*64]['running']=True;self.ns['OUTS']['sis-proc-own']=('/unused','/out','c'*64)
        self.owned['stop_samplers']('own')
        self.assertTrue({'sis-sampler-own','sis-proc-own'}<=self.ns['TERMINAL_CAPTURED'])
        self.assertNotIn('b'*64,self.instances);self.assertNotIn('c'*64,self.instances)
        self.assertEqual(self.operations().count('cp'),2)
        before=len(self.calls);self.ns['sync_samplers']();self.assertEqual(len(self.calls),before)
    def test_foreign_owner_is_not_stopped_or_removed(self):
        self.instances['b'*64]['labels']['sis.owner']='foreign'
        self.assertFalse(self.owned['_remove_owned_by_name']('sis-sampler-own',stop=True))
        self.assertNoCopies();self.assertNotIn('stop',self.operations());self.assertNotIn('rm',self.operations())
    def test_terminal_capture_not_repeated_on_cid_removal(self):
        self.ns['dc']('logs','sis-load-own');self.ns['dc']('rm','-f','a'*64)
        self.assertEqual(self.operations(),['logs','cp','rm'])
    def test_failed_terminal_copy_blocks_normal_removal(self):
        self.failed_copies.add('a'*64)
        with self.assertRaisesRegex(RuntimeError,'required container output copy failed'):self.ns['dc']('rm','-f','a'*64)
        self.assertNotIn('rm',self.operations());self.assertFalse(self.ns['SYNCING']);self.assertEqual(len(self.ns['COPY_FAILURES']),1)
    def test_invalid_point_cleanup_can_remove_failed_capture(self):
        self.failed_copies.add('a'*64);self.ns['CLEANING']=True;self.ns['dc']('rm','-f','a'*64)
        self.assertEqual(self.operations(),['rm']);self.assertNotIn('sis-load-own',self.ns['TERMINAL_CAPTURED'])
    def test_explicit_sampler_copy_is_not_terminal(self):
        self.ns['sync_samplers']();self.assertEqual(self.operations(),['cp']);self.assertEqual(self.ns['TERMINAL_CAPTURED'],set())
    def test_sampler_metadata_is_synced_before_reader(self):
        with tempfile.TemporaryDirectory() as d:
            out=pathlib.Path(d);order=[]
            def sampler():
                order.append('copy');(out/'soak-metrics.jsonl').write_text(json.dumps({'ts':1,'pg':{},'vk':{},'pool':{},'audit_queue':{}})+'\n')
            def metadata(*a,**k):
                self.assertTrue((out/'soak-metrics.jsonl').is_file());order.append('read');return {'ok':True}
            self.ns.update(sync_samplers=sampler,ORIG_HEALTH=metadata)
            self.assertTrue(self.ns['health']('own',out)['real_sample_ok']);self.assertEqual(order,['copy','read','copy'])
    def test_fault_finalization_stops_waits_and_copies_remaining_instance(self):
        self.instances['a'*64]['running']=True
        result=self.ns['finalize_outputs'](timeout_s=5)
        ops=self.operations();self.assertLess(ops.index('stop'),ops.index('wait'));self.assertLess(ops.index('wait'),ops.index('cp'))
        self.assertEqual(result['stopped'],['sis-load-own']);self.assertTrue(result['errors'])
        self.assertEqual(set(result['terminal_captured']),set(self.ns['OUTS']))
    def failed_stop_wait_fixture(self,timeout=False,stopped=False):
        self.instances['a'*64]['running']=True;raw=self.raw
        def failing(*args,**kwargs):
            if args[0] in ['stop','wait']:
                self.calls.append(('docker',args[0],args[1:]))
                if stopped and args[0]=='stop':self.instances['a'*64]['running']=False
                if timeout:raise TimeoutError('fixture command timeout')
                return types.SimpleNamespace(returncode=1,stdout='',stderr='')
            return raw(*args,**kwargs)
        self.ns['RAW']=failing
        return self.ns['finalize_outputs'](timeout_s=5)
    def test_failed_stop_and_wait_only_capture_partial_running_output(self):
        result=self.failed_stop_wait_fixture()
        self.assertIn('sis-load-own',result['partial_captured']);self.assertNotIn('sis-load-own',result['terminal_captured'])
        self.assertTrue(result['errors']);self.assertIn('sis-sampler-own',result['terminal_captured'])
        self.assertFalse(next(c for c in self.ns['COPY_OPS'] if c['container']=='sis-load-own')['terminal'])
    def test_stop_and_wait_timeout_only_capture_partial_running_output(self):
        result=self.failed_stop_wait_fixture(timeout=True)
        self.assertIn('sis-load-own',result['partial_captured']);self.assertNotIn('sis-load-own',result['terminal_captured'])
        self.assertTrue(result['errors']);self.assertEqual(self.operations().count('cp'),2)
    def test_failed_commands_with_inspected_stopped_instance_capture_terminal(self):
        result=self.failed_stop_wait_fixture(stopped=True)
        self.assertNotIn('sis-load-own',result['partial_captured']);self.assertIn('sis-load-own',result['terminal_captured'])
        self.assertTrue(result['errors'])
    def test_one_failed_copy_does_not_skip_other_outputs(self):
        self.failed_copies.add('a'*64);result=self.ns['finalize_outputs'](timeout_s=5)
        self.assertTrue(result['errors']);self.assertIn('sis-sampler-own',self.ns['TERMINAL_CAPTURED']);self.assertEqual(self.operations().count('cp'),2)
    def test_finalization_does_not_mutate_foreign_instance(self):
        self.instances['a'*64]['labels']['sis.owner']='foreign';self.instances['a'*64]['running']=True
        result=self.ns['finalize_outputs'](timeout_s=5)
        self.assertTrue(result['errors']);self.assertNotIn('stop',self.operations());self.assertIn('a'*64,self.instances)
    def run_fixture(self,verdict='PASS',timeout=False):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);request=root/'point.json';request.write_text('{"name":"own","phase":"multi"}')
            out=root/'results/multi/own';capture_calls=[];cleaned=[]
            self.ns.update(E=root,R=root,P='own',M={'source_sha':'source','label':'own','harness_file_sha256':{},
                'requests':{'s21':{'path':str(request),'sha256':hashlib.sha256(request.read_bytes()).hexdigest()}}})
            def worker(path):
                (out/'short-result.json').write_text(json.dumps({'verdict':verdict,'metrics':{'retained':42},'health':{}}))
                if timeout:raise TimeoutError('worker deadline')
            self.ns.update(sb=types.SimpleNamespace(worker=worker),capture=lambda *a:capture_calls.append(True),
                sis=types.SimpleNamespace(stack_down=lambda:cleaned.append(True),SIS_LABEL='sis.owner'),VOLS={},
                save=lambda p,v:pathlib.Path(p).write_text(json.dumps(v)))
            with self.assertRaises(SystemExit) as stopped:self.ns['run']('s21')
            return stopped.exception.code,json.loads((out/'short-result.json').read_text()),capture_calls,cleaned
    def test_failed_sampler_copy_does_not_skip_state_capture_or_cleanup(self):
        self.failed_copies.add('b'*64);rc,result,capture,cleaned=self.run_fixture()
        self.assertEqual(rc,2);self.assertEqual(result['verdict'],'INVALID');self.assertFalse(result['health']['collector_copy_complete'])
        self.assertEqual(capture,[True]);self.assertEqual(cleaned,[True]);self.assertEqual(result['metrics'],{'retained':42})
    def test_worker_timeout_preserves_failure_metrics_and_finalizes_live_workload(self):
        self.instances['a'*64]['running']=True;rc,result,capture,cleaned=self.run_fixture(verdict='FAIL',timeout=True)
        self.assertEqual(rc,2);self.assertEqual(result['verdict'],'FAIL');self.assertEqual(result['metrics'],{'retained':42})
        self.assertIn('stop',self.operations());self.assertIn('cp',self.operations());self.assertEqual(capture,[True]);self.assertEqual(cleaned,[True])

if __name__=='__main__':unittest.main(verbosity=2)
