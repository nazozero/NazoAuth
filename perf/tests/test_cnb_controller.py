import ast
import json
import pathlib
import tempfile
import types
import unittest

code = (pathlib.Path(__file__).resolve().parents[1]/'tools/cnb_controller.py').read_text()
tree = ast.parse(code)
selected = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ['dc','health','sync_samplers','sync_one','run']]
compiled = compile(ast.Module(body=selected,type_ignores=[]),'<public-adapter-functions>','exec')

class CopyPolicy(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        def raw(*args,**kwargs):
            self.calls.append(('docker',args[0],args[1:]));return types.SimpleNamespace(returncode=0,stdout='true\n',stderr='')
        self.ns={'RAW':raw,'OUTS':{'sis-load-own':('/unused','/out'),'sis-sampler-own':('/unused','/out')},
                 'INSPECT_SKIPS':[],'SYNCING':False,'TERMINAL_CAPTURED':set(),'COPY_FAILURES':[],'COPY_OPS':[],
                 'os':types.SimpleNamespace(environ={}), 'pathlib':pathlib,
                 'time':__import__('time'),'signal':types.SimpleNamespace(SIGALRM=1,SIGTERM=2,signal=lambda *a:None,alarm=lambda *a:None),'hashlib':__import__('hashlib'),'json':json,'SECRETS':[],'E':pathlib.Path('/unused'),
                 'scrub':lambda s:s,'event':lambda *a,**k:None,
                 'save':lambda *a,**k:None,'ORIG_HEALTH':lambda *a,**k:{'ok':True}}
        exec(compiled,self.ns)
    def test_state_inspection_never_copies(self):
        q=self.ns['dc']('inspect','sis-load-own','--format','{{.State.Running}}')
        self.assertEqual(q.stdout,'true\n');self.assertEqual(len(self.ns['INSPECT_SKIPS']),1)
        self.assertEqual([x for x in self.calls if x[0]=='copy'],[])
    def test_untracked_inspection_never_copies(self):
        self.ns['dc']('inspect','owned-app');self.assertEqual(self.ns['INSPECT_SKIPS'],[])
    def test_logs_preserve_capture(self):
        self.ns['dc']('logs','sis-load-own')
        self.assertEqual([x[1] for x in self.calls],['logs','cp']);self.assertIn('sis-load-own',self.ns['TERMINAL_CAPTURED'])
    def test_terminal_removal_copies_first(self):
        self.ns['dc']('rm','-f','sis-load-own')
        self.assertEqual([x[1] for x in self.calls],['cp','rm'])
    def test_explicit_sampler_copy_preserved(self):
        self.ns['sync_samplers']()
        self.assertEqual([x[1] for x in self.calls],['cp']);self.assertEqual(self.ns['TERMINAL_CAPTURED'],set())
    def test_real_sampler_preflight_still_requires_sample(self):
        with tempfile.TemporaryDirectory() as d:
            out=pathlib.Path(d)
            def sampler():
                self.calls.append(('sample',));(out/'soak-metrics.jsonl').write_text(json.dumps({'ts':1,'pg':{},'vk':{},'pool':{},'audit_queue':{}})+'\n')
            self.ns['sync_samplers']=sampler
            def metadata_gate(*args,**kwargs):
                self.assertTrue((out/'soak-metrics.jsonl').is_file(), 'Metadata must be synced before the native metadata reader')
                self.calls.append(('metadata-read',));return {'ok':True}
            self.ns['ORIG_HEALTH']=metadata_gate
            result=self.ns['health']('own',out)
            self.assertTrue(result['ok']);self.assertTrue(result['real_sample_ok']);self.assertEqual(self.calls,[('sample',),('metadata-read',),('sample',)])

    def test_terminal_capture_is_not_repeated_on_removal(self):
        self.ns['dc']('logs','sis-load-own')
        self.ns['dc']('rm','-f','sis-load-own')
        self.assertEqual([x[1] for x in self.calls],['logs','cp','rm'])
    def test_terminal_copy_failure_prevents_removal(self):
        self.ns['RAW']=lambda *a,**k:types.SimpleNamespace(returncode=1,stdout='',stderr='copy failed')
        with self.assertRaisesRegex(RuntimeError,'required container output copy failed'):
            self.ns['dc']('rm','-f','sis-load-own')
        self.assertEqual(len(self.ns['COPY_FAILURES']),1)
        self.assertNotIn('sis-load-own',self.ns['TERMINAL_CAPTURED'])
        self.assertFalse(self.ns['SYNCING'])
    def test_failed_point_cleanup_can_remove_after_failed_capture(self):
        self.ns['COPY_FAILURES'].append({'container':'sis-load-own','exit':1,'terminal':True})
        self.ns['dc']('rm','-f','sis-load-own')
        self.assertEqual([x[1] for x in self.calls],['rm'])
        self.assertNotIn('sis-load-own',self.ns['TERMINAL_CAPTURED'])
    def test_failed_final_copy_downgrades_pass_and_cleans(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);request=root/'point.json';request.write_text('{"name":"own","phase":"multi"}')
            out=root/'results/multi/own';out.mkdir(parents=True)
            import hashlib
            self.ns.update(E=root,R=root,P='own',M={'source_sha':'source','label':'own','harness_file_sha256':{},
                'requests':{'s21':{'path':str(request),'sha256':hashlib.sha256(request.read_bytes()).hexdigest()}}})
            def worker(path):
                (out/'short-result.json').write_text(json.dumps({'verdict':'PASS','metrics':{},'health':{}}))
            def failed_sync():raise RuntimeError('required output copy failed')
            cleaned=[]
            self.ns.update(sb=types.SimpleNamespace(worker=worker),sync_samplers=failed_sync,
                capture=lambda *a:None,sis=types.SimpleNamespace(stack_down=lambda:cleaned.append(True),SIS_LABEL='sis.owner'),
                VOLS={},save=lambda p,v:pathlib.Path(p).write_text(json.dumps(v)))
            self.ns['RAW']=lambda *a,**k:types.SimpleNamespace(returncode=0,stdout='',stderr='')
            with self.assertRaises(SystemExit) as stopped:self.ns['run']('s21')
            self.assertEqual(stopped.exception.code,2);self.assertEqual(cleaned,[True])
            result=json.loads((out/'short-result.json').read_text())
            self.assertEqual(result['verdict'],'INVALID');self.assertFalse(result['health']['collector_copy_complete'])

if __name__=='__main__':unittest.main(verbosity=2)
