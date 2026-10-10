from pathlib import Path
import hashlib,json,subprocess
R=Path('/workspace'); E=R/'evidence/pr238-reverify-20261009'; O=R/'evidence/storage-placement-20261009'
build=json.loads((E/'build.json').read_text()); images=build['images']
aff=json.loads(subprocess.check_output(['docker','exec','nazoauth-reverify-controller-20261009','python','-c','import os,json;print(json.dumps(sorted(os.sched_getaffinity(0))))'],text=True))
assert len(aff)>=64, 'Original 16+16+1+31 allocation must be available'
aff=aff[:64]
(E/'container-affinity.json').write_text(json.dumps({'allowed_selected':aff,'scope':'test controller container only; no host probing'},indent=2))
controller=(O/'diagnostic_controller.py').read_text()
(E/'diagnostic_controller.py').write_text(controller)
observer=(O/'point-observer-cycle.py').read_text().replace('/src/evidence/storage-placement-20261009','/src/evidence/pr238-reverify-20261009')
observer=observer.replace('BEGIN+540','BEGIN+555')
# Keep periodic sampling alive through verification and natural reclamation.
observer=observer.replace(' STOP.set()\n if OBSERVER:OBSERVER.join(timeout=25)\n','')
(E/'point-observer-cycle.py').write_text(observer)
(E/'observer.sql').write_bytes((O/'observer.sql').read_bytes())
for key in ['REV360','MIX300']:
    D=E/key;(D/'requests').mkdir(parents=True,exist_ok=False)
    original=json.loads((O/key/'requests'/f'{key}.json').read_text());p=json.loads(json.dumps(original))
    for path,digest in p['harness_file_sha256'].items():
        assert hashlib.sha256((R/path).read_bytes()).hexdigest()==digest,path
    p.update(name='pr238-reverify-'+key.lower()+'-20261009',source_sha=build['source_sha'],source_modified=False,image=images['app'],expected_binary_sha256=build['binary_sha256'],runner_image=images['load'],helpers={'keyset':images['keyset'],'receiver':images['receiver']},app_cpus=aff[:16],postgres_cpus=aff[16:32],valkey_cpus=aff[32:33],infra_cpus=aff[33:],replicate=2,status='AUTHORIZED_SAME_CANDIDATE_REVERIFICATION')
    p.pop('source_patch_sha256',None)
    changes={k:{'before':original.get(k),'after':p.get(k)} for k in set(original)|set(p) if original.get(k)!=p.get(k)}
    (D/'request-delta.json').write_text(json.dumps(changes,indent=2))
    for k in ['scenario','rate','duration','effective_seconds','warmup_ms','pre_vus','max_vus','user_count','sidecars','gate','app_env_overrides','durability','stream_evidence','stream_workers']:
        assert original.get(k)==p.get(k),k
    target=D/'requests'/f'{key}.json';target.write_text(json.dumps(p,indent=2))
    manifest={'project':p['name'],'source_sha':build['source_sha'],'runner_image':images['load'],'app_image':images['app'],'helpers':p['helpers'],'collection_contract':p['collection_contract'],'cpus':{'allowed':aff},'harness_file_sha256':p['harness_file_sha256'],'post_observe_s':0,'requests':{key:{'path':str(target).replace('/workspace/','/src/'),'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}}}
    (D/'requests/manifest.json').write_text(json.dumps(manifest,indent=2))
    for reference in p['infra_image_refs'].values():
        q=subprocess.run(['docker','pull',reference],capture_output=True,text=True)
        if q.returncode:raise RuntimeError(q.stderr[-500:])
    print(key,'prepared',flush=True)
