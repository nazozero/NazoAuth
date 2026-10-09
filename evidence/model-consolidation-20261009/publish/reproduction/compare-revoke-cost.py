from pathlib import Path
import json,collections
R=Path('/workspace/evidence');E=R/'model-consolidation-20261009';out={}
for label,p in [('historical',R/'pr230-performance-repair-20261009/BREAD10'),('candidate',E/'MODEL10')]:
 pre=json.loads(next(p.rglob('pgss-pre.json')).read_text())['statements'];post=json.loads(next(p.rglob('pgss-post.json')).read_text())['statements'];before={(r['queryid'],r.get('userid'),r.get('toplevel')):r for r in pre};rows=[]
 for r in post:
  if not r.get('toplevel'):continue
  b=before.get((r['queryid'],r.get('userid'),r.get('toplevel')),{});calls=r['calls']-b.get('calls',0);ms=r['total_exec_time']-b.get('total_exec_time',0)
  if calls>0:rows.append({'role':r.get('rolname'),'query':r['q'],'calls':calls,'total_exec_ms':ms,'ms_per_call':ms/calls})
 out[label]={'top_by_time':sorted(rows,key=lambda r:r['total_exec_ms'],reverse=True)[:15],'calls_by_role':dict(collections.Counter({role:sum(r['calls'] for r in rows if r['role']==role) for role in set(r['role'] for r in rows)}))}
(E/'revoke-cost-comparison.json').write_text(json.dumps(out,indent=2))
for label,r in out.items():print(label,r['calls_by_role']);print(json.dumps(r['top_by_time'][:5],indent=2))
