from pathlib import Path
import json,sys
E=Path('/workspace/evidence/pr238-longrun-20261010')
for key in sys.argv[1:]:
 D=E/key
 print(key)
 for f in ['load-boundary.json','load-ended.json','natural-final.json']:
  if (D/f).exists():
   x=json.loads((D/f).read_text());print(f,{k:x.get(k) for k in ['load_start','load_return','ts','pending','oldest_pending_s','target_decisions','full_cycle_after_target_deadline'] if k in x})
 if (D/'storage.jsonl').exists():
  a=[json.loads(s) for s in (D/'storage.jsonl').read_text().splitlines()];x=a[-1];print('latest', {k:x.get(k) for k in ['ts','pending','oldest_pending_s','db_bytes','target_decisions']})
