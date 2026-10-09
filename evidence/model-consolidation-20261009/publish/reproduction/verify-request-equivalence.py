from pathlib import Path
import json
E=Path('/workspace/evidence/model-consolidation-20261009');O=E.parent/'pr230-performance-repair-20261009';rows=[]
allowed={'name','request_key','arm','source_sha','source_tree','image','expected_binary_sha256','diagnostic_only'}
for key,old in [('MODEL02','BREAD2'),('MODEL10','BREAD10'),('MODEL03','BREAD03'),('MODEL04','BREAD04')]:
 a=json.loads((O/old/'requests'/f'{old}.json').read_text());b=json.loads((E/key/'requests'/f'{key}.json').read_text());diff=[k for k in a.keys()|b.keys() if a.get(k)!=b.get(k)];assert set(diff)<=allowed,(key,diff);m=json.loads((E/key/'requests/manifest.json').read_text());row={'key':key,'baseline_request':old,'changed_fields':diff,'unchanged_workload_and_gates':True,'decision_follow':m.get('decision_follow'),'decision_observe_budget_s':m.get('decision_observe_budget_s',450)};rows.append(row)
(E/'request-equivalence.json').write_text(json.dumps(rows,indent=2));print(rows)
