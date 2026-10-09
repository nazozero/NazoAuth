from pathlib import Path
import json,re,datetime
p=Path('/src/evidence/pr230-performance-repair-20261009/BREAD2');terminal=json.loads((p/'decision-cohort-terminal.json').read_text());log=(p/'application-ledger-maintenance-final.log').read_text();lines=[re.sub(r'\x1b\[[0-9;]*m','',l) for l in log.splitlines() if 'security-state maintenance ' in l]
cycles=[l for l in lines if 'cycle completed' in l];last=cycles[-1];ts=datetime.datetime.fromisoformat(last.split(' ')[0].replace('Z','+00:00')).timestamp();assert ts>terminal['last_retain'];assert 'stop_reason="drained"' in last;assert terminal['terminal']['remaining']==0
storage=[json.loads(l) for l in (p/'storage.jsonl').read_text().splitlines()];print('STORAGE first',storage[0]);print('STORAGE last',storage[-1])
result={'status':'PASS','cohort_size':terminal['cohort_size'],'last_retain_epoch':terminal['last_retain'],'final_cycle':last,'zero_observation':terminal['terminal'],'same_final_instance':terminal['same_instance'],'natural_delete_total':sum(int(re.search(r'authorization_decisions=(\d+)',l).group(1)) for l in lines if 'batch completed' in l),'boundary':'Frozen batch zero and completed natural cycle; no claim of all security state zero or indefinite disk bound.'};(p/'decision-natural-reclamation.json').write_text(json.dumps(result,indent=2));print(result)


