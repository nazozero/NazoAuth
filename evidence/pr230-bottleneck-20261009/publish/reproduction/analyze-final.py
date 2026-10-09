from pathlib import Path
import subprocess
p=Path('/src/evidence/pr230-bottleneck-20261009');f=p/'analyze-round.py';s=f.read_text().replace("'A04','B04']:","'A04','B04','Q32','Q64']:");f.write_text(s);r=subprocess.run(['python3',str(f)],capture_output=True,text=True);print(r.returncode,r.stdout[-7500:],r.stderr[-1500:]);assert r.returncode==0
