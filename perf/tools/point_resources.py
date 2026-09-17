import json,glob,os,csv
# load sampler (epoch,app_jif,app_rss,pg_jif,pg_rss,vk_jif,vk_rss,run_jif,run_rss)
def load(f):
    rows=[]
    for r in csv.reader(open(f)):
        if not r or r[0]=="epoch" or len(r)<8: continue
        try: rows.append([int(r[0])]+[int(x) if x else 0 for x in r[1:8]])
        except: pass
    return rows
allrows=load("/workspace/perf-results/proc-stats.csv")
allrows+=load("/workspace/perf-results/soak/proc-stats.csv")
allrows.sort()
def cpu_between(t0,t1):
    w=[r for r in allrows if t0<=r[0]<=t1]
    if len(w)<2: return None
    dt=w[-1][0]-w[0][0]
    if dt<=0: return None
    out={}
    for i,name in [(1,"app"),(3,"pg"),(5,"vk"),(7,"run")]:
        dj=w[-1][i]-w[0][i]
        out[name+"_cpu"]=round(dj/100.0/dt,2)  # cores
        out[name+"_rss_mb"]=round(w[-1][i+1]/1024.0,1)
    out["n"]=len(w)
    return out
res={}
for d in sorted(glob.glob("/workspace/perf-results/ladder/*")):
    if not os.path.isdir(d): continue
    fs=glob.glob(d+"/*.summary.json")
    if not fs: continue
    s=json.load(open(fs[0]))
    el=s.get("elapsed_seconds",75)
    t1=int(os.path.getmtime(fs[0]))  # summary written at end
    t0=int(t1-el-15)
    c=cpu_between(t0,t1)
    if c: res[os.path.basename(d)]=c
json.dump(res,open("/workspace/perf-results/aggregate/point_resources.json","w"),indent=1)
for k,v in res.items(): print(k,v)
