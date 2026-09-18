import json,sys,glob
d=sys.argv[1]; scen=sys.argv[2]
fs=glob.glob(d+"/*.summary.json")
if not fs: sys.exit(0)
s=json.load(open(fs[0]))
k6=s.get("k6",{}); m=k6.get("measure") or {}
ops=m.get("ops_per_s") or k6.get("rps",0)
errs=m.get("errors") if m.get("errors") is not None else round(k6.get("error_rate",0)*k6.get("http_reqs",0))
p99=(m.get("latency_ms") or k6.get("latency_ms",{})).get("p99",0)
cpu=0
for c in s.get("containers",{}).get("stats",[]) or []:
    if "nazoauth" in str(c.get("name","")): cpu=c.get("cpu_pct") or c.get("cpu") or 0
if not cpu:
    cpu=(s.get("containers",{}).get("app_cpu_pct") or 0)
print(f"{ops} {errs} {p99} {cpu}")
