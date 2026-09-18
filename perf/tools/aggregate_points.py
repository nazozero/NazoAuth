import json,glob,os
OUT="/workspace/perf-results/aggregate"
os.makedirs(OUT,exist_ok=True)
rows=[]
for d in sorted(glob.glob("/workspace/perf-results/ladder/*")):
    if not os.path.isdir(d): continue
    name=os.path.basename(d)
    fs=glob.glob(d+"/*.summary.json")
    if not fs:
        rows.append({"point":name,"status":"no_summary"})
        continue
    try: s=json.load(open(fs[0]))
    except Exception as e:
        rows.append({"point":name,"status":"parse_error"}); continue
    k=s.get("k6",{}); m=k.get("measure") or {}
    lat=m.get("latency_ms") or k.get("latency_ms") or {}
    row={"point":name,"scenario":s.get("scenario"),"status":s.get("status"),
        "ops_per_s":m.get("ops_per_s") or k.get("rps"),
        "http_rps":k.get("rps"),"http_reqs":k.get("http_reqs"),
        "errors":m.get("errors"),"error_rate":k.get("error_rate"),
        "p50":lat.get("p50"),"p95":lat.get("p95"),"p99":lat.get("p99"),
        "dropped_iterations":k.get("dropped_iterations"),
        "load_model":s.get("load_model"),
        "postgres":s.get("postgres"),"db_pool":s.get("db_pool"),"valkey":s.get("valkey"),
        "error_breakdown":s.get("error_breakdown"),
        "steps":[{ "step":x["step"],"rps":x["rps"],"error_rate":x["error_rate"],
                   "p50":x["latency_ms"].get("p50"),"p95":x["latency_ms"].get("p95"),"p99":x["latency_ms"].get("p99")}
                 for x in s.get("steps",[])]}
    rows.append(row)
json.dump(rows,open(OUT+"/ladder_summary.json","w"),indent=1)
print("points:",len(rows))
for r in rows:
    if r.get("status")=="passed" or r.get("ops_per_s"):
        print(f"{r['point']:55s} {str(r.get('status')):18s} ops={r.get('ops_per_s')}")
