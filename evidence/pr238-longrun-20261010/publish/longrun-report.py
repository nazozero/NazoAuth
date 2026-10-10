from pathlib import Path
import json,datetime,hashlib,csv,sys
E=Path('/workspace/evidence/pr238-longrun-20261010');P=E/'publish';P.mkdir(exist_ok=True)
KEYS=['REVOKE20','INTROSPECT10','MTLS10','PAR10','NATIVE10','REQUIRED15','MIX30','AUTH10','CC10','REFRESH10','FAPI10','COLD10','NATIVE6R2','REQUIRED5R2','AUTH1R2','MIX1R2','REFRESH1R2']
LABELS=['撤销','内省','mTLS 客户端凭证','签名 PAR','Native SSO','Required mixed','Disabled mixed','授权码','客户端凭证','刷新','FAPI 已登录授权','冷登录＋刷新','Native SSO 修正夹具复测','Required mixed 修正夹具复测','授权码环境复测','mixed 环境复测','刷新环境补测']
def read(p):return json.loads(p.read_text())
def show(x):return '—' if x is None else str(round(x,3)) if isinstance(x,float) else str(x)
def mdtable(names,rows):return ['| '+' | '.join(names)+' |','| '+' | '.join(['---']*len(names))+' |']+['| '+' | '.join(map(show,r))+' |' for r in rows]
def q(v):return '—' if v is None else str(v[0])+'–'+str(v[1])
capacity=[];trend=[];storage=[];side=[];details=[];raw=[];costs=[]
for key,label in zip(KEYS,LABELS):
    f=E/key/'analysis.json'
    if not f.exists():
        blocked=E/key/'not-started.json'
        state='BLOCKED' if blocked.exists() else '未完成'
        capacity.append([label,state,*['—']*10])
        if blocked.exists():details.append({'key':key,'label':label,'capacity':state,'reason':read(blocked)})
        continue
    a=read(f);r=a['result']
    if not a.get('lanes'):
        capacity.append([label,'INVALID',*['—']*10]);details.append({'key':key,'label':label,'capacity':'INVALID','reason':r.get('metrics'),'result':r});continue
    m=r['metrics'];lane=a['lanes']['load'];measure=lane['measure'];lat=lane['latency_ms'];req=a['request']
    n=measure['measure_completed_exact'];success=measure['measure_outcomes'].get('success',0)
    capacity.append([label,r['verdict'],lane['window_seconds']/60,req['rate'],lane['rate'],f"{show(lat['p50'])}/{show(lat['p95'])}/{show(lat['p99'])}",f"{measure['measure_dropped_exact']} ({100*measure['measure_drop_fraction']:.4f}%)",m['unexpected_errors'],measure['measure_outcomes'].get('expected_rejection',0),sum(v for k,v in measure['measure_outcomes'].items() if k not in ['success','expected_rejection']),measure['measure_started_exact']-n,f"{100*success/measure['measure_started_exact']:.5f}%"])
    mins=[x for x in lane['minute'] if x['full_bucket']];third=[]
    for i in range(3):
        xs=mins[len(mins)*i//3:len(mins)*(i+1)//3];count=sum(x['completed'] for x in xs)
        third.append(sum(x['mean_ms']*x['completed'] for x in xs)/count if count else None)
    trend.append([label,' / '.join(show(x) for x in third),' / '.join(q(x['p99_interval_ms']) for x in mins),sum(x['dropped_approx_boundary'] for x in mins),a['storage_during_load']['pending']['max'],a['storage_during_load']['oldest_pending_s']['max']])
    thirds=a['storage_mature_thirds'];res=read(E/key/'resource-analysis.json') if (E/key/'resource-analysis.json').exists() else {}
    db=' / '.join(show(x['values']['db_bytes']['median']/1048576) for x in thirds)
    retained=' / '.join(show(x['values']['decision_retained']['median']) for x in thirds)
    vk=' / '.join(show(x['valkey']['mem']['median']/1048576) for x in res.get('mature_thirds',[]) if x['valkey']['mem'])
    whole=res.get('whole_window',{});cp=whole.get('cpu',{});kv=whole.get('valkey',{}).get('mem');wal=res.get('wal_sample_window')
    costs.append([label,cp.get('app',{}).get('time_weighted_mean_cores'),cp.get('postgres',{}).get('time_weighted_mean_cores'),wal['delta_bytes']/1048576 if wal else None,f"{show(kv['min']/1048576)}–{show(kv['max']/1048576)}" if kv else '—'])
    final=a['natural_final'];co=final.get('target_decisions',{})
    storage.append([label,db,vk,retained,co.get('count'),final.get('full_cycle_after_target_deadline'),final.get('pending'),r.get('cost',{}).get('wal_per_success_bytes')])
    for name,sl in a['lanes'].items():
        if name=='load':continue
        sm=sl['measure'];ll=sl['latency_ms'];side.append([label,name,sl['window_seconds'],sl['rate'],f"{show(ll['p50'])}/{show(ll['p95'])}/{show(ll['p99'])}",sm['measure_dropped_exact'],sl['unexpected_errors'],sm['measure_started_exact']-sm['measure_completed_exact']])
    details.append({'key':key,'label':label,'capacity':r['verdict'],'health':r.get('health'),'audit':r.get('audit'),'forensic_diag':m.get('forensic_diag'),'queue':r.get('queue'),'observer_errors_during_load':a['observer_errors_during_load'],'natural_final':final,'request_sha256':hashlib.sha256((E/key/'requests'/f'{key}.json').read_bytes()).hexdigest()})
    raw.append({'key':key,'label':label,'source_sha':a['source'],'window_s':lane['window_seconds'],'rate':req['rate'],'success_ops_s':lane['rate'],**lat,'drop':measure['measure_dropped_exact'],'drop_fraction':measure['measure_drop_fraction'],'unexpected':m['unexpected_errors'],'expected_rejections':measure['measure_outcomes'].get('expected_rejection',0),'other_failures':sum(v for k,v in measure['measure_outcomes'].items() if k not in ['success','expected_rejection']),'unfinished':measure['measure_started_exact']-n,'capacity':r['verdict'],'pending_peak':a['storage_during_load']['pending']['max'],'pending_age_peak_s':a['storage_during_load']['oldest_pending_s']['max']})
completed=len(raw);finalized='--final' in sys.argv
now=datetime.datetime.now(datetime.timezone.utc).isoformat();lines=['# PR #238 持续负载验证（2026-10-10）','',f"状态：{'最终记录' if finalized else '进行中快照'}；17 个计划点中已有 {len(details)} 个终态、{completed} 份正式测量记录（含失败测量；12 个场景及 5 份独立复测（刷新补测以剩余时间允许为条件））。生成时间 {now}。",'',
'测试源码 HEAD：`6714d3187c528ac2b9aac5c67729b1653b67a427`。生产代码提交：`667060893661dae2c2e31289d5d86ca6474132c3`。新容器重新 release 构建，应用 SHA-256：`35f0cb47b9776883f64d5ce4c52e286661ae4e4a8c16ecad99b75452302c7dd5`。本轮未修改生产代码。','',
'## 方法与边界','',
'仅在用户授权隔离容器、单 checkout、单 target 中串行执行。应用 16 CPU，各点原负载、VUs 与主体配置保持不变，具体参数见 request-public.json；原混合侧车保持不变。原完整操作门槛 P95/P99 100/250ms、成功率 99.5%、drop 0.1%；冷登录沿用原专用延迟门槛。Required mixed 计划 freshness/max_lag=10s，但首次夹具缺少部署身份且未覆盖 freshness，应用启动失败，未形成有效测量；修正后 Required 补测实际核对为 required/freshness10/max_lag10，见 required-runtime-config.json。其他场景应用 Disabled anchor，均配独立 exporter 与签名 receiver。没有降低负载、缩短安全 TTL、手工删数据或手工 vacuum。没有重跑 main。目录名保留最初标识，实际分钟数以请求和测量窗口为准，不能从 MIX30、NATIVE6R2 等名称推断执行时长。','',
'这覆盖原多核业务矩阵及 mixed 中的 UserInfo、token exchange 和 metadata 侧车；不代表仓库所有管理、Device、VC 等协议路径，也未单独重跑单核变体。持续测量窗口为 5–20 分钟，另有两次 1 分钟异常复测、两次 3 分钟夹具修正后短测，属于有限持续负载证据，不是天级稳定性证明。容量门槛通过也不代表每个分钟无尖峰。drop 是未发起的计划迭代，不能与已处理业务错误混为一谈。健康窗口不意味着 Optional/Disabled 在无限期导出故障下磁盘有界。','',
'初始 MIX60 在启动负载前被原 harness 的 1800 秒预算拒绝，退出码 2，记 INVALID_NO_MEASUREMENT。随后在各点启动前重新分配时间：撤销/Disabled mixed 各 20 分钟，其余各 10 分钟，原计划 140 分钟正式窗口。随后只调整未启动的客户端凭证、刷新、FAPI、冷登录各为 7 分钟，补入 Native 6 分钟和 Required mixed 5 分钟的修正夹具复测；完整时间重分配记录见 final-budget-reallocation.json。随后用户要求负载平缓后复测异常，增加授权码与 mixed 各 60 秒，并仅将尚未启动的刷新、FAPI、冷登录改为各 5 分钟，见 environment-retest-plan.json。Native 修正夹具复测在启动前再由 6 分钟调整为 5 分钟，见 supplement-budget-final.json。为满足三小时截止，最终两次夹具修正后补测在启动前均定为 3 分钟，见 supplement-budget-deadline.json。原未启动计划保留；未将失败测量窗口截短。','',
'## 完整操作容量结果','']
lines+=mdtable(['链路','门槛','分钟','目标 ops/s','成功 ops/s','P50/P95/P99 ms','drop','分类意外错误','预期拒绝','其他失败含准备','未完成','成功/已发起'],capacity)
lines+=['','Native SSO 首次点的 240000 次正式迭代全部为 prepare_sut_failed，成功吞吐为 0；其低延迟仅为准备失败耗时，不能作为业务性能或存储稳定证据。下面按原始结果保留 FAIL。Required 点未启动正式负载，保留 INVALID。\n\n## 时间分段与积压','',
'各分钟 P99 为完整操作直方图的上下界，不伪造精确分位数。全程精确 P50/P95/P99 见上表。分钟按完成时间取整，边界约有一秒归属误差；正式 cohort 的成功、drop、错误与未完成数量精确。前三等分平均延迟包括全部完整分钟，不排除尖峰。','']
lines+=mdtable(['链路','前/中/后均值 ms','逐分钟 P99 区间 ms','分钟 drop 合计','pending 采样峰值','最老 pending 采样峰值秒'],trend)
lines+=['','## 存储与自然回收','',
'三组存储值为正式窗口第 6 分钟之后的前/中/后三等分中位数；不足或等于 6 分钟的复测不填此列，完整时序仍保留，不能将空列解释为零或成熟稳态。DB 为物理体量，不等同活跃行数；Valkey 为 used_memory，不等同持久化磁盘。WAL/成功操作来自原 collector 的正式窗口插值。自然回收跟踪前 120 秒形成的目标 decision，需越过其最后 business_retain_until 后的完整自然维护周期；不要求仍在持续产生的全库数据归零。没有 decision 的场景以原观察器的 N/A 证据解释。','']
lines+=mdtable(['链路','DB MiB 三段','KV MiB 三段','合法保留 decision 三段','目标剩余','完整周期','最终 pending','WAL B/op'],storage)
lines+=['','## CPU、WAL 与 KV 采样成本','','CPU 为本测试服务进程 jiffy 增量的时间加权占用核数，采样端点不一定严格重合正式窗口。已退出 PG backend 的 jiffy 无法累计，负增量区间被排除，因此 PG CPU 仅为有边界的观测。WAL 为保留端点间差值；KV 为正式窗口内 used_memory 范围，均不能直接解释成每次操作成本。','']+mdtable(['链路','应用平均核数','PG 平均核数','WAL 采样增量 MiB','KV min–max MiB'],costs)
if side:lines+=['','## 混合链路侧车','']+mdtable(['主点','侧车','秒','成功 ops/s','P50/P95/P99 ms','drop','意外错误','未完成'],side)
lines+=['','## 证据限制与已定位现象','',
'撤销第二分钟出现集中尖峰：全程 1081 次 drop 集中在该分钟。逐秒对照中，掉量附近的 PG 采样显示 32 个应用运行角色连接等待 WALWrite；随后恢复。此为关联证据，不能直接断定共享宿主机或磁盘为根因。其后大部分分钟 P99 20–50ms，并非持续抬升。','',
'数据库精确状态约每 10 秒采样一次，pending 峰值只是采样峰值，不能排除更短尖峰；原 collector 另有高频指标。采样查询有开销，各点 observer_peak_seconds 保留实际耗时，本轮没有额外无采样对照来扣除该开销。共享服务器负载仅从用户指定页面的 1 分钟值和趋势记录，不读取 CPU 百分比来判断环境，也不把共享负载当作门槛失败的自动免责。\n\n可选逐请求 forensic diagnostic 可能达到固定 512MiB 逻辑预算而截断；完整正式 cohort、每秒聚合直方图和存储时间序列分别保留。不能声称逐请求 trace 完整。黑盒数据库采样不能证明进程内 best-effort 队列长度；这些内部门禁保留 UNVERIFIED，不能从 HTTP200 推断持久回执。持久审计以数据库、签名 checkpoint、receiver journal 对账为准。维护周期完成、stop_reason 与错误汇总见 maintenance-summary.json；未出现的 saturated 字段不解释为 false。','',
'`commands.jsonl` 保留实际 Docker/Python 命令、起止时间及退出码；`details.json` 保留各点健康、回执、自然回收与诊断限制；各点原始 `*.series.json`、`storage.jsonl`、`pg-roles.jsonl`、`valkey-series.jsonl`、`maintenance.log`、`target-cohort.json` 及分析 CSV 可复核。','']
if (P/'conclusions.md').exists():lines += ['## 综合结论','',(P/'conclusions.md').read_text()]
(P/'REPORT.md').write_text('\n'.join(lines)+'\n');(P/'details.json').write_text(json.dumps(details,ensure_ascii=False,indent=2))
if raw:
    with (P/'capacity.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(raw[0]));w.writeheader();w.writerows(raw)
(P/'report-state.json').write_text(json.dumps({'generated_at':now,'completed':completed,'terminal_points':len(details),'expected':17,'finalized':finalized},indent=2))
print(json.dumps({'completed':completed,'finalized':finalized,'report':str(P/'REPORT.md')}))










