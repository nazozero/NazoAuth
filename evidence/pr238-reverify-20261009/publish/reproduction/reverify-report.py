from pathlib import Path
import datetime,hashlib,json,re,subprocess,tarfile
R=Path('/workspace');E=R/'evidence/pr238-reverify-20261009';P=E/'publish';P.mkdir(exist_ok=False)
rows=json.loads((E/'summary.json').read_text());assert len(rows)==2
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip()
assert sha=='e8242c44aab842e1828b471413905f74b4132325'
assert not subprocess.check_output(['git','diff','--name-only'],cwd=R,text=True).strip()
text='''# PR #238 新容器定向复测（2026-10-09）

受测源码 HEAD：`e8242c44aab842e1828b471413905f74b4132325`，业务源码提交为 `7203ab33a79dc2db2cad801e15d75e313fdc689b`。本轮没有修改业务源码、迁移、负载、安全配置、成功定义或验收阈值。只复测撤销与 mixed，不重跑 main 或旧通过矩阵。以下人类可读时刻使用北京时间 UTC+08:00；原始时间序列保留 UTC/Unix 时间。

## 本轮结论

| 项目 | 结果 | 范围 |
| --- | --- | --- |
| CODE | PASS | 同一源码原质量证据；该受测 HEAD 的 7 项 GitHub 检查全部成功；新容器 release 重建成功 |
| SECURITY | PASS | 两点状态校验、独立 exporter 与签名 receiver 审计对账通过，无意外业务错误 |
| RECOVERY | PASS（复用） | 同一业务源码已有真实 PG 故障回归，本轮不声称重跑全部故障负载 |
| PERFORMANCE | FAIL | 撤销 PASS；mixed 主链路及三条侧车 FAIL |
| STORAGE | INVALID | 撤销完整自然终态 PASS；mixed 观察上限前仍有 105 条已到期 decision，缺下一完整周期 |

因此不能宣布全面验收通过，也不能用 CI 绿色替代性能验收。

## 原参数与执行

撤销：16 应用 CPU、960 ops/s、992 VUs/主体，15 秒预热 + 360 秒正式窗口。
mixed：16 应用 CPU、1600 ops/s、992 VUs/主体，60 秒预热 + 300 秒正式窗口。原四条侧车持续 390 秒（正式统计 375 秒）：冷登录 8/s、metadata 200/s、FAPI 30/s、refresh 600/s，分别使用 8/16/32/64 VUs。

应用 Disabled anchor、连接池 32、独立 exporter 与签名 receiver、真实 PostgreSQL/Valkey 及持久性配置均保持原值。CPU 号按新容器可用集合映射，16/16/1/31 的应用/PG/Valkey/负载分配不变。原主链路门槛 P95/P99 100/250ms、成功率 99.5%、drop 0.1% 不变；冷登录沿用其专用门槛。请求差异逐项保存在 request-delta.json。

单 checkout、单 target；构建全部结束后才开始压测。撤销命令退出 0，用时 549.536 秒；mixed 命令退出 2，用时 578.448 秒。两点均低于 10 分钟；实际命令与退出码见 commands.jsonl，构建命令见对应 *-exit.json。没有手工删除记录、缩短 TTL、手工 vacuum 或改清理调度。

## 完整操作指标

| 场景 | 成功 ops/s | P50/P95/P99 ms | 正式 drop | 结果 |
| --- | ---: | --- | --- | --- |
'''
for x in rows:
    m=x['measure'];lat=x['latency_ms']
    text+=f"| {x['key']} | {x['ops_s']} | {lat['p50']}/{lat['p95']}/{lat['p99']} | {m['measure_dropped_exact']}（{100*m['measure_drop_fraction']:.4f}%） | {x['verdict']} |\n"
    if x['sidecar_gates']:
        for name,g in x['sidecar_gates'].items():
            m=g['metrics'];lat=m['complete_operation_latency_ms'];measure=m['measure']
            text+=f"| mixed/{name} | {m['rate_for_gate']} | {lat['p50']:.2f}/{lat['p95']:.2f}/{lat['p99']:.2f} | {measure['measure_dropped_exact']}（{100*measure['measure_drop_fraction']:.4f}%） | {g['verdict']} |\n"
text+='''
撤销 345600/345600 正式操作成功，0 未完成。mixed 正式完成 477479 次，其中 477475 成功、4 个预期拒绝、0 意外错误、0 已启动未完成；相对计划约 480000 次，成功率约 99.474%，也未达到 99.5%。各侧车已启动操作均完成，无意外错误；drop 与成功吞吐下降仍是实际失败。

上一轮相同候选撤销 P95/P99 为 127/485ms，本轮 20/33ms，严重尾延迟没有复现。mixed 上轮主链路 51/146ms，本轮 43/361ms，成功吞吐下降、drop 增加；不能因 P95 下降写成改善。新容器仍不能稳定通过混合负载。

## 是否存在积压导致 P99 持续增长

撤销：12 个完整 30 秒桶的 P99 均在 (20,50]ms 区间，没有观察到持续抬升。
mixed：正式窗口前 210 秒大部分桶的 P99 在 (10,20]ms；最后三个完整桶分别落在 (500,1000]、(200,500]、(1000,2000]ms，属于后段明显恶化。分桶值是 histogram 区间，不能当精确分位数。不能据此宣称 mixed 已经拉平，也不能由短测证明长期稳态。

两点 pending 最终均为 0。10 秒采样中的 pending 峰值/最老年龄：撤销 111/0.02921 秒，mixed 1946/0.966193 秒。到期 decision 最老年龄峰值分别约 57.90/58.65 秒，多次维护日志为 drained。记录数量存在周期性回落，没有证明持久未处理队列一直增长；但这并未解释 mixed 后段停顿的具体机制。相关性不能替代连接持有、调度或 I/O 的因果证据。

## 存储

| 点 | DB 初值/负载峰值/观察终值 MiB | Valkey 采样峰值 MiB | WAL B/成功操作 | 应用/PG 平均核数 |
| --- | --- | ---: | ---: | --- |
'''
for x in rows:
    text+=f"| {x['key']} | {x['db_initial_mib']:.2f}/{x['db_peak_mib']:.2f}/{x['db_final_mib']:.2f} | {x['valkey_peak_mib']:.2f} | {x['wal_per_success']:.3f} | {x['cpu_cores']['app']}/{x['cpu_cores']['postgres']} |\n"
text+='''
WAL/成功操作使用原统计口径，mixed 包含侧车工作；不同 drop 和完成量限制成本归因。DB 是物理大小，不能将其增加全部算成业务活数据或把终值未归零当泄漏。CSV 与原始 JSONL 同时记录 live/eligible/oldest_due、dead tuples、索引及表大小；Valkey 包含仍在 TTL 内的合法状态。

撤销目标批次自然归零，并覆盖最后保留期之后的完整清理周期，终态没有到期 issuance；仍保留 231507 条尚未到期的 issuance 和 992 条活跃 family。没有为了清空数据库提前删除安全状态。删除后的可重用高水位及等待 autovacuum 的空间不保证立即返还给文件系统。

mixed 终态还有 105 条已导出的、已到期 decision，尚无最后保留期后的完整周期。最后截止是 23:31:48.066865；最近周期结束于 23:31:44.681204，早于该截止。观察结束约 23:32:25，下一自然周期预计不早于 23:32:44，超出本轮为终态观察预留的预算。此结果为 INVALID，而不是证明清理器卡死。终态另有 56162 条未到期、11403 条已到期待下一轮清理的 issuance，未要求全库归零。

补充观察器持续采样到容器清理阶段，撤销有 2 次、mixed 的次数见 summary.json，报数据库容器停止或不存在。这些均晚于记录 natural-final 的时刻，之前采样无错误；原始错误保留，不能冒充业务运行期间的数据库故障。

## 环境线索及证据边界

23:34 左右，所有压测服务已经退出，仅余休眠的构建/控制工具容器。CNB 页面显示 CPU 0%，1/5/15 分钟负载先为 47.90/37.59/32.20、随后为 42.83/36.85/32.01；磁盘速率约 1.2–1.4 GB/s。环境规格内存 128 GiB，面板总内存却为 556.61 GB。

这说明指标统计范围可能不一致，支持环境干扰的可能性；面板是在负载结束后读取，不能证明 mixed 异常窗口的原因，也不能据此免除实际门槛失败。未探测宿主机。后续如继续调查，应同步记录面板与异常时段，而不是追加同一代码的完整矩阵。

## 审计与 CI

撤销 1080003 个、mixed 856770 个审计事件与数据库、receiver 和签名 checkpoint 对账均 PASS。低事件数伴随不同成功量，不能解释成降低安全审计覆盖。详细校验位于各点 short-result.json 的 audit。

受测 HEAD 的 Rust quality gate、CodeQL Rust analysis、source-policy-gate、Python script syntax gate、supply-chain-gate、real-http-security-matrix 和 CodeQL 均 SUCCESS（ci.json）。本报告后续提交只增加证据，不改变受测业务源码；该 CI 记录不冒充后续报告提交的新 CI 运行。

剩余问题：mixed 原门槛仍 FAIL，后段延迟恶化根因未确定；mixed 完整自然回收终态证据不足。没有通过调低负载、放宽阈值、缩短安全期限、修改队列或重复取最好成绩来改变判定。
'''
(E/'REPORT.md').write_text(text,encoding='utf-8')
files=[]
for pattern in ['*.json','*.jsonl','*.log','*.md','*.sql','*.py']:
    files+=list(E.glob(pattern))
for key in ['REV360','MIX300']:
    D=E/key
    for pattern in ['*.json','*.jsonl','*.csv','*.log']:
        files+=list(D.glob(pattern))
    files+=[D/'requests'/f'{key}.json']
    files+=list(D.rglob('short-result.json'))+list(D.rglob('*.series.json'))
    files+=list(D.rglob('task-cleanup.json'))+list(D.rglob('task-finalization.json'))
manifest=[]
for f in sorted(set(files)):
    raw=f.read_bytes();content=raw.decode()
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|postgres(?:ql)?://[^\s]+:[^\s]+@|github_pat_|gh[pousr]_[A-Za-z0-9]{20}',content):
        raise RuntimeError('Sensitive content requires review: '+str(f.relative_to(E)))
    target=P/f.relative_to(E);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    manifest.append({'file':str(target.relative_to(P)),'sha256':hashlib.sha256(raw).hexdigest()})
(P/'manifest.json').write_text(json.dumps(manifest,indent=2))
with tarfile.open('/tmp/pr238-reverify-evidence.tar.gz','w:gz') as archive:archive.add(P,arcname='pr238-reverify-20261009')
print(json.dumps({'files':len(manifest),'bytes':Path('/tmp/pr238-reverify-evidence.tar.gz').stat().st_size}))
