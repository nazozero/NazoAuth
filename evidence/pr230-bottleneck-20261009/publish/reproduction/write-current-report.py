from pathlib import Path
import json,re
E=Path('/src/evidence/pr230-bottleneck-20261009');P=E/'publish';P.mkdir(exist_ok=True)
rows=json.loads((E/'round-analysis.json').read_text());by={x['key']:x for x in rows};src=json.loads((E/'final-source.json').read_text())
status=json.loads((E/'verification-summary.json').read_text()) if (E/'verification-summary.json').exists() else {}
s='''# PR #230：连接占用重写与自然回收证据，2026-10-09

**原容量门槛仍未通过，本报告不证明“性能问题已解决”或“达到全部合并标准”。**

本轮核对远端后的 A 为 `7d7ed5fddc5c91201bcac94553a6e72836d471d7`；最终源码 B 为 `3da0734de491a380b315fc2fb2827f4043c04823`。B 的发布二进制 SHA256 为 `7b199250bb8fb82f8fee2b084d465081b9ddd8532c703f8216a2776ebebaa35d`。报告提交 SHA 记录在 PR 正文/评论中，以免文档自引用。

本轮正常提交 `0af6e89e894d6c7d482f204e5c47de3faab8d003` 与 `3da0734de491a380b315fc2fb2827f4043c04823`。历史报告保留，不重跑 main 或旧通过全矩阵。只有一个授权 CNB checkout、一个 target 缓存、一个写入者；构建和负载串行，测试数据库与性能数据库隔离。没有合并、部署、force push 或宿主探测。

## 结论及证据边界

| 项目 | 判定 | 边界 |
|---|---|---|
| CODE | 见下方最终质量门禁 | 本轮 owning package 回归、workspace Clippy、格式和静态边界；未以旧完整 workspace suite 替代最终源码的新测试。 |
| SECURITY | 见最终 PostgreSQL 回归 | 提交确认、晚期失败/取消/断连、旧 backend 退出和替换连接、Required 回滚、撤销/重放/容量及租户绑定均由实际测试检查。 |
| RECOVERY | 既有故障负载证据沿用，本轮不重复完整故障矩阵 | 本轮未修改 exporter、签名回执或 Telemetry 恢复队列；新增事务边界仍需最终真实数据库回归。 |
| PERFORMANCE | **FAIL** | 原负载、100/250 ms、99.5% 成功率、0.1% drop 门槛未放宽。局部调用次数下降不等于容量通过。 |
| STORAGE：decision 自然回收 | **PASS** | 最终源码的 42,320 条目标 decision 在最后保留期限后的完整自然维护周期归零。 |
| STORAGE：目标负载长期稳定 | **INVALID** | 短测存在掉量，不能证明原目标负载的长期拉平或无限导出故障下磁盘有界。 |

CI 只在本轮本地工作和报告完成后检查；其结果单独记录在 PR，不覆盖 PERFORMANCE FAIL。

## 已证实机制、重写与剩余根因

新建 refresh family 原来在同一个事务中逐次跨数据库连接调用：principal 检查、scope/family/victim 锁、容量淘汰审计、contract 引用、插入。固定工作量回归中，前十次新建各 10 次数据调用，触发淘汰后三次各 13 次；先验证 13 次真实提交、10 个有效 family、3 个淘汰、13 个 token_issued 和 3 个淘汰审计，再检查调用数。A 上实际运行 exit 101，失败在调用次数断言，不是编译/夹具缺失。第一次重写降为 5 次，最终 Fresh 模式降为 3 次，行为断言全部保留。AuthorizationCode 模式另有必要的单次消费 receipt 调用，为 4 次数据调用，加 BEGIN/COMMIT 对应诊断中的 6 次 driver 调用。这是确定的低效机制及其修复证明。

- `nazo_create_refresh_family` 将同一事务内依赖的数据转换放到数据库执行；旧逐步 Rust 实现移除，没有第二套权威。仍先 scope 锁、new-family 锁，再按原顺序锁容量淘汰对象；每个实际淘汰保留一条 Required 事实。
- `nazo_lock_token_principals` 将原有 SET LOCAL 和 client/user 顺序锁检查合并为一次调用，仍在调用者事务内。专门回归证明 2 秒 lock_timeout 在函数返回后仍有效，事务结束后恢复原设置。
- 两个函数均为 invoker rights，表/函数引用明确，运行角色通过原 allowlist 获得权限；保留 contract payload/digest 一致性与 KEY SHARE 回收 fence。
- 不移除 COMMIT 确认、不恢复 Required 人工凑批、不缩短 TTL、不扩大正式连接池。JoinSet 取消和 DiscardOnDrop 的不确定提交连接丢弃路径保留。取消可能已经提交，测试不强行声称回滚。

**但当前剩余瓶颈没有解决。** 完整授权码操作仍约 11 次借连接。最终诊断 D2 的 362 个正式窗口 pool 状态样本均为 size/max=32、available=0，最高 waiting=948。请求尚未得到连接就等待较长时间，有限 VU 随之耗尽并出现计划迭代 drop。不能把这种“有界等待”或尾延迟平台期称为高并发稳定。

## 修前/修后连接账本

以下为每阶段均值，单位 ms；诊断采样与正式无重日志性能结果分开。完整操作约 5 次 client、3 次 user、1 次 audit preflight、1 次 decision、1 次 issuance checkout。数据调用回归中的 3 次不包含 BEGIN/COMMIT，也不等于整个 HTTP 操作只有 3 次借连接。

| 阶段/版本 | acquire | checkout 持有 | driver 调用 | SQL await（不含 BEGIN/COMMIT） | COMMIT await | owner ready | owner poll |
|---|---:|---:|---:|---:|---:|---:|---:|
| issuance A / D0 | 0.461 | 10.060 | 16 | 7.139 | 2.589 | 0.130 | 0.270 |
| issuance 第一版 / D1 | 124.935 | 17.123 | 8 | 10.773 | 5.252 | 0.625 | 0.182 |
| issuance 最终 B / D2 | 146.605 | 21.249 | 6 | 13.457 | 7.299 | 0.572 | 0.213 |
| decision A / D0 | 0.495 | 3.532 | 1 | 见原始账本 | — | 见原始账本 | 见原始账本 |
| decision 最终 B / D2 | 145.300 | 8.062 | 1 | 7.903 | — | 见原始账本 | 见原始账本 |

`D*/final-ledger-analysis.json` 保存逐阶段 checkout 次数、SQL/提交/应用其他时间及采样分母。SQL await 包含服务端、网络、驱动和任务调度；owner ready 时间与其重叠，不能相加或称为完全分离的网络往返。诊断 ledger 仅用低基数阶段分类，没有把 request_id/user_id 当指标标签。`pg-roles.jsonl` 按运行角色/exporter/观测连接分别保留状态，不把所有 ClientRead 归为应用池。

应用容器自身 `/proc/1/task/*/schedstat`：D1 的 26.074 秒窗口累计线程运行 42.428 秒、runqueue 等待 174.915 线程秒；B06R 的 25.969 秒窗口分别为 29.783/115.250。它证明存在调度等待，但不识别竞争者，也不证明所有回退都由 CNB 造成。待进一步分离的部分包括连接驱动任务唤醒、socket/服务端等待与提交同步；不能以源码审查代替性能通过。PG statement parent/nested 执行时间不能重复相加。

## 原始容量结果

所有 ops/s 为完整操作成功吞吐；所有 P50/P95/P99 为完整操作，非 HTTP 子请求。drop 是未启动的计划迭代，不是业务返回错误。已启动成功率和计划成功比例分别保留在 `round-analysis.json`。A06 因 controller 缺 cryptography、负载前失败，保留 INVALID，未参与比较。

| 点 | 源码 | 诊断 | 场景 / CPU | 目标 / VUs | 成功 ops/s | P50/P95/P99 ms | drop | 判定 | WAL bytes/成功 | app/PG 平均核数 |
|---|---|---|---|---|---:|---|---:|---|---:|---|
'''
for r in rows:
 if not r.get('source_sha'):
  s+=f"| {r['key']} | — | — | — | — | — | — | — | {r.get('verdict')} | — | — |\n";continue
 l=r.get('latency_ms',{});c=r.get('cpu_cores',{});s+=f"| {r['key']} | {r['source_sha'][:10]} | {r.get('diagnostic_only')} | {r.get('scenario')} / {r.get('app_cpus')} | {r.get('rate')} / {r.get('vus')} | {r.get('success_ops_s')} | {l.get('p50')}/{l.get('p95')}/{l.get('p99')} | {100*r.get('drop_fraction',0):.4f}% | {r.get('verdict')} | {r.get('wal_bytes_per_success')} | {c.get('app')}/{c.get('postgres')} |\n"
s+='''
A06R 与最终 B06R 的正式窗口不紧邻，不能将差值全部归因于代码。B06R 比 A06R 吞吐少、drop 多，虽然 P99 较低，**不写成改善**。D0 的 800 ops/s 与后来较差窗口也不构成候选全面通过证据。

Q32/Q64 为同一最终源码、800 ops/s、992 VUs、相同安全配置的连接数单变量诊断。Q64 仅把 DATABASE_MAX_CONNECTIONS/pool_connections 从 32 改为 64，不作为原 32 连接验收，不更改生产默认值。Q32→Q64 的成功吞吐502.7→702.75（约+39.8%），drop37.1625%→12.1508%，P99 2702.39→1960ms；运行角色采样分别实际看到32/64连接。app/PG平均占用核数1.53/3.19→2.04/5.19。这个对照支持池预算限制了有效并行度，不能全部归咎于共享CPU，但64连接仍FAIL。短时序实验受共享调度波动影响；Q64线程调度采样跨warm/formal边界，不能直接与Q32的正式窗口子集作同窗因果对比。详见pool-experiment-analysis.json。

历史 `pr230-performance-20261009/publish` 的 B 生产源码与本轮 A 相同（见 `historical-baseline-equivalence.json`），但容器/窗口不同，只能历史参考。历史 B03R 为396.6 ops/s、193/341ms、drop0.85%；B04R 为1071.383、2526/2745ms、33.0364%；B10 为410.917、2851/2993ms、57.1962%。本轮未重跑 main，历史报告未覆盖。

### 原 mixed 侧车

mixed1 主负载400、64 VUs/users，mixed16为1600、992 VUs/users；warm/formal均60/60秒，侧车持续150秒。mixed1 的 argon2/meta/FAPI/refresh 分别1/13/2/38 ops/s，VUs8/16/32/64；mixed16分别8/200/30/600，VUs相同。授权码与撤销 warm/formal15/60秒；撤销960 ops/s、992 VUs/users。完整请求、主体/向量数和实际共同测量窗口见各点 requests 与结果文件，没有猜测参数或降低负载。

| 点 | 侧车 | 判定 | 成功 ops/s | P95/P99 ms | drop |
|---|---|---|---:|---|---:|
'''
for r in rows:
 for name,g in r.get('sidecar_gates',{}).items():
  m=g['metrics'];l=m.get('complete_operation_latency_ms') or {};w=m.get('measure') or {};s+=f"| {r['key']} | {name} | {g.get('verdict')} | {m.get('rate_for_gate')} | {l.get('p95')}/{l.get('p99')} | {w.get('measure_drop_fraction')} |\n"
s+='''
### 延迟平台与实际积压

各点 `time-analysis.json` 使用完整 cap_iter_ms 直方图流按完成时间分10秒桶，全部正式 cohort 完成数对账。分桶分位数是区间，不能冒充精确 P99；正式全窗口分位数/精确 drop 仍以 short-result 为准。不能使用有采样上限的 diagnostic raw 点计算无偏分位数。

最终授权码的秒级等待伴随约29% drop。即便P99后段不再上升，也是有限VUs/池占用约束下的掉量平台，不能宣称目标800/s始终拉平。应用池等待、持久 outbox pending、合法保留、死元组和物理高水位是不同量，分别记录。

## decision 自然回收终态

B06R 的 follower 在最终应用重建、audit pair 启动后才绑定实际实例 ID，结束时复核同一实例，并回读最终实例日志。固定目标批次42,320条，最后 business_retain_until=`1791509204.231941`；完整自然维护周期在 `2026-10-09T01:27:30.278130Z` 结束，40 batches、9810 rows、stop_reason=drained。随后 `1791509255.527388` 的直接查询确认目标 remaining/eligible/retained/unexported全0。跨本轮完整周期累计自然删除42,320。详见 `B06R/decision-natural-reclamation.json`、cohort/series及 maintenance日志。

保留9,920个有效family、42,320条仍合法保留的issuance receipt、992个被引用contract；orphan/pending/spent终态为0。数据库/receiver/签名checkpoint对齐118,032条审计：decision42,320、token_issued42,320、capacity_retired33,392；journal642批、连续无重复。token_issued对账保留原 `reported_only_no_clean_denominator` 边界，不擅自升级为额外业务成功率证明。

物理DB终态233,969,343 bytes，不要求全库/文件归零。空的chain_entries仍有约13,852,672 bytes索引；audit_events等pg_stat删除/死元组计数可能落后最后周期，直接行数是逻辑回收终态依据。真实autovacuum与表/索引体积已记录在 `B06R/storage-series.csv`/storage.jsonl。未手工删除decision、缩短TTL或手工vacuum制造通过。物理空间不能精确等同全部bloat，未复用空间与等待vacuum的死元组分开记录。没有宣称Optional/Disabled在无限期导出失败下磁盘有界。

## 最终质量门禁、负向证明和真实故障

'''
s+='```json\n'+json.dumps(status,ensure_ascii=False,indent=2)+'\n```\n\n'
s+='''每个 `*-exit.json` 记录真实子命令退出码，外层 SSH 成功不代替 cargo 成功。以下包含失败尝试，不删除失败测试/日志：

'''
for f in sorted(E.glob('*-exit.json')):
 x=json.loads(f.read_text());cmd=x.get('command');s+=f"- `{f.name}`：exit **{x.get('exit')}**；`{' '.join(cmd) if isinstance(cmd,list) else cmd}`。\n"
s+='''
首次隔离schema重新应用函数、历史保留migration fixture、硬编码oauth数据库夹具及旧调用数golden产生过失败；它们与真实性能失败分开。新增函数使用CREATE OR REPLACE以适配隔离schema迁移重放；历史retention测试只补充当前运行实现需要的函数定义，不改变旧表/保留断言；数字golden降为新调用数，行为/提交断言保留。最终从空的两个隔离unit数据库按规范先初始化迁移，再执行最终package suite。性能数据库没有被该操作清空。

`audit_commit_boundary` 和 `security_state_commit_boundary` 的日志保留真实晚期错误、取消、断连、独立观察旧backend消失和替换连接检查。若取消后 durable_changed=true，结论是“没有返回确认成功”，不是“必然回滚”。最终回归日志中的事实优先于早期单条混合命令的失败结果。

原始负载命令与exit在 `formal-commands.jsonl`。每个物理测点不足10分钟；多个诊断重复的累计时长不冒充单次时长。B06R仅增加有限自然维护日志和观察时长，直到目标保留期后的完整周期；没有修改生产调度/保留期。

## 剩余问题

1. 原四点容量仍需通过；减少SQL调用的确定性回归不能替代吞吐、P95/P99和drop结果。当前不保证无性能回退，不建议据本报告宣布已达合并标准。
2. 池中的长等待是已观测到的直接机制；连接驱动调度/数据库提交等待的比例尚未完全分离。增加连接只作为诊断，不能把等待转移到数据库后声称根因已修。
3. 本轮decision自然回收证据闭环；原负载长期存储增量稳定仍缺证据。未重复已经完成且未受修改影响的全面故障负载或旧通过矩阵。

`artifact-index.json` 给出原始及发布文件hash/size。容量原始流保留cap_*、drop、iterations、vus/vus_max原行，省略可能含请求URL的HTTP细节；签名journal只发布hash、数量及checkpoint对账，不公开原始payload、私钥和凭据。构建/测试/诊断复现脚本随报告保存。历史报告不覆盖。
'''
s+='\n## 物理存储增量与 pending 时间序列\n\n下表为实际采样首末/峰值，单位 bytes；采样时段长度不同，不能当作统一60秒、每操作成本或长期增长率。完整采样时间戳、表/索引和安全状态数见各点 storage-series.csv 与 storage.jsonl；WAL 的正式成功操作归一化值见上表。\n\n| 点 | 采样秒数 | DB 首/末 | 增量 | 峰值 | pending 峰值 | 最老 pending 秒数峰值 |\n|---|---:|---|---:|---:|---:|---:|\n'
for r in rows:
 st=r.get('storage_sampling') or {}
 if st.get('db_first') is not None:
  s+=f"| {r['key']} | {st['end']-st['start']:.3f} | {st['db_first']}/{st['db_last']} | {st['db_last']-st['db_first']} | {st['db_peak']} | {st['pending_peak']} | {st['oldest_pending_peak_s']} |\n"
s=s.replace('CODE | 见下方最终质量门禁', 'CODE | **'+status.get('CODE','BLOCKED')+'**（本轮本地门禁）').replace('SECURITY | 见最终 PostgreSQL 回归', 'SECURITY | **'+status.get('SECURITY','BLOCKED')+'**（受影响边界）').replace('RECOVERY | 既有故障负载证据沿用，本轮不重复完整故障矩阵', 'RECOVERY | **'+status.get('RECOVERY','BLOCKED')+'**（受影响事务回归；完整故障负载沿用历史证据）')
timing=json.loads((E/'execution-time.json').read_text())
s+=f"\n## 总体验证时间\n\n从记录到的首次远端检查到最终源码本地质量门禁结束为 {timing['elapsed_seconds']/60:.2f} 分钟（不含报告发布及CI），**超过此前两小时预算**。每个性能测点不足10分钟不等于整体验证在两小时内完成。最后PG package命令耗时825.708秒，其中既有1500万行审计fixture构造263.209秒；实际命令/时间均保留，未缩小夹具或删测试获得通过。见 execution-time.json。\n"
(P/'README.md').write_text(s);print('wrote report',len(s))






