# PR #222 失败点补测（执行中 checkpoint）

完成状态：INCOMPLETE。验收状态：尚未完成，不宣称 PASS。

原始 TASK_STARTED_AT 为 2026-09-29T10:40:36Z；负载截止 11:35:36Z，交付硬截止 11:40:36Z。生产源码和性能 harness 冻结在 a4a818d9d4df8ee2f913dbbb498f0e944cc3c16e；生产构建输入与旧 3b6d8d3c 完全相同，运行二进制 SHA-256 仍为 0731ed36ff88e10f0b12279ec684b6e5323626d69aaf238d3b9f33db9854c1ed。

范围仅是四个旧失败点：多核 code 800（15+60秒），单核 mixed 400（60+60秒），多核 mixed 1600（60+60秒），多核 mixed 800 成熟确认（60+570秒）。五个旧通过点不重跑，旧报告和容量矩阵保留。

本部署动态分配为 app single 1 / multi 16、PG 16、Valkey 1、generator 31；CPU ID 由当前控制进程与 runner 的实际可运行集合取得。本部署 .cnb.yml 明确预算 64。连接池 32；主 runner single 64 VU / multi 992 VU；实际种子数 single 64 / multi 992；refresh sidecar 64 VU、multi 600 ops/s。所有 sidecar 共用种子文件。

单核 mixed 初次尝试在负载结束后的证据整理阶段达到既有 240 秒 worker 上限，记为 INVALID，并保留原始尝试。工具修复仅为含 residency observer 的点增加 60 秒 worker 收尾预算，正式窗口、速率、sidecar、状态、安全、协议、耐久性和验收门槛均未改变。只有 INVALID 点补测，真实 FAIL 不因该工具修复重跑。

initial_driver.py 是本轮已执行初始编排的精确字节记录，SHA-256 为 3e07b9fb11f167e7e6f1dfaf1dc8a5f5c5257bb685f80c9be83ac12a09d0ca61。retest_driver.py 是修正工具收尾预算的四点复现入口；均复用 short_baseline.prepare/make_point/worker/bounded_child/own_cleanup，不调用默认九点套件，也不新增验收逻辑。retry_driver.py 保存超时尝试后仅补无效点；control_driver.py 在四个必测均有效后才允许一个预热对照。diagnose.py 只离线投影原生证据，不重新定义判定。

当前授权码 800 和多核 mixed 1600 已再次 FAIL；成熟确认仍在执行。授权码 SQL/等待证据指向 family 查询、WALWrite/WalSync 和早期统计信息候选，尚无应用连接实际缓存计划，不宣称已确认唯一根因或问题已解决。

最终结果、旧新并列表、脱敏 SQL/等待/逐秒诊断、归档校验及精确 CI 快照在后续交付提交补齐。本 checkpoint 不是最终验收。
