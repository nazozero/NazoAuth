# PR #238 遗留模型、性能与回收闭环

最终源码：`667060893661dae2c2e31289d5d86ca6474132c3`。本报告提交仅增加证据；报告提交 SHA 记录在 PR 评论及 Git 历史中。

本轮完成剩余模型收敛、原 300 秒 mixed 的完整侧车门槛验证、受影响撤销链路验证，以及持续负载下 decision 目标批次自然回收验证。B1 的 FAPI P95=109ms 实际 FAIL，保留该失败；在交错确认计划记录之后只追加一次 A2/B2，最终 B2 结果独立列出，未覆盖 B1。没有修改负载、VUs、成功定义、安全期限、连接池或容量门槛；没有手工删除应用数据或 vacuum 制造容量/回收结果。

| 项目 | 结论 | 实际范围 |
| --- | --- | --- |
| CODE | PASS | 最终源码格式、Clippy、静态/依赖/密码学边界、迁移与完整 workspace |
| SECURITY | PASS | Required 立即写入且等提交；真实 PG 的批次健康、撤销、租户/保留边界；实际 exporter/receiver 签名对账 |
| RECOVERY | PASS | 最终 workspace 中真实 PG 提交边界、取消/断连和审计恢复回归；未重复无修改的整套外部故障负载 |
| PERFORMANCE | PASS（最终原配置确认） | B2 MIX300 主链路和四侧车、REV360；B1 FAPI P95 FAIL 原样保留，不声称所有重复窗口或未重跑全矩阵均通过 |
| STORAGE | PASS | 已知回收缺口修复、目标批次自然归零及完整维护周期、占用分类与实际新行布局减少；保持合法安全保留 |

## 具体根因和修复

既有短期性能失败与可证明的数据冗余分开处理。原 300 秒 mixed 的 refresh 侧车历史 drop 0.4698% 本轮在 A1/B1 中均未复现；B1 另有 FAPI P95 超标，随后预先固定一次 A2/B2 对照；不把这一变化全部归因于字段删除，也不以共享 CPU 为由将 FAIL 自动改成 PASS。所有本轮采样和结果保留，没有挑掉预热之后的差窗口。

本轮可证实的额外成本是：撤销行有一个无人读取、无外键引用的 UUID 和其独立唯一索引，健康查询投影了只有 claim 路径才需要的租约字段，两个控制回执/历史时间字段只有写入者。`66706089` 删除这些冗余，使用原 tenant/JTI 唯一身份，保持提交、ACK、租户/client 绑定、原始截止和回放拒绝。另删除无读者 mTLS 有效性布尔值、局部 checkpoint 时间副本；真实 DER 校验和持久快照完整性仍在。

PR 此前修复的缺口继续生效：到期 remembered MFA/identity approval 有小时回收；已用 backup verifier 在原审计事务内删除；TOTP 无用元数据移除；原 refresh SID 只有一个权威；RefreshToken 组合既有 contract；DCR 复用 create command；已消费 VCI offer 不再保留无消费者的敏感载荷。历史负向/正向证明见 `evidence/storage-minimize-20261010/publish/REPORT.md`，不覆盖原始报告。

## 原负载性能结果

A 源码：`088afcd5d9b22dd915438d19fbea85c3add71ecd`，运行时 HEAD `34402ffea83c574a6c3805ca91ab82e511ba74f8` 与 A 的业务源码/迁移/perf 相同。B 源码为上面的最终 SHA。二进制和镜像 hash 在各自 build.json；请求差异 allowlist 在 request-delta.json。

MIX300：16 应用 CPU，1600 ops/s，992 VUs/主体，60 秒预热 + 300 秒正式统计；侧车 cold/meta/FAPI/refresh 为 8/200/30/600 ops/s，8/16/32/64 VUs，390 秒总运行、375 秒正式统计。REV360：16 CPU，960 ops/s，992 VUs/主体，15 秒预热 + 360 秒正式统计。连接池 32，应用 Disabled anchor，真实 PostgreSQL/Valkey、独立 exporter 和签名 receiver。完整操作 P95/P99 100/250ms、成功率 99.5%、drop 0.1%；cold 沿用原专用门槛。

| 点 | 成功 ops/s | 完整操作 P50/P95/P99 ms | drop/计划数 | 预期拒绝 | 已开始未完成 | 结果 |
| --- | ---: | --- | --- | ---: | ---: | --- |
| A1 mixed | 1599.983 | 3/12/20 | 0/480000 | 5 | 0 | PASS |
| B1 mixed | 1599.977 | 4/35/71 | 0/479997 | 4 | 0 | FAIL |
| B revoke | 960.000 | 13/58/85 | 0/345600 | 0 | 0 | PASS |
| A2 mixed | 1599.990 | 3/12/24 | 0/480001 | 4 | 0 | PASS |
| B2 mixed | 1599.973 | 3/12/19 | 0/480000 | 8 | 0 | PASS |
| A1 mixed/argon2 | 8.000 | 135/148/163 | 0/3000 | 0 | 0 | PASS |
| A1 mixed/meta | 200.000 | 1/1/1 | 0/75000 | 0 | 0 | PASS |
| A1 mixed/fapi | 30.000 | 20/28/44 | 0/11250 | 0 | 0 | PASS |
| A1 mixed/refresh | 600.000 | 4/8/18 | 0/225000 | 0 | 0 | PASS |
| B1 mixed/argon2 | 8.000 | 156/221/245 | 0/3000 | 0 | 0 | PASS |
| B1 mixed/meta | 200.000 | 1/5/8 | 0/75000 | 0 | 0 | PASS |
| B1 mixed/fapi | 30.000 | 29/109/128 | 0/11250 | 0 | 0 | FAIL |
| B1 mixed/refresh | 600.000 | 5/12/25 | 0/225000 | 0 | 0 | PASS |
| A2 mixed/argon2 | 8.000 | 138/159/183 | 0/3000 | 0 | 0 | PASS |
| A2 mixed/meta | 200.000 | 1/1/1 | 0/75000 | 0 | 0 | PASS |
| A2 mixed/fapi | 30.000 | 20/31/53 | 0/11250 | 0 | 0 | PASS |
| A2 mixed/refresh | 599.437 | 4/8/21 | 211/225000 | 0 | 0 | PASS |
| B2 mixed/argon2 | 8.000 | 133/144/158 | 0/3000 | 0 | 0 | PASS |
| B2 mixed/meta | 200.000 | 0/1/1 | 0/75000 | 0 | 0 | PASS |
| B2 mixed/fapi | 30.000 | 19/29/42 | 0/11250 | 0 | 0 | PASS |
| B2 mixed/refresh | 600.000 | 4/8/17 | 0/225000 | 0 | 0 | PASS |

所有点的完整 success/error/drop/outcome 计数见 short-result.json。主链路意外错误：MIX300=0, REV360=0。预期拒绝没有被计为成功。历史 e824 撤销 960/s、12/20/33ms、drop 0 只作为已有参考；未伪造本轮撤销 A。

## 时间序列、积压与自然回收

### MIX300

预先定义 cohort 为负载启动后第 120 秒及此前创建的所有 decision；持续运行原负载，未缩短 deadline。记录最大实际保留截止：2026-10-10T01:02:22.941265+00:00；截止后首次采样为零：2026-10-10T01:02:43.103469+00:00；负载返回：2026-10-10T01:05:38.612477+00:00。最终 cohort=0，完整截止后自然周期=True。跟随最终应用 container ID 的日志见 followed-instance.json 和 maintenance.log。

最终 pending=0；eligible decision=6470；合法 retained decision=5626；eligible family=0；orphan contract=0；eligible spent=0；仍合法保留 family/spent=10240/13851。issuance 终态：`{"total": 87078, "eligible": 6348, "retained": 80730, "oldest_due_s": 22.795493, "oldest_created_retention_remaining_s": -22.795493}`。后续批次的合法保留或等待下一周期，不能误报成目标批次未回收。

30 秒桶保留原秒级 histogram，以下 P99 是区间而非伪造精确分位数：

| 起点 s | 完成数 | P95 区间 ms | P99 区间 ms | 最大值 ms |
| ---: | ---: | --- | --- | ---: |
| 0 | 47230 | [10, 20] | [20, 50] | 71.0 |
| 30 | 48002 | [10, 20] | [10, 20] | 86.0 |
| 60 | 47998 | [10, 20] | [10, 20] | 61.0 |
| 90 | 48000 | [10, 20] | [10, 20] | 40.0 |
| 120 | 48000 | [10, 20] | [10, 20] | 109.0 |
| 150 | 48000 | [10, 20] | [10, 20] | 87.0 |
| 180 | 47998 | [10, 20] | [10, 20] | 69.0 |
| 210 | 48001 | [10, 20] | [20, 50] | 83.0 |
| 240 | 47999 | [10, 20] | [10, 20] | 60.0 |
| 270 | 48001 | [10, 20] | [10, 20] | 46.0 |
| 300 | 771 | [10, 20] | [10, 20] | 25.0 |

采样 pending 峰值 80，最老 pending 峰值 0.024674s；decision 到期待回收年龄峰值 57.668s。完整周期日志、live/eligible/dead tuples、角色分离采样均保留。观察错误分类：`{"during_observation": [], "after_natural_final": [{"ts": 1791594383.0142152, "error": "task command failed rc=2: psql: error: connection to server on socket \"/var/run/postgresql/.s.PGSQL.5432\" failed: FATAL:  the database system is shutting down\n"}, {"ts": 1791594392.9810865, "error": "task command failed rc=1: Error response from daemon: No such container: pr238-closure-confirm-b2-20261010-postgres-1\n"}]}`。
### REV360

预先定义 cohort 为负载启动后第 120 秒及此前创建的所有 decision；持续运行原负载，未缩短 deadline。记录最大实际保留截止：2026-10-10T00:45:39.37552+00:00；截止后首次采样为零：2026-10-10T00:45:59.441589+00:00；负载返回：2026-10-10T00:48:37.188974+00:00。最终 cohort=0，完整截止后自然周期=True。跟随最终应用 container ID 的日志见 followed-instance.json 和 maintenance.log。

最终 pending=0；eligible decision=9199；合法 retained decision=41371；eligible family=0；orphan contract=0；eligible spent=0；仍合法保留 family/spent=992/0。issuance 终态：`{"total": 307777, "eligible": 7237, "retained": 300540, "oldest_due_s": 7.947791, "oldest_created_retention_remaining_s": -7.947791}`。后续批次的合法保留或等待下一周期，不能误报成目标批次未回收。

30 秒桶保留原秒级 histogram，以下 P99 是区间而非伪造精确分位数：

| 起点 s | 完成数 | P95 区间 ms | P99 区间 ms | 最大值 ms |
| ---: | ---: | --- | --- | ---: |
| 0 | 28725 | [20, 50] | [100, 200] | 163.0 |
| 30 | 28809 | [50, 100] | [100, 200] | 141.0 |
| 60 | 28818 | [50, 100] | [50, 100] | 166.0 |
| 90 | 28797 | [20, 50] | [20, 50] | 134.0 |
| 120 | 28777 | [20, 50] | [20, 50] | 80.0 |
| 150 | 28825 | [20, 50] | [20, 50] | 65.0 |
| 180 | 28800 | [10, 20] | [20, 50] | 94.0 |
| 210 | 28800 | [20, 50] | [20, 50] | 93.0 |
| 240 | 28713 | [20, 50] | [20, 50] | 166.0 |
| 270 | 28882 | [20, 50] | [20, 50] | 127.0 |
| 300 | 28802 | [20, 50] | [20, 50] | 76.0 |
| 330 | 28800 | [20, 50] | [50, 100] | 139.0 |
| 360 | 52 | [10, 20] | [20, 50] | 20.0 |

采样 pending 峰值 22939，最老 pending 峰值 7.956630s；decision 到期待回收年龄峰值 58.835s。完整周期日志、live/eligible/dead tuples、角色分离采样均保留。观察错误分类：`{"during_observation": [], "after_natural_final": [{"ts": 1791593369.9144342, "error": "task command failed rc=2: psql: error: connection to server on socket \"/var/run/postgresql/.s.PGSQL.5432\" failed: FATAL:  the database system is shutting down\n"}, {"ts": 1791593379.402725, "error": "task command failed rc=1: Error response from daemon: No such container: pr238-closure-final-rev360-20261010-postgres-1\n"}]}`。

这些窗口用于判断是否出现随负载时间累积的恶化；不把累计 P99 单点或更低吞吐下的更低 P99 当作改善。末尾不足 30 秒的桶不单独用于趋势结论。最终结论同时核对吞吐、drop、未完成量和积压，不把短测外推为无限期稳态。

本轮 A 的旧“停压后整批”观察仍缺最后一个周期，原样保留为该项 INVALID。B 在开测前定义可在十分钟预算内完整观察的早期批次，且继续原负载；证明的是该批次的自然回收，不谎称末尾全部记录已经过期。

## CPU、WAL 与物理占用

| 点 | 应用/PG 平均核数 | WAL B/主链路成功操作 | DB 初值/峰值/观察终值 MiB | Valkey 峰值 MiB |
| --- | --- | ---: | --- | ---: |
| A1 mixed | 3.26/3.72 | 4476.568 | 11.94/261.84/216.20 | 48.39 |
| B1 mixed | 3.4/3.9 | 4483.448 | 11.93/292.33/275.77 | 48.43 |
| B revoke | 2.54/4.37 | 10840.702 | 11.93/629.10/598.70 | 82.19 |
| A2 mixed | 3.3/3.76 | 4472.032 | 11.95/263.48/248.18 | 48.35 |
| B2 mixed | 3.14/3.65 | 4490.672 | 11.95/268.40/252.76 | 48.39 |

停压后终态表统计如下。dead tuple 是 PG 统计估计，不是未处理请求；表/索引页可以被后续写入复用。

| 点/表 | heap MiB | index MiB | dead tuple 估计 | autovacuum 次数 |
| --- | ---: | ---: | ---: | ---: |
| MIX300/access_token_revocations | 0.00 | 0.02 | 0 | 0 |
| MIX300/security_audit_events | 45.77 | 36.95 | 13505 | 7 |
| MIX300/oauth_token_issuances | 38.64 | 26.80 | 20946 | 5 |
| MIX300/security_audit_chain_entries | 0.02 | 27.15 | 0 | 7 |
| MIX300/oauth_refresh_contracts | 1.43 | 0.60 | 542 | 6 |
| MIX300/oauth_refresh_families | 8.58 | 27.23 | 1860 | 7 |
| MIX300/oauth_refresh_spent_tokens | 9.64 | 13.98 | 1337 | 7 |
| REV360/access_token_revocations | 0.00 | 0.02 | 0 | 0 |
| REV360/security_audit_events | 159.66 | 109.59 | 40192 | 7 |
| REV360/oauth_token_issuances | 134.30 | 94.45 | 40192 | 6 |
| REV360/security_audit_chain_entries | 0.02 | 25.47 | 0 | 7 |
| REV360/oauth_refresh_contracts | 1.86 | 0.63 | 992 | 6 |
| REV360/oauth_refresh_families | 10.20 | 42.31 | 16145 | 7 |
| REV360/oauth_refresh_spent_tokens | 0.01 | 0.02 | 0 | 0 |

MIX300 最晚 Valkey 采样 offset=421.5s：keys={"oauth:client_assertion": 19460, "oauth:dpop": 44218, "oauth:jar": 52074, "oauth:rate": 6, "oauth:session": 4113, "tenant-directory:snapshot": 1}，used_memory=44141416B，expired_keys=80064。原始 TTL 分桶保留在 valkey-series.jsonl。

REV360 最晚 Valkey 采样 offset=423.9s：keys={"oauth:jar": 190007, "oauth:rate": 2, "oauth:session": 993, "tenant-directory:snapshot": 1}，used_memory=72687984B，expired_keys=170006。原始 TTL 分桶保留在 valkey-series.jsonl。

WAL 的 mixed 分母是主链路成功数，分子包含侧车；不是每条业务链路隔离成本。CPU 核数不是每操作成本。DB 物理高水位与活数据不同；Valkey census 和 TTL 分桶区分仍合法的 replay/session 与到期回收。短期键占用随接收窗口增长是必要 live state，已经消费且没有后续消费者的 payload/字段则已移除。没有为了使图表归零缩短安全期限。

新记录布局对照保持真实列顺序、已删除列槽位、默认值、类型和索引，使用事务内临时表各 10,000 行。它测量新行表示成本，不声称 DROP COLUMN 立即缩小已有堆文件。

| 表 | 平均 tuple B 前→后 | heap+index B 前→后 | 减少 |
| --- | --- | --- | ---: |
| access_token_revocations | 160.00→144.00 | 3710976→3186688 | 14.13% |
| admin_provision_receipts | 120.00→112.00 | 2482176→2392064 | 3.63% |
| controller_recovery_root_key_history | 88.00→76.00 | 2007040→1925120 | 4.08% |

本轮容量点撤销的是 refresh token，所采样 access_token_revocations 为 0 行。因此 14.13% 是独立的 10,000 行 AT 撤销布局实验结果，不能包装成 mixed 或 RT 撤销链路的整体降幅。B2 的 WAL 4490.672 B/成功操作相比 A2 的 4472.032 约高 0.42%，DB 物理峰值 268.40 相比 263.48 MiB 约高 1.87%，Valkey 峰值基本相同；不声称所有成本都下降。具体删除冗余的收益以同形布局实验为证据，整点物理差值还包含随机操作分布、维护/vacuum 时点和测量窗口差异。此前 MFA 布局减少的证据仍在原报告，本报告不重复声明为本次新增收益。58 表生命周期和 1,716 模型的责任/字段账本见 MODEL-REVIEW.md；当前审查范围内没有遗留的已知可删除事实或无主回收项。

## 实际质量命令与退出码

命令均在授权 CNB 的同一 checkout、同一 target 容器执行。真实 PG/Valkey/S3 夹具已配置；敏感配置不发布。

| 命令 | 退出码 | 秒 | tests passed/failed/ignored |
| --- | ---: | ---: | --- |
| `cargo test --locked --all-features -p nazo-postgres --test audit_ledger -- --nocapture` | 0 | 221.46 | 20/0/0 |
| `cargo clippy --workspace --all-targets --all-features --locked --keep-going -- -D warnings` | 0 | 36.51 | 0/0/0 |
| `cargo test --locked --all-features -p nazo-postgres --test controller_registry --test controller_recovery -- --nocapture` | 0 | 21.16 | 25/0/0 |
| `python3 scripts/check_crypto_boundary.py` | 0 | 0.79 | 0/0/0 |
| `cargo test --locked --all-features -p nazoauth --lib par_fapi2_rejects_shared_secret_client_auth_after_authentication -- --ignored --nocapture` | 0 | 0.69 | 1/0/0 |
| `cargo fmt --check` | 0 | 2.32 | 0/0/0 |
| `cargo fmt` | 0 | 2.35 | 0/0/0 |
| `cargo test --locked --all-features -p nazoauth --lib adapters::audit -- --nocapture` | 0 | 68.11 | 99/0/0 |
| `cargo test --locked --all-features -p nazo-postgres --test migrations pending_migrations_create_all_runtime_module_state_tables` | 0 | 28.73 | 1/0/0 |
| `cargo test --locked --all-features -p nazo-oauth-server --lib security::mtls -- --nocapture` | 0 | 9.76 | 19/0/0 |
| `python3 scripts/check_persistence_dependency_graph.py` | 0 | 2.23 | 0/0/0 |
| `cargo build --release --locked -p nazoauth --bin nazoauth` | 0 | 122.23 | 0/0/0 |
| `cargo test --locked --all-features -p nazo-postgres --test access_token_retention -- --nocapture` | 0 | 2.89 | 6/0/0 |
| `cargo test --locked --all-features -p nazo-postgres --lib repositories::access_token_revocation -- --nocapture` | 0 | 17.19 | 7/0/0 |
| `cargo test --locked --all-features -p nazo-postgres --test schema_cleanup -- --nocapture` | 0 | 1.38 | 8/0/0 |
| `python3 scripts/verify_static_contracts.py --check` | 0 | 5.14 | 0/0/0 |
| `cargo test --workspace --all-features --locked --no-fail-fast -- --nocapture` | 0 | 938.46 | 3717/0/4 |

真实 PG 提交边界、取消、断连后独立连接检查以及替换连接测试的名称和结果保留在 quality/workspace.log。迁移 round-trip 与状态保留测试实际执行，未将缺夹具提前返回或编译失败当作通过。取消可能发生在提交之后，因此只验证没有提前确认成功和旧连接被回收，不把取消强行断言成回滚。必要断言保留，没有删除失败测试。完整 suite 保留 4 个原有 ignored 标记；其中需要真实 PG/Valkey 的 FAPI PAR 用例另行以 --ignored 显式执行并计入独立命令。其他标记分别是由父测试调用的 TLS 子进程、下载当前官方 UI 的联网测试、独立控制器 wire 输入测试，不伪装为本命令通过。

## 负载命令、审计对账与交付

- A1 `setup`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/MIX300 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/point-observer-cycle.py setup`；退出 0，3.623s。
- A1 `MIX300`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/MIX300 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/point-observer-cycle.py MIX300`；退出 0，579.319s。
- B1/REV `setup`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/candidate-load/MIX300 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/candidate-load/point-observer-cycle.py setup`；退出 0，3.800s。
- B1/REV `MIX300`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/candidate-load/MIX300 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/candidate-load/point-observer-cycle.py MIX300`；退出 2，518.407s。
- B1/REV `setup`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/candidate-load/REV360 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/candidate-load/point-observer-cycle.py setup`；退出 0，3.413s。
- B1/REV `REV360`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/candidate-load/REV360 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/candidate-load/point-observer-cycle.py REV360`；退出 0，493.972s。
- A2 `setup`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/control-A2/MIX300 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/control-A2/point-observer-cycle.py setup`；退出 0，3.571s。
- A2 `MIX300`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/control-A2/MIX300 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/control-A2/point-observer-cycle.py MIX300`；退出 0，511.478s。
- B2 `setup`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/confirm-B2/MIX300 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/confirm-B2/point-observer-cycle.py setup`；退出 0，1.432s。
- B2 `MIX300`：`docker exec -e SIS_WORKSPACE=/src -e SIS_CNB_EVIDENCE=/src/evidence/pr238-closure-20261010/confirm-B2/MIX300 -w /src nazoauth-reverify-controller-20261009 python /src/evidence/pr238-closure-20261010/confirm-B2/point-observer-cycle.py MIX300`；退出 0，491.711s。
- A1 mixed：866348 events，DB head/anchor 与 receiver sequence/hash、deployment、签名 checkpoint 对账 PASS；journal gaps=0、duplicate sequences=0；原始 journal hash 见 short-result.json。
- B1 mixed：866456 events，DB head/anchor 与 receiver sequence/hash、deployment、签名 checkpoint 对账 PASS；journal gaps=0、duplicate sequences=0；原始 journal hash 见 short-result.json。
- B revoke：1080003 events，DB head/anchor 与 receiver sequence/hash、deployment、签名 checkpoint 对账 PASS；journal gaps=0、duplicate sequences=0；原始 journal hash 见 short-result.json。
- A2 mixed：864497 events，DB head/anchor 与 receiver sequence/hash、deployment、签名 checkpoint 对账 PASS；journal gaps=0、duplicate sequences=0；原始 journal hash 见 short-result.json。
- B2 mixed：865641 events，DB head/anchor 与 receiver sequence/hash、deployment、签名 checkpoint 对账 PASS；journal gaps=0、duplicate sequences=0；原始 journal hash 见 short-result.json。

旧 harness 的 queue_full_zero/dropped_required_zero 等健康布尔项没有被当成新的内部队列计数仪表；本轮 HTTP 容量点使用 Disabled anchor，Required 的提交与故障语义由真实回归证明。聚合指标、原始 storage JSONL/CSV、PG 角色采样、Valkey census、maintenance 日志、请求配置和 histogram 均发布。凭据、私钥和完整逐事件 receiver journal 不提交；日志按夹具值脱敏，journal hash 与精确对账保留。脚本见 reproduction/，所有发布文件有 SHA256SUMS.json。

本轮已闭合剩余具体模型冗余和 decision 自然周期证据缺口，并完成最终原配置确认。FAPI 的 B1 失败仍是有效失败样本；FAPI-INVESTIGATION.md、fapi-diagnostic.json、confirmation-plan.json 和共享服务器面板记录说明为何进行一次 A2/B2 交错控制。不同运行窗口的差异不全部归因于代码，最终通过也不表示共享环境中从未波动。仍然适用的产品边界是原协议安全保留、旧键 namespace 的在线升级契约，以及 Optional/Disabled 在无限期导出故障下不保证磁盘有界；这些没有被新过期计数或无证据机制掩盖。本轮未合并、未部署、未 force push。最终报告提交的 GitHub CI 在工作完成并推送后另行记录，不以 CI 代替上述验收。
