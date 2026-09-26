# 性能测量口径

本契约适用于当前容量工具；历史报告保留原始结果与当时口径，不追溯改写 PASS。

## 成功吞吐

`capacity_search.py` 和 `pool_size_ab.py` 使用 `successful-ops-v1`：容量验收的吞吐分子是测量窗口内成功完成的逻辑操作，阈值仍为目标的 99.5%。`cap_mixed` 与其他 `capRun` 场景使用同一规则。`expected_rejection` 是协议正确拒绝，`local_no_request` 没有发出请求；两者保留为诊断量，均不计成功吞吐。

`measured_ops_s` / `attempted_ops_per_s` 表示完成迭代速率，不能当作成功操作速率，也不等于 HTTP req/s。Pool A/B 的 `attainment` 使用成功操作速率除以目标速率。所有容量 gate 仍检查同一测量 cohort 的 dropped iterations、完整迭代 P95/P99 和异常。

测量窗口由所有 VU 共用的 scenario clock 定义，按迭代进入时间归属 cohort，graceful-stop 期间完成的迭代仍属于原 cohort。正式运行必须提供完整 stream 证据；成功、拒绝、无请求、异常和准备失败的 stream outcome 与 named counter 必须逐项一致。缺失、未知标签或冲突不能静默变为零。

## 准备阶段失败

实际 producer 使用 `unexpected`，消费者不得改称 `unexpected_error`。准备阶段可包括本地向量/签名处理，也可包括真实登录、PAR、授权、签发请求，因此不能将所有准备失败归因为注入器故障。

| Outcome | 证据 | Gate |
| --- | --- | --- |
| `unexpected` | 操作出现非预期失败 | FAIL |
| `prepare_sut_failed` | 明确的准备 HTTP 失败状态或缺少应返回的令牌 | FAIL，即使比例低于吞吐容差 |
| `prepare_local_failed` | 发请求前本地 fixture / 签名构造异常 | INVALID |
| `prepare_failed` | 旧未分类失败，或不能归因的 JS / 解析 / 传输异常 | INVALID |

同一 bootstrap 被 `cap_mixed` 的操作阶段调用时仍保留上述分类。HTTP 阶段发生未知异常并不自动证明 SUT 故障。成功和失败准备都计入 `cap_iter_ms`（迭代 entry → end）；`cap_measure_ms` 仅记录操作执行时间，不能替代完整迭代延迟。全部迭代都在准备阶段失败、没有 `cap_measure_ms` 时，runner 仍输出测量摘要。

## PostgreSQL 驻留证据

Observer 为 `pg_stat_activity` 的每一行记录数据库 `clock_timestamp()` 为 `pg_ts`。Idle-in-transaction age 使用 `pg_ts - state_change`，不能使用 HTTP 采样前的主机时间；主机时钟偏差和采样先后顺序会制造负值。缺失数据库时间、缺失 `state_change`、非有限值或负 age 使样本无效，不能 clamp 为零。旧证据没有 `pg_ts` 时不能据此推断 idle age。

兼容字段 `time_weighted_share` 是按采样时观察到的 idle age 加权的分布，不是累计连接驻留时间。连接池和 PostgreSQL 状态来自非原子快照；只在数量恒等关系成立时作归因，仍需保留样本有效率。

## SQL 与连接计数

`pg_stat_statements` 包含不同角色及嵌套 SQL。累计 calls / HTTP request 是语句执行计数，不能直接解释为单请求的串行网络往返。连接池 acquire 也可能包含后台任务。串行往返应以具体成功/失败分支的源码调用顺序核对，并将工作负载、窗口、角色和命令类别写清楚。

## 回归验证

`perf/tests/test_capacity_producer.py` 使用 Node 执行真实 `measurement_clock.js`、`capRun` 和 bootstrap 分类代码，以 k6 I/O shims 注入本地错误、SUT 503、未知错误和正常操作，再交给 Python stream 消费者与容量 gate。它验证生产标签、named counter、故障归因和完整迭代延迟；不替代真实 k6 / PostgreSQL 性能运行。
