# 失败点代码复核与修复

本复核以 `c0d2d05f` 的公开脱敏证据和生产代码为依据。原四点均 FAIL，五个旧通过点未重跑；历史数据和验收判定保持不变。报告提交的 CI 已另行核实为 11 success、2 条件 skipped，不再是交付时的 pending。

## 已确认的多余工作

| 链路 | 证据与职责 | 修复 |
| --- | --- | --- |
| 新建 refresh family 的重名检查 | 调用者只使用 `load_family(...).is_some()`，没有消费任何 member、audience 或 sender-binding 字段。授权码点该宽行查询累计 53,400 次、158,818 ms；缺少 pre 行，只能作为 since-reset 观察。 | `25e06584` 改为按 tenant + family 的窄 `EXISTS`。正常 rotation 仍读取完整权威状态；不新增索引或缓存。 |
| rotation 后的 spent-proof 裁剪 | 原查询先读最新 64 个 member ID，再对 family 做 `NOT IN` 补集判断。成熟 mixed 的该语句累计 455,324 次、85,166 ms；这不是 CPU 时间，也不是严格测量窗口差分。 | 保留相同 `spent_at DESC, member_id DESC` 顺序，直接选出第 64 条之后的 digest，再通过 tenant + digest 主键关联删除，外层同时保留 family 限定。未超额时候选为空；正常边界从 65 条删除最旧的 1 条。 |

这两处分别删除不需要的返回值和补集判定，不创造计数器、缓存、额外表或写放大。`EXISTS` 本身不保证特定执行计划，`DELETE USING` 的实际访问路径仍由 PostgreSQL 选择；需要用新版本真实计划和压测核对收益。

## 不变量复核

- grant-scope → family advisory lock 顺序、调用者拥有的事务和 tenant 谓词不变。
- 任意同租户同 family UUID，包括已撤销/compromise 的 family，仍构成碰撞。原 member 不被替换，原 compromise 事实不被重置，失败请求写 Required reuse audit。
- 家族上限、确定性退休顺序及退休审计未改变。family 的级联 spent-proof 删除已有 `(tenant_id, token_family_id)` 索引，没有依据增加重复索引。
- rotation 的当前 member、合同、sender binding 与 lost-response 边检查不变；仍插入必要的 predecessor proof、保留最新 64 条，并在同一事务更新 current member。裁剪按证明自身主键定位，不删除其余 tenant/family 的证明。
- 不改变 SingleUse 收据、Fresh 零 ownership 行、审计耐久性、密码成本、准入、连接池或任何性能门槛。

## 最小回归与证据边界

新增 `auth_repositories::new_family_collision_is_tenant_scoped_and_preserves_compromise_audit`，通过真实仓库覆盖同 UUID 跨租户创建、活跃及已 compromise family 的重复碰撞、原 member 保留、败者无 token、Required audit 和另一租户不受影响。

增强既有 `refresh_family_capacity::spent_proofs_stay_bounded_under_sustained_rotation`，复用原 72 次轮换，在初始/64/65/末次边界断言计数，并逐个检查最旧证明确已消失、最新 64 个 spent presentation 仍可解析、current member 仍有效。原测试只有总数与 current lookup，注释声称的旧证明消失此前没有实际断言。更新 query-count 测试的过时注释，语句数量断言不变。

本地静态契约、diff 和性能结果目录检查通过。本工作区没有 Cargo、rustfmt、PostgreSQL 或 Docker；依赖图检查因缺 Cargo 无法执行，未声称完成本地 Rust/数据库验证。提交后的 CI 结果单独回复到 PR，不能借用旧提交的成功状态。

仍未解决或未证实的部分：

1. 实际应用连接的 generic/custom 缓存计划，尤其冷启动及统计信息更新前后；独立观察者的计划不能代替它。
2. family 退休 DELETE 的执行成本与级联/触发器成本分解。已确认有索引，不据累计耗时盲改事务。
3. mixed 中 WAL 提交等待、SQL 工作、单核密码计算竞争及生成器停顿各自贡献。当前证据不能给出唯一根因。

修复后应先跑上述两项仓库回归和既有 rotation/重放/家族上限测试，再在同一部署、同一冻结配置下复测受影响的四点。只更换应用源码和对应身份；保留原预热、四种 sidecar、用户/会话人口、VU、池和门槛。记录新 `EXISTS`/裁剪语句的完整 PGSS 身份及有效前后计数，并核对实际计划、pool wait、逐秒 drop、审计和 WAL。即使某点通过，也不能在没有配对证据时计算跨容器提升比例。

本文件记录代码修复与后续验证范围，不将原 FAIL 改为 PASS，不构成性能问题全部解决或最大容量证明。
