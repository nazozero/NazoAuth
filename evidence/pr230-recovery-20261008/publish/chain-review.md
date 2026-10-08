# 本轮链路复核

源码候选：`bbe4fb2d4078f859ffb690a83d7ac9a6f088d0ac`。结论须与最终门禁和真实负载结果一起阅读。

- Required worker 按 completion 路由，现有 10ms coalesce 只作用于 Telemetry。Required 进入现有 append 后等待提交确认，成功才完成 oneshot；没有增加人工等待或队列。
- 丢弃边界同时要求从未尝试 append、无 Required waiter，并由原 allowlist 明确判定为 Telemetry。未知名称默认 Required。已有 attempt latch 在调用 repository 前设置，故结果不确定仍重试完整原批次。
- 最初仅按年龄丢弃仍会把接近 10 秒的内存事件重新写入，随后立即超过 lag 门槛；真实 fault-B1 的持续请求已经复现。修复直接拒绝门禁关闭时尚未尝试的 best-effort 事件，单列 unavailable_export_unattempted_telemetry；不把它伪称过期或持久回执。
- 健康时的过期比较继续使用原 age/max_lag 秒边界；Optional/Disabled 不进入 Required 健康门禁，原无限导出故障下可能持续磁盘增长的语义保留。
- 四个清理 count SELECT 从读取首行改为消费完整结果；SQL、每批 256 上限、游标、原事务和所有安全 TTL 未变。一批仍使用原单一 guarded 连接；错误/取消由原连接丢弃机制处理，没有添加外层事务或恢复层。
- 清理故障测试在独立 audit_test 的新建子库注入 deferred constraint，独立 observer 先确认旧 backend 消失，才借用替换连接。cancel 分支允许原操作已提交，不断言回滚；未来 nonce 始终保留。
- 本轮 A→B 没有修改迁移、撤销、消费 fence、防重放、租户绑定、签名协议或 contract 引用锁定路径。孤儿引用竞争与既有保留期由实际 maintenance 回归及最终完整套件复验。
- 本轮修复不改变四个 Disabled anchor 场景的负载、成功定义或门槛；Required 恢复通过不能替代它们的性能结果。

证据边界：真实 HTTP 故障点验证 exporter 故障、恢复和签名确认链；真实 PG 集成测试验证晚期提交错误、取消、断连和确认丢失。二者不是同一故障注入。共享 CPU 和短窗口不证明长期满目标稳定。
