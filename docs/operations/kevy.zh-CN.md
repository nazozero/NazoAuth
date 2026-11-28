# 嵌入式临时状态

可选适配器 `nazo-kevy` 使用 Kevy 7.0.0 实现原生服务器现有的临时状态端口。
每个部署仅支持一个进程，该进程的线程与租户绑定共享后端。账户、授权关系、
令牌消费、刷新轮换及审计仍由 PostgreSQL 持久化。

## 构建与配置

```sh
cargo build --release --locked -p nazo-server \
  --no-default-features --features kevy --bin nazoauth-kevy
target/release/nazoauth-kevy server
```

首次运行生成常规原生配置及所选适配器的配置。现有配置使用以下状态设置：

```yaml
KEVY_REPLAY_DIR: "runtime/kevy-replay"
KEVY_STATE_EPOCH: "019c8ca2-30a6-7000-8000-00000000e103"
```

为部署生成新的 UUIDv7 恢复 epoch，不要照抄示例。`KEVY_REPLAY_DIR` 相对于
配置文件解析，默认值为 `runtime/kevy-replay`。使用持久化本地文件系统，重启时
保留目录，并将访问权限限制为服务账户。PostgreSQL 及其他原生配置照常生效。
Valkey 专用配置属于默认的 `nazoauth` 启动器。

`valkey` 仍是默认 Cargo feature。上述嵌入式构建的生产依赖不包含 Fred 或
Valkey 适配器。Kevy 只启用 `core` 与 `persist`；listener、replication、index、
vector、tiering 均关闭。上游内部的 `kevy-resp` 提供命令元数据和 AOF 编码；
适配器直接调用原生 Rust 方法，不使用 RESP 客户端、监听器、套接字、命令分发器
或 Lua 解释器。

嵌入宿主在请求路径之外调用一次 `KevyBackend::open(path, deployment_id)`，
再通过 `server_state_bindings(backend)` 注入现有装配。打开和回放是阻塞启动操作。
按租户绑定只克隆共享句柄，不重新打开存储。

## 状态与重启

| 状态 | 所有者 | 重启行为 |
| --- | --- | --- |
| 会话、PAR、consent、授权码载荷、Device/CIBA 及 ping 工作、重新认证和 DPoP nonce、Passkey/federation 状态、邮件挑战、投递及头像阶段、限流计数 | 内存 Kevy | 丢弃；用户重新登录，重启未完成流程，计数器归零。 |
| 已接收的 DPoP、JAR、JWT assertion、client-attestation PoP、CIBA request object、SAML 和 HTTP 签名防重放标记 | 独占的持久化 Kevy | 保留到接收窗口结束，进程崩溃后仍有效。 |
| 租户目录投影 | 进程内共享快照 | 从持久化事实源重建。 |
| 授权决定、授权码消费回执、刷新家族、撤销及 Required 审计 | 原有持久化适配器 | 保持原有事务与恢复语义。 |

内存存储使用一个 shard，复合变更在同一个原生锁内原子完成。CAS 与租约转换
保留记录最初的逻辑截止时间。CIBA 到期工作通过有界有序索引获取，每个成员独立
到期，不给整个队列设置 TTL。

防重放存储启用 AOF 和 no-eviction。一个独立阻塞线程通过有界队列接收请求，
每批处理当前已排队的至多 256 项，不等待定时窗口。它按顺序检查并写入标记，
调用原生 `fsync_aof` 完成后才返回消费成功。并发请求可以共用这次持久化同步；
同键标记有效期间仍至多有一个成功者。每项请求实际处理时使用所有者时钟检查截止时间。

引擎使用 `AppendFsync::No` 关闭逐命令自动同步，由适配器负责显式批次同步；
staging ring 和 mapped AOF 均关闭。启动也会在接收请求前同步 deployment binding。
写入、同步、重写或必要的目录同步出错时，该 replay owner 会保持不可用，后续
消费及健康检查同样失败。取消等待不会回滚已入队的消费，结果不确定的写入不会
被报告为已接受证明。

流程状态通过原生 TTL 回收。防重放标记将绝对截止时间保存在值中，不设置原生
TTL；消费直接检查该时间，避免 AOF 恢复缩短证明的防重放窗口。压缩时才清理
已过期标记；存储空闲期间，它们会保留到下次压缩。

Kevy 7.0.0 的后台 AOF rewrite 只记录切换错误，不向调用者返回错误，因此
适配器关闭该后台重写，在同一个 replay 锁内清理逻辑上已过期的标记并调用原生
`rewrite_aof`：日志达到 64 MiB 时触发，之后的阈值为上次压缩大小的两倍，
且至少 64 MiB。重新打开的日志若已达到该下限，会在下一次接受证明时压缩。
原生引擎写出压缩日志期间，证明消费等待；其他流程状态操作独立进行。
启动会同步 AOF 所在目录及新建的全部祖先目录入口；每次原生重写成功后，先同步
目录，再接受触发重写的批次。普通批次只需原生文件同步。接收窗口内的标记始终保留。

证明键绑定租户、用途及带长度的标识符，刻意不包含 `KEVY_STATE_EPOCH`。
更换运维 epoch 无法使外部签名证明失效，因此不能借此遗忘已消费标记。
该配置仍用于原有 `RecoveryInvalidate` 运维命令的身份校验。
每个 replay 目录绑定唯一的 deployment identity。

## 独占与恢复

每个部署只能由一个进程提供服务。适配器在检查日志前锁定持续持有的目录句柄，
Kevy 同时保留自己的原生进程锁。即使 replay 线程失败，后端与租户句柄仍保留
该所有权。最后一个共享 worker 句柄释放时关闭队列，等待线程退出后才释放存储。
不同目录是独立的安全状态源，不能同时服务同一个部署。需要多个应用进程共享
状态时使用 Valkey。

正常重启必须先打开保留的 replay 目录，再接收请求；不恢复流程快照。不得将
replay 目录当缓存删除，也不能直接恢复旧快照。空目录仅用于新部署，或已经完成
状态丢失恢复的部署。

启动先持有目录锁，通过原生流式读取器校验 AOF，再打开引擎。损坏、截断或异常
全零尾部会使启动失败，原文件保持不变；已有隔离文件或 staging ring 同样阻止启动。
这增加一次启动时的日志读取，防止引擎自动修复在启动中断时抹掉故障证据。
保留目录以供检查。发生丢失、损坏或回滚后，保持入口关闭，
直到在已验证时钟边界下全部相关证明接收窗口结束，或使对应信任/凭据失效。
单独更换 epoch 不够。原有 refresh/access/ID token 恢复等待期不能替代外部证明
窗口；参见 [client-attestation 防重放](../protocol/client-attestation-replay.md)
及[状态丢失恢复](ha-operations.md)。

停止存储后制作离线副本可以保留当时的文件，但恢复旧副本可能丢失后来已确认的
标记，必须遵循相同恢复流程。本地同步持久化不提供复制或多实例故障切换。

## 可复现比较

构建现有 [Goose runner](../../perf/README.md)，为 Valkey 与嵌入式实例使用相同
的 PostgreSQL、签名和协议配置，通过
[bench-kevy-valkey.py](../../scripts/bench-kevy-valkey.py) 采集结果。
所有服务进程共同使用相同的服务端 CPU 集合，其中包括 PostgreSQL，以及使用时的
Valkey。Goose 与采样器使用独立 CPU 集合。Valkey 的持久化和 no-eviction 配置
须满足相同的防重放保证。

两侧显式选择相同的 `--goose-profile`：默认 `base`；`journal-wide` 使用专用线程
写入完成记录。该选项选择 runner 的完成回收与记录方式，保留本地 worker 数、
并发槽和网络设置。输出会记录这些参数，并包含生成器 CPU 和采样 PSS。

工具保留逐到达请求账本，报告成功 TPS、P95/P99/P99.9、失败和未发请求、
分组件及合计 CPU/PSS，以及环境可提供的宿主压力指标。交替运行两个后端，
每档重复测试，并重复验证实际吞吐开始无法跟随目标负载的边界。
仅一组低负载结果不能确定可持续容量。
本地 `measurement_valid` 字段检查生成器、采样和 CPU 亲和性；服务阈值与宿主
资源分配需要分别报告。缺少外部争用证据时，不能据此确认完整的 published 性能 PASS。

已认证授权加授权码兑换覆盖普通会话与一次性消费路径。评估防重放吞吐时还应
测量携带证明的协议配置，因为同步落盘与普通内存流程的成本不同。
运行记录和采用决策随被测 PR/版本保存，生成的单次运行数据不提交到源码树。
