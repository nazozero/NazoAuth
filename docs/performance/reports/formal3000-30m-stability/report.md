# formal3000-30m-stability — 30 分钟 3000 ops/s 稳定性确认

- 任务: `formal3000-30m-stability`
- 分支: `perf/formal3000-30m-stability-c8b97708`
- BASE_SHA: `c8b977085861f4587b69e05322422d8a32f8b5c2`
- HARNESS_SHA: `a9e47fcdcbb11e74fa94e5e1269bef547bad44f4` → `1a8357e826ef9df20fd92ca449e951b7bb83f1c7`
- 唯一正式点: `F3000-30M`（cap_mixed, constant-arrival-rate 3000/s, scenario 1800s, warmup 15000ms, 测量窗口 1785s, preAllocatedVUs=maxVUs=2048）
- 证据包: `evidence/`（point.json / provenance.json / soak-metrics.jsonl / load 与四个 sidecar 输出 / ledger / pgss / wal / budget.json / verdict / manifest）

## 结论

```text
FORMAL_30M_3000_STABILITY = INVALID
fail_class              = LOAD_MODEL_INVALID
```

判定依据（任一条独立成立即 INVALID）：

1. **测量队列计数越过已登记边界不确定度**：`scheduled = 5,355,000`，`started = 5,355,005`，`schedule_delta = +5 > 允许上界 +3`（3000/s × 1ms）。按预登记合约，该差异不得靠扩大容差吸收 → cohort 判 INVALID。同一证据同时给出 `drop_lower_bound = 0`、`drop_upper_bound = 5`（上界 drop fraction = 1e-06），`dropped` 字段全程非负——边界不确定度以可证上界呈现，不再出现负 dropped。
2. **harness 工作区配置错误导致观测面缺失**：运行时未设 `SIS_WORKSPACE`，`sis.TOOLS`/`COMPOSE_FILE`/`RESULTS` 落回 `/workspace`（旧检出 `bb5f42c6`）。挂载进采样器的 `proc_detail_sampler.py`、`residency_observer.py` 在旧树中不存在，docker 将缺失宿主文件挂成空目录 → `sis-proc`/`sis-residency` 容器启动即退出 → `proc-detail.jsonl`/`residency.jsonl` 全缺。旧版 `soak_sampler.py`（`script_sha256=b377f7b4`，meta 行实证）不含 `audit_queue` 读取块、checkpoint 只采 `timed/requested` → audit-queue、checkpoint done/write/sync/buffers、residency 池/WAL 数据不可验证。
3. **argon2 sidecar 启动竞态**：`sis-side-argon2` 于主负载 +3.0s 启动，init 阶段读取共享 `perf_state` 卷的 `vectors.json` 时该文件尚未由主容器 bootstrap 写入 → exit 1（`cap-oidc-cold-login-refresh.k6log`：`stat /perf-state/vectors.json: no such file`）。同一竞态在 F3000R2 中曾偶然获胜。

`SUSTAINED_CLIFF` 判定器本身未能完整执行（residency 缺失使规则 B 无数据），但 k6 桶数据显示无需 cliff 也可 INVALID。

## 测量队列核算（cap-scenario-window-v1，contract 校验全过，无 divergent VU）

| 字段 | 值 |
|---|---|
| scheduled | 5,355,000 |
| started | 5,355,005 |
| completed | 5,355,005 |
| schedule_delta | **+5（超过允许上界 +3 → INVALID）** |
| boundary_overshoot | 5 |
| drop_lower_bound / dropped | 0 |
| drop_upper_bound | 5 |
| drop_fraction_upper | 1e-06 |
| measured rate | 3000.003 ops/s（目标 ≥2985） |
| logical iter p50 / p95 / p99 | 5 / 25 / 43 ms（门限 100/250） |
| unexpected | 0 |
| late_vu_fraction | 0.0 |
| whole-run begins | 5,399,955（k6 自报 scheduled_estimate 5,400,006，dropped 51，其中测量前估计 ~50、窗口后 ~1） |

### +5 边界差异的归因观察（合约待复审，不自动扩容）

- k6 constant-arrival-rate 对 1800s 场景自报调度 5,400,006 槽位，比精确有理值 5,400,000 多 **+6**；测量窗口 [15000,1800000)ms 内多出 **+5** 个 begin。10 分钟点为 +1，与本窗口 +5 同向——与 executor 侧随窗口长度放大的调度/时钟边界不确定度一致（≈每 300s +1 的量级），而非 SUT 行为。
- 预登记的 ±1ms/≈3 arrivals 上界是为**亚毫秒级窗口边缘抖动**登记的，不覆盖此类 executor 级 +6 调度盈余。按任务规约：超界即 INVALID、重新调查合约、不自动放宽。后续任务应以可证实的上界形式化 executor 调度盈余（例如把允许界定义在 k6 自报 scheduled_estimate 与有理计划的差值上），而非简单放大毫秒容差。
- `cap_iter_begin`(whole-run)=5,399,955 = 5,400,006 − 51 drops；`cap_iter_begin_measure`=5,355,005；`cap_iter_end`=5,399,955；late_vu=0；warmup 阶段另有 ~50 个 drop（初始化波），与测量队列无关。

## 每分钟桶（测量窗口 m1–m30；m30 为 45s 尾桶）

| bucket | span_s | ops | ops/s | p50 | p95 | p99 | reauth | refresh_update |
|---|---|---|---|---|---|---|---|---|
| m1 | 60 | 179981 | 2999.7 | 5 | 32 | 55 | 0 | 26705 |
| m2 | 60 | 180004 | 3000.1 | 5 | 25 | 47 | 0 | 26438 |
| m3 | 60 | 179996 | 2999.9 | 5 | 24 | 43 | 0 | 25836 |
| m4 | 60 | 180006 | 3000.1 | 5 | 27 | 66 | 8 | 25937 |
| m5 | 60 | 179994 | 2999.9 | 5 | 26 | 47 | 24 | 25514 |
| m6 | 60 | 180005 | 3000.1 | 5 | 24 | 45 | 36 | 25746 |
| m7 | 60 | 179946 | 2999.1 | 5 | 24 | 41 | 37 | 26054 |
| m8 | 60 | 180042 | 3000.7 | 5 | 25 | 49 | 16 | 25785 |
| m9 | 60 | 180008 | 3000.1 | 4 | 24 | 43 | 31 | 25905 |
| m10 | 60 | 180006 | 3000.1 | 5 | 24 | 38 | 18 | 25876 |
| m11 | 60 | 180001 | 3000.0 | 5 | 24 | 39 | 25 | 25292 |
| m12 | 60 | 179998 | 3000.0 | 4 | 23 | 32 | 31 | 25845 |
| m13 | 60 | 179998 | 3000.0 | 4 | 24 | 38 | 26 | 25287 |
| m14 | 60 | 179991 | 2999.8 | 5 | 25 | 48 | 34 | 25546 |
| m15 | 60 | 180005 | 3000.1 | 4 | 24 | 38 | 36 | 25616 |
| m16 | 60 | 179993 | 2999.9 | 4 | 23 | 37 | 27 | 25681 |
| m17 | 60 | 180008 | 3000.1 | 4 | 23 | 34 | 27 | 25681 |
| m18 | 60 | 180001 | 3000.0 | 4 | 23 | 32 | 29 | 25693 |
| m19 | 60 | 179998 | 3000.0 | 4 | 23 | 34 | 30 | 25730 |
| m20 | 60 | 179993 | 2999.9 | 5 | 24 | 38 | 26 | 25823 |
| m21 | 60 | 180009 | 3000.2 | 4 | 24 | 37 | 29 | 25897 |
| m22 | 60 | 180001 | 3000.0 | 5 | 26 | 43 | 24 | 25696 |
| m23 | 60 | 179998 | 3000.0 | 5 | 27 | 50 | 30 | 25487 |
| m24 | 60 | 180006 | 3000.1 | 5 | 25 | 39 | 19 | 25453 |
| m25 | 60 | 179996 | 2999.9 | 5 | 25 | 40 | 25 | 25339 |
| m26 | 60 | 179986 | 2999.8 | 5 | 29 | 91 | 25 | 25688 |
| m27 | 60 | 180014 | 3000.2 | 5 | 25 | 40 | 34 | 25785 |
| m28 | 60 | 179999 | 3000.0 | 5 | 24 | 34 | 39 | 25815 |
| m29 | 60 | 179995 | 2999.9 | 5 | 25 | 38 | 29 | 25636 |
| m30 | 45 | 135027 | 3000.6 | 5 | 25 | 37 | 18 | 19334 |

**p95>100ms 或 p99>250ms 的 bucket：无。** m26 p99=91ms 为全程最高，仍在门内。
pool/WAL/CPU 列因观测面缺失记为 `NOT_MEASURED`（见上），不影响本表（k6 桶数据完整）。

## 持续 cliff 判定

- 规则 A（5 连桶中 ≥4 桶 p95>100 或 p99>250）：**未触发**（0 个异常桶）。
- 规则 B（连续 5min pool waiting>500 且 checked_out≥31）：**不可判**——residency.jsonl 缺失（harness 缺口）。作为补充信号，k6 侧全程 active VU mean=24.3 / p95=40 / max=306（首个 300s 初始化波 max=2044），若池耗尽队列会推高并发驻留；稳态 12–51 区间与 10m 点一致，无逐步爬升。
- 规则 C（连续 5min 完成速率 <2850/s）：**未触发**（最弱桶 m7=2999.1 ops/s）。

`SUSTAINED_CLIFF = NO`（基于可得的 k6/队列证据；residency 缺口的不可判部分已在 INVALID 中覆盖）。

## checkpoint 专项

旧采样器只记录 `timed/requested` 计数（无 done/write_time/sync_time/buffers）：

| 事件 | 起始观测区间 (epoch s) | kind | write/sync/buffers |
|---|---|---|---|
| 1 | (1790304059, 1790304061] | timed | NOT_MEASURED |
| 2 | ~(1790304360) | timed | NOT_MEASURED |
| 3 | ~(1790304660) | timed | NOT_MEASURED |
| 4 | ~(1790304961) | timed | NOT_MEASURED |
| 5 | ~(1790305261) | timed | NOT_MEASURED |
| 6 | ~(1790305560) | timed | NOT_MEASURED |

6 次 timed checkpoint 启动、约 5min 间隔、覆盖 m4/m8/m13/m18/m23/m28 附近；**这些分钟内无任何 latency 异常桶**——10m 点 m7 的 checkpoint-window spike（p95=109/p99=395）在 30m 内**未复现**。checkpoint 写窗关联判为 `correlation only / not observed again`。

## subject 生命周期

| 指标 | 值 |
|---|---|
| initial_mint | 2,048 |
| refresh_update | 772,902（均匀分布于各分钟） |
| expired_reauth | 733（≈24.7/min 均值；单分钟峰值 39；远低于 500/min 异常线） |

无再同步 herd；refresh 均匀，符合修复后期望。

## 健康门状态

| 检查 | 结果 | 说明 |
|---|---|---|
| point_completed / unexpected_zero / oom_none / no_restarts | PASS | unexpected=0, OOM=false, restart=0 |
| queue_full_zero / dropped_required_zero / db_outbox_drained | PASS | 应用日志扫描 + DB outbox |
| audit_reconciled / journal_contiguous | PASS | receiver/DB 序列、hash、deployment 全一致；journal gap=0 dup=0；drain 完成 anchor_seq=last_seq=7,518,429, pending=0 |
| active_per_scope_le_10 / spent_per_family_le_64 / expired_backlog_zero | PASS | 10 / 64 / 0 |
| sidecars_complete | **FAIL** | argon2 exit 1（vectors.json 启动竞态）；refresh/meta/fapi exit 0 且 terminal_summary=true |
| queue_dropped_zero / pending_zero_post_drain / enqueued_eq_persisted | **FAIL（不可验证）** | 旧采样器无 audit_queue 采集 → `no audit_queue samples` |
| pool_size_observed / runtime_backends_match | **FAIL（不可验证）** | residency.jsonl 缺失 |
| capacity_gate_pass | **FAIL** | schedule_delta +5 > 3 |

## generator

| 指标 | 值 |
|---|---|
| main_exit_code | 0 |
| main_oom_killed | false |
| late_vu_fraction | 0.0 |
| active VU mean / p95 / max | 24.3 / 40 / 306（init 波 first300s_max=2044，符合 pre=max=2048 构造） |
| RSS / CPU / MemAvailable | NOT_MEASURED（proc-detail.jsonl 缺失） |
| FORMAL_REAL_LOAD_TIME | 1820.6s ≤ 1860s 硬上限（budget.json 单点） |

## PG / durability 不变量（provenance 实测）

`pg_checkpoint_timeout=5min`、`checkpoint_completion_target=0.9`、`max_wal_size=8GB`、`shared_buffers=128MB`、`fsync=on`、`synchronous_commit=on`、`full_page_writes=on`、`pg_track_io_timing=on`、PostgreSQL 18.6、`DATABASE_MAX_CONNECTIONS=32`。WAL 侧观察：`wal_bytes_per_s≈13.71MB/s`、`wal_fsyncs_delta=1,860,763`、`commits_delta=5,111,924`、`commits/fsync≈2.747`（点级合计，来自 pgss 前后快照）。WAL wait share / pool waits：NOT_MEASURED。

## 一个遗留 provenance 异常（如实记录）

应用镜像 `sisr2-nazoauth:latest`=image `2d7672` 内二进制 sha256=`046c7d40…` 经字节搜索不含 `db_pool`/`audit_queue` 字面量；但运行期 `/__perf/metrics` 对全部 879 次采样均返回了 `db_pool`（旧采样器据此成功写入 pool 行，全程无 app_err）。保留证据无法证明响应进程与所记录二进制同一；候选解释包括运行容器与镜像二进制的漂移、共享 cargo target 缓存提供的陈旧对象、或网络内其他应答者。该异常只影响 provenance 可信度声明，不改变上述 INVALID 判定（两条独立 INVALID 依据均不依赖它），已列为下次运行的显式核查项（对运行容器直接 sha256sum + 复现 endpoint 响应）。

## 对任务问题的回答

- **3000/s 能否跨多个自然 5min checkpoint 周期持续稳定？** SUT 侧可见证据：30 个分钟桶全部 ~3000 ops/s、p95≤32ms、p99≤91ms、zero unexpected、6 次 timed checkpoint 期间无异常——未见不稳；但正式判定为 INVALID（计数合约违约 + 健康门不可验证），不能登记 PASS。
- **10m m7 spike 是孤立还是演化成 cliff？** 30m 内未复现；m7（checkpoint 1 窗口）本点 p95=24/p99=41；最接近的 m26 p99=91ms 与 checkpoint 5 写窗相邻但远在门内。判定：孤立短暂现象，未演化。
- **历史 10–15min 吞吐/排队恶化是否仍存在？** m10–m15 桶全部 ≥2999.8 ops/s、p95≤25ms——未复发（k6 证据；residency 排队面不可验证）。
- **限制归因？** 无 SUT 容量限制证据；本次 INVALID 为 load-model/harness 性质（计数合约 + 观测配置 + sidecar 竞态）。

## 注册

```text
FORMAL_10M_3000_CAPACITY   = PASS
FORMAL_30M_3000_STABILITY  = INVALID
READY_FOR_MERGE            = NO    # 30m 稳定性未被本点证实；不撤销已确认生产优化
PRIMARY_LIMIT              = LOAD_MODEL
NEXT_PRODUCTION_CANDIDATE  = NONE
POOL_32                    = PASS
DATABASE_MAX_CONNECTIONS   = 32
RSA_REUSE_STATUS           = CONFIRMED_AND_PRESENT
AUDIT_BATCH_STATUS         = PASS_AND_PRESENT
TOKEN_AUDIT_PREFLIGHT_STATUS = PASS_AND_PRESENT
GROUP_COMMIT_CANDIDATE     = FAIL
COMMIT_DELAY               = 0
WAL_SYNC_METHOD_CANDIDATE  = NOT_TESTED
DURABILITY_CHANGED         = NO
PRODUCTION_CODE_CHANGED    = NO
```

后续（新任务，不属本轮）：修正 workspace 传递（SIS_WORKSPACE 指向任务 worktree）、为 sidecar vectors.json 读就绪加等待、复审计数合约对 executor 调度盈余的合法上界、验证运行容器二进制 provenance，然后按规约重跑一次 30m 点。

---

**SUPERSEDED_FOR_FORMAL_CERTIFICATION_BY = F3000-30M-R2**（`docs/performance/reports/formal3000-30m-harness-repair`）。本报告原始 verdict `INVALID` 保持不变；R2 以完整 provenance 与 stream-authoritative accounting 执行，其结果（INVALID：`stream_evidence_invalid: diag_overflow`）以自身证据独立判定，不回改本报告结论。

**EVIDENCE-CHAIN UPDATE**：`F3000-30M-R2` 旧契约下为 INVALID，经 `formal-evidence-contract-repair` 契约修正后对同证据离线重评为 PASS。本报告的 INVALID 与 supersession 记录均保持原样。
