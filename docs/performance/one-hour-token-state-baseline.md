# 主体状态精简：一小时短测

入口：`python perf/tools/short_baseline.py`。只测试 PR #222 当前生产源码；本任务不跑完整容量矩阵，不修改或替换已验收的 `current-capacity.json`。原历史容量只作注明版本的参考，不计算跨环境提升比例。

## 时间与范围

从执行者开始工作时计时，**准备、构建、测试、整理交付合计 60 分钟**。必须把原始开始时间传入脚本，重试不重置时钟。

- 准备目标 15 分钟：复用经身份校验的应用及 runner 镜像；缺失时利用已有缓存构建。不要重建已验证且生产输入完全相同的应用。
- 必测：单实例单逻辑 CPU / 动态多 CPU，各测 client credentials、mixed、authorization code、refresh，共 8 个点，每点正式测量 60 秒。非 mixed 预热 15 秒，mixed 预热 60 秒。
- 多核 mixed 再确认一次：正式测量 570 秒、预热 60 秒。保留原 360 秒 retention 与 120 秒到期年龄 SLO，因此有 210 秒成熟观察期；审计必须 drain、对齐 checkpoint 并验证 journal。
- mixed 保留 Argon2 冷登录、metadata/JWKS、FAPI、refresh 四种 sidecar；独立进行计数和延迟判定。它们不替代各自的完整容量搜索。
- 只在必测完成且时间足够时，单核/多核 mixed 各追加一个 +25% 负载点。没有有效失败点就只报告实测下界，不称为最大容量。
- 默认必测最坏点预算共 41 分钟，加 15 分钟准备、4 分钟停止负载与交付预留，合计一小时。准备较慢时，脚本在首点之前一次性将八个短窗口冻结为 30 秒，成熟窗口不缩短。每点超时被记为 INVALID；不足以跑完的点如实列为未完成，不缩短正在执行的正式窗口。
- 只有一个可调度 CPU 时不重复“多核”测试；执行四个单核短点及单核成熟确认，报告多核不可用。CPU ID 来自当前控制进程与 runner 自身可运行集合的交集；不探宿主拓扑或祖先配额。组件重叠时明确标记 SHARED_INFRA。

初始负载按应用可用逻辑 CPU 数动态计算，仅为探索起点，不是沿用旧硬件容量。VU、用户数、连接池和流式分析并发随实际分配变化。内存上限未知不假定无限，也不据此停在资源调查；通过组件自身占用、OOM、重启与生成器有效性诊断。有已知的本部署 CPU 配额时可用 `--cpu-budget` 提供规划上限。

## 执行

在 CNB 中使用一个普通 checkout，不创建 worktree。源码及依赖来自当前 PR 分支；所有构建、k6 负载都在 CNB 内进行。`gcc`（可静态编译 pinset）、Python 3.11+、Docker/Compose 和 Git 需要可用。控制脚本仅用 Python 标准库；runner 镜像包含现有版本的 k6 和数据解析依赖。

在任务开始时保存时钟，然后进入仓库、拉取当前分支：

```sh
TASK_STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
export TASK_STARTED_AT
# 保留这一个时间，包含下面的拉取和构建；不要在重试时重新赋值。
git fetch origin perf/db-hotpath-minimal-0c70d746
git switch perf/db-hotpath-minimal-0c70d746
git pull --ff-only origin perf/db-hotpath-minimal-0c70d746
BENCH_SHA=$(git rev-parse HEAD)
```

需要四个镜像：`nazoauth-perf-nazoauth`（`perf-runtime`）、`nazoauth-perf-perf`、`nazoauth-perf-keyset`、`nazoauth-perf-audit-receiver`。存在可验证镜像时优先复用；脚本检查应用 OCI revision、内置 source-sha、运行二进制 hash、生产构建输入无差异，以及 runner 实际运行的脚本 hash。旧标签不等于旧内容，同样新标签不证明新内容。若需构建：

```sh
# 只构建缺失/不匹配的服务；给此命令设置原始时钟剩余的准备时间上限。
docker compose -f docker-compose.perf.yml -p nazoauth-perf build \
  --build-arg SOURCE_SHA="$BENCH_SHA" nazoauth perf keyset audit-receiver
```

已有可信 runner 基础镜像时，也可只更新其 `COPY perf /perf` 层并记录新镜像 ID，复用原 k6 二进制和依赖；脚本仍会逐文件核验当前 runner 源码，不能靠修改标签绕过。

这条命令仅构建镜像，不执行共享项目的 up/down。实际测试由脚本创建独占随机项目，所有组件和 CPU 限制均由既有点生命周期管理；每点重新初始化隔离数据库，密钥卷在本次点间复用。“单核”限制的是应用进程，数据库和生成器另列 CPU 分配，不能解释为整套系统只用一个 CPU。既有 PostgreSQL 耐久性与受控 benchmark 配置保持不变。禁止为过门槛关闭 fsync、同步提交、审计、准入或协议检查。

```sh
python perf/tools/short_baseline.py \
  --started-at "$TASK_STARTED_AT" \
  --output "$PWD/perf-results/short-token-state-$(date -u +%Y%m%dT%H%M%SZ)"
```

镜像名不同时可传 `--app-image`、`--runner-image`。输出目录必须新建且不可复用；同一次任务的重试仍传原始 `TASK_STARTED_AT`。脚本只清理自身精确标签匹配的容器，不清除其他项目或 volume，原始证据留在输出目录。不要运行遗留 `env-check` 或 `run_capacity.sh` 资源收集流程。

## 判定与交付

复用 `current_capacity.evaluate_point` / `capacity_search` 的原判定：成功逻辑操作、完整操作 P50/P95/P99、HTTP req/s、错误、拒绝、drop、未完成、生成器有效性，以及全部 sidecar、连接池、维护、审计和 journal 检查。缺证据是 INVALID，不是零，也不能成为服务容量上界。

新增状态检查在停载后执行，避免把检查成本计入请求热路径：

- 新数据库中普通 Fresh 所有权行与 legacy 行均须为零。
- 纯 client credentials 的 `oauth_token_issuances` 总行数和累计插入计数也须为零。
- 其他路径保留并报告 SingleUse 收据和 subject binding 数量；不要求合法收据为零。
- WAL 生成量、写入量分别报告。每主成功操作成本包含 sidecar 和后台工作；沿用原采样窗口插值，不宣称纯主请求成本或无证据的 SQL 归因。

`summary.json` 分开记录测量完成状态和必测点验收状态；完整执行但有失败点不等于验收通过。退出码 0=完整且必测通过，1=完整但必测失败，2=证据/范围未完成。`report.md` 是简表，详细判定在 `summary.json` 和逐点 `point.json`。

交付：保留源码/镜像身份、注册参数、逐点有效窗口、流式原生证据及成熟点 journal；原始产物在容器外保存并校验 SHA-256 后才允许销毁容器。对外只提交脱敏后的报告与精简结构化结果到本 PR 分支，每次提交后回复 PR。不要提交私钥、凭据、会话夹具、原始 token 或未经审查的完整日志。提交报告不需要等待整个 Rust CI 再跑一轮才在一小时内交付：准确记录该报告提交检查状态，区分已测源码、harness 与交付提交；不得将 pending 写成 success。

等待负载时每 2–3 分钟查看一次，不高频轮询。执行模型可自行修复环境或工具问题；修复需提交 checkpoint 并标明哪些点受影响。若生产源码改变，旧点不能冒充新源码结果。任何困难都不能延长原始硬截止或削弱判定；应在截止前交付已经取得的结果和明确失败原因。
