# 全新环境部署与生产启用

本文用于在既有主机上清除 NazoAuth 运行容器和旧源码目录，以全新
PostgreSQL 数据目录部署一个可审计的生产版本。它不是日常滚动发布流程；
保留现有数据时应使用 [deployment.zh-CN.md](deployment.zh-CN.md)。

## 完成条件

只有同时满足以下条件，部署才算正式启用：

1. 后端、前端均来自已推送、工作区干净的精确提交；
2. 发布镜像只有 `nazoauth` 一个应用二进制；
3. PostgreSQL 使用本次运行创建的新数据库和新卷，迁移成功；
4. 生产健康检查、发现文档、登录 UI 及其静态资源均通过；
5. 远端主机本地运行的 OIDF OIDC/FAPI 矩阵和 OpenID4VC 矩阵全部通过；
6. 运行记录包含提交、镜像 ID、新数据库名、备份路径、测试结果和时间。

任何 OIDF 失败都应先视为部署流程、配置或运行时状态不完整。只有取得可复现
证据后，才可以把失败归因于产品缺陷或外部套件问题；不得把失败计划改成跳过
或预期失败来完成验收。

## 并行与串行边界

流程使用带闸门的 DAG，而不是全串行或无约束并行。

| 阶段 | 工作 | 调度 | 原因 |
| --- | --- | --- | --- |
| A1 | 后端测试、静态检查、精确提交和镜像构建 | 与 A2、A3 并行 | 不修改远端运行状态 |
| A2 | 数据库逻辑备份、配置/密钥哈希、旧源码归档 | 与 A1、A3 并行 | 只读生产服务；输出写入独立备份目录 |
| A3 | 容量、端口、网络、反向代理和 OIDF 运行器预检 | 与 A1、A2 并行 | 只读检查 |
| 闸门 A | A1、A2、A3 全部成功 | 串行汇合 | 未有制品或恢复点时禁止停机 |
| B1 | 停止并精确删除已盘点的应用、数据库、缓存和 OIDF 容器 | 串行 | 进入维护窗口，避免旧服务继续写入 |
| B2 | 删除 `/home/nazoAuth` | 在 B1 后串行 | 避免运行器仍引用即将删除的源码 |
| B3 | 创建新 PostgreSQL/Valkey 卷和新数据库，修改配置 | 在 B2 后串行 | 数据库地址必须与新实例一致 |
| B4 | 迁移、启动候选服务、切换 UI | 在 B3 后串行 | 迁移必须先于服务接收请求 |
| C1 | 生产冒烟和外部接口检查 | 串行闸门 | 失败时不进入一致性验收 |
| C2 | OIDC/FAPI 矩阵 | 在 C1 后 | 共享浏览器、动态客户端和代理状态 |
| C3 | OpenID4VC 矩阵 | 在 C2 后 | 与 C2 串行，避免共享状态相互污染 |
| 闸门 C | C1、C2、C3 全部成功 | 串行汇合 | 通过后才记录“正式启用” |

A1 内部可以并行运行互不写同一输出目录的检查；镜像构建只能在所有生成源文件
的检查完成后开始。A2 的数据库备份和源码归档可以并行，但不得写同名临时文件。
OIDF 计划本身使用 `--plan-group-size 1`，因为这些计划会共享浏览器会话、动态
客户端及反向代理配置。

## 运行变量和精确目标

先为本次运行创建不可变标识。示例中的值必须替换成实际值：

```bash
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
backend_sha="<40-character-backend-sha>"
frontend_sha="<40-character-frontend-sha>"
new_database="oauth_fresh_${run_id}"
backup_root="/opt/nazo-oauth/backups/${run_id}"
source_root="/opt/nazo-oauth/conformance/sources/${backend_sha}"
```

删除前必须把容器清单保存到 `$backup_root/container-inventory.txt`，并逐项审核。
允许删除的名称必须来自该清单，例如：

```text
nazo-oauth-server
nazo-oauth-server-rollback-*
nazo-oauth-postgres
nazo-oauth-valkey
<本次盘点确认的 OIDF compose 项目容器>
```

禁止使用按镜像、标签模糊匹配后直接批量删除的命令，也禁止删除未在清单中确认的
共享容器、网络或卷。

## A：并行准备和恢复点

### A1：本地制品

后端和前端提交必须已推送且与上游一致。运行项目要求的 Rust、Python、静态合同
和前端聚合验证；随后使用 `scripts/deploy_live.ps1` 构建并发布精确提交。该脚本
会再次验证工作区、远端地址、分支、镜像 revision、UI 哈希和远端镜像 ID。

预合并部署必须显式传入评审分支，不能冒充 `main`：

```powershell
pwsh -NoLogo -NoProfile -NonInteractive -File .\scripts\deploy_live.ps1 `
  -RemoteHost hostinger `
  -BackendCommit <backend-sha> `
  -FrontendCommit <frontend-sha> `
  -ExpectedIssuer https://auth.nazo.run `
  -ExpectedBackendBranch <backend-branch> `
  -ExpectedFrontendBranch <frontend-branch> `
  -LocalBackendWorktree D:\self\NazoAuth `
  -LocalFrontendWorktree D:\self\NazoAuthWeb
```

在全新基础设施尚未就绪时只完成本地验证和制品准备，不执行脚本的远端事务。

### A2：远端备份

备份目录必须为 root 私有。数据库逻辑备份、运行配置、密钥清单和旧源码归档是
不同输出，可以并行：

```bash
install -d -m 0700 "$backup_root"
podman ps -a --format '{{.Names}} {{.Image}} {{.Status}}' \
  >"$backup_root/container-inventory.txt"
podman volume ls --format '{{.Name}}' >"$backup_root/volume-inventory.txt"
podman exec nazo-oauth-postgres pg_dump -U postgres -d oauth -Fc \
  >"$backup_root/oauth.dump"
cp --preserve=mode,timestamps /opt/nazo-oauth/.env.yaml \
  "$backup_root/env.yaml"
find /opt/nazo-oauth/runtime/keys -type f -print0 |
  sort -z | xargs -0 sha256sum >"$backup_root/key-sha256.txt"
test -z "$(git -C /home/nazoAuth status --porcelain)"
git -C /home/nazoAuth rev-parse HEAD >"$backup_root/source-commit.txt"
git -C /home/nazoAuth archive --format=tar.gz \
  --output="$backup_root/nazoAuth-source.tar.gz" HEAD
chmod 0600 "$backup_root"/*
```

分别以 `podman run --rm -i postgres:18 pg_restore --list <oauth.dump`、
`tar -tzf`、`sha256sum -c` 验证备份，不能假设主机已安装 `pg_restore`。
`target` 是可再生构建缓存，不进入源码归档；删除前记录其容量。备份失败时禁止
进入闸门 A。备份包含生产配置和可能的私密材料，不得复制到公开制品或 CI 日志。

### A3：只读预检

确认磁盘至少有 1 GiB 可用、`nazo_oauth_net` 为
`10.101.0.0/24`/`10.101.0.1`、Angie 上游指向 `10.101.0.20:8000`，并记录
PostgreSQL、Valkey、OIDF compose 项目的精确容器名。确认 OIDF operator suite
提交和运行器虚拟环境存在且工作区干净。

## B：维护窗口和全新数据面

### B1：删除已确认容器

先停止外部写入，再按清单逐个删除。数据库和缓存容器在应用之后删除；OIDF
容器可以与应用容器一起停止，但删除仍需使用精确名称：

```bash
podman rm -f nazo-oauth-server
podman rm -f nazo-oauth-postgres
podman rm -f nazo-oauth-valkey
podman rm -f <confirmed-oidf-container-1> <confirmed-oidf-container-2>
```

旧卷保留为恢复点，不复用于本次全新部署。

### B2：删除旧源码

```bash
test "$(realpath /home/nazoAuth)" = /home/nazoAuth
test -s "$backup_root/nazoAuth-source.tar.gz"
tar -tzf "$backup_root/nazoAuth-source.tar.gz" >/dev/null
rm -rf --one-file-system /home/nazoAuth
test ! -e /home/nazoAuth
```

OIDF 使用的精确源码通过本地 `git archive` 上传并解压到 `$source_root`；不得重新
创建 `/home/nazoAuth`。

### B3：创建全新数据库和缓存

创建带运行标识的新卷；不要挂载旧的 `nazo-oauth_postgres_data` 或
`nazo-oauth_valkey_data`：

```bash
pg_volume="nazo-oauth-postgres-${run_id}"
valkey_volume="nazo-oauth-valkey-${run_id}"
podman volume create "$pg_volume"
podman volume create "$valkey_volume"
```

从 root 私有配置中读取现有 PostgreSQL 凭据，仅把数据库路径改为
`$new_database`。不要在终端或日志中打印密码。随后创建固定地址的基础设施：

```bash
podman run -d --name nazo-oauth-postgres --restart=unless-stopped \
  --network nazo_oauth_net --ip 10.101.0.10 \
  -e POSTGRES_USER=postgres -e POSTGRES_DB="$new_database" \
  -e POSTGRES_PASSWORD="$db_password" \
  -v "$pg_volume:/var/lib/postgresql" docker.io/library/postgres:18

podman run -d --name nazo-oauth-valkey --restart=unless-stopped \
  --network nazo_oauth_net --ip 10.101.0.11 \
  -v "$valkey_volume:/data" docker.io/valkey/valkey:8-alpine \
  valkey-server --save 60 1 --loglevel warning
```

等待 `pg_isready` 和 `valkey-cli ping` 成功，并验证新实例中只有
`$new_database` 与 PostgreSQL 系统数据库。不得向新数据库恢复旧 dump。

### B4：部署和迁移

此时执行 A1 中的 `deploy_live.ps1`。脚本依次完成迁移、候选容器启动、内部健康
检查、发现文档检查、Angie 上游验证、UI 原子切换和公开静态资源验证。任一检查
失败时保留事务证据并回滚应用/UI；数据库恢复必须人工使用 A2 的恢复点，不由
脚本隐式覆盖新数据库。

## C：生产验收与 OIDF

先验证：

```bash
curl -fsS https://auth.nazo.run/health
curl -fsS https://auth.nazo.run/.well-known/openid-configuration
curl -fsS https://auth.nazo.run/ui/auth
```

然后重新创建经锁定 revision 的远端本地 OIDF compose 项目。OIDF 容器属于测试
基础设施，不加入 `nazo_oauth_net`，也不装入生产镜像。

从 `$source_root` 依次运行：

1. OIDC/FAPI 全矩阵，`--plan-group-size 1`；
2. 清理动态客户端、浏览器会话和临时代理状态；
3. OpenID4VC 全矩阵，`--plan-group-size 1`；
4. 清理 onboarding 和临时私钥。

每次运行使用唯一 `run_id`，结果写入
`/opt/nazo-oauth/conformance/results/<run_id>`。必须记录套件 revision、生产
提交、计划总数、通过数、失败数和清理状态。OIDC/FAPI 与 OpenID4VC 不并行，
但结果摘要、日志哈希和生产只读监控可以在单个矩阵结束后并行生成。

## 正式启用记录

将以下字段写入 root 私有的部署记录，并把不含秘密的摘要提交到项目文档：

```text
run_id=
backend_sha=
frontend_sha=
image_id=
database_name=
postgres_volume=
valkey_volume=
backup_root=
deployment_record=
oidf_suite_revision=
oidc_result_directory=
oidc_passed/total=
openid4vc_result_directory=
openid4vc_passed/total=
activated_at_utc=
```

在两个矩阵全绿前，状态只能是“候选已部署”，不能写“正式启用”。
