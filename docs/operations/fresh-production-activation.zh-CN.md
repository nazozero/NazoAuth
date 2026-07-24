# 全新环境部署与生产启用

本流程用于有意替换现有 NazoAuth 数据面，并以远端主机本地 OIDF 一致性测试作为
正式启用闸门。它不是快速开始流程；普通首次部署或升级应使用
[部署指南](deployment.zh-CN.md)。

流程统一使用 Docker Compose 作为平台无关的控制入口。使用其他编排平台时，也
必须保持相同的顺序、隔离、持久化和验证边界。

## 完成条件

只有同时满足以下条件，才能记录为“生产已启用”：

1. 后端和前端制品来自干净、已审查的精确提交；
2. 应用镜像只包含一个 `nazoauth` 应用二进制；
3. PostgreSQL 和 Valkey 使用本次新建的存储；
4. 迁移、健康、发现文档和公开 UI 检查通过；
5. 申请人和管理员均完成全新公开用户旅程；
6. 远端主机本地 OIDC/FAPI 与 OpenID4VC 矩阵通过；
7. 启用记录包含制品、数据、备份和测试证据。

不得为了通过闸门而把失败改成 expected failure 或 skip。

## 并行与串行边界

| 阶段 | 工作 | 调度 |
| --- | --- | --- |
| A1 | 核对提交、测试、构建不可变制品 | 与 A2、A3 并行 |
| A2 | 数据库备份、配置/密钥清单、源码归档 | 与 A1、A3 并行 |
| A3 | 容量、网络、代理和 OIDF 预检 | 与 A1、A2 并行 |
| 闸门 A | A1、A2、A3 全部成功 | 停机前串行汇合 |
| B1 | 停写并只删除清单中的容器 | 串行 |
| B2 | 删除已验证归档的旧源码目录 | 在 B1 后 |
| B3 | 创建新存储和空数据库 | 在 B2 后 |
| B4 | 迁移、启动、切流 | 在 B3 后 |
| B5 | 创建两条隔离的全新用户旅程 | 用户之间可并行，单个用户内部有序 |
| 闸门 B | 用户、资料、管理员和冒烟检查通过 | 串行汇合 |
| C1 | OIDC/FAPI 矩阵 | 在闸门 B 后；内部按阶段调度 |
| C2 | OpenID4VC 矩阵 | 在闸门 B 后；C1 worktree 建立后可与 C1 重叠 |
| 闸门 C | 两套矩阵、证据和清理通过 | 正式启用 |

不要把全串行或无限并发作为默认方案，应使用有界 DAG：

| 通道 | 当前 8 vCPU 主机配置 | 必须满足的隔离 |
| --- | --- | --- |
| OIDC/FAPI `01`、`02`、`04`-`07` | 2 个组 worker | 每个 worker 使用独立、干净的 suite worktree；别名和导出目录互不重叠 |
| FAPI-CIBA `03a`-`03d` | 串行 | 共享申请人和 CIBA 时序状态；每组内部同时使用 `--no-parallel` |
| Logout/session `08`-`11` | 2 个组 worker | 每个 worker 使用独立 suite worktree；每组内部使用 `--no-parallel` |
| OpenID4VC | 17 个计划作为一个有界批次 | 独立 run namespace、别名、onboarding state 和基础 suite 配置 |

先启动 OIDC/FAPI。等它完成基础 suite 干净检查、创建 worker worktree，并已启动
`01` 组后，再启动 OpenID4VC。顺序反过来时，OpenID4VC 的临时配置会被 OIDC
干净预检正确拒绝。之后两套矩阵并行执行，在闸门 C 汇合。

该配置有意不采用单独运行 OIDC 时的最快档。4 个 OIDC 安全组 worker 只带来
有限墙钟收益，却使 suite CPU 和内存约翻倍，并令主机接近 CPU 上限。联合生产
闸门使用 `--safe-group-workers 2 --browser-group-workers 2`。可移植的保守回退
是两个 OIDC 通道各 1 个 worker，OpenID4VC 使用 `--plan-group-size 1`。只读
监控、日志哈希和结果汇总仍可并行。该决策的实测数据及失败启动顺序记录见
[2026-07-24 OIDF 并发调优记录](2026-07-24-oidf-concurrency-tuning.zh-CN.md)。

## A：不停机准备

### A1：构建精确制品

要求源码提交已推送、工作区干净，并运行项目质量闸门。制品只构建一次，同时记录
镜像 ID 和源码 revision：

```sh
docker compose build
docker compose images
```

如果镜像来自制品库或隔离构建机，应固定 digest 并核对其中的源码 revision。
后续阶段不得分别重复构建同一提交。

### A2：创建恢复点

创建新的受限备份目录，并行保存：

- 精确容器和卷清单；
- PostgreSQL custom-format dump；
- 运行配置和密钥文件哈希清单；
- 精确源码提交归档；
- 当前镜像 ID 和公开 UI revision。

使用匹配版本的 PostgreSQL 镜像验证 dump，检查源码归档目录，并核对全部哈希。
恢复证据未全部通过前不得停机。

### A3：预检

确认：

- 磁盘足以容纳新镜像、数据库、测试结果和回滚副本；
- 反向代理上游和公开 HTTPS issuer 已明确；
- OIDF suite revision 已固定，运行器工作区完整干净；
- 新数据库、存储和结果目录名称不会冲突；
- 回滚路径已验证且不会覆盖备份。

## B：替换数据面

1. 停止外部写入。
2. 只删除审核清单中的应用、PostgreSQL、Valkey 和 OIDF 容器；旧卷保留为恢复
   证据。
3. 再次验证源码归档，解析旧源码目录的精确路径，然后只删除该目录。
4. 创建全新的 PostgreSQL、Valkey、密钥和头像存储；启动空数据库，不恢复旧
   dump。
5. 通过 `NAZOAUTH_CONFIG` 选择新的私有配置。
6. 执行迁移并启动候选服务：

```sh
docker compose up -d
docker compose ps
```

健康与发现文档通过前，反向代理继续指向旧服务；通过后再原子切换。单节点
Compose 部署已经把候选服务发布到 loopback，不需要绑定某一种代理或宿主脚本。

## 全新用户闸门

不得复用旧数据库的用户、会话或 subject ID。

为申请人和管理员分别使用独立验证码和 Cookie jar，通过 `/auth/register` 注册。
同一用户的注册、登录、资料更新和头像上传保持顺序；身份及会话材料完全隔离时，
两名用户可以并行。

如果项目没有公开的首位管理员引导接口，只允许对本次公开注册的管理员执行一次
受控数据库角色提升。不得直接插入用户或复制旧库记录。申请人必须包含 OIDC
`profile`、`address` 和 `phone` 范围需要的完整资料。

## C：生产与 OIDF 闸门

先验证公开 HTTPS origin：

- `/health`；
- `/.well-known/openid-configuration`；
- `/ui/auth` 及其引用的至少一个静态资源。

从精确、干净的源码导出执行：

1. 使用 `--safe-group-workers 2 --browser-group-workers 2` 启动
   OIDC/FAPI；
2. 等隔离 suite worktree 建立后，使用 `--plan-group-size 17` 启动
   OpenID4VC；
3. 由 OIDC runner 串行完成四个 CIBA 组，并等待两套矩阵汇合；
4. 两套矩阵都必须通过即时检查和 45 秒稳定检查；
5. 清理动态客户端、浏览器会话、临时代理状态、onboarding state、生成的 suite
   配置、临时私钥和 suite worktree。

验证运维 runner 时，runner revision 可以暂时与已部署应用 revision 不同，但
边界必须明确：单独传入精确 runner revision，并让
`--deployed-source-dir` 指向与 `--deployed-sha` 一致的干净源码。不得把 runner
revision 写成已部署应用 revision。

OpenID4VC operator 物化必须通过 `--subject-id` 绑定本次新申请人。只有本次确实
请求至少一个 trust anchor 时，才要求 mTLS trust bundle 非空。

product source 与 OIDF suite 最终都必须满足 `git status --porcelain` 为空，
包括未跟踪文件。

## 启用记录

记录：

```text
启用状态和 UTC 时间
后端/前端提交
镜像名称、digest 和源码 revision
新数据库和存储标识
备份标识及验证状态
部署/编排版本
OIDF suite revision
OIDC/FAPI 结果目录、计数和退出码
OpenID4VC 结果目录、计数和退出码
源码、suite、onboarding 和私密材料清理状态
```

在两个矩阵和清理闸门全部通过前，状态只能是“候选已部署”，不能写“生产已启用”。
