# 2026-07-17 公网黑盒 OIDF 全矩阵结果

## 摘要

这是当前生产部署的一致性证据记录。只有针对公网
`https://auth.nazo.run` 执行的官方套件黑盒运行计入证据。

| 门禁 | 结果 |
|---|---|
| 生产部署 revision | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| 公网生产健康检查 | `success` |
| OIDC / FAPI / FAPI-CIBA 官方公网矩阵 | `success` |
| OpenID4VC Final / HAIP 官方公网矩阵 | `success` |
| 失败模块 / 失败条件 | `0` |

两条官方 workflow 共覆盖 42 个 plan：

- `oidf-conformance-full` 的 25 个 OIDC / FAPI / FAPI-CIBA plan
- `openid4vc-conformance` 的 17 个 OpenID4VC Final / HAIP alpha plan

两个 workflow 都在 GitHub Actions 中针对公网生产 origin 执行。本记录不接受
本地 Podman DNS、loopback、内网反向代理、私有测试 CA 或
`https://nginx:8443` 作为证据。

## 被测 revision 与生产边界

| 项目 | 值 |
|---|---|
| 被测 commit | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| 被测 origin | `https://auth.nazo.run` |
| 生产健康检查 | `{"status":"正常"}` |
| 生产 OCI revision | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| 本地套件 TLS 覆盖 | 不存在（未设置 `SSL_CERT_FILE`） |
| 生产容器中的本地/内网标记 | 未发现 `nginx`、`8443` 或 `oidf-local` |

测试即生产。可接受的测试目标只能是外部客户端真实使用的公网服务面。依赖内网地址、
私有 Podman DNS、本地信任 CA 或 suite-local callback origin 的本地官方套件运行，
不计入本记录证据。

## OIDC / FAPI / FAPI-CIBA 官方公网矩阵

| 项目 | 值 |
|---|---|
| Workflow | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29543012193) |
| Head SHA | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| 结果 | `success` |
| 主矩阵 job | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29543012193/job/87768979875) |
| Front-channel job | [`frontchannel`](https://github.com/nazozero/NazoAuth/actions/runs/29543012193/job/87768979854) |
| Session-management job | [`session-management`](https://github.com/nazozero/NazoAuth/actions/runs/29543012193/job/87768979855) |
| Plans | `25`（`23` 个并发 + `2` 个浏览器隔离） |
| Finished modules | `787` |
| Condition successes | `59,738` |
| Condition failures | `0` |
| 有界 warnings | `26` |
| 预期 skips | `8` |
| Review entries | `104` |

26 个 warning 全部是 FAPI-CIBA ping 回调在官方公网套件入口观察到的
`Client doesn't support TLS 1.3`。这些 warning 受仓库精确合同约束，不代表
NazoAuth 的传输或协议失败。8 个 skip 是
[`oidf-full-matrix.zh-CN.md`](oidf-full-matrix.zh-CN.md#expected-skip-策略)
记录的 `alg: none` 可选兼容实例。

Artifacts:

- `oidf-conformance-results-concurrent`
- `oidf-conformance-results-frontchannel`
- `oidf-conformance-results-session-management`
- `oidf-public-plan-configs`

## OpenID4VC Final / HAIP 官方公网矩阵

| 项目 | 值 |
|---|---|
| Workflow | [`openid4vc-conformance`](https://github.com/nazozero/NazoAuth/actions/runs/29545407427) |
| Head SHA | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| 结果 | `success` |
| Job | [`official-openid4vc-matrix`](https://github.com/nazozero/NazoAuth/actions/runs/29545407427/job/87776518188) |
| Plans | `17` |
| Finished modules | `391` |
| Condition successes | `41,781` |
| Condition failures | `0` |
| 有界 warnings | `4` |
| 预期 skips | `7` |
| Review entries | `32` |

4 个 warning 是预期的 HAIP refresh-token advisory：

> The server supports refresh tokens, but did not issue one.

这符合 HAIP 客户端的受限策略。OpenID4VC 上游 plan 族仍是 alpha regression
plan；本记录是官方套件回归证据，不是 OpenID Foundation 对 OpenID4VC 的正式认证声明。

Artifact:

- `openid4vc-conformance-ae19cc50af4cc50f3f35f678a3a1c38332d475e2`

## 合并结果

| 指标 | 值 |
|---|---:|
| 官方公网 workflows | `2` |
| Plan executions | `42` |
| Finished modules | `1,178` |
| Condition successes | `101,519` |
| Condition failures | `0` |
| 有界 warnings | `30` |
| 预期 skips | `15` |
| Review entries | `136` |

## 证据边界

本记录刻意不把 Hostinger 本地套件运行作为通过证据。本地运行可以用于调试，但本项目
的一致性声明必须基于针对 `https://auth.nazo.run` 的公网黑盒运行，并使用真实对外可达
的 issuer、redirect surface、callback path、TLS 配置和客户端可见 metadata。

如果后续某次运行需要本地 endpoint、私有 DNS、本地 CA 注入或 suite-only callback
才能通过，那次运行不是生产等价证据，不能用于声明 OIDF conformance。
