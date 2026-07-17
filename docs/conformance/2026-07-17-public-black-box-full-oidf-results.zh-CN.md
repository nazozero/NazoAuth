# 2026-07-17 公网黑盒 OIDF 全矩阵结果

## 摘要

这是当前生产部署的一致性证据记录。只有针对操作者显式提供的生产 issuer
执行的官方套件公网黑盒运行计入证据。公开仓库中的 `https://issuer.example`
只是脱敏占位符，不是默认测试目标，也不是仓库默认部署地址。

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
非公网 endpoint、私有 DNS、私有反向代理、私有测试 CA 或
suite-private endpoint 作为证据。

## 被测 revision 与生产边界

| 项目 | 值 |
|---|---|
| 被测 commit | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |
| 被测 origin | 操作者提供的生产 HTTPS origin，公开文档脱敏为 `https://issuer.example` |
| 生产健康检查 | `{"status":"正常"}` |
| 生产 OCI revision | `ae19cc50af4cc50f3f35f678a3a1c38332d475e2` |

测试即生产。可接受的测试目标只能是外部客户端真实使用的公网服务面。依赖非公网连通性、
私有信任根或 suite-private callback origin 的诊断运行，不计入本记录证据。

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

4 个 warning 是预期的 HAIP refresh-token advisory：服务端总体支持 refresh token，
但受限 HAIP 客户端策略不会在这些流程中签发 refresh token。这符合 HAIP 客户端的
受限策略。OpenID4VC 上游 plan 族仍是 alpha regression plan；本记录是官方套件回归
证据，不是 OpenID Foundation 对 OpenID4VC 的正式认证声明。

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

本记录刻意不把诊断套件运行作为通过证据。诊断运行可以用于调试，但本项目
的一致性声明必须基于针对显式配置生产 issuer 的公网黑盒运行，并使用真实对外可达
的 issuer、redirect surface、callback path、TLS 配置和客户端可见 metadata。
运行公开 workflow 的用户必须提供自己的 `OIDF_TARGET_ISSUER` 与
`OPENID4VC_TARGET_ORIGIN`；仓库不得默认把一致性流量导向任何仓库自有服务。

如果后续某次运行需要非公网 endpoint、私有信任根或 suite-only callback 才能通过，
那次运行不是生产等价证据，不能用于声明 OIDF conformance。
