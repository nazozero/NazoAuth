# 2026-07-19 公网黑盒 OIDF 全矩阵结果

## 摘要

本记录对应生产协议版本
`1df7e6c2947833ae4faad15d1699526efa8bb8ec`。操作者运行的公网套件与
OpenID Foundation 公网套件测试的都是外部客户端实际访问的服务表面。公开仓库
统一用 `https://issuer.example` 作为脱敏占位符；运行者必须提供自己的 issuer 和
suite origin。

| 门禁 | 结果 |
| --- | --- |
| 生产部署 revision | `1df7e6c2947833ae4faad15d1699526efa8bb8ec` |
| 公网生产健康检查 | `success` |
| 操作者公网黑盒 OIDC / FAPI / FAPI-CIBA 矩阵 | `25 / 25` |
| 操作者公网黑盒 OpenID4VC 矩阵 | `17 / 17` |
| 官方 OIDC / FAPI / FAPI-CIBA workflow | `success` |
| 官方 OpenID4VC Final / HAIP workflow | `success` |
| 失败模块 / 条件 | `0` |

两条官方 workflow 共执行 42 个 plan：

- 25 个 OIDC / FAPI / FAPI-CIBA plan；
- 17 个 OpenID4VC Final / HAIP plan。

非公网 endpoint、私有 DNS、套件内部 callback、私有反向代理地址或仓库维护者的
默认 issuer 均不能作为证据。客户端接入和信任锚审批使用生产集成方可使用的同一套
公网管理流程。

## 公网黑盒前置门禁

请求官方 workflow 前，同一部署 revision 已通过操作者运行的公网套件：

| 矩阵 | 结果 | 执行边界 |
| --- | --- | --- |
| OIDC / FAPI 主矩阵 | `19 / 19` | 针对公网 issuer 的有界并发分组 |
| FAPI-CIBA | `4 / 4` | `private_key_jwt` 与 mTLS 客户端认证下的 poll、ping |
| Front-Channel Logout | `1 / 1` | 浏览器隔离 |
| Session Management | `1 / 1` | 浏览器隔离 |
| OpenID4VC Final / HAIP | `17 / 17` | 公网 issuer 与公网 wallet/verifier callback |

操作者套件固定到 OpenID Foundation Conformance Suite commit
`dee9a25160e789f0f80517674693ef7989ab9fa1`。协议实现与断言源码树没有修改。
唯一的 runner 侧适配是仓库维护的终态等待和结果导出集成；它不能修改协议断言、
结果分类或通过条件。

## 官方 OIDC / FAPI / FAPI-CIBA 矩阵

| 项目 | 值 |
| --- | --- |
| Workflow | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29672914368) |
| Head SHA | `1df7e6c2947833ae4faad15d1699526efa8bb8ec` |
| 结果 | `success` |
| 主任务 | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29672914368/job/88155023034) |
| Front-channel 任务 | [`frontchannel`](https://github.com/nazozero/NazoAuth/actions/runs/29672914368/job/88155023069) |
| Session-management 任务 | [`session-management`](https://github.com/nazozero/NazoAuth/actions/runs/29672914368/job/88155023070) |
| Plans | `25` |
| 模块实例 | `787` |
| 模块结果 | `748 PASSED`、`22 WARNING`、`9 REVIEW`、`8 SKIPPED` |
| 成功条件 | `56,988` |
| 失败条件 | `0` |
| Warning 条件 | `26` |

22 个 `WARNING` 模块只来自两个 FAPI-CIBA ping plan，其中共有 26 条官方入口
提示 `Client doesn't support TLS 1.3`。操作者运行的公网套件实际协商了 TLS 1.3，
没有出现该 warning，因此这里记录为官方入口条件，不是产品传输层例外。

9 个 `REVIEW` 是 Basic static、Basic dynamic-registration 和 Form Post plan 中
`prompt=login`、`max_age=1`、已注册 redirect URI 错误页面的受限人工检查。8 个
`SKIPPED` 是
[`oidf-full-matrix.zh-CN.md`](oidf-full-matrix.zh-CN.md#expected-skip-策略)
登记的 unsigned JWT 兼容用例。服务不声明也不接受 `alg: none`；任何新增或错配的
skip 都会导致运行失败。

Artifacts：

- `oidf-conformance-results-concurrent`
- `oidf-conformance-results-frontchannel`
- `oidf-conformance-results-session-management`
- `oidf-public-plan-configs`

## 官方 OpenID4VC Final / HAIP 矩阵

| 项目 | 值 |
| --- | --- |
| Workflow | [`openid4vc-conformance`](https://github.com/nazozero/NazoAuth/actions/runs/29672915479) |
| Head SHA | `1df7e6c2947833ae4faad15d1699526efa8bb8ec` |
| 结果 | `success` |
| Job | [`official-openid4vc-matrix`](https://github.com/nazozero/NazoAuth/actions/runs/29672915479/job/88155025116) |
| Plans | `17` |
| 模块实例 | `391` |
| 模块结果 | `384 PASSED`、`7 SKIPPED` |
| 成功条件 | `40,041` |
| 失败条件 | `0` |
| Warning 条件 | `4` |

4 条 warning 是受限的 HAIP refresh-token 提示。7 个 skip 是 OpenID4VC 矩阵契约
登记的 plan 可选路径，没有意外 skip。当前 OpenID4VC plan family 属于官方套件
回归测试，不能表述为 OpenID Foundation 已颁发的认证。

Artifact：

- `openid4vc-conformance-1df7e6c2947833ae4faad15d1699526efa8bb8ec`

## 官方结果合计

| 指标 | 值 |
| --- | ---: |
| 官方公网 workflows | `2` |
| Plan executions | `42` |
| 模块实例 | `1,178` |
| Passed 模块结果 | `1,132` |
| Warning 模块结果 | `22` |
| Review 模块结果 | `9` |
| 预期 skipped 模块结果 | `15` |
| 成功条件 | `97,029` |
| 失败条件 | `0` |
| Warning 条件 | `30` |

## 证据边界

本记录证明的是被测试生产协议 revision，不等同于 OpenID Foundation 官方认证列表。
依赖私有网络、内部 callback、数据库直接 seed、套件专用产品分支或放宽协议行为的
诊断运行，都不是生产等价证据，不能用于一致性声明。

可重复执行的接入、信任锚审批、有界并发、官方套件提交、结果分类与清理流程见
[`OIDF 公网黑盒一致性测试流程`](oidf-public-black-box-runbook.zh-CN.md)。
