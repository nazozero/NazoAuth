# 2026-07-20 自动化 OIDF 最终结果

## 摘要

本记录取代 2026-07-19 的 `1df7e6c2` 运行组，作为当前最新的生产等价
一致性证据。最终生产 revision 为
`0a747b42228962e562af012638297c56e3af5505`。OpenID4VC 官方运行使用
`0bea51247913d7f6535374ad2de7d121c9234859`；从该提交到最终 revision 仅修改
`scripts/run_oidf_conformance.py` 及其单元测试，没有协议实现变更。

操作者公网黑盒运行使用源提交
`a6b75bbac5f6d8b40c01b14cce13d3edb99c8800`，其 Git tree
`9ad1c8e715b5cfa95589310fb6aa297ac38c3544` 与合并后的 `0bea5124` 完全一致。
公开文档继续以 `https://issuer.example` 表示实际生产 issuer。

| 门禁 | 结果 |
| --- | --- |
| 操作者公网 OIDC / FAPI / FAPI-CIBA | `25 / 25` plan 完成，退出码 `0` |
| 操作者公网 OpenID4VC Final / HAIP | `17 / 17` plan 完成，所有非通过结果均与精确登记一致 |
| 官方 OIDC / FAPI / FAPI-CIBA | [`29705159845`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845) `success` |
| 官方 OpenID4VC Final / HAIP | [`29700527789`](https://github.com/nazozero/NazoAuth/actions/runs/29700527789) `success` |
| 最终 PR 检查 | PR #84：`11 passed`、`0 failed` |
| 公网 Discovery | 最终部署后 HTTP `200` |

## 套件版本

操作者维护的原版套件工作树固定在
`946451d1ce29965c9ab7aee05f5003552233160e`，工作树无修改；导出模块报告
suite version `5.2.0`。官方 workflow 固定在
`dee9a25160e789f0f80517674693ef7989ab9fa1`。两者都使用上游断言，不修改
协议测试源码或通过条件。

## 操作者公网 OIDC / FAPI / FAPI-CIBA

执行时间范围为 `2026-07-19T18:51:57Z` 至 `2026-07-19T19:15:27Z`。

| 指标 | 值 |
| --- | ---: |
| Plan archives / plan IDs | `25 / 25` |
| 模块实例 | `787` |
| `PASSED` | `769` |
| 有界 `REVIEW` | `9` |
| 预期 `SKIPPED` | `8` |
| 精确登记的 `WARNING` | `1` |
| `SUCCESS` conditions | `57,013` |
| `FAILURE` conditions | `0` |
| `WARNING` conditions | `1` |

唯一 warning 是 `oidcc-3rd_party-init-login` 的
`UnregisterDynamicallyRegisteredClient`。RFC 7592 允许读取客户端时轮换 registration
access token；该上游模块在尽力清理时没有采用轮换后的 token。产品的运行级 cleanup
会独立停用该客户端，因此它按 configuration、variant、module 和 condition 精确登记，
不能放宽为通配 warning。

Plan IDs：

```text
0VBaoLcjdljI1 3LjN5Zv35t5na 4S9mdwDHWaW8J 9E2DRM0zP5i4O 9RHzwF98I0NRi
BFIyCz1dNhmGq O9tjhWWY1DTXw RcmHDC3dhpuTQ WPBThJvTR71ac WpgsS8LIVgD4U
XNaM8OaI69bIx ZJlvF4WueIYH2 ZVueIMnS64m8M ZcKFUpDHmktBI b4v9c8betyYQP
bHhRnodzPBXi6 gV0CwYNtbYBYU kinHfkVmKHPjS n94lHtAX42Duh oPgTG25FdVf6y
sLVib9Ll4ALoN tgseyORV7HmO6 vnQBWCP6cUU2x wnkPco7geO2lt zMcoevPTpxdt2
```

脱敏 evidence manifest SHA-256：
`b563075afff6c981ca5bb7f0e7942d80f8522a809eb7f76a75f3d80ff5362b14`。

## 操作者公网 OpenID4VC Final / HAIP

执行时间范围为 `2026-07-19T18:42:34Z` 至 `2026-07-19T18:50:28Z`。

| 指标 | 值 |
| --- | ---: |
| Plan archives / plan IDs | `17 / 17` |
| 模块实例 | `391` |
| `PASSED` | `382` |
| 精确预登记的 `FAILED` | `2` |
| 预期 `SKIPPED` | `7` |
| `SUCCESS` conditions | `39,792` |
| 精确预登记的 `FAILURE` conditions | `2` |
| 有界 `WARNING` conditions | `4` |

两个 `FAILED` 都是
`oid4vci-1_0-issuer-happy-flow-multiple-clients` 的 issuer-initiated
pre-authorized-code 变体，分别覆盖 `mdoc` 和 `sd_jwt_vc`。上游模块让第二个客户端
再次兑换同一个 pre-authorized code，而 OpenID4VCI 1.0 Final 第 4.1.1 节要求该 code
一次性使用。实现保持规范要求；例外精确绑定这两个 variant，不适用于其他模块。

Plan IDs：

```text
8L9yFwEaEJoOL 8dbkHQITlLas9 MsFyeilZbXvju O8sq0teuI3AKt OLfJGeGp0wd4T
QHmgRZanz00Pc QitMgPJe9x2CU TLbjTMdIUjLFN bBs47fevUm9BW d0Chz3Af3eQLE
hPXaLs8sCpVij jNn82eNaqaSEA mwvNvZXu1Ztp0 npeY755k4EDvp oFPlC6rX06wnr
xKVCHbrBKYJSO zKcE2UkP2CElp
```

脱敏 evidence manifest SHA-256：
`35298a395edb0b32a87b134a402d50e84a8f0945ef9fea30b33923ac04314e91`。

## 官方运行

### OIDC / FAPI / FAPI-CIBA

| 项目 | 值 |
| --- | --- |
| Workflow | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845) |
| Head SHA | `0a747b42228962e562af012638297c56e3af5505` |
| 主矩阵 job | [`oidf-conformance-full`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845/job/88240803466) `success` |
| Front-Channel job | [`frontchannel`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845/job/88240803484) `success` |
| Session Management job | [`session-management`](https://github.com/nazozero/NazoAuth/actions/runs/29705159845/job/88240803467) `success` |
| 运行时间 | `2026-07-19T21:53:23Z` 至 `2026-07-19T22:41:05Z` |

该次 workflow 尚未启用安全 manifest 上传，因此没有 Actions artifact。结果证据由
workflow/job 终态、固定 suite revision、精确 expected-result 契约和同版本操作者公网
manifest 共同构成；不能虚构不存在的官方导出统计。

### OpenID4VC Final / HAIP

| 项目 | 值 |
| --- | --- |
| Workflow | [`openid4vc-conformance`](https://github.com/nazozero/NazoAuth/actions/runs/29700527789) |
| Head SHA | `0bea51247913d7f6535374ad2de7d121c9234859` |
| Job | [`official-openid4vc-matrix`](https://github.com/nazozero/NazoAuth/actions/runs/29700527789/job/88228721614) `success` |
| 运行时间 | `2026-07-19T19:24:34Z` 至 `2026-07-19T19:45:01Z` |

该次旧 workflow 上传的是套件原始 ZIP，而非真正脱敏的 evidence。发现原始导出包含
浏览器配置后，artifact 已于 2026-07-20 删除，不再作为持久证据。workflow/job 终态
仍保留；模块级统计以同一协议 tree 的操作者公网 manifest 为准。

## 证据留存边界

套件原始 ZIP 会包含 `testInfo.config` 和日志正文，可能携带浏览器凭据、客户端密钥、
token 或私钥，严禁提交仓库或上传通用 artifact。本次原始 ZIP 已在成功生成 manifest
后删除。manifest 仅保留 archive 名称及原始 SHA-256、plan/module 标识、variant、终态、
签名文件存在性和 condition 结果计数；不保留配置、日志正文、操作者身份或秘密值。

后续 workflow 只能上传 `evidence-manifest.json`。GitHub artifact 仍会过期，因此本记录
持久保存实现 SHA、suite SHA、run/job URL、统计、plan ID 和 manifest digest。

