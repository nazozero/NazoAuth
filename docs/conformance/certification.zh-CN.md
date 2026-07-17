# 认证与一致性证据

本文是认证状态和当前官方套件证据的入口。协议能力明细见
[标准与 Profile 支持](../integration/openid-connect.zh-CN.md)。

## OpenID Foundation 认证列表

OpenID Foundation 认证页面列出了 `Nazo Auth Server 0.1.0`，日期为
`09-Jun-2026`，对应认证 profile 如下：

| Profile | 证据 |
| --- | --- |
| OIDC Basic OP | [Plan 结果](https://www.certification.openid.net/plan-detail.html?plan=Srk6iaVDVcqO5) |
| OIDC Config OP | [Plan 结果](https://www.certification.openid.net/plan-detail.html?plan=fGiz8QZYR1LVy) |

官方列表页面：

- [OpenID Connect Certified providers](https://openid.net/certification/#OPs)
- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

## 当前公网黑盒证据

当前一致性证据记录在
[2026-07-17 公网黑盒 OIDF 全矩阵结果](2026-07-17-public-black-box-full-oidf-results.zh-CN.md)。
运行目标是操作者提供的生产 HTTPS issuer。公开文档中的
`https://issuer.example` 只是脱敏占位符。仓库 workflow 要求操作者提供自己的公网可达
`target_issuer` / `target_origin` workflow 输入，或在自己的仓库中配置私有自动化变量。

| 矩阵 | 结果 | 范围 |
| --- | --- | --- |
| OIDC / FAPI / FAPI-CIBA | 成功 | 25 个官方公网 plan：23 个并发 plan，加 2 个浏览器隔离 plan |
| OpenID4VC Final / HAIP | 成功 | 17 个官方套件回归 plan |

合并导出结果：

| 指标 | 值 |
| --- | ---: |
| Plan executions | 42 |
| Finished modules | 1,178 |
| Condition successes | 101,519 |
| Condition failures | 0 |
| 有界 warnings | 30 |
| 预期 skips | 15 |
| Review entries | 136 |

有界 warning 和预期 skip 记录在链接的证据文档中。它们不是隐藏项：
OIDC/FAPI/FAPI-CIBA 矩阵不是 zero-warning 或 zero-skipped 证据。

## 矩阵范围

| 领域 | 范围文档 |
| --- | --- |
| OIDC / FAPI / FAPI-CIBA | [OIDF full matrix](oidf-full-matrix.zh-CN.md) |
| OpenID4VC Final / HAIP | [OpenID4VC Final matrix](openid4vc-final-matrix.md) |
| RFC 9967 SCIM SET 本地黑盒回归 | [RFC 9967 SCIM SET black-box matrix](rfc9967-scim-set-matrix.md) |

## 证据边界

本仓库的一致性声明必须来自针对明确配置的生产 issuer 执行的公网黑盒官方套件运行。
依赖非公网 endpoint、私有 DNS、私有信任根、本地专用 callback origin 或
suite-private hostname 的运行只能作为诊断记录，不能作为生产一致性证据。

OpenID4VC 套件结果是官方套件回归证据。除非 OpenID Foundation 发布对应认证结果，
否则它不是 OpenID Foundation 认证列表。
