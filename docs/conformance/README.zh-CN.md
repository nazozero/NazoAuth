# Conformance 记录

## 范围

本目录保存 OpenID Foundation Conformance Suite 的长期证据索引。GitHub Actions artifact 会过期，因此仓库内记录保留 run metadata、plan ID、artifact digest 和被测试 commit SHA。

## 当前认证状态

Nazo Auth Server 已发布在 OpenID Foundation 官方认证列表中：

- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

认证部署名为 `Nazo Auth Server 0.1.0`，日期为 `09-Jun-2026`。

## 当前证据

- 认证基线：[2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- 最新 Hostinger 本地 full matrix：[2026-06-26 security findings OIDF full matrix](2026-06-26-security-findings-full-matrix.md)
- 最新官方 full matrix：[2026-06-27 PR 15 official OIDF full matrix](2026-06-27-pr15-official-oidf-full-matrix.md)

`2026-06-09` full matrix 是当前官方认证证据，针对 `https://auth.nazo.run` 执行，覆盖 OIDC Basic、OIDC Config、FAPI2 Security Profile Final、FAPI2 Message Signing Final、mTLS、DPoP、`private_key_jwt`、client credentials 变体。结果为全计划完成，`0 failures`，`0 warnings`。

最新记录的官方 full-matrix suite run 是 2026-06-27 PR 15 官方运行，针对 `https://auth.nazo.run` 和 runtime commit `be7ef9f6a9197520235a59d42866a0918a293014` 执行。该运行从 `https://www.certification.openid.net/` 导出全部 16 个 plan archives，最终结果为 `0 failures`、`0 warnings`。

最新 Hostinger 本地 full-matrix 回归记录对应 `oidf-local-results/run-20260626T165725Z`，测试对象同样是公网 issuer 和同一 commit。该运行导出全部 16 个 plan archives，日志包含 16 个 plan 汇总，均为 `0 failures`、`0 warnings`。

baseline OIDC metadata 会在 `request_object_signing_alg_values_supported` 中声明 `none`，用于 unsigned Request Object 的 OIDC 兼容路径。该能力不是高安全 profile 能力；FAPI2 Security Profile Final、FAPI2 Message Signing Final、要求 PAR request object 的客户端以及 holder-bound token 客户端仍然 fail closed，必须使用签名 Request Object 或被拒绝。

## 记录格式

每份记录应包含：

- implementation commit SHA
- 文档 commit SHA，如果与实现 commit 不同
- workflow 名称和 run URL
- job URL 和 matrix 名称
- 通过时间和 suite 运行时间
- profiles 和 feature combinations
- artifact 名称、digest、过期时间、zip 文件名
- plan ID 和 plan detail URL
- failure / warning 计数
- 允许的 review 状态
- public issuer 与测试环境说明

## 边界

本目录索引的是 suite 输出和工程证据。官方认证状态以 OpenID Foundation 公布页面为准。
