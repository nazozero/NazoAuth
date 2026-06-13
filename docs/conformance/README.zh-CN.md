# Conformance 记录

## 范围

本目录保存 OpenID Foundation Conformance Suite 的长期证据索引。GitHub Actions artifact 会过期，因此仓库内记录保留 run metadata、plan ID、artifact digest 和被测试 commit SHA。

## 当前认证状态

Nazo Auth Server 已发布在 OpenID Foundation 官方认证列表中：

- [Certified OpenID Provider profiles](https://openid.net/certification/certified-openid-providers-profiles/)
- [Certified FAPI 2.0 OP Security Profile Final and Message Signing Final](https://openid.net/certification/certified-fapi-2-0-op-security-profile-final-message-signing-final/)

认证部署名为 `Nazo Auth Server 0.1.0`，日期为 `09-Jun-2026`。

## 当前证据

- [2026-06-09 OIDF full matrix](2026-06-09-oidf-full-matrix.md)
- [2026-06-13 real public UI OIDF regression](2026-06-13-real-public-ui-regression.md)

`2026-06-09` full matrix 是当前官方认证证据，针对 `https://auth.nazo.run` 执行，覆盖 OIDC Basic、OIDC Config、FAPI2 Security Profile Final、FAPI2 Message Signing Final、mTLS、DPoP、`private_key_jwt`、client credentials 变体。结果为全计划完成，`0 failures`，`0 warnings`。

`2026-06-13` 记录保存了移除 OIDF-only 前端页面后的真实公网 UI 回归结果。官方 workflow run `27468700891` 在 `main` 的 `98105ae30d8b83c3e93c17ef3ae787fbd592dad3` 上完成 full matrix，GitHub conclusion 为 `success`，artifact 为 `oidf-conformance-results-full`。后续 JSON-only 后端错误响应变更已完成本地 full matrix 回归；其官方 rerun `27470527340` 的 GitHub conclusion 为 `failure`，失败点是 runner 仍带有旧的浏览器任务名 `Capture authorization error page`，不是新的认证通过记录。

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
