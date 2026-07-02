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
- 矩阵范围说明：[OIDF 完整矩阵](oidf-full-matrix.zh-CN.md)
- 最新私有 full-matrix 回归：[2026-07-01 TP/PS OIDF full matrix](2026-07-01-tp-ps-full-matrix.md)
- 最新官方 full matrix：[2026-07-02 NI-004 official OIDF full matrix](2026-07-02-ni-004-official-oidf-full-matrix.md)
- 最新 RFC 覆盖检查：[2026-07-01 NI-002 RFC 8628 OIDF coverage](2026-07-01-ni-002-oidf-coverage.md)

`2026-06-09` full matrix 是当前官方认证证据，针对 `https://auth.nazo.run` 执行，覆盖 OIDC Basic、OIDC Config、FAPI2 Security Profile Final、FAPI2 Message Signing Final、mTLS、DPoP、`private_key_jwt`、client credentials 变体。结果为全计划完成，`0 failures`，`0 warnings`。

最新记录的官方 full-matrix suite run 是 2026-07-02 NI-004 官方运行，针对 `https://auth.nazo.run` 执行，开始时间为 `2026-07-02 01:32:57 +08:00`，workflow head SHA 为 `0b00ea7d50443cb54fc17631a9238126fa837e42`。该运行完成 17-plan 矩阵，最终结果为 `0 failures`、`0 warnings`，但 dynamic-registration OIDC Basic plan 中存在 2 个 expected `SKIPPED` module；本次 workflow 日志未独立记录 runtime implementation commit，因此不能作为 zero-SKIPPED 证据。

最新私有 full-matrix 回归记录是 2026-07-01 TP/PS 运行，测试对象为 `https://auth.nazo.run`，runtime commit 为 `31e8f9f`。该运行使用仓库原有 16-plan 完整矩阵，导出 16 个 plan archives，共执行 578 个测试模块，结果为 `0 failures`、`0 warnings`。

baseline OIDC metadata 会在 `request_object_signing_alg_values_supported` 中声明 `none`，用于 unsigned Request Object 的 OIDC 兼容路径。该能力不是高安全 profile 能力；FAPI2 Security Profile Final、FAPI2 Message Signing Final、要求 PAR request object 的客户端以及 holder-bound token 客户端仍然 fail closed，必须使用签名 Request Object 或被拒绝。

## 覆盖更新规则

每新增一个 RFC、OIDC/FAPI profile 或标准协议能力支持，都必须检查 OIDF 一致性套件覆盖。检查范围包括 OpenID Foundation Conformance Suite 的官方 production/staging 计划、公开源代码和 release notes，确认是否已有对应官方测试。

如果已有官方覆盖，必须在同一变更中更新本仓库的 OIDF 矩阵执行内容，包括 workflow/config 输入、plan 列表、矩阵文档和 conformance 记录。如果暂无官方覆盖，必须在对应实现记录或 conformance 记录中写明未发现官方覆盖的检索结论和日期。无论 OIDF 是否已有覆盖，本地正向、负向、metadata truth 和安全边界测试仍然必须保留。

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
- skipped module 计数，以及是否满足 zero-SKIPPED 验收门槛
- 允许的 review 状态
- public issuer 与测试环境说明

## 边界

本目录索引的是 suite 输出和工程证据。官方认证状态以 OpenID Foundation 公布页面为准。

## 兼容性跳过项

当前 OIDC dynamic-registration 兼容矩阵中有 2 个 expected official suite
skips：服务不支持也不声明 unsigned ID Token；`request_uri` 参数未启用
（`request_uri_parameter_supported=false`）。这两个跳过项符合当前安全边界，
但不能视为 zero-SKIPPED 证据。
