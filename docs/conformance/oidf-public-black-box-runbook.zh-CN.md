# OIDF 公网黑盒一致性测试流程

本文规定唯一受支持的 OIDF 一致性测试流程。被测对象是正常的公网生产部署；测试工具不得获得数据库访问权、私有服务网络地址、特权运行时挂载或另一套协议行为。

## 规范面与控制面边界

| 能力 | 规范依据 | 必须遵守的边界 |
|---|---|---|
| OAuth 客户端注册与管理 | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html)、[RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) | 一致性测试客户端与普通客户端走同一套申请、审批、凭据交付、注册和管理流程。 |
| CIBA 令牌生命周期 | [OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | CIBA 成功令牌响应可以包含 refresh token，因此客户端注册允许 `ciba + refresh_token`，不虚构对 authorization code 的依赖；运行时仍要求客户端登记该 grant 并满足 `offline_access` 策略。 |
| Logout 客户端元数据 | [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)、[OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | 两个 `*_logout_session_required` 的规范默认值都是 `false`；需要 `sid` 的客户端必须登记对应 URI 并显式启用。 |
| mTLS 客户端认证和证书绑定访问令牌 | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html)、[RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.html)、[RFC 4517](https://www.rfc-editor.org/rfc/rfc4517.html) | `tls_client_auth` 与证书绑定令牌是两个独立能力；授权服务器要求唯一 subject selector、规范 DN 匹配、按类型匹配 SAN，并只允许附加证书 pin 收紧结果。 |
| X.509 验证 | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) | 只有当前有效、使用受支持公钥、带 critical CA Basic Constraints 和 critical `keyCertSign` 的 CA 证书才能提交信任申请。 |
| 信任锚管理 | [RFC 6024](https://www.rfc-editor.org/rfc/rfc6024.html) | RFC 6024 提供信任锚管理的安全模型：认证并授权来源、保护完整性、检测重放、限制信任用途并保留恢复能力。产品控制面另行强制不同人员审批、有界原因、追加式审计和撤销。 |
| OpenID4VC 签发与出示 | [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)、[OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | 协议端点按正式规范实现。OpenID4VCI 没有定义签发方数据集管理 API，因此该能力只能位于带管理员认证和 CSRF 防护的控制面，不能宣告为协议端点。 |

规范没有定义运维 API，并不意味着可以提供无边界接口。非标准控制面必须满足最小权限、同源、身份认证、CSRF 防护、结构与大小限制、租户绑定、失败关闭和持久化审计。

部署安全策略将单租户当前有效的不同信任锚限制为 128 个，单客户端限制为 8 个；单客户端最多保留 4 个待审批申请，单用户在每个租户最多保留 16 个待审批申请。创建和审批都会获取租户级数据库 advisory lock，因此并发请求也不能绕过上限。这些数值属于产品资源边界，不宣称是 RFC 8705 或 RFC 6024 的规范要求。

## 硬性不变量

- 发行方和套件地址由运行者输入，必须是公网 HTTPS origin；仓库不提供任何部署域名默认值。
- Discovery 中的 `issuer` 必须等于被测公网 origin。
- 套件只能访问公网 HTTPS。禁止私有 DNS、裸 IP、loopback、容器服务名和关闭 TLS 校验。
- 产品逻辑不得根据 plan 名称、suite alias、callback path、测试 header 或 conformance 编译开关分支。
- 准备工具不得执行 SQL，也不得加载生产 server crate。
- 申请人与审批人必须是两个不同的有效账号；审批人的 `admin_level` 必须大于 0。自动化账号仍遵守正常账号生命周期和 MFA 策略。
- 每次运行使用独立命名空间；运行结束后停用所有新建客户端并撤销本次批准的信任锚。
- expected skip/review 必须精确绑定 configuration、plan、variant 和 module；任何额外 skip、review、warning 或 failure 都使运行失败。

## 1. 生成不可变的 runner 材料

检出待部署的精确 commit，并确保工作区干净。由运行者设置公网地址和账号：

```sh
export OIDF_TARGET_ISSUER=https://issuer.example
export OIDF_MTLS_TARGET_ISSUER=https://mtls.issuer.example
export OIDF_SUITE_BASE_URL=https://suite.example
export OIDF_APPLICANT_EMAIL=conformance-applicant@example.com
export OIDF_APPLICANT_PASSWORD=...
export OIDF_ADMIN_EMAIL=conformance-approver@example.com
export OIDF_ADMIN_PASSWORD=...
export OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN=...
export OIDF_CIBA_AUTOMATED_DECISION_TOKEN=...
python scripts/prepare_oidf_black_box.py
```

命令只在 `runtime/oidf` 生成 runner 配置、密钥、证书、onboarding manifest 以及精确的 plan/skip/review 清单。这些是测试输入，不是生产记录，也不具备修改生产数据库的权限。

## 2. 部署精确提交

部署该 commit 的正常 runtime 镜像和 UI。不得通过 SQL、迁移、专用预置二进制或特殊容器入口安装客户端、credential dataset 或 CA。核对运行镜像的 OCI revision、健康端点、Discovery issuer、JWKS、UI 静态资源和回滚记录。

## 3. 通过生产控制面完成客户端接入

执行：

```sh
python scripts/apply_public_conformance_onboarding.py apply \
  --target-issuer "$OIDF_TARGET_ISSUER"
```

每个客户端都执行普通运行者可用的正式流程：

1. 申请人登录；
2. 提交客户端接入申请；
3. 由不同管理员审批；
4. 申请人领取一次性客户端凭据；
5. 用实际交付的客户端标识替换 runner 中的逻辑标识；
6. 需要 mTLS 的客户端提交 CA 信任申请；
7. 由不同管理员审批；
8. 从公网服务导出当前已经批准的租户信任 bundle。

所有请求都必须是精确同源 HTTPS 请求：启用正常证书校验、禁止重定向、限制响应大小、校验 JSON Content-Type，并在变更请求中携带 CSRF token。输出的状态文件与 bundle 均属于私密运行材料。

状态文件会在第一次公网变更前创建，并在每次申请、审批、凭据交付和信任决策后原子更新。apply 失败或中断后，必须先执行 cleanup，不能直接覆盖重跑。cleanup 会通过同一公网控制面拒绝已记录的待审批申请、撤销已批准信任锚并停用已交付客户端。

## 4. 只安装已经批准的信任 bundle

使用部署系统正常的原子配置流程，把 `runtime/oidf/approved-mtls-trust-anchors.pem` 安装到公网反向代理的客户端证书信任库。记录 bundle SHA-256，建立回滚副本，验证完整代理配置，reload 后从公网验证 mTLS alias。不得直接安装 runner 生成目录中的 CA 文件。

代理负责验证证书链；授权服务器仍会按 RFC 8705 验证客户端登记的 subject selector 和客户端策略。代理信任一个 CA 不等于授权该 CA 签发的所有证书。

## 5. 通过管理员 API 安装专用 OpenID4VC 数据

OpenID4VC runner 只能使用明确标记的专用 conformance 用户。driver 通过同一个公网发行方以管理员身份登录，只能向该 subject 写入有界数据：
`/admin/openid4vci/credential-datasets/{subject}/{configuration}`。

该端点要求管理员 session 和 CSRF token，按 credential format、有效期、保留 claim、JSON 大小/深度进行验证，并在同一事务中写入数据和追加式审计事件。它是签发方控制面，不是 OpenID4VCI 协议端点。driver 必须在 `finally` 中删除数据；清理失败即测试失败。

## 6. 执行完整公网矩阵

完整仓库矩阵必须针对公网发行方运行。并发安全的 plan 可以并发；logout、session management 以及其他共享浏览器状态的 plan 必须使用隔离 job。延长终态等待只用于吸收套件完成传播延迟，不能放宽任何协议断言。

定向 plan 只用于诊断，不能代替全矩阵证据。必须保存精确 target commit、公网 origin、plan ID、module 结果、expected skip/review 匹配和 runner 版本。

## 7. 执行官方套件

只有同一精确部署提交的完整公网黑盒矩阵通过后，才可请求官方 OIDF 运行。官方配置也必须经过相同的生产接入流程；不得用本地 runner 材料覆盖现有客户端凭据或信任记录。

直接观察官方套件的 module 终态。CI 是交付证据，但不能替代官方套件的最终 module 结果。

## 8. 清理和证据留存

无论运行结果如何，均执行：

```sh
python scripts/apply_public_conformance_onboarding.py cleanup \
  --target-issuer "$OIDF_TARGET_ISSUER"
```

清理过程通过公网管理员 API 撤销信任申请并停用本次创建的客户端。只有代理回滚流程确认旧信任配置恢复后，才能删除安装的 CA。留存脱敏后的结果、精确 commit、plan manifest、bundle digest、审批/撤销审计 ID 和官方 run ID；文档中严禁保存密码、私钥、session cookie、CSRF token、client secret 或一次性交付 token。
