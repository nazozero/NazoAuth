# OIDF 公网黑盒一致性测试流程

## 目的

本文定义 OpenID Foundation 一致性回归的固定流程。套件结果只能作为验证证据，不能作为实现依据。实现决策必须来自对应 RFC、OpenID、FAPI、OpenID4VC、HAIP 或安全 BCP 的规范文本，而不是某个测试模块的行为。

## 硬性边界

| 边界 | 要求 |
|---|---|
| 规范优先 | 先实现规范和安全 profile 的语义。如果套件结果与当前规范或已记录的安全策略冲突，只有在实现错误时才修改实现；否则应修订矩阵、expected skip 或文档。 |
| 公网黑盒目标 | 被测 issuer 必须是操作者显式提供的公网 HTTPS origin。仓库 workflow 和生成文件不得默认指向任何仓库自有生产 issuer。 |
| 不泄露私有目标 | 生成的 plan config 和提交的文档不得把 suite 私有主机名、内部反向代理名、localhost issuer 或私有信任根 endpoint 作为被测 issuer。 |
| 控制面分离 | 可以使用本地 conformance-suite 控制面驱动测试，但被测 issuer 必须仍然是公网 HTTPS origin。控制面地址本身不是一致性证据。 |
| 禁止测试专用产品行为 | 产品代码不得根据 suite alias、suite hostname、test plan 名称或 conformance 专用请求形状分支。 |
| 只允许确定性播种 | runner 可以从本次执行的精确 plan artifact 播种 client、key、redirect URI、scope 和测试用户；不得手工修改协议状态来制造通过。 |
| 证据必须精确 | 记录 commit SHA、部署 runtime revision、脱敏 target issuer、suite 版本、plan set、expected skip、review allowance、artifact digest 和 run URL。 |

## 正确流程

1. 确认实现边界。

   - 阅读相关规范章节和安全 BCP。
   - 区分强制行为、可选行为、不支持行为和明确的安全策略拒绝。
   - 在使用套件结果前，先补齐本地正向、负向、metadata truth 和安全边界测试。

2. 为目标 issuer 生成运行材料。

   - 操作者必须显式提供公网 issuer 和 suite base URL。
   - 生成配置中，所有协议可见的 issuer、redirect、logout、notification、credential、verifier endpoint 都必须是公网 HTTPS URL。
   - 运行前扫描生成配置；内部主机名、localhost issuer 和私有反向代理名均视为失败。

3. 使用同一 artifact 播种。

   - 本地/公网 dry run 必须使用本次生成的公网 artifact 播种。
   - 官方运行必须使用该官方 workflow 产出的 artifact 播种。
   - 不得混用本地套件和官方套件的 key、certificate、callback URL 或 client JWKS。

4. 执行公网黑盒矩阵。

   - 可并发计划应并发执行。
   - 共享浏览器会话、轮询状态、callback alias 或 CIBA transaction 状态的计划必须拆成隔离批次。
   - Front-Channel Logout 和 Session Management 与主并发矩阵隔离。
   - FAPI-CIBA poll 和 ping 变体不得在同一批次中共享可变 CIBA transaction alias。

5. 解读套件结果。

   - `FAILURE` 或非预期 `WARNING` 不可接受。
   - `SKIPPED` 只有在与提交的 expected-skip 清单精确匹配时才可接受。
   - `REVIEW` 只有在清单精确限定 plan、config、alias 和 module 时才可接受。
   - 任何新增 skip、review、warning 或 module interruption 都必须诊断。

6. 公网黑盒矩阵通过后，才运行官方套件。

   - 用官方 artifact 恢复或播种官方 client 材料。
   - 再次确认部署 revision 和公网 issuer 健康状态。
   - 启动官方矩阵，并保持本地/公网证据与官方证据分离。

7. 只有所有门禁满足后才能合并。

   - PR checks 必须通过，除非仓库负责人明确声明某项检查与本变更无关。
   - 公网黑盒矩阵必须通过。
   - 官方套件矩阵必须通过。
   - 一致性记录必须写入最终证据。

## Artifact 卫生检查

每次公网或官方运行前必须确认：

- 生成的 plan 文件只包含预期的公网 issuer 占位符或操作者提供的公网 issuer；
- 生成的 plan 文件没有把内部主机名作为被测 issuer；
- expected skip 按批次生成，不能把全局清单当作宽泛绕过；
- review allowance 绑定到精确的 plan/config/module；
- 播种输入和执行的 plan config 来自同一次 artifact 生成；
- 已部署服务报告的 revision 与被测 commit 一致。

## 作弊定义

以下行为禁止：

- 产品代码识别 suite plan、alias、hostname 或 module name；
- 只为 conformance client 放宽校验；
- 用本地或私有 issuer URL 作为被测目标，却声称是公网一致性证据；
- 手工修改数据库协议状态以绕过认证、同意、轮询、签发、撤销或 callback 行为；
- 没有提交有界理由就接受新增 skip、review、warning 或 interruption；
- 在同一证据运行中混用官方套件和本地套件的 client 材料。

## 失败处理

当套件失败时：

1. 先找第一个协议可见失败，而不是只看 runner 最终退出码。
2. 将观察到的行为与相关规范比对。
3. 如果实现错误，修复实现，并在协议边界增加本地回归测试。
4. 如果 suite 输入或矩阵错误，只修复生成、播种、分批或 expected-skip/review 元数据，不改变产品协议行为。
5. 先重跑受影响的公网黑盒批次，再跑完整公网矩阵，最后跑官方矩阵。

## 结果记录

一致性结果记录必须包含：

- implementation commit SHA；
- deployed runtime revision；
- suite version 或 source commit；
- 脱敏 target issuer；
- plan set 和 batching mode；
- expected skip 数量和精确原因；
- review 数量和精确原因；
- condition success、warning、failure 计数；
- artifact 名称和 digest；
- 声称官方证据时的 official run URL。
