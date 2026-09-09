# 发布安全

## 范围

依赖、镜像、签名和来源证明检查都是发布门禁。只有这些门禁针对精确提交或
tag 全部通过后，发布制品才可信。

## 持续门禁

`conformance-security` 工作流会对代码、依赖、migration、脚本、部署、容器、
运行时配置和工作流改动执行供应链检查：

- 对 `Cargo.lock` 运行 `cargo audit`
- 使用 `deny.toml` 运行 `cargo deny`
- 为 Rust 依赖生成 CycloneDX SBOM
- 使用 `Containerfile` 构建容器镜像
- 使用 Trivy 扫描实际构建的镜像
- 将 SBOM 保存为工作流制品

供应链任务与 Rust 单元/集成测试门禁相互独立。在一个部署形态的 Release 被信任
之前，依赖或镜像回归必须先使流程失败。

`dependency-review` 还会每周运行 `cargo audit`，因此即使仓库没有新提交，新公布
的安全公告也会被检查。Dependabot 和唯一的根级 `renovate.json` 覆盖 Cargo、
GitHub Actions、容器/Compose 输入、锁定的 Python 输入、精确 Rust stable 版本及
安全 CLI 版本。Renovate 漏洞告警不受普通每周更新窗口限制。

## Tag 发布门禁

`release-security` 工作流由 `v*` tag 或手动调度触发：

- tag 触发只接受精确稳定版 `vMAJOR.MINOR.PATCH`；去掉 `v` 后的版本必须等于
  `[workspace.package].version`，并且 `cargo metadata --locked` 解析出的每一个
  workspace member 都必须是同一版本。任何不一致都会在构建或发布制品之前终止
  policy 任务
- tag commit 必须可达 `main`，并具有精确 SHA 的成功 `main` push 质量门。任意其他
  子分支以及未经精确门禁验证的 tag 都会失败
- 对可达 `main` 的提交执行 `workflow_dispatch` 是不发布的原生矩阵演练：它执行
  policy、原生测试、二进制构建和 OCI 组装，同时跳过所有仅限 tag 的证明与发布任务
- 在原生 x86-64 和 Arm64 Linux、Windows、macOS runner 上使用固定 Rust
  toolchain 构建八个平台目标
- 在每个原生目标上实际执行 server 二进制
- 验证 server 二进制的包版本和 operator protocol 版本
- 从唯一源码打包一次 `nazo-operator-protocol`，校验包构建与 digest，并为精确
  `.crate` 生成标准 build provenance
- 对精确 tag 再次运行 `cargo audit` 和 `cargo deny`
- 构建一个同时包含 `linux/amd64` 与 `linux/arm64` 的 OCI index
- 使用 Trivy 扫描精确 OCI archive，并且不二次构建，直接发布同一 archive
- 为 server Rust 依赖生成 CycloneDX SBOM
- 使用自定义 `https://nazo.run/attestations/release-manifest/v1` GitHub attestation，
  将每个 server 二进制绑定到封闭的 schema-7 ReleaseManifest
- 从 Rust 协议源码读取 operator protocol 版本，控制端校验发布格式和协议版本
- 签名 OCI index；重跑时仅当现有 tag 指向精确的已扫描 digest 才接受，否则拒绝
- 将 SBOM、OCI archive、predicate 和 Sigstore bundle 保存为内部 CI 证据
- GitHub Release 持久制品严格只包含 8 个带平台后缀的 server 可执行文件和精确
  版本的 `nazo-operator-protocol` crate；JSON、tar、bundle、脚本、checksum 和 SBOM
  不属于 Release 制品
- 只在每个既有 Release 制品逐字节一致时恢复部分发布，绝不覆盖 digest 不同的
  tag 或制品
- 除自定义 manifest predicate 外，还生成标准 provenance attestation

独立生产部署通过 `nazozero/NazoAuthCtl` 独立发布的 `nazoauthctl` 使用这些
server 制品。生命周期工具先获取制品的
GitHub attestation，验证 tag 专属工作流身份和封闭 predicate，再解析制品名称或
修改运行时状态，并验证 OCI descriptor。自定义部署流水线必须实施
相同的制品身份、digest、目标平台和数据库恢复边界。

NazoAuthWeb 是默认提供的可选 UI。首次使用时，NazoAuth 从 NazoAuthWeb 自己的
GitHub 仓库获取最新正式 Release，用该制品的摘要和大小校验下载，然后将可写
静态文件安装到 `${DATA_DIR}/ui/current`。后端发布证明不记录前端版本或摘要。
已有 `index.html` 时直接使用，更新后端不覆盖 UI，也不会重新校验本地文件摘要。

前端文件可在后端运行期间替换。`UI_STATIC_DIR` 用于指定已有的自定义目录，
`UI_ENABLED=false` 关闭静态 UI 托管。首次下载失败会记录日志，API 仍然启动；
之后可以直接向 UI 目录放入文件。前端只需兼容所使用的 API，不要求三个仓库一起发布。

schema-7 发布证明不再包含前端锁定、ctl SemVer 范围或人工回退策略。执行迁移后，
若激活失败，ctl 停止写入服务并要求经过验证的恢复；若更新成功，则清除上一制品
引用。数据库恢复完成后也清除旧引用，避免让旧程序使用不匹配的数据库。
没有执行迁移的更新继续使用现有的上一制品回退路径。

控制端部署状态升级为 schema 8，备份清单升级为 schema 5。旧格式不会被静默解释
为新格式；准备切换时需保留旧控制端及其恢复材料。本次源码修改不迁移已部署的
状态或备份。

精确的原生目标与托管生命周期资格边界见
[platform-support.zh-CN.md](platform-support.zh-CN.md)。

## 必须保留的证据

每次生产发布都必须保留：

- Git tag 与 commit SHA
- `conformance-security` 工作流 URL 和结论
- `release-security` 工作流 URL 和结论
- 全部 8 个 server 二进制制品名称与 digest
- operator protocol 包名称、digest 与 provenance attestation URL
- 每个平台目标的自定义 ReleaseManifest attestation URL
- 内部 server SBOM 制品名称与 digest
- Trivy 扫描结果
- Sigstore 证书身份与 issuer
- OCI index digest 与两个平台 manifest digest
- GitHub artifact attestation URL 与内部 bundle 引用

任何 audit、deny、SBOM 生成、镜像扫描、签名或 provenance attestation 失败时，
都不得发布 Release 镜像。
