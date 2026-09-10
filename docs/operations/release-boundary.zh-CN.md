# 发布物与黑盒验证边界

NazoAuth 生产发布物只包含协议实现、数据库迁移和独立签名的 `nazoauth`。
`nazoauthctl` 由 `nazozero/NazoAuthCtl` 独立构建、签名和发布。

服务仓库与发布物不包含第三方测试 runner、plan 清单、浏览器自动化、测试凭据、
测试专用接入模型或预期结果目录。外部验证器只是普通客户端：它通过公开 HTTPS
协议和所有集成都可使用的租户/客户端管理能力访问服务。产品代码不得根据验证器
身份、plan 名称、callback path、测试 header 或编译开关改变行为。

长期运行容器只包含 `nazoauth`。`server` 入口不能修改 schema；宿主机特权工作通过
签名控制协议执行。外部验证工具在仓库之外独立版本化和运行。持续维护的协议契约
和官方认证链接位于 [docs/conformance](../conformance/README.md)。单次运行的制品身份、
原始结果、人工复核、清理及证据摘要保存在 CI 制品或对应 issue/PR 中；私有日志和
测试 secret 不打包进可执行文件，也不作为项目文档提交。

`crates/operator-protocol` 是控制协议与密码规则的唯一事实源。发布互操作契约由
协议版本和 Release manifest schema 声明，不支持的组合失败关闭；schema 7 不包含
控制器 SemVer 范围。
