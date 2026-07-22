impl ConfigSource {
    pub(crate) fn from_pairs_for_test(
        values: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> Self {
        Self {
            file_values: values
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
            env_values: HashMap::new(),
        }
    }

    pub(crate) fn from_owned_pairs_for_test(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Self {
        // 动态端点测试需要在运行时生成配置值；生产加载仍只走文件和环境变量。
        Self {
            file_values: values.into_iter().collect(),
            env_values: HashMap::new(),
        }
    }

    fn load_from_dir(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::load_from_dir_with_env(path, std::iter::empty::<(String, String)>())
    }
}
