//! 启动配置辅助函数。
// 配置文件只在启动阶段读取；运行期通过 AppState 共享不可变快照。

use std::{collections::HashMap, env, fs::File, path::Path};

use anyhow::{Context, bail};
use yaml_serde::Value as YamlValue;

use super::prelude::*;

#[derive(Clone, Debug, Default)]
pub struct ConfigSource {
    file_values: HashMap<String, String>,
}

impl ConfigSource {
    pub fn load() -> anyhow::Result<Self> {
        let mut source = Self::default();
        source.merge_yaml_file("env.yaml")?;
        source.merge_yaml_file("env.yml")?;
        source.merge_dotenv_file(".env")?;
        Ok(source)
    }

    pub fn get(&self, key: &str) -> Option<String> {
        env::var(key)
            .ok()
            .or_else(|| self.file_values.get(key).cloned())
    }

    pub fn string(&self, key: &str, default: &str) -> String {
        self.get(key).unwrap_or_else(|| default.to_owned())
    }

    pub fn parse<T>(&self, key: &str, default: T) -> anyhow::Result<T>
    where
        T: std::str::FromStr,
    {
        let Some(value) = self.get(key) else {
            return Ok(default);
        };
        let Ok(parsed) = value.parse() else {
            bail!("{key} must be a valid {}", std::any::type_name::<T>());
        };
        Ok(parsed)
    }

    pub fn bool(&self, key: &str, default: bool) -> anyhow::Result<bool> {
        let Some(value) = self.get(key) else {
            return Ok(default);
        };
        let Some(parsed) = parse_bool(&value) else {
            bail!("{key} must be a boolean value");
        };
        Ok(parsed)
    }

    fn merge_dotenv_file(&mut self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(());
        }

        let iter = dotenvy::from_path_iter(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        for entry in iter {
            let (key, value) =
                entry.with_context(|| format!("failed to parse {}", path.display()))?;
            self.file_values.insert(key, value);
        }
        Ok(())
    }

    fn merge_yaml_file(&mut self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(());
        }

        let file =
            File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
        let value = yaml_serde::from_reader::<_, YamlValue>(file)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let YamlValue::Mapping(values) = value else {
            bail!("{} must be a top-level key/value mapping", path.display());
        };
        for (key, value) in values {
            let Some(key) = key.as_str().map(str::trim).filter(|key| !key.is_empty()) else {
                bail!("{} contains a non-string or empty key", path.display());
            };
            let value = yaml_value_to_string(key, &value)?;
            self.file_values.insert(key.to_owned(), value);
        }
        Ok(())
    }
}

pub fn normalize_database_url(url: &str) -> String {
    url.replace("postgresql+psycopg://", "postgresql://")
}

pub(crate) fn random_urlsafe_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn yaml_value_to_string(key: &str, value: &YamlValue) -> anyhow::Result<String> {
    match value {
        YamlValue::String(value) => Ok(value.clone()),
        YamlValue::Bool(value) => Ok(value.to_string()),
        YamlValue::Number(value) => Ok(value.to_string()),
        YamlValue::Sequence(values) => {
            let values = values
                .iter()
                .map(|value| yaml_value_to_string(key, value))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(values.join(","))
        }
        _ => bail!("{key} must be a scalar or a sequence of scalars"),
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_sequence_becomes_comma_separated_value() {
        let value = YamlValue::Sequence(vec![
            YamlValue::String("http://127.0.0.1:3000".to_owned()),
            YamlValue::String("http://localhost:3000".to_owned()),
        ]);

        assert_eq!(
            yaml_value_to_string("CORS_ALLOWED_ORIGINS", &value).unwrap(),
            "http://127.0.0.1:3000,http://localhost:3000"
        );
    }

    #[test]
    fn invalid_numeric_config_is_error() {
        let mut source = ConfigSource::default();
        source
            .file_values
            .insert("SESSION_TTL_SECONDS".to_owned(), "soon".to_owned());

        assert!(source.parse::<u64>("SESSION_TTL_SECONDS", 28_800).is_err());
    }

    #[test]
    fn invalid_boolean_config_is_error() {
        let mut source = ConfigSource::default();
        source.file_values.insert(
            "EMAIL_CODE_DEV_RESPONSE_ENABLED".to_owned(),
            "maybe".to_owned(),
        );

        assert!(
            source
                .bool("EMAIL_CODE_DEV_RESPONSE_ENABLED", false)
                .is_err()
        );
    }
}
