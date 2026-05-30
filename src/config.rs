//! Runtime configuration file loading.
// Configuration is read once at startup from .env.yaml.

use std::{collections::HashMap, fs::File, path::Path};

use anyhow::{Context, bail};
use yaml_serde::Value as YamlValue;

const CONFIG_FILE: &str = ".env.yaml";
const UNSUPPORTED_DOTENV_FILE: &str = ".env";

#[derive(Clone, Debug, Default)]
pub struct ConfigSource {
    file_values: HashMap<String, String>,
}

impl ConfigSource {
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from_dir(".")
    }

    fn load_from_dir(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let dotenv_path = path.join(UNSUPPORTED_DOTENV_FILE);
        if dotenv_path.exists() {
            bail!(".env is not supported; use .env.yaml");
        }

        let mut source = Self::default();
        source.merge_yaml_file(path.join(CONFIG_FILE))?;
        Ok(source)
    }

    pub fn required_string(&self, key: &str) -> anyhow::Result<String> {
        let Some(value) = self
            .get(key)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
        else {
            bail!("{key} is required");
        };
        Ok(value)
    }

    pub fn optional_string(&self, key: &str) -> Option<String> {
        self.get(key)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.file_values.get(key).cloned()
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

    fn merge_yaml_file(&mut self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        let file = File::open(path)
            .with_context(|| format!("failed to read required {}", path.display()))?;
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

    #[test]
    fn dotenv_file_is_rejected() {
        let path = std::env::temp_dir().join(format!(
            "nazo_config_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join(".env"), "BIND=127.0.0.1:8000\n").unwrap();

        let result = ConfigSource::load_from_dir(&path);
        let _ = std::fs::remove_dir_all(&path);

        assert!(result.is_err());
    }

    #[test]
    fn missing_config_file_is_rejected() {
        let path = std::env::temp_dir().join(format!(
            "nazo_config_missing_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();

        let result = ConfigSource::load_from_dir(&path);
        let _ = std::fs::remove_dir_all(&path);

        assert!(result.is_err());
    }
}
