//! Runtime configuration loading.
// Configuration is read once at startup from defaults, .env.yaml, and whitelisted environment variables.

use std::{collections::HashMap, fs::File, path::Path};

use anyhow::{Context, bail};
use yaml_serde::Value as YamlValue;

const CONFIG_FILE: &str = ".env.yaml";
const UNSUPPORTED_DOTENV_FILE: &str = ".env";
const ENV_CONFIG_KEYS: &[&str] = &[
    "ACCESS_TOKEN_TTL_SECONDS",
    "AUTH_CODE_TTL_SECONDS",
    "AUTH_RATE_LIMIT_MAX_REQUESTS",
    "AVATAR_MAX_BYTES",
    "AVATAR_STORAGE_DIR",
    "BIND",
    "CLIENT_DELIVERY_TTL_SECONDS",
    "CLIENT_IP_HEADER_MODE",
    "COOKIE_SECURE",
    "CORS_ALLOWED_ORIGINS",
    "CSRF_COOKIE_NAME",
    "DATABASE_URL",
    "DEFAULT_AUDIENCE",
    "EMAIL_CODE_DEV_RESPONSE_ENABLED",
    "EMAIL_CODE_PEER_COOLDOWN_SECONDS",
    "EMAIL_CODE_SEND_COOLDOWN_SECONDS",
    "EMAIL_CODE_TTL_SECONDS",
    "EMAIL_DELIVERY",
    "EMAIL_FROM",
    "EMAIL_SMTP_HOST",
    "EMAIL_SMTP_PASSWORD",
    "EMAIL_SMTP_PORT",
    "EMAIL_SMTP_TLS",
    "EMAIL_SMTP_USERNAME",
    "FRONTEND_BASE_URL",
    "ID_TOKEN_TTL_SECONDS",
    "ISSUER",
    "JWK_KEYS_DIR",
    "MTLS_ENDPOINT_BASE_URL",
    "PAIRWISE_SUBJECT_SECRET",
    "PAR_TTL_SECONDS",
    "RATE_LIMIT_WINDOW_SECONDS",
    "REFRESH_TOKEN_TTL_SECONDS",
    "REQUIRE_PUSHED_AUTHORIZATION_REQUESTS",
    "RUST_LOG",
    "SESSION_COOKIE_NAME",
    "SESSION_TTL_SECONDS",
    "SUBJECT_TYPE",
    "TOKEN_MANAGEMENT_RATE_LIMIT_MAX_REQUESTS",
    "TOKEN_RATE_LIMIT_MAX_REQUESTS",
    "TRUSTED_PROXY_CIDRS",
    "VALKEY_COMMAND_TIMEOUT_MS",
    "VALKEY_URL",
];

#[derive(Clone, Debug, Default)]
pub struct ConfigSource {
    file_values: HashMap<String, String>,
    env_values: HashMap<String, String>,
}

impl ConfigSource {
    pub fn load() -> anyhow::Result<Self> {
        Self::load_from_dir_with_env(".", std::env::vars())
    }

    #[cfg(test)]
    fn load_from_dir(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::load_from_dir_with_env(path, std::iter::empty::<(String, String)>())
    }

    fn load_from_dir_with_env(
        path: impl AsRef<Path>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let dotenv_path = path.join(UNSUPPORTED_DOTENV_FILE);
        if dotenv_path.exists() {
            bail!(".env is not supported; use .env.yaml");
        }

        let mut source = Self::default();
        let config_path = path.join(CONFIG_FILE);
        if config_path.exists() {
            source.merge_yaml_file(config_path)?;
        }
        source.merge_env(env)?;
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
        self.env_values
            .get(key)
            .or_else(|| self.file_values.get(key))
            .cloned()
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

    fn merge_env(&mut self, env: impl IntoIterator<Item = (String, String)>) -> anyhow::Result<()> {
        for (key, value) in env {
            if !ENV_CONFIG_KEYS.contains(&key.as_str()) {
                continue;
            }
            if key.trim().is_empty() {
                bail!("environment config key must not be empty");
            }
            self.env_values.insert(key, value);
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
    fn missing_config_file_can_be_replaced_by_whitelisted_environment() {
        let path = std::env::temp_dir().join(format!(
            "nazo_config_env_only_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();

        let result = ConfigSource::load_from_dir_with_env(
            &path,
            [
                ("ISSUER".to_owned(), "https://issuer.example".to_owned()),
                (
                    "FRONTEND_BASE_URL".to_owned(),
                    "https://frontend.example".to_owned(),
                ),
            ],
        );
        let _ = std::fs::remove_dir_all(&path);

        let source = result.unwrap();
        assert_eq!(
            source.required_string("ISSUER").unwrap(),
            "https://issuer.example"
        );
    }

    #[test]
    fn environment_overrides_yaml_by_allowlist() {
        let mut source = ConfigSource::default();
        source
            .file_values
            .insert("ISSUER".to_owned(), "https://yaml.example".to_owned());
        source
            .merge_env([
                ("ISSUER".to_owned(), "https://env.example".to_owned()),
                ("VALKEY_COMMAND_TIMEOUT_MS".to_owned(), "1000".to_owned()),
                ("UNKNOWN_ENV".to_owned(), "ignored".to_owned()),
            ])
            .unwrap();

        assert_eq!(source.string("ISSUER", ""), "https://env.example");
        assert_eq!(source.string("VALKEY_COMMAND_TIMEOUT_MS", ""), "1000");
        assert!(source.get("UNKNOWN_ENV").is_none());
    }

    #[test]
    fn invalid_environment_type_is_error() {
        let mut source = ConfigSource::default();
        source
            .merge_env([("SESSION_TTL_SECONDS".to_owned(), "soon".to_owned())])
            .unwrap();

        assert!(source.parse::<u64>("SESSION_TTL_SECONDS", 28_800).is_err());
    }
}
