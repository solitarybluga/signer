//! Server configuration loaded from `signer.toml`.

use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration as StdDuration;

use serde::Deserialize;
use signer_core::storage::PoolConfig;
use thiserror::Error;
use time::Duration;

const DEFAULT_GRPC_ADDR: &str = "127.0.0.1:50051";
const DEFAULT_DATA_DIR: &str = "data";
const DEFAULT_SESSION_TTL_SECS: u64 = 600;

/// Server configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub grpc_addr: String,
    pub data_dir: PathBuf,
    pub session_ttl_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            grpc_addr: DEFAULT_GRPC_ADDR.to_string(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// SQLite URL, `sqlite://...`, or `postgres://...`.
    /// When omitted, `$data_dir/signer.db` is used.
    pub url: Option<String>,

    /// Backend default: 10 for PostgreSQL, 1 for SQLite.
    pub max_connections: Option<u32>,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    /// 0 disables the idle timeout.
    pub idle_timeout_secs: u64,
    /// 0 disables the maximum lifetime.
    pub max_lifetime_secs: u64,
    /// SQLite busy timeout; ignored by PostgreSQL.
    pub sqlite_busy_timeout_secs: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: None,
            max_connections: None,
            min_connections: 0,
            acquire_timeout_secs: 5,
            idle_timeout_secs: 600,
            max_lifetime_secs: 1800,
            sqlite_busy_timeout_secs: 5,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Write an `audit_log` row for every Sign attempt. Keep enabled outside
    /// controlled benchmarks; disabling it removes non-repudiation for Sign.
    pub sign_enabled: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { sign_enabled: true }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Default tracing filter, used when RUST_LOG is not set.
    pub level: String,
    pub format: LogFormat,
    /// Include source file and line number in each event.
    pub location: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Text,
            location: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

impl DatabaseConfig {
    /// Build pool settings for the selected backend.
    pub fn pool_config(&self, default_max_connections: u32) -> Result<PoolConfig, ConfigError> {
        let max_connections = self.max_connections.unwrap_or(default_max_connections);
        if max_connections == 0 {
            return Err(ConfigError::Invalid("max_connections must be positive"));
        }
        if self.min_connections > max_connections {
            return Err(ConfigError::Invalid(
                "min_connections must not exceed max_connections",
            ));
        }
        if self.acquire_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "acquire_timeout_secs must be positive",
            ));
        }
        if self.sqlite_busy_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "sqlite_busy_timeout_secs must be positive",
            ));
        }

        Ok(PoolConfig {
            max_connections,
            min_connections: self.min_connections,
            acquire_timeout: StdDuration::from_secs(self.acquire_timeout_secs),
            idle_timeout: (self.idle_timeout_secs > 0)
                .then(|| StdDuration::from_secs(self.idle_timeout_secs)),
            max_lifetime: (self.max_lifetime_secs > 0)
                .then(|| StdDuration::from_secs(self.max_lifetime_secs)),
            sqlite_busy_timeout: StdDuration::from_secs(self.sqlite_busy_timeout_secs),
        })
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },

    #[error("invalid config: {0}")]
    Invalid(&'static str),

    #[error("SIGNER_SESSION_TTL_SECS must be a positive integer")]
    InvalidSessionTtl,

    #[error("invalid server.grpc_addr: {0}")]
    InvalidGrpcAddr(#[source] std::net::AddrParseError),
}

impl Config {
    /// Load configuration.
    ///
    /// Precedence:
    /// 1. explicit `--config` path;
    /// 2. `SIGNER_CONFIG`;
    /// 3. `./signer.toml` when it exists;
    /// 4. built-in defaults.
    ///
    /// Environment overrides are applied after the file is parsed. They are
    /// intended for container/CI secrets and deployment-specific values.
    pub fn load(explicit: Option<PathBuf>) -> Result<Self, ConfigError> {
        let path = resolve_path(explicit);
        let mut config = match path {
            Some(path) => {
                let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
                    path: path.clone(),
                    source,
                })?;
                toml::from_str(&raw).map_err(|source| ConfigError::Parse {
                    path,
                    source: Box::new(source),
                })?
            }
            None => Self::default(),
        };

        config.apply_env()?;
        config.validate()?;
        Ok(config)
    }

    pub fn grpc_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.server
            .grpc_addr
            .parse()
            .map_err(ConfigError::InvalidGrpcAddr)
    }

    pub fn session_ttl(&self) -> Result<Duration, ConfigError> {
        if self.server.session_ttl_secs == 0 {
            return Err(ConfigError::Invalid("session_ttl_secs must be positive"));
        }
        let seconds = i64::try_from(self.server.session_ttl_secs)
            .map_err(|_| ConfigError::Invalid("session_ttl_secs is too large"))?;
        Ok(Duration::seconds(seconds))
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.data_dir.as_os_str().is_empty() {
            return Err(ConfigError::Invalid("data_dir must not be empty"));
        }
        if let Some(url) = &self.database.url
            && url.trim().is_empty()
        {
            return Err(ConfigError::Invalid("database.url must not be empty"));
        }
        if self.logging.level.trim().is_empty() {
            return Err(ConfigError::Invalid("logging.level must not be empty"));
        }
        self.database.pool_config(10)?;
        self.grpc_addr()?;
        self.session_ttl()?;
        Ok(())
    }

    fn apply_env(&mut self) -> Result<(), ConfigError> {
        if let Some(value) = non_empty_env("SIGNER_GRPC_ADDR") {
            self.server.grpc_addr = value;
        }
        if let Some(value) = non_empty_env("SIGNER_DATA_DIR") {
            self.server.data_dir = PathBuf::from(value);
        }
        if let Some(value) = non_empty_env("SIGNER_DATABASE_URL") {
            self.database.url = Some(value);
        }
        if let Some(value) = non_empty_env("SIGNER_SESSION_TTL_SECS") {
            self.server.session_ttl_secs =
                value.parse().map_err(|_| ConfigError::InvalidSessionTtl)?;
        }
        Ok(())
    }
}

fn resolve_path(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if explicit.is_some() {
        return explicit;
    }
    if let Some(value) = non_empty_env("SIGNER_CONFIG") {
        return Some(PathBuf::from(value));
    }
    let default = PathBuf::from("signer.toml");
    default.exists().then_some(default)
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        let config = Config::default();
        assert_eq!(config.server.grpc_addr, DEFAULT_GRPC_ADDR);
        assert_eq!(config.server.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(config.server.session_ttl_secs, DEFAULT_SESSION_TTL_SECS);
        assert!(config.audit.sign_enabled);
        config.validate().unwrap();
    }

    #[test]
    fn sign_audit_can_be_disabled() {
        let default = Config::default();
        assert!(default.audit.sign_enabled);

        let config: Config = toml::from_str("[audit]\nsign_enabled = false\n").unwrap();
        assert!(!config.audit.sign_enabled);
    }

    #[test]
    fn partial_file_uses_defaults() {
        let config: Config = toml::from_str(
            r#"
[server]
grpc_addr = "127.0.0.1:50052"
session_ttl_secs = 120
"#,
        )
        .unwrap();

        assert_eq!(config.server.grpc_addr, "127.0.0.1:50052");
        assert_eq!(config.server.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(config.server.session_ttl_secs, 120);
        assert_eq!(config.database.url, None);
    }

    #[test]
    fn rejects_unknown_fields_and_invalid_values() {
        let unknown: Result<Config, _> = toml::from_str("[server]\nunknown = 1\n");
        assert!(unknown.is_err());

        let config: Config = toml::from_str("[server]\nsession_ttl_secs = 0\n").unwrap();
        assert!(config.validate().is_err());

        let config: Config = toml::from_str("[server]\ngrpc_addr = \"not-an-address\"\n").unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn logging_defaults_and_overrides() {
        let config = Config::default();
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, LogFormat::Text);
        assert!(config.logging.location);

        let config: Config = toml::from_str(
            r#"
[logging]
level = "debug"
format = "json"
location = false
"#,
        )
        .unwrap();
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.format, LogFormat::Json);
        assert!(!config.logging.location);

        let empty: Config = toml::from_str("[logging]\nlevel = \"\"\n").unwrap();
        assert!(empty.validate().is_err());
    }

    #[test]
    fn database_pool_defaults_and_validation() {
        let database = DatabaseConfig::default();
        let sqlite = database.pool_config(1).unwrap();
        assert_eq!(sqlite.max_connections, 1);
        assert_eq!(sqlite.acquire_timeout, StdDuration::from_secs(5));
        assert_eq!(sqlite.sqlite_busy_timeout, StdDuration::from_secs(5));

        let postgres = database.pool_config(10).unwrap();
        assert_eq!(postgres.max_connections, 10);

        let invalid = DatabaseConfig {
            max_connections: Some(0),
            ..DatabaseConfig::default()
        };
        assert!(invalid.pool_config(1).is_err());

        let invalid = DatabaseConfig {
            max_connections: Some(2),
            min_connections: 3,
            ..DatabaseConfig::default()
        };
        assert!(invalid.pool_config(2).is_err());
    }

    #[test]
    fn database_url_is_optional() {
        let config: Config =
            toml::from_str("[database]\nurl = \"postgres://localhost/signer\"\n").unwrap();
        assert_eq!(
            config.database.url.as_deref(),
            Some("postgres://localhost/signer")
        );
    }
}
