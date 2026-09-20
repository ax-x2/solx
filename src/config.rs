use crate::{Result, fail};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub vault: PathBuf,
    pub mode: Mode,
    pub rpc: RpcConfig,
    pub security: SecurityConfig,
    pub history: HistoryConfig,
    pub aliases: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Cli,
    Ui,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RpcConfig {
    pub url: Option<String>,
    pub cluster: String,
    pub timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub confirm_every_transaction: bool,
    pub show_details: bool,
    pub simulate_before_send: bool,
    pub show_simulation: bool,
    pub optimize_compute_units: bool,
    pub compute_unit_margin_percent: u8,
    pub cache_unlocked_in_shell: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryConfig {
    pub fetch_on_start: bool,
    pub interval_secs: Option<u64>,
    pub wallets: Vec<String>,
    pub limit: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vault: default_dir().join("vault.enc"),
            mode: Mode::Cli,
            rpc: RpcConfig::default(),
            security: SecurityConfig::default(),
            history: HistoryConfig::default(),
            aliases: BTreeMap::new(),
        }
    }
}
impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            url: None,
            cluster: "devnet".into(),
            timeout_secs: 15,
        }
    }
}
impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            confirm_every_transaction: true,
            show_details: true,
            simulate_before_send: true,
            show_simulation: true,
            optimize_compute_units: true,
            compute_unit_margin_percent: 10,
            cache_unlocked_in_shell: true,
        }
    }
}
impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            fetch_on_start: false,
            interval_secs: None,
            wallets: Vec::new(),
            limit: 10,
        }
    }
}

pub fn default_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".solx")
}

pub fn default_path() -> PathBuf {
    default_dir().join("config.toml")
}

pub fn load(path: &Path) -> Result<Config> {
    let mut config = if path.exists() {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if metadata.len() > 64 * 1024 {
            return fail("config is too large");
        }
        let mut content = String::with_capacity(metadata.len() as usize);
        file.take(64 * 1024 + 1).read_to_string(&mut content)?;
        if content.len() > 64 * 1024 {
            return fail("config is too large");
        }
        toml::from_str::<Config>(&content)?
    } else {
        Config::default()
    };
    config.vault = expand_home(&config.vault);
    config.validate()?;
    Ok(config)
}

fn expand_home(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        default_dir()
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf()
    } else if let Some(rest) = text.strip_prefix("~/") {
        default_dir().parent().unwrap_or(Path::new(".")).join(rest)
    } else {
        path.to_path_buf()
    }
}

impl Config {
    fn validate(&self) -> Result<()> {
        if !(1..=120).contains(&self.rpc.timeout_secs) {
            return fail("rpc.timeout_secs must be 1..=120");
        }
        if !(1..=100).contains(&self.history.limit) {
            return fail("history.limit must be 1..=100");
        }
        if self.security.compute_unit_margin_percent > 100 {
            return fail("security.compute_unit_margin_percent must be 0..=100");
        }
        if self.history.wallets.len() > 16 {
            return fail("history.wallets supports at most 16 entries");
        }
        if let Some(interval) = self.history.interval_secs
            && interval < 10
        {
            return fail("history.interval_secs must be at least 10");
        }
        if self.aliases.len() > 64 {
            return fail("too many aliases");
        }
        for (name, words) in &self.aliases {
            if !valid_name(name)
                || words.is_empty()
                || words.len() > 16
                || words.iter().any(|word| word.len() > 256)
            {
                return fail("invalid command alias");
            }
        }
        if let Some(url) = &self.rpc.url {
            let parsed = reqwest::Url::parse(url)?;
            let local = matches!(
                parsed.host_str(),
                Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
            );
            if parsed.scheme() != "https" && !(parsed.scheme() == "http" && local) {
                return fail("RPC must use HTTPS, except loopback HTTP");
            }
            if parsed.username() != "" || parsed.password().is_some() {
                return fail("RPC URL must not contain credentials");
            }
        }
        Ok(())
    }

    pub fn rpc_timeout(&self) -> Duration {
        Duration::from_secs(self.rpc.timeout_secs)
    }

    pub fn expand_alias(&self, args: &[String]) -> Result<Vec<String>> {
        let Some(first) = args.first() else {
            return Ok(Vec::new());
        };
        if let Some(prefix) = self.aliases.get(first) {
            let mut expanded = prefix.clone();
            expanded.extend_from_slice(&args[1..]);
            Ok(expanded)
        } else {
            Ok(args.to_vec())
        }
    }
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub const EXAMPLE: &str = include_str!("../config.example.toml");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_example_parses() {
        let config: Config = toml::from_str(EXAMPLE).unwrap();
        assert_eq!(config.mode, Mode::Cli);
        config.validate().unwrap();
    }
    #[test]
    fn alias_expands_once() {
        let mut config = Config::default();
        config.aliases.insert(
            "x1".into(),
            vec!["list".into(), "--wallet".into(), "main".into()],
        );
        assert_eq!(
            config.expand_alias(&["x1".into()]).unwrap(),
            ["list", "--wallet", "main"]
        );
    }
}
