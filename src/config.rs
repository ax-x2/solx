use crate::{Result, fail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    #[serde(skip)]
    pub vault: PathBuf,
    pub mode: Mode,
    pub rpc: RpcConfig,
    pub security: SecurityConfig,
    pub history: HistoryConfig,
    pub aliases: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Cli,
    Ui,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct RpcConfig {
    pub url: Option<String>,
    pub cluster: String,
    pub expected_genesis_hash: Option<String>,
    pub timeout_secs: u64,
    pub show_balances: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
            cluster: "mainnet".into(),
            expected_genesis_hash: None,
            timeout_secs: 15,
            show_balances: false,
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
            cache_unlocked_in_shell: false,
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

impl Config {
    /// Compare persisted settings, excluding the launch-only vault locator.
    pub fn same_settings(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.rpc == other.rpc
            && self.security == other.security
            && self.history == other.history
            && self.aliases == other.aliases
    }

    pub fn validate(&self) -> Result<()> {
        crate::rpc::expected_genesis(self)?;
        match self.rpc.cluster.as_str() {
            "mainnet" | "devnet" | "testnet" => {}
            "custom" if self.rpc.expected_genesis_hash.is_some() => {}
            _ => {
                return fail(
                    "cluster must be mainnet, devnet, testnet, or custom with expected_genesis_hash",
                );
            }
        }
        if let Some(hash) = &self.rpc.expected_genesis_hash {
            use std::str::FromStr;
            solana_message::Hash::from_str(hash)?;
        }
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
                || matches!(name.as_str(), "shell" | "exit" | "quit")
                || crate::commands::PLUGINS
                    .iter()
                    .any(|command| command.name == name)
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

#[cfg(test)]
pub const EXAMPLE: &str = include_str!("../config.example.toml");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn balance_queries_default_off_and_changes_are_persisted_settings() {
        let mut config = Config::default();
        assert!(!config.rpc.show_balances);
        assert!(
            !serde_json::from_str::<Config>("{\"rpc\":{}}")
                .unwrap()
                .rpc
                .show_balances
        );
        let original = config.clone();
        config.rpc.show_balances = true;
        assert!(!config.same_settings(&original));
        let stored = serde_json::to_vec(&config).unwrap();
        assert!(
            serde_json::from_slice::<Config>(&stored)
                .unwrap()
                .rpc
                .show_balances
        );
    }

    #[test]
    fn aliases_cannot_shadow_commands_and_caching_defaults_off() {
        let mut config = Config::default();
        assert!(!config.security.cache_unlocked_in_shell);
        for name in crate::commands::PLUGINS
            .iter()
            .map(|p| p.name)
            .chain(["shell", "exit", "quit"])
        {
            config.aliases.clear();
            config.aliases.insert(name.into(), vec!["transfer".into()]);
            assert!(config.validate().is_err(), "{name}");
        }
    }
    #[test]
    fn stored_locator_is_rejected() {
        assert!(
            toml::from_str::<Config>("vault = '/attacker/vault.enc'")
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
        assert!(
            !toml::to_string(&Config::default())
                .unwrap()
                .contains("vault")
        );
    }
    #[test]
    fn custom_networks_require_a_pin_and_known_pins_cannot_be_overridden() {
        let mut config = Config::default();
        config.rpc.cluster = "custom".into();
        assert!(config.validate().is_err());
        config.rpc.expected_genesis_hash =
            Some(solana_message::Hash::new_from_array([7; 32]).to_string());
        config.validate().unwrap();
        config.rpc.cluster = "mainnet".into();
        assert!(config.validate().is_err());
    }
    #[test]
    fn config_example_parses() {
        let config: Config = toml::from_str(EXAMPLE).unwrap();
        assert_eq!(config.mode, Mode::Cli);
        config.validate().unwrap();
    }
    #[test]
    fn alias_expands_once() {
        let mut config = Config::default();
        config
            .aliases
            .insert("x1".into(), vec!["list".into(), "main".into()]);
        assert_eq!(
            config.expand_alias(&["x1".into()]).unwrap(),
            ["list", "main"]
        );
    }
}
