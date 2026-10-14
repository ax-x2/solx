#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("solx supports Linux and macOS only");

mod commands;
mod config;
mod kdf;
mod line_editor;
mod rpc;
mod secret;
mod secure_file;
mod settings;
mod signer;
#[cfg(test)]
mod test_alloc;
#[cfg(test)]
mod test_support;
mod vault;

use crate::{
    config::{Config, Mode},
    vault::{Session, Vault},
};
use std::{
    error::Error,
    io::{self, BufRead, Write},
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn fail<T>(message: &str) -> Result<T> {
    Err(message.to_owned().into())
}

pub struct App {
    config: Config,
    session: Option<Session>,
    shell: bool,
    last_history: Option<Instant>,
}

impl App {
    fn unlock(&mut self) -> Result<&Session> {
        if self.session.is_none() {
            kdf::prepare_memlock_allowance()?;
            let password = secret::prompt("Vault password: ", 1024)?;
            self.session = Some(Session::open(&self.config.vault, &password)?);
        }
        Ok(self.session.as_ref().expect("session just opened"))
    }

    fn vault(&mut self) -> Result<Vault> {
        self.unlock()?.load()
    }
    fn release_session(&mut self) {
        if !self.shell || !self.config.security.cache_unlocked_in_shell {
            self.session = None;
        }
    }
    fn public_vault(&mut self) -> Result<vault::PublicVault> {
        let result = self.vault().map(|vault| vault.public_snapshot());
        self.release_session();
        result
    }
    fn load_policy(&mut self) -> Result<()> {
        let path = self.config.vault.clone();
        let mut vault = self.vault()?;
        self.config = std::mem::take(&mut vault.config);
        self.config.vault = path;
        drop(vault);
        self.release_session();
        if self.config.security.cache_unlocked_in_shell {
            eprintln!("Session caching is enabled: use 'lock' to clear the unlocking key.");
        }
        Ok(())
    }
    fn save_vault(&mut self, vault: &mut Vault) -> Result<()> {
        self.unlock()?.save(vault)
    }

    fn remember_recipient(&mut self, target: &solana_pubkey::Pubkey) {
        let result = (|| -> Result<()> {
            let mut vault = self.vault()?;
            if !vault.is_known_recipient(target) {
                vault.remember_recipient(target);
                self.save_vault(&mut vault)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("Transfer confirmed, but could not remember recipient: {error}");
        }
    }

    fn with_session<T>(&mut self, operation: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let result = operation(self);
        if !self.config.security.cache_unlocked_in_shell {
            self.session = None;
        }
        result
    }
    fn rpc(&self) -> Result<rpc::Rpc> {
        let rpc = rpc::Rpc::new(&self.config)?;
        rpc.verify_cluster()?;
        Ok(rpc)
    }

    fn dispatch(&mut self, words: &[String]) -> Result<()> {
        let words = Zeroizing::new(self.config.expand_alias(words)?);
        self.dispatch_resolved(&words)
    }

    fn dispatch_resolved(&mut self, words: &[String]) -> Result<()> {
        self.with_session(|app| {
            let Some(command) = words.first() else {
                return Ok(());
            };
            let plugin = commands::PLUGINS
                .iter()
                .find(|p| p.name == command)
                .ok_or_else(|| format!("unknown command '{command}'; use 'help'"))?;
            (plugin.run)(app, &words[1..])
        })
    }

    fn refresh_history(&mut self, force: bool) -> Result<()> {
        self.with_session(|app| app.refresh_history_inner(force))
    }

    fn refresh_history_inner(&mut self, force: bool) -> Result<()> {
        let history = &self.config.history;
        if !force {
            let Some(interval) = history.interval_secs else {
                return Ok(());
            };
            if self
                .last_history
                .is_some_and(|t| t.elapsed() < Duration::from_secs(interval))
            {
                return Ok(());
            }
        }
        if history.wallets.is_empty() {
            return Ok(());
        }
        let wallets = history.wallets.clone();
        let limit = history.limit;
        self.last_history = Some(Instant::now());
        let vault = self.public_vault()?;
        let mut rpc = None;
        for name in wallets {
            if !vault.contains(&name) {
                eprintln!("History: skipping unknown wallet '{name}'.");
                continue;
            }
            let account = vault.account(&name)?;
            let rpc = match &rpc {
                Some(rpc) => rpc,
                None => rpc.insert(self.rpc()?),
            };
            let rows = rpc.signatures(&account.pubkey, limit)?;
            println!("History for {name} ({}):", account.pubkey);
            commands::print_history(&rows);
        }
        Ok(())
    }

    fn shell(&mut self) -> Result<()> {
        self.shell = true;
        let mut history = line_editor::CommandHistory::default();
        println!("Solana wallet CLI. Type 'help' or 'exit'.");
        if self.config.history.fetch_on_start
            && let Err(error) = self.refresh_history(true)
        {
            eprintln!("History refresh: {error}");
        } else if !self.config.history.fetch_on_start {
            self.last_history = Some(Instant::now());
        }
        loop {
            if let Err(error) = self.refresh_history(false) {
                eprintln!("History refresh: {error}");
            }
            print!("solx> ");
            io::stdout().flush()?;
            let line = match history.read_line("solx> ") {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(error) => {
                    eprintln!("Error: {error}");
                    continue;
                }
            };
            let line = Zeroizing::new(line);
            let words = Zeroizing::new(
                line.split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            );
            if matches!(words.first().map(String::as_str), Some("exit" | "quit")) {
                break;
            }
            let words = Zeroizing::new(self.config.expand_alias(&words)?);
            history.remember(&line, &words);
            if let Err(error) = self.dispatch_resolved(&words) {
                eprintln!("Error: {error}");
            }
        }
        self.session = None;
        Ok(())
    }
}

fn read_bounded_line() -> io::Result<Option<String>> {
    const MAX_LINE: usize = 4096;
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let mut bytes = Zeroizing::new(Vec::with_capacity(128));
    let mut seen = false;
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if !seen {
                return Ok(None);
            }
            break;
        }
        seen = true;
        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |i| i + 1);
        let complete = end <= available.len() && available[end - 1] == b'\n';
        if !oversized {
            if bytes.len() + end <= MAX_LINE {
                bytes.extend_from_slice(&available[..end]);
            } else {
                oversized = true;
            }
        }
        reader.consume(end);
        if complete {
            break;
        }
    }
    if oversized {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "command line exceeds 4096 bytes",
        ));
    }
    String::from_utf8(std::mem::take(&mut *bytes))
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "command line is not UTF-8"))
}

fn run() -> Result<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut config = Config::default();
    if args.first().is_some_and(|a| a == "--config") {
        return fail("external config is not supported; use solx config to edit vault settings");
    }
    if args.first().is_some_and(|a| a == "--vault") {
        if args.len() < 2 {
            return fail("--vault needs a path");
        }
        config.vault = PathBuf::from(args.remove(1));
        args.remove(0);
    }
    let shell = args.is_empty() || args[0] == "shell";
    let mut app = App {
        config,
        session: None,
        shell,
        last_history: None,
    };
    if !matches!(
        args.first().map(String::as_str),
        Some("init" | "help" | "config")
    ) {
        app.load_policy()?;
    }
    if args.is_empty() {
        return match app.config.mode {
            Mode::Cli => app.shell(),
            Mode::Ui => fail("soon; set mode = 'cli'"),
        };
    }
    if args[0] == "shell" {
        return app.shell();
    }
    app.dispatch(&args)
}

fn main() {
    if let Err(error) = secret::protect_process().and_then(|()| run()) {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_snapshots_release_non_cached_secrets() {
        let mut wallet = crate::test_support::TestWallet::new();
        let snapshot = wallet.app.public_vault().unwrap();
        assert!(wallet.app.session.is_none());
        assert_eq!(
            snapshot.account("test").unwrap().pubkey,
            wallet.identity.pubkey
        );
    }

    #[test]
    fn policy_is_loaded_only_from_authenticated_vault() {
        let mut wallet = crate::test_support::TestWallet::new();
        let session = wallet.app.session.as_ref().unwrap();
        let mut vault = session.load().unwrap();
        let mut config = Config::default();
        config.aliases.insert("trusted".into(), vec!["list".into()]);
        vault.config = config;
        session.save(&mut vault).unwrap();
        wallet.app.load_policy().unwrap();
        assert_eq!(wallet.app.config.aliases["trusted"], ["list"]);
        assert!(wallet.app.session.is_none());
        assert!(wallet.app.config.vault.ends_with("vault.enc"));
    }

    fn app(cached: bool) -> App {
        let mut config = Config::default();
        config.security.cache_unlocked_in_shell = cached;
        // An empty path always fails to load, without reading any user's wallet.
        config.vault = PathBuf::new();
        App {
            config,
            session: Some(Session::test_session(std::path::Path::new(""))),
            shell: true,
            last_history: None,
        }
    }

    #[test]
    fn session_cleanup_covers_command_and_history_result_paths() {
        let mut success = app(false);
        success.dispatch(&[]).unwrap();
        assert!(success.session.is_none());
        let mut failure = app(false);
        assert!(failure.dispatch(&["unknown".into()]).is_err());
        assert!(failure.session.is_none());
        let mut history = app(false);
        history.refresh_history(true).unwrap();
        assert!(history.session.is_none());
        for force in [false, true] {
            let mut history = app(false);
            history.config.history.wallets.push("main".into());
            history.config.history.interval_secs = Some(10);
            assert!(history.refresh_history(force).is_err());
            assert!(history.session.is_none());
        }
        let mut cached = app(true);
        cached.dispatch(&[]).unwrap();
        assert!(cached.session.is_some());
    }
}
