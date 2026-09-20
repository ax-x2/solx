mod commands;
mod config;
mod line_editor;
mod rpc;
mod signer;
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
    config_path: PathBuf,
    session: Option<Session>,
    shell: bool,
    last_history: Option<Instant>,
}

impl App {
    fn unlock(&mut self) -> Result<&Session> {
        if self.session.is_none() {
            let password = Zeroizing::new(rpassword::prompt_password("Vault password: ")?);
            self.session = Some(Session::open(&self.config.vault, &password)?);
        }
        Ok(self.session.as_ref().expect("session just opened"))
    }

    fn vault(&mut self) -> Result<Vault> {
        self.unlock()?.load()
    }
    fn save_vault(&mut self, vault: &Vault) -> Result<()> {
        self.unlock()?.save(vault)
    }
    fn rpc(&self) -> Result<rpc::Rpc> {
        rpc::Rpc::new(&self.config)
    }

    fn dispatch(&mut self, words: &[String]) -> Result<()> {
        let words = Zeroizing::new(self.config.expand_alias(words)?);
        let Some(command) = words.first() else {
            return Ok(());
        };
        let plugin = commands::PLUGINS
            .iter()
            .find(|p| p.name == command)
            .ok_or_else(|| format!("unknown command '{command}'; use 'help'"))?;
        let result = (plugin.run)(self, &words[1..]);
        if self.shell && !self.config.security.cache_unlocked_in_shell {
            self.session = None;
        }
        result
    }

    fn refresh_history(&mut self, force: bool) -> Result<()> {
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
        let vault = self.vault()?;
        let rpc = self.rpc()?;
        for name in wallets {
            let account = vault.account(&name)?;
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
            history.remember(&line);
            let words = Zeroizing::new(
                line.split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            );
            if matches!(words.first().map(String::as_str), Some("exit" | "quit")) {
                break;
            }
            if let Err(error) = self.dispatch(&words) {
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
    let mut config_path = config::default_path();
    if args.first().is_some_and(|a| a == "--config") {
        if args.len() < 2 {
            return fail("--config needs a path");
        }
        config_path = PathBuf::from(args.remove(1));
        args.remove(0);
    }
    let config = config::load(&config_path)?;
    let mut app = App {
        config,
        config_path,
        session: None,
        shell: false,
        last_history: None,
    };
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
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}
