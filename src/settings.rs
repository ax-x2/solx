//! Foreground settings editing; no work here runs in prepared signing.
use crate::{
    App, Result,
    config::{Config, valid_name},
    fail,
    line_editor::CommandHistory,
    secret::LockedBytes,
    vault::ConfigAudit,
};
use std::{
    io::{self, IsTerminal, Write},
    str::FromStr,
    time::Instant,
};
use zeroize::Zeroizing;

trait EditorIo {
    fn write(&mut self, text: &str) -> Result<()>;
    fn read(&mut self, prompt: &str) -> Result<Option<Zeroizing<String>>>;
}

fn read_input(io: &mut impl EditorIo, prompt: &str) -> Result<Option<Zeroizing<String>>> {
    let input = io.read(prompt)?;
    if input.as_ref().is_some_and(|value| value.trim() == "exit") {
        io.write("Settings edit cancelled.\n")?;
        // Every nested editor propagates None as cancellation of the whole draft.
        return Ok(None);
    }
    Ok(input)
}

#[derive(Default)]
struct Terminal {
    input: CommandHistory,
}
impl EditorIo for Terminal {
    fn write(&mut self, text: &str) -> Result<()> {
        let mut output = io::stdout().lock();
        output.write_all(text.as_bytes())?;
        output.flush()?;
        Ok(())
    }
    fn read(&mut self, prompt: &str) -> Result<Option<Zeroizing<String>>> {
        self.write(prompt)?;
        // Never remember settings input in the shell's command history.
        Ok(self.input.read_edit_line(prompt)?.map(Zeroizing::new))
    }
}

pub fn run(app: &mut App, args: &[String]) -> Result<()> {
    if !args.is_empty() && args != ["show"] {
        return fail("usage: solx config [show]; config import has been removed");
    }
    if args.is_empty() && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        return fail(
            "config editing requires an interactive terminal; use config show to inspect settings",
        );
    }
    run_with_io(app, args.is_empty(), &mut Terminal::default())
}

fn run_with_io(app: &mut App, editing: bool, io: &mut impl EditorIo) -> Result<()> {
    let result = (|| {
        let mut vault = app.vault()?;
        let audit = vault.config_audit();
        let revision = vault
            .revision()
            .ok_or("settings require a saved vault")?
            .to_vec();
        let mut original = std::mem::take(&mut vault.config);
        original.vault = app.config.vault.clone();
        drop(vault); // Do not retain wallet secrets while waiting for input.
        app.config = original.clone();
        show_audit(io, audit)?;
        if !editing {
            return show_config(io, &original);
        }
        if let Some(candidate) = edit(io, &original)? {
            let audit = commit(app, &revision, candidate)?;
            io.write("Settings saved in the authenticated vault.\n")?;
            show_audit(io, audit)?;
        }
        Ok(())
    })();
    app.release_session();
    result
}

fn commit(app: &mut App, original_revision: &[u8], candidate: Config) -> Result<ConfigAudit> {
    candidate.validate()?;
    check_size(&candidate)?;
    let mut current = app.vault()?;
    if current.revision() != Some(original_revision) {
        return fail("vault changed while editing; reopen config and review the current settings");
    }
    current.config = candidate;
    let result = app.save_vault(&mut current);
    // The revision changes exactly at rename, including a later sync failure.
    // Adopt committed settings even if durability could not be confirmed.
    if current.revision() != Some(original_revision) {
        app.config = std::mem::take(&mut current.config);
        app.last_history = Some(Instant::now());
    }
    result?;
    Ok(current.config_audit())
}

fn show_audit(io: &mut impl EditorIo, audit: ConfigAudit) -> Result<()> {
    let last = match audit.last_edit() {
        None => "never".to_owned(),
        Some(seconds) => format!("{} (local system clock)", utc_time(seconds)?),
    };
    io.write(&format!(
        "Settings edits: {}\nLast settings edit: {last}\n\
         Protection: authenticated with this vault. Older vault restores and \
         edits by a password holder cannot be detected; time is not independently verified.\n",
        audit.edits()
    ))
}

fn utc_time(seconds: u64) -> Result<String> {
    let seconds = libc::time_t::try_from(seconds)?;
    let mut value = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: live input/output; gmtime_r initializes output on success.
    if unsafe { libc::gmtime_r(&seconds, value.as_mut_ptr()) }.is_null() {
        return fail("settings timestamp cannot be displayed");
    }
    let value = unsafe { value.assume_init() };
    Ok(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        value.tm_year + 1900,
        value.tm_mon + 1,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        value.tm_sec
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Url,
    Cluster,
    Pin,
    Timeout,
    Balances,
    Confirm,
    Details,
    Simulate,
    Simulation,
    Compute,
    Margin,
    Cache,
    Fetch,
    Interval,
    Limit,
}
const RPC: &[(Field, &str)] = &[
    (Field::Url, "RPC URL"),
    (Field::Cluster, "Cluster"),
    (Field::Pin, "Expected genesis hash"),
    (Field::Timeout, "Timeout seconds"),
    (Field::Balances, "Show balances"),
];
const SECURITY: &[(Field, &str)] = &[
    (Field::Confirm, "Confirm every transaction"),
    (Field::Details, "Show details"),
    (Field::Simulate, "Simulate before sending"),
    (Field::Simulation, "Show simulation"),
    (Field::Compute, "Optimize compute units"),
    (Field::Margin, "Compute margin percent"),
    (Field::Cache, "Keep vault unlocked in shell"),
];
const HISTORY: &[(Field, &str)] = &[
    (Field::Fetch, "Fetch on startup"),
    (Field::Interval, "Refresh interval seconds"),
    (Field::Limit, "History entry limit"),
];
const GROUPS: &[(&str, &[(Field, &str)])] =
    &[("RPC", RPC), ("Security", SECURITY), ("History", HISTORY)];

impl Field {
    fn read_only(self, config: &Config) -> bool {
        self == Self::Pin && config.rpc.cluster != "custom"
    }

    fn value(self, config: &Config) -> String {
        match self {
            Self::Url => config
                .rpc
                .url
                .as_ref()
                .map_or_else(|| "not set".into(), |url| format!("{url:?}")),
            Self::Cluster => format!("{:?}", config.rpc.cluster),
            Self::Pin => {
                let value = match crate::rpc::expected_genesis(config) {
                    Ok(hash) => hash.to_owned(),
                    Err(error) => format!("not available ({error})"),
                };
                if self.read_only(config) {
                    format!("{value} [read-only]")
                } else {
                    value
                }
            }
            Self::Timeout => config.rpc.timeout_secs.to_string(),
            Self::Balances => config.rpc.show_balances.to_string(),
            Self::Confirm => config.security.confirm_every_transaction.to_string(),
            Self::Details => config.security.show_details.to_string(),
            Self::Simulate => config.security.simulate_before_send.to_string(),
            Self::Simulation => config.security.show_simulation.to_string(),
            Self::Compute => config.security.optimize_compute_units.to_string(),
            Self::Margin => config.security.compute_unit_margin_percent.to_string(),
            Self::Cache => config.security.cache_unlocked_in_shell.to_string(),
            Self::Fetch => config.history.fetch_on_start.to_string(),
            Self::Interval => format!("{:?}", config.history.interval_secs),
            Self::Limit => config.history.limit.to_string(),
        }
    }

    fn set(self, config: &mut Config, input: &str) -> Result<()> {
        if self.read_only(config) {
            return fail("genesis hash is read-only for built-in networks");
        }
        let number = |min, max| -> Result<u64> {
            let value: u64 = input.parse().map_err(|_| "expected an unsigned integer")?;
            if !(min..=max).contains(&value) {
                return fail(&format!("value must be {min}..={max}"));
            }
            Ok(value)
        };
        let boolean = || -> Result<bool> {
            match input {
                "on" | "true" => Ok(true),
                "off" | "false" => Ok(false),
                _ => fail("use on or off"),
            }
        };
        match self {
            Self::Url => {
                let url = (input != "clear").then(|| input.to_owned());
                let mut check = Config::default();
                check.rpc.url = url.clone();
                check.validate()?;
                config.rpc.url = url;
            }
            Self::Cluster => {
                if !matches!(input, "mainnet" | "devnet" | "testnet" | "custom") {
                    return fail("use mainnet, devnet, testnet, or custom");
                }
                if config.rpc.cluster != input {
                    config.rpc.expected_genesis_hash = None;
                    config.rpc.cluster = input.into();
                }
            }
            Self::Pin => {
                if input == "clear" {
                    config.rpc.expected_genesis_hash = None;
                } else {
                    solana_message::Hash::from_str(input)?;
                    config.rpc.expected_genesis_hash = Some(input.into());
                }
            }
            Self::Timeout => config.rpc.timeout_secs = number(1, 120)?,
            Self::Balances => config.rpc.show_balances = boolean()?,
            Self::Confirm => config.security.confirm_every_transaction = boolean()?,
            Self::Details => config.security.show_details = boolean()?,
            Self::Simulate => config.security.simulate_before_send = boolean()?,
            Self::Simulation => config.security.show_simulation = boolean()?,
            Self::Compute => config.security.optimize_compute_units = boolean()?,
            Self::Margin => config.security.compute_unit_margin_percent = number(0, 100)? as u8,
            Self::Cache => config.security.cache_unlocked_in_shell = boolean()?,
            Self::Fetch => config.history.fetch_on_start = boolean()?,
            Self::Interval => {
                config.history.interval_secs = if input == "clear" {
                    None
                } else {
                    Some(number(10, u64::MAX)?)
                }
            }
            Self::Limit => config.history.limit = number(1, 100)? as usize,
        }
        Ok(())
    }
}

fn check_size(config: &Config) -> Result<()> {
    let mut bytes = LockedBytes::with_capacity(64 * 1024)?;
    serde_json::to_writer(&mut bytes, config).map_err(|_| "settings exceed 64 KiB")?;
    Ok(())
}

fn show_config(io: &mut impl EditorIo, config: &Config) -> Result<()> {
    for (name, fields) in GROUPS {
        io.write(&format!("\n{name}:\n"))?;
        for (field, label) in *fields {
            io.write(&format!("  {label}: {}\n", field.value(config)))?;
        }
    }
    io.write(&format!(
        "  Wallets: {:?}\n\nAliases:\n",
        config.history.wallets
    ))?;
    show_aliases(io, config)
}

fn show_aliases(io: &mut impl EditorIo, config: &Config) -> Result<()> {
    for (name, words) in &config.aliases {
        io.write(&format!("  {name:?}: {words:?}\n"))?;
    }
    Ok(())
}

fn review(io: &mut impl EditorIo, old: &Config, new: &Config) -> Result<()> {
    io.write("\nSettings changes:\n")?;
    for (group, fields) in GROUPS {
        for (field, label) in *fields {
            let before = field.value(old);
            let after = field.value(new);
            if before != after {
                io.write(&format!(
                    "  {group} / {label}: {before} -> {after} (changed)\n"
                ))?;
            }
        }
    }
    if old.history.wallets != new.history.wallets {
        io.write(&format!(
            "  History wallets: {:?} -> {:?}\n",
            old.history.wallets, new.history.wallets
        ))?;
    }
    if old.aliases != new.aliases {
        io.write("  Aliases before:\n")?;
        show_aliases(io, old)?;
        io.write("  Aliases after:\n")?;
        show_aliases(io, new)?;
    }
    Ok(())
}

fn edit(io: &mut impl EditorIo, original: &Config) -> Result<Option<Config>> {
    let mut draft = original.clone();
    loop {
        io.write(concat!(
            "\nSettings\n",
            "  1 RPC (URL, Cluster, Genesis hash, Timeout, Show balances)\n",
            "  2 Security (Confirm, Details, Simulate, Simulation output, Compute units, Margin, Session cache)\n",
            "  3 History (Startup fetch, Refresh interval, Wallets, Limit)\n",
            "  4 Aliases (Names, Command words)\n",
            "  s Save\n  c Cancel\n",
            "Type exit at any prompt to leave config without saving.\n",
        ))?;
        let Some(input) = read_input(io, "config> ")? else {
            return Ok(None);
        };
        match input.trim() {
            "1" | "2" | "3" => {
                let group = input.trim().parse::<usize>()? - 1;
                if !edit_group(io, &mut draft, group)? {
                    return Ok(None);
                }
            }
            "4" => {
                if !edit_aliases(io, &mut draft)? {
                    return Ok(None);
                }
            }
            "s" | "save" => {
                if draft.same_settings(original) {
                    io.write("No settings changes.\n")?;
                    return Ok(None);
                }
                if let Err(error) = draft.validate().and_then(|()| check_size(&draft)) {
                    io.write(&format!("Cannot save: {error}\n"))?;
                    continue;
                }
                review(io, original, &draft)?;
                let Some(answer) =
                    read_input(io, "Type SAVE to apply, or Enter to keep editing: ")?
                else {
                    return Ok(None);
                };
                if answer.trim() == "SAVE" {
                    return Ok(Some(draft));
                }
            }
            "c" | "cancel" => {
                io.write("Settings edit cancelled.\n")?;
                return Ok(None);
            }
            "" => {}
            _ => io.write("Choose 1-4, s, c, or exit.\n")?,
        }
    }
}

fn edit_group(io: &mut impl EditorIo, draft: &mut Config, group: usize) -> Result<bool> {
    let (name, fields) = GROUPS[group];
    loop {
        io.write(&format!("\n{name}:\n"))?;
        for (index, (field, label)) in fields.iter().enumerate() {
            io.write(&format!(
                "  {} {label}: {}\n",
                index + 1,
                field.value(draft)
            ))?;
        }
        if group == 2 {
            io.write(&format!("  4 Wallets: {:?}\n", draft.history.wallets))?;
        }
        io.write("  b Back\n")?;
        let Some(input) = read_input(io, "field> ")? else {
            return Ok(false);
        };
        if matches!(input.trim(), "b" | "back" | "") {
            return Ok(true);
        }
        if group == 2 && input.trim() == "4" {
            if !edit_wallets(io, draft)? {
                return Ok(false);
            }
            continue;
        }
        let field = input
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| fields.get(i));
        let Some((field, label)) = field else {
            io.write("Unknown field.\n")?;
            continue;
        };
        if field.read_only(draft) {
            io.write("Genesis hash is read-only for built-in networks.\n")?;
            continue;
        }
        let prompt =
            format!("{label} (Enter keeps; on/off for booleans; clear unsets optional values): ");
        let Some(value) = read_input(io, &prompt)? else {
            return Ok(false);
        };
        if value.trim().is_empty() {
            continue;
        }
        let mut next = draft.clone();
        match field
            .set(&mut next, value.trim())
            .and_then(|()| check_size(&next))
        {
            Ok(()) => *draft = next,
            Err(error) => io.write(&format!("Invalid value: {error}\n"))?,
        }
    }
}

fn edit_wallets(io: &mut impl EditorIo, draft: &mut Config) -> Result<bool> {
    let Some(action) = read_input(io, "Wallet action (add/remove/clear/back): ")? else {
        return Ok(false);
    };
    let action = action.trim();
    if matches!(action, "back" | "") {
        return Ok(true);
    }
    let mut next = draft.clone();
    if action == "clear" {
        next.history.wallets.clear();
    } else if matches!(action, "add" | "remove") {
        let Some(name) = read_input(io, "Wallet name: ")? else {
            return Ok(false);
        };
        let name = name.trim();
        if !valid_name(name) {
            io.write("Invalid wallet name.\n")?;
            return Ok(true);
        }
        if action == "remove" {
            next.history.wallets.retain(|n| n != name);
        } else if !next.history.wallets.iter().any(|n| n == name) {
            if next.history.wallets.len() >= 16 {
                io.write("At most 16 history wallets.\n")?;
                return Ok(true);
            }
            next.history.wallets.push(name.into());
        }
    } else {
        io.write("Unknown wallet action.\n")?;
        return Ok(true);
    }
    check_size(&next)?;
    *draft = next;
    Ok(true)
}

fn edit_aliases(io: &mut impl EditorIo, draft: &mut Config) -> Result<bool> {
    show_aliases(io, draft)?;
    let Some(action) = read_input(io, "Alias action (set/remove/back): ")? else {
        return Ok(false);
    };
    if matches!(action.trim(), "back" | "") {
        return Ok(true);
    }
    if !matches!(action.trim(), "set" | "remove") {
        io.write("Unknown alias action.\n")?;
        return Ok(true);
    }
    let Some(name) = read_input(io, "Alias name: ")? else {
        return Ok(false);
    };
    let name = name.trim();
    if !valid_name(name) {
        io.write("Invalid alias name.\n")?;
        return Ok(true);
    }
    let mut next = draft.clone();
    if action.trim() == "remove" {
        next.aliases.remove(name);
    } else {
        let Some(words) = read_input(io, "Command words (space separated): ")? else {
            return Ok(false);
        };
        let words: Vec<String> = words
            .split_whitespace()
            .take(17)
            .map(str::to_owned)
            .collect();
        next.aliases.insert(name.into(), words);
    }
    let check = Config {
        aliases: next.aliases.clone(),
        ..Config::default()
    };
    match check.validate().and_then(|()| check_size(&next)) {
        Ok(()) => *draft = next,
        Err(error) => io.write(&format!("Invalid alias: {error}\n"))?,
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_support::{Fault, TestWallet, with_fault},
        vault::Session,
    };
    use std::{collections::VecDeque, fs};

    struct Script {
        input: VecDeque<String>,
        output: String,
    }
    impl Script {
        fn new(input: &[&str]) -> Self {
            Self {
                input: input.iter().map(|s| (*s).into()).collect(),
                output: String::new(),
            }
        }
    }
    impl EditorIo for Script {
        fn write(&mut self, text: &str) -> Result<()> {
            self.output.push_str(text);
            Ok(())
        }
        fn read(&mut self, _: &str) -> Result<Option<Zeroizing<String>>> {
            Ok(self.input.pop_front().map(Zeroizing::new))
        }
    }

    #[test]
    fn genesis_editor_locks_builtin_hashes_and_preserves_custom_pins() {
        let custom_hash = solana_message::Hash::new_from_array([7; 32]).to_string();
        for cluster in ["mainnet", "devnet", "testnet"] {
            let mut config = Config::default();
            config.rpc.cluster = cluster.into();
            let original = config.clone();
            assert!(Field::Pin.set(&mut config, &custom_hash).is_err());
            assert!(Field::Pin.set(&mut config, "clear").is_err());
            assert!(config.same_settings(&original));

            // Selecting the read-only row must not consume the next field choice.
            let mut script = Script::new(&["1", "3", "4", "22", "b", "s", "SAVE"]);
            let saved = edit(&mut script, &config).unwrap().unwrap();
            assert!(script.input.is_empty());
            assert_eq!(saved.rpc.timeout_secs, 22);
            assert_eq!(saved.rpc.expected_genesis_hash, None);
            let hash = crate::rpc::expected_genesis(&config).unwrap();
            assert!(script.output.contains(&format!("{hash} [read-only]")));
            let mut shown = Script::new(&[]);
            show_config(&mut shown, &saved).unwrap();
            assert!(shown.output.contains(&format!("{hash} [read-only]")));
        }

        let mut script = Script::new(&["1", "2", "custom", "3", &custom_hash, "b", "s", "SAVE"]);
        let mut custom = edit(&mut script, &Config::default()).unwrap().unwrap();
        assert_eq!(
            custom.rpc.expected_genesis_hash.as_deref(),
            Some(custom_hash.as_str())
        );
        custom.validate().unwrap();
        Field::Cluster.set(&mut custom, "custom").unwrap();
        assert_eq!(
            custom.rpc.expected_genesis_hash.as_deref(),
            Some(custom_hash.as_str())
        );
        assert!(Field::Pin.set(&mut custom, "invalid hash").is_err());
        Field::Cluster.set(&mut custom, "mainnet").unwrap();
        assert_eq!(custom.rpc.expected_genesis_hash, None);
        custom.validate().unwrap();
        Field::Cluster.set(&mut custom, "custom").unwrap();
        assert!(custom.validate().is_err());
    }

    #[test]
    fn editor_saves_all_groups_and_updates_session_policy_and_history() {
        let mut wallet = TestWallet::new();
        wallet.app.shell = true;
        let path = wallet.app.config.vault.clone();
        let mut script = Script::new(&[
            "1",
            "1",
            "https://provider.example/private-token?api-key=secret",
            "2",
            "devnet",
            "4",
            "22",
            "5",
            "on",
            "b",
            "2",
            "7",
            "on",
            "b",
            "3",
            "1",
            "on",
            "2",
            "60",
            "3",
            "20",
            "4",
            "add",
            "test",
            "b",
            "4",
            "set",
            "mine",
            "list test",
            "s",
            "SAVE",
        ]);
        run_with_io(&mut wallet.app, true, &mut script).unwrap();
        assert!(script.input.is_empty());
        assert!(
            script
                .output
                .contains("https://provider.example/private-token?api-key=secret")
        );
        assert!(script.output.contains("RPC / Show balances: false -> true"));
        assert!(wallet.app.config.rpc.show_balances);
        assert!(script.output.contains("Settings edits: 1"));
        assert!(script.output.contains("local system clock"));
        assert!(script.output.contains("cannot be detected"));
        assert!(wallet.app.session.is_some());
        let saved = Session::test_session(&path).load().unwrap();
        assert_eq!(saved.config.rpc.timeout_secs, 22);
        assert!(saved.config.rpc.show_balances);

        let mut shown = Script::new(&[]);
        run_with_io(&mut wallet.app, false, &mut shown).unwrap();
        assert!(
            shown
                .output
                .contains("https://provider.example/private-token?api-key=secret")
        );
        assert!(shown.output.contains("Show balances: true"));
        assert_eq!(saved.config.history.interval_secs, Some(60));
        assert_eq!(saved.config.history.wallets, ["test"]);
        assert_eq!(saved.config.aliases["mine"], ["list", "test"]);
        assert!(saved.config.security.confirm_every_transaction);
        assert_eq!(saved.config_audit().edits(), 1);

        let mut disable = Script::new(&["1", "5", "off", "b", "2", "7", "off", "b", "s", "SAVE"]);
        run_with_io(&mut wallet.app, true, &mut disable).unwrap();
        assert!(wallet.app.session.is_none());
        assert!(!wallet.app.config.rpc.show_balances);
        assert!(
            !Session::test_session(&path)
                .load()
                .unwrap()
                .config
                .rpc
                .show_balances
        );
        assert_eq!(
            Session::test_session(&path)
                .load()
                .unwrap()
                .config_audit()
                .edits(),
            2
        );
    }

    #[test]
    fn cancellation_noop_invalid_values_and_eof_never_write() {
        for input in [
            vec!["c"],
            vec!["1", "5", "on", "b", "c"],
            vec!["1", "5", "invalid", "b", "s"],
            vec!["s"],
            vec!["2", "7", "on", "b", "c"],
            vec!["2", "7", "on"],                       // EOF in a submenu
            vec!["1", "4", "0", "b", "s"],              // invalid timeout is discarded
            vec!["1", "2", "custom", "b", "s", "c"],    // missing genesis pin
            vec!["4", "set", "list", "list test", "s"], // reserved alias
        ] {
            let mut wallet = TestWallet::new();
            let before = fs::read(&wallet.app.config.vault).unwrap();
            let original = wallet.app.config.clone();
            let mut script = Script::new(&input);
            run_with_io(&mut wallet.app, true, &mut script).unwrap();
            assert!(original.same_settings(&wallet.app.config));
            assert!(wallet.app.session.is_none());
            assert_eq!(fs::read(&wallet.app.config.vault).unwrap(), before);
        }
    }

    #[test]
    fn exit_at_every_prompt_discards_draft_without_saving() {
        let paths: &[&[&str]] = &[
            &["exit"],
            &[" exit "],
            &["2", "exit"],
            &["1", "1", "exit"],
            &["s", "exit"],
            &["3", "4", "exit"],
            &["3", "4", "add", "exit"],
            &["4", "exit"],
            &["4", "set", "exit"],
            &["4", "set", "mine", "exit"],
        ];
        for path in paths {
            let mut wallet = TestWallet::new();
            wallet.app.shell = true;
            let before = fs::read(&wallet.app.config.vault).unwrap();
            let original = wallet.app.config.clone();
            // First make a real draft change, then exit at the selected prompt.
            let mut input = vec!["1", "4", "22", "back"];
            input.extend_from_slice(path);
            input.extend_from_slice(&["s", "SAVE"]);
            let mut script = Script::new(&input);
            run_with_io(&mut wallet.app, true, &mut script).unwrap();
            assert_eq!(
                script.input.iter().map(String::as_str).collect::<Vec<_>>(),
                ["s", "SAVE"],
                "editor kept reading after {path:?}"
            );
            assert_eq!(script.output.matches("Settings edit cancelled.").count(), 1);
            assert!(!script.output.contains("Settings saved"));
            assert!(original.same_settings(&wallet.app.config));
            assert!(wallet.app.shell);
            assert!(wallet.app.session.is_none());
            // Identical ciphertext also proves the authenticated audit did not change.
            assert_eq!(fs::read(&wallet.app.config.vault).unwrap(), before);
        }
    }

    #[test]
    fn values_containing_exit_remain_editable() {
        let mut script = Script::new(&[
            "1",
            "1",
            "https://provider.example/exit",
            "back",
            "4",
            "set",
            "mine",
            "list exit",
            "s",
            "SAVE",
        ]);
        let saved = edit(&mut script, &Config::default()).unwrap().unwrap();
        assert!(script.input.is_empty());
        assert_eq!(
            saved.rpc.url.as_deref(),
            Some("https://provider.example/exit")
        );
        assert_eq!(saved.aliases["mine"], ["list", "exit"]);
    }

    #[test]
    fn interrupted_input_discards_draft_and_releases_session() {
        struct Interrupted;
        impl EditorIo for Interrupted {
            fn write(&mut self, _: &str) -> Result<()> {
                Ok(())
            }
            fn read(&mut self, _: &str) -> Result<Option<Zeroizing<String>>> {
                Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled").into())
            }
        }
        let mut wallet = TestWallet::new();
        let before = fs::read(&wallet.app.config.vault).unwrap();
        assert!(run_with_io(&mut wallet.app, true, &mut Interrupted).is_err());
        assert!(wallet.app.session.is_none());
        assert_eq!(fs::read(&wallet.app.config.vault).unwrap(), before);
    }

    #[test]
    fn settings_save_failure_distinguishes_precommit_and_committed_state() {
        for point in [
            Fault::Random,
            Fault::Write,
            Fault::FileSync,
            Fault::Rename,
            Fault::DirectorySync,
        ] {
            let mut wallet = TestWallet::new();
            wallet.app.shell = true;
            let path = wallet.app.config.vault.clone();
            let before = fs::read(&path).unwrap();
            let mut script = Script::new(&["2", "7", "on", "b", "s", "SAVE"]);
            let error =
                with_fault(point, || run_with_io(&mut wallet.app, true, &mut script)).unwrap_err();
            let saved = Session::test_session(&path).load().unwrap();
            if point == Fault::DirectorySync {
                assert!(error.to_string().contains("vault saved"));
                assert!(wallet.app.config.security.cache_unlocked_in_shell);
                assert!(wallet.app.session.is_some());
                assert_eq!(saved.config_audit().edits(), 1);
                assert!(saved.config.security.cache_unlocked_in_shell);
            } else {
                assert_eq!(fs::read(&path).unwrap(), before);
                assert!(!wallet.app.config.security.cache_unlocked_in_shell);
                assert!(wallet.app.session.is_none());
                assert_eq!(saved.config_audit().edits(), 0);
            }
        }
    }

    #[test]
    fn settings_commit_rejects_concurrent_changes_without_overwriting_history() {
        let mut wallet = TestWallet::new();
        let session = Session::test_session(&wallet.app.config.vault);
        let mut vault = session.load().unwrap();
        let revision = vault.revision().unwrap().to_vec();
        vault.config.rpc.timeout_secs = 21;
        session.save(&mut vault).unwrap();
        let before = fs::read(&wallet.app.config.vault).unwrap();
        let mut candidate = wallet.app.config.clone();
        candidate.history.limit = 30;
        assert!(
            commit(&mut wallet.app, &revision, candidate)
                .unwrap_err()
                .to_string()
                .contains("vault changed")
        );
        assert_eq!(fs::read(&wallet.app.config.vault).unwrap(), before);
        assert_eq!(session.load().unwrap().config_audit().edits(), 1);
    }

    #[test]
    fn editor_bounds_clear_values_and_utc_display() {
        let mut draft = Config::default();
        assert!(Field::Timeout.set(&mut draft, "121").is_err());
        assert!(Field::Margin.set(&mut draft, "101").is_err());
        assert!(Field::Limit.set(&mut draft, "0").is_err());
        assert!(Field::Interval.set(&mut draft, "9").is_err());
        assert!(Field::Url.set(&mut draft, "http://remote.example").is_err());
        Field::Interval.set(&mut draft, "10").unwrap();
        Field::Interval.set(&mut draft, "clear").unwrap();
        assert_eq!(draft.history.interval_secs, None);
        Field::Url
            .set(&mut draft, "https://example.com/token")
            .unwrap();
        Field::Url.set(&mut draft, "clear").unwrap();
        assert_eq!(draft.rpc.url, None);
        for index in 0..64 {
            draft
                .aliases
                .insert(format!("a{index}"), vec!["list".into()]);
        }
        let mut input = Script::new(&["set", "extra", "list"]);
        edit_aliases(&mut input, &mut draft).unwrap();
        assert_eq!(draft.aliases.len(), 64);
        draft
            .aliases
            .values_mut()
            .for_each(|v| *v = vec!["x".repeat(256); 16]);
        assert!(check_size(&draft).is_err());
        assert_eq!(utc_time(1_700_000_000).unwrap(), "2023-11-14 22:13:20 UTC");
    }
}
