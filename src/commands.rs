use crate::secret::{LockedBytes, LockedKeypair};
use crate::{
    App, Result,
    config::valid_name,
    fail,
    rpc::{Rpc, TokenAccount, safe_text},
    signer::Keypair,
    vault::{self, Session},
};
use serde_json::Value;
use solana_message::{AccountMeta, Hash, Instruction, VersionedMessage, v0};
use solana_pubkey::Pubkey;
use solana_transaction::{Signature, versioned::VersionedTransaction};
use std::{
    collections::HashSet,
    fs,
    io::{self, Read, Write},
    path::Path,
    str::FromStr,
};

const SYSTEM: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
const TOKEN: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const TOKEN_2022: Pubkey = Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const ASSOCIATED_TOKEN: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const COMPUTE_BUDGET: Pubkey =
    Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");
const NATIVE_MINT: Pubkey = Pubkey::from_str_const("So11111111111111111111111111111111111111112");
const NATIVE_MINT_2022: Pubkey =
    Pubkey::from_str_const("9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP");
const MAX_TRANSACTION_BYTES: usize = 1232;
const MAX_COMPUTE_UNITS: u32 = 1_400_000;
const OUTPUT_RULE: &str = "------------------------------------------------";

pub struct Plugin {
    pub name: &'static str,
    pub summary: &'static str,
    pub run: fn(&mut App, &[String]) -> Result<()>,
}

pub static PLUGINS: &[Plugin] = &[
    Plugin {
        name: "config",
        summary: "edit vault settings or show authenticated settings history",
        run: crate::settings::run,
    },
    Plugin {
        name: "help",
        summary: "show commands",
        run: help,
    },
    Plugin {
        name: "init",
        summary: "create encrypted vault and first master wallet",
        run: init,
    },
    Plugin {
        name: "new",
        summary: "create a new recovery phrase, or share one with --wallet NAME",
        run: new_wallet,
    },
    Plugin {
        name: "import",
        summary: "import a mnemonic or private key",
        run: import,
    },
    Plugin {
        name: "export",
        summary: "show a private key or recovery phrase, with confirmation",
        run: export,
    },
    Plugin {
        name: "list",
        summary: "list wallets; query balances when enabled in config",
        run: list,
    },
    Plugin {
        name: "delete",
        summary: "delete a local wallet; optionally erase its unused recovery phrase",
        run: delete,
    },
    Plugin {
        name: "history",
        summary: "show recent signatures",
        run: history,
    },
    Plugin {
        name: "transfer",
        summary: "send SOL",
        run: transfer,
    },
    Plugin {
        name: "token-transfer",
        summary: "send SPL tokens",
        run: token_transfer,
    },
    Plugin {
        name: "close-ata",
        summary: "close empty ATAs, optionally burn balances first",
        run: close_ata,
    },
    Plugin {
        name: "lock",
        summary: "clear the unlocked session key",
        run: lock,
    },
    Plugin {
        name: "ui",
        summary: "(future version)",
        run: ui,
    },
];

fn help(_: &mut App, args: &[String]) -> Result<()> {
    no_args(args)?;
    println!(
        "Usage: solx [--vault PATH] <command> [options]\n       solx shell\n       solx config\n       solx config show"
    );
    for plugin in PLUGINS {
        println!("  {:<15} {}", plugin.name, plugin.summary);
    }
    println!(
        "\nCommands:\n  solx init [NAME]\n  solx new NAME [--wallet SOURCE]\n  solx import NAME (--mnemonic | --base58 | --keypair-file PATH)\n  solx export NAME (--private-key | --mnemonic)\n  solx list [NAME]\n  solx delete NAME\n  solx history [--wallet NAME] [--limit N]\n  solx transfer --wallet NAME --to ADDRESS --amount SOL|ALL\n  solx token-transfer --wallet NAME --mint MINT --to ADDRESS --amount TOKENS\n  solx close-ata [--wallet NAME] [--burn] (--all | MINT [MINT ...])"
    );
    Ok(())
}

fn no_args(args: &[String]) -> Result<()> {
    if args.is_empty() {
        Ok(())
    } else {
        fail("unexpected arguments; use 'help'")
    }
}

fn init(app: &mut App, args: &[String]) -> Result<()> {
    if args.len() > 1 {
        return fail("usage: solx init [NAME]");
    }
    let name = args.first().map(String::as_str).unwrap_or("main");
    if !valid_name(name) {
        return fail("invalid wallet name");
    }
    if app.config.vault.exists() {
        return fail("vault already exists");
    }
    crate::kdf::prepare_memlock_allowance()?;
    let password = crate::secret::prompt("New vault password: ", 1024)?;
    let confirmation = crate::secret::prompt("Repeat password: ", 1024)?;
    if password != confirmation {
        return fail("passwords do not match");
    }
    if password.len() < 12 {
        return fail("password must be at least 12 bytes");
    }
    let entropy = vault::fresh_entropy()?;
    let phrase = vault::phrase(&entropy)?;
    let mut data = vault::Vault::default();
    data.config = app.config.clone();
    data.add_master(name, entropy)?;
    let session = Session::create(&app.config.vault, &password, &mut data)?;
    let account = data.account(name)?;
    println!("Created {name}: {}", account.pubkey);
    println!(
        "Recovery phrase (shown once; store it securely):\n{}",
        phrase.as_str()
    );
    if app.shell && app.config.security.cache_unlocked_in_shell {
        app.session = Some(session);
    }
    Ok(())
}

fn new_wallet(app: &mut App, args: &[String]) -> Result<()> {
    new_wallet_with_output(app, args, &mut io::stdout())
}

fn new_wallet_with_output(app: &mut App, args: &[String], output: &mut impl Write) -> Result<()> {
    let (name, source) = match args {
        [name] => (name.as_str(), None),
        [name, flag, source] if flag == "--wallet" => (name.as_str(), Some(source.as_str())),
        _ => return fail("usage: solx new NAME [--wallet SOURCE]"),
    };
    if !valid_name(name) || name.starts_with('-') {
        return fail("invalid new wallet name; usage: solx new NAME [--wallet SOURCE]");
    }
    if source.is_some_and(|source| !valid_name(source) || source.starts_with('-')) {
        return fail("invalid source wallet name; usage: solx new NAME [--wallet SOURCE]");
    }
    let mut data = app.vault()?;
    if let Some(source) = source {
        data.add_derived(name, source)?;
        app.save_vault(&mut data)?;
        writeln!(output, "Created {name}: {}", data.account(name)?.pubkey)?;
        writeln!(output, "Shared recovery phrase with {source}.")?;
        writeln!(
            output,
            "Derivation path: m/44'/501'/{}'/0'",
            data.derivation_index(name)?
                .ok_or("missing derivation index")?
        )?;
    } else {
        let entropy = vault::fresh_entropy()?;
        let phrase = vault::phrase(&entropy)?;
        data.add_master(name, entropy)?;
        app.save_vault(&mut data)?;
        writeln!(output, "Created {name}: {}", data.account(name)?.pubkey)?;
        writeln!(
            output,
            "New recovery phrase (shown once; store it securely):\n{}",
            phrase.as_str()
        )?;
    }
    output.flush()?;
    Ok(())
}

fn import(app: &mut App, args: &[String]) -> Result<()> {
    if args.len() < 2 || args.len() > 3 {
        return fail("usage: solx import NAME (--mnemonic | --base58 | --keypair-file PATH)");
    }
    if args[1] == "--base58" && args.len() == 3 {
        return fail("inline private keys are disabled; omit KEY for a hidden prompt");
    }
    let name = &args[0];
    let data = app.public_vault()?;
    if data.contains(name) {
        return fail("wallet name already exists");
    }
    enum ImportedSecret {
        Mnemonic(LockedBytes),
        Key(LockedKeypair),
    }
    let imported = match args[1].as_str() {
        "--mnemonic" if args.len() == 2 => {
            let phrase = crate::secret::prompt("Mnemonic (hidden): ", 1024)?;
            let entropy = vault::parse_phrase(&phrase)?;
            ImportedSecret::Mnemonic(entropy)
        }
        "--base58" if args.len() == 2 => {
            let secret = crate::secret::prompt("Base58 private key (hidden): ", 90)?;
            ImportedSecret::Key(decode_base58_keypair(&secret)?)
        }
        "--keypair-file" if args.len() == 3 => {
            let path = Path::new(&args[2]);
            let mut options = fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let mut file = options.open(path)?;
            if !file.metadata()?.is_file() || file.metadata()?.len() > 1024 {
                return fail("keypair file is too large");
            }
            let mut contents = LockedBytes::zeroed(1025)?;
            let mut length = 0;
            while length < contents.len() {
                let read = file.read(&mut contents[length..])?;
                if read == 0 {
                    break;
                }
                length += read;
            }
            if length > 1024 {
                return fail("keypair file is too large");
            }
            let bytes = parse_keypair_json(&contents[..length])?;
            ImportedSecret::Key(bytes)
        }
        _ => {
            return fail("usage: solx import NAME (--mnemonic | --base58 | --keypair-file PATH)");
        }
    };
    let mut data = app.vault()?;
    match imported {
        ImportedSecret::Mnemonic(entropy) => data.add_master(name, entropy)?,
        ImportedSecret::Key(bytes) => data.add_imported(name, bytes)?,
    }
    app.save_vault(&mut data)?;
    println!("Imported {name}: {}", data.account(name)?.pubkey);
    if args[1] == "--keypair-file" {
        eprintln!("Warning: the source keypair file is still on disk.");
    }
    Ok(())
}

fn parse_keypair_json(input: &[u8]) -> Result<LockedKeypair> {
    use serde::de::{Error, SeqAccess, Visitor};
    struct KeyVisitor(LockedKeypair);
    impl<'de> Visitor<'de> for KeyVisitor {
        type Value = LockedKeypair;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("exactly 64 keypair bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut bytes = self.0;
            for byte in bytes.iter_mut() {
                *byte = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("keypair needs 64 bytes"))?;
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(A::Error::custom("keypair has excess bytes"));
            }
            Ok(bytes)
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(input);
    let bytes =
        serde::Deserializer::deserialize_seq(&mut decoder, KeyVisitor(LockedKeypair::new()?))
            .map_err(|_| "invalid keypair JSON; expected exactly 64 bytes")?;
    decoder.end().map_err(|_| "trailing keypair JSON data")?;
    Ok(bytes)
}

fn decode_base58_keypair(input: &str) -> Result<LockedKeypair> {
    let input = input
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            input
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(input);
    let mut bytes = LockedKeypair::new()?;
    let len = bs58::decode(input).onto(&mut bytes[..])?;
    match len {
        32 => {
            let pubkey = Keypair::from_seed_bytes(bytes[..32].try_into()?)?.pubkey();
            bytes[32..].copy_from_slice(pubkey.as_ref());
        }
        64 => {}
        _ => return fail("base58 private key must decode to 32 or 64 bytes"),
    }
    Keypair::try_from(&bytes[..])?;
    Ok(bytes)
}

#[derive(Clone, Copy)]
enum ExportKind {
    PrivateKey,
    Mnemonic,
}

fn parse_export(args: &[String]) -> Result<(&str, ExportKind)> {
    match args {
        [name, flag] if flag == "--private-key" => Ok((name, ExportKind::PrivateKey)),
        [name, flag] if flag == "--mnemonic" => Ok((name, ExportKind::Mnemonic)),
        _ => fail("usage: solx export NAME (--private-key | --mnemonic)"),
    }
}

fn export(app: &mut App, args: &[String]) -> Result<()> {
    let (name, kind) = parse_export(args)?;
    let data = app.vault()?;
    let expected = data.account(name)?.pubkey;
    let index = data.derivation_index(name)?;
    if matches!(kind, ExportKind::Mnemonic) && index.is_none() {
        return fail("imported private-key wallets have no stored recovery phrase");
    }
    drop(data);
    app.release_session();
    println!("Export wallet: {name}\nAddress: {expected}");
    if matches!(kind, ExportKind::Mnemonic) {
        println!(
            "Derivation path: m/44'/501'/{}'/0'\nThis phrase controls every account derived from this master.",
            index.unwrap()
        );
    }
    println!("Warning: secret output can remain in terminal scrollback or redirected files.");
    print!("Type '{name}' to reveal the secret: ");
    io::stdout().flush()?;
    if crate::read_bounded_line()?.as_deref().map(str::trim) != Some(name) {
        return fail("export cancelled");
    }
    let data = app.vault()?;
    if data.account(name)?.pubkey != expected || data.derivation_index(name)? != index {
        return fail("wallet changed after export approval");
    }
    write_export_secret(&data, name, kind, &mut io::stdout())
}

#[cfg(test)]
fn export_wallet(
    data: &vault::Vault,
    name: &str,
    kind: ExportKind,
    mut read_line: impl FnMut() -> io::Result<Option<String>>,
    output: &mut impl Write,
) -> Result<()> {
    let account = data.account(name)?;
    let index = match kind {
        ExportKind::Mnemonic => Some(
            data.derivation_index(name)?
                .ok_or("imported private-key wallets have no stored recovery phrase")?,
        ),
        ExportKind::PrivateKey => None,
    };
    writeln!(
        output,
        "{OUTPUT_RULE}\nExport wallet: {name}\nAddress: {}",
        account.pubkey
    )?;
    if let Some(index) = index {
        writeln!(output, "Derivation path: m/44'/501'/{index}'/0'")?;
        writeln!(
            output,
            "Warning: this recovery phrase also controls wallets derived from the same master."
        )?;
    } else {
        writeln!(output, "Export type: private key (base58, 64-byte keypair)")?;
    }
    writeln!(
        output,
        "Warning: secret output can remain in terminal scrollback or redirected files."
    )?;
    write!(output, "Type '{name}' to reveal the secret: ")?;
    output.flush()?;
    if read_line()?.as_deref().map(str::trim) != Some(name) {
        return fail("export cancelled");
    }
    write_export_secret(data, name, kind, output)
}

fn write_export_secret(
    data: &vault::Vault,
    name: &str,
    kind: ExportKind,
    output: &mut impl Write,
) -> Result<()> {
    match kind {
        ExportKind::PrivateKey => {
            let bytes = data.signer(name)?.to_keypair_bytes()?;
            let mut encoded = LockedBytes::zeroed(88)?;
            let len = bs58::encode(&bytes[..]).onto(&mut encoded[..])?;
            let text = std::str::from_utf8(&encoded[..len])?;
            writeln!(
                output,
                "\n{OUTPUT_RULE}\nPrivate key (base58):\n{text}\n{OUTPUT_RULE}"
            )?;
        }
        ExportKind::Mnemonic => {
            let text = data.mnemonic(name)?;
            writeln!(
                output,
                "\n{OUTPUT_RULE}\nRecovery phrase:\n{}\n{OUTPUT_RULE}",
                text.as_str()
            )?;
        }
    }
    output.flush()?;
    Ok(())
}

fn delete(app: &mut App, args: &[String]) -> Result<()> {
    let [name] = args else {
        return fail("usage: solx delete NAME");
    };
    let data = app.vault()?;
    let was_default = data.first_name()? == name;
    let pubkey = data.account(name)?.pubkey;
    let usage = data.recovery_phrase_use(name)?;
    let revision = data.revision().map(<[u8]>::to_vec);
    drop(data);
    app.release_session();
    let erase_phrase = confirm_delete_metadata(name, pubkey, usage, crate::read_bounded_line)?;
    let mut data = app.vault()?;
    if data.revision() != revision.as_deref() {
        return fail("vault changed after deletion approval; review again");
    }
    data.remove_account(name, erase_phrase)?;
    app.save_vault(&mut data)?;
    println!("Deleted local wallet {name}.");
    if erase_phrase {
        println!("Unused recovery phrase erased from the vault.");
    }
    if was_default {
        match data.first_name() {
            Ok(next) => println!("Default wallet: {next}"),
            Err(_) => println!("The vault has no saved wallets."),
        }
    }
    Ok(())
}

#[cfg(test)]
fn confirm_delete(
    data: &vault::Vault,
    name: &str,
    read_line: impl FnMut() -> io::Result<Option<String>>,
) -> Result<bool> {
    let account = data.account(name)?;
    let usage = data.recovery_phrase_use(name)?;
    confirm_delete_metadata(name, account.pubkey, usage, read_line)
}

fn confirm_delete_metadata(
    name: &str,
    pubkey: Pubkey,
    usage: vault::RecoveryPhraseUse,
    mut read_line: impl FnMut() -> io::Result<Option<String>>,
) -> Result<bool> {
    println!("Delete local wallet: {name}\nAddress: {pubkey}");
    println!("Funds stay on-chain. Keep a backup if you need access later.");
    match usage {
        vault::RecoveryPhraseUse::ImportedKey => println!("The saved private key will be removed."),
        vault::RecoveryPhraseUse::Shared => {
            println!("The recovery phrase is shared by other wallets and will stay.")
        }
        vault::RecoveryPhraseUse::UnusedAfterDeletion => {
            println!("No other saved wallet uses this recovery phrase.")
        }
    }
    print!("Type '{name}' to delete this wallet: ");
    io::stdout().flush()?;
    if read_line()?.as_deref().map(str::trim) != Some(name) {
        return fail("deletion cancelled");
    }
    if usage == vault::RecoveryPhraseUse::UnusedAfterDeletion {
        print!("Also erase its recovery phrase from the vault? Type 'ERASE', or Enter to keep: ");
        io::stdout().flush()?;
        match read_line()?.as_deref().map(str::trim) {
            Some("ERASE") => Ok(true),
            Some("") => Ok(false),
            _ => fail("deletion cancelled"),
        }
    } else {
        Ok(false)
    }
}

fn list(app: &mut App, args: &[String]) -> Result<()> {
    list_with_output(app, args, &mut io::stdout())
}

fn list_with_output(app: &mut App, args: &[String], output: &mut impl Write) -> Result<()> {
    let filter = match args {
        [] => None,
        [name] => Some(name.as_str()),
        _ => return fail("usage: solx list [NAME]"),
    };
    let data = app.public_vault()?;
    if let Some(name) = filter {
        data.account(name)?;
    }
    if data.accounts.is_empty() {
        writeln!(output, "No saved wallets.")?;
        return Ok(());
    }
    let rpc = if app.config.rpc.show_balances && app.config.rpc.url.is_some() {
        Some(app.rpc()?)
    } else {
        None
    };
    for account in data
        .accounts
        .iter()
        .filter(|a| filter.is_none_or(|name| a.name == name))
    {
        writeln!(output, "{}  {}", account.name, account.pubkey)?;
        if let Some(rpc) = &rpc {
            let balance = rpc.balance(&account.pubkey)?;
            writeln!(output, "  SOL: {}", format_amount(balance, 9))?;
            if balance == 0 {
                eprintln!("  Warning: {} has zero SOL balance", account.name);
            }
            for program in [TOKEN, TOKEN_2022] {
                for token_account in rpc.token_accounts(&account.pubkey, &program)? {
                    writeln!(
                        output,
                        "  token {}  {}  account {}",
                        token_account.mint,
                        format_amount(token_account.raw_amount, token_account.decimals),
                        token_account.address
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn history(app: &mut App, args: &[String]) -> Result<()> {
    let options = Options::parse(args, &["wallet", "limit"])?;
    let data = app.public_vault()?;
    let name = data.name_or_first(options.get("wallet"))?;
    let account = data.account(name)?;
    let limit = options
        .get("limit")
        .map(str::parse)
        .transpose()?
        .unwrap_or(app.config.history.limit);
    if !(1..=100).contains(&limit) {
        return fail("history limit must be 1..=100");
    }
    let rows = app.rpc()?.signatures(&account.pubkey, limit)?;
    println!("History for {name} ({}):", account.pubkey);
    print_history(&rows);
    Ok(())
}

pub fn print_history(rows: &[Value]) {
    if rows.is_empty() {
        println!("  no recent signatures");
    }
    for row in rows {
        let signature = row.get("signature").and_then(Value::as_str).unwrap_or("?");
        let slot = row.get("slot").and_then(Value::as_u64).unwrap_or(0);
        let status = if row.get("err").is_some_and(Value::is_null) {
            "ok"
        } else {
            "error"
        };
        println!("  {}  slot {}  {}", safe_text(signature, 100), slot, status);
    }
}

#[derive(Clone, Copy)]
struct SpendAll {
    balance: u64,
    target: Pubkey,
}

fn spend_all_lamports(balance: u64, fee: u64) -> Result<u64> {
    match balance.checked_sub(fee) {
        Some(amount) if amount > 0 => Ok(amount),
        _ => fail("insufficient SOL to send ALL after the network fee"),
    }
}

fn ensure_all_would_drain(simulation: &Value) -> Result<()> {
    let remaining = simulation
        .pointer("/postBalances/0")
        .and_then(Value::as_u64)
        .ok_or("simulation omitted the fee payer's remaining balance")?;
    if remaining != 0 {
        return fail("source balance changed; ALL would leave SOL behind, retry the transfer");
    }
    Ok(())
}

fn system_transfer(source: &Pubkey, target: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM,
        accounts: vec![
            AccountMeta::new(*source, true),
            AccountMeta::new(*target, false),
        ],
        data,
    }
}

fn transfer(app: &mut App, args: &[String]) -> Result<()> {
    let options = Options::parse(args, &["wallet", "to", "amount"])?;
    let data = app.public_vault()?;
    let source_name = data.name_or_first(options.get("wallet"))?;
    let source = data.account(source_name)?;
    let target = target_address(&data, options.required("to")?)?;
    let amount_text = options.required("amount")?;
    let all = amount_text == "ALL";
    let lamports = if all {
        0
    } else {
        parse_amount(amount_text, 9)?
    };
    if !all && lamports == 0 {
        return fail("amount must be positive");
    }
    if source.pubkey() == target {
        return fail("cannot transfer to the same wallet");
    }
    let rpc = app.rpc()?;
    warn_destination(&data, &rpc, &target)?;
    let spend_all = if all {
        Some(SpendAll {
            balance: rpc.balance(&source.pubkey())?,
            target,
        })
    } else {
        None
    };
    let instruction = system_transfer(&source.pubkey(), &target, lamports);
    let details = format!(
        "SOL transfer: {}\nFrom: {} ({})\nTo: {}",
        if all {
            "ALL".to_owned()
        } else {
            format!("{} SOL", format_amount(lamports, 9))
        },
        source_name,
        source.pubkey(),
        target
    );
    if send_transaction(
        app,
        &rpc,
        source,
        vec![instruction],
        &details,
        false,
        spend_all,
    )? && !data.is_known_recipient(&target)
    {
        app.remember_recipient(&target);
    }
    Ok(())
}

fn token_transfer(app: &mut App, args: &[String]) -> Result<()> {
    let options = Options::parse(args, &["wallet", "mint", "to", "amount"])?;
    let data = app.public_vault()?;
    let source_name = data.name_or_first(options.get("wallet"))?;
    let source = data.account(source_name)?;
    let mint = Pubkey::from_str(options.required("mint")?)?;
    let target = target_address(&data, options.required("to")?)?;
    if source.pubkey() == target {
        return fail("cannot transfer to the same wallet");
    }
    let rpc = app.rpc()?;
    let token_program = mint_program(&rpc, &mint)?;
    ensure_transfer_program(token_program)?;
    let decimals = rpc.token_decimals(&mint)?;
    let amount = parse_amount(options.required("amount")?, decimals)?;
    if amount == 0 {
        return fail("amount must be positive");
    }
    let source_ata = ata(&source.pubkey(), &mint, &token_program);
    let destination_ata = ata(&target, &mint, &token_program);
    let balance = rpc
        .token_balance(&source_ata)?
        .ok_or("source associated token account does not exist")?;
    if balance < amount {
        return fail("insufficient token balance");
    }
    warn_destination(&data, &rpc, &target)?;
    let instructions = vec![
        create_ata_idempotent(&source.pubkey(), &target, &mint, &token_program),
        transfer_checked(
            &source_ata,
            &mint,
            &destination_ata,
            &source.pubkey(),
            amount,
            decimals,
            token_program,
        ),
    ];
    let details = format!(
        "Token transfer: {} units\nMint: {}\nFrom: {} ({})\nTo: {}\nDestination ATA: {}\nMay fund recipient ATA rent",
        format_amount(amount, decimals),
        mint,
        source_name,
        source.pubkey(),
        target,
        destination_ata
    );
    if send_transaction(app, &rpc, source, instructions, &details, false, None)?
        && !data.is_known_recipient(&target)
    {
        app.remember_recipient(&target);
    }
    Ok(())
}

struct CloseCandidate {
    mint: Pubkey,
    address: Pubkey,
    program: Pubkey,
    raw_amount: u64,
    decimals: u8,
}

impl CloseCandidate {
    fn requires_burn(&self) -> bool {
        self.raw_amount != 0 && !is_native_mint(&self.mint, &self.program)
    }

    fn append_instructions(&self, authority: &Pubkey, instructions: &mut Vec<Instruction>) {
        if self.requires_burn() {
            instructions.push(burn_checked(
                &self.address,
                &self.mint,
                authority,
                self.raw_amount,
                self.decimals,
                self.program,
            ));
        }
        instructions.push(close_token_account(&self.address, authority, self.program));
    }
}

fn is_native_mint(mint: &Pubkey, program: &Pubkey) -> bool {
    (*mint == NATIVE_MINT && *program == TOKEN)
        || (*mint == NATIVE_MINT_2022 && *program == TOKEN_2022)
}

enum CloseEligibility {
    Eligible(CloseCandidate),
    NonEmpty,
    NonAssociated,
}

struct CloseSelection {
    wallet: Option<String>,
    all: bool,
    burn: bool,
    mints: Vec<String>,
}

fn close_ata(app: &mut App, args: &[String]) -> Result<()> {
    let selection = parse_close_selection(args)?;
    let data = app.public_vault()?;
    let name = data.name_or_first(selection.wallet.as_deref())?;
    let signer = data.account(name)?;
    let rpc = app.rpc()?;
    let candidates = if selection.all {
        let (candidates, nonempty, non_ata) =
            eligible_atas(&rpc, &signer.pubkey(), selection.burn)?;
        println!(
            "Found {} eligible ATAs; skipped {nonempty} non-empty and {non_ata} non-associated token accounts.",
            candidates.len()
        );
        candidates
    } else {
        selected_atas(&rpc, &signer.pubkey(), &selection.mints, selection.burn)?
    };
    send_close_batches(app, &rpc, signer, name, candidates)
}

fn parse_close_selection(args: &[String]) -> Result<CloseSelection> {
    let mut wallet = None;
    let mut mints = Vec::new();
    let mut all = false;
    let mut burn = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--wallet" {
            i += 1;
            if wallet.is_some() {
                return fail("duplicate --wallet");
            }
            wallet = Some(args.get(i).ok_or("--wallet needs a name")?.clone());
        } else if args[i] == "--all" {
            if all {
                return fail("duplicate --all");
            }
            all = true;
        } else if args[i] == "--burn" {
            if burn {
                return fail("duplicate --burn");
            }
            burn = true;
        } else if args[i].starts_with('-') {
            return fail("unknown close-ata option");
        } else {
            mints.push(args[i].clone());
            if mints.len() > 512 {
                return fail("too many mint addresses");
            }
        }
        i += 1;
    }
    if all == !mints.is_empty() {
        return fail("use --all or provide mint addresses");
    }
    Ok(CloseSelection {
        wallet,
        all,
        burn,
        mints,
    })
}

fn eligible_atas(
    rpc: &Rpc,
    owner: &Pubkey,
    burn: bool,
) -> Result<(Vec<CloseCandidate>, usize, usize)> {
    let mut candidates = Vec::new();
    let mut nonempty = 0;
    let mut non_ata = 0;
    let mut seen = HashSet::new();
    for program in [TOKEN, TOKEN_2022] {
        for account in rpc.token_accounts(owner, &program)? {
            match close_eligibility(owner, program, account, burn) {
                CloseEligibility::NonAssociated => non_ata += 1,
                CloseEligibility::NonEmpty => nonempty += 1,
                CloseEligibility::Eligible(candidate) if seen.insert(candidate.address) => {
                    candidates.push(candidate);
                }
                CloseEligibility::Eligible(_) => {}
            }
        }
    }
    Ok((candidates, nonempty, non_ata))
}

fn close_eligibility(
    owner: &Pubkey,
    program: Pubkey,
    account: TokenAccount,
    burn: bool,
) -> CloseEligibility {
    if account.address != ata(owner, &account.mint, &program) {
        CloseEligibility::NonAssociated
    } else if account.raw_amount != 0 && !burn {
        CloseEligibility::NonEmpty
    } else {
        CloseEligibility::Eligible(CloseCandidate {
            mint: account.mint,
            address: account.address,
            program,
            raw_amount: account.raw_amount,
            decimals: account.decimals,
        })
    }
}

fn selected_atas(
    rpc: &Rpc,
    owner: &Pubkey,
    mints: &[String],
    burn: bool,
) -> Result<Vec<CloseCandidate>> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::with_capacity(mints.len());
    for mint_text in mints {
        let mint = Pubkey::from_str(mint_text)?;
        if !seen.insert(mint) {
            return fail("duplicate mint address");
        }
        let program = mint_program(rpc, &mint)?;
        let address = ata(owner, &mint, &program);
        let info = rpc
            .account_info(&address)?
            .ok_or("associated token account does not exist")?;
        if info.get("owner").and_then(Value::as_str) != Some(program.to_string().as_str()) {
            return fail("associated token account has unexpected owner program");
        }
        let raw_amount = rpc
            .token_balance(&address)?
            .ok_or("associated token account missing")?;
        if raw_amount != 0 && !burn {
            return fail("associated token account is not empty");
        }
        let decimals = if raw_amount != 0 && !is_native_mint(&mint, &program) {
            rpc.token_decimals(&mint)?
        } else {
            0
        };
        candidates.push(CloseCandidate {
            mint,
            address,
            program,
            raw_amount,
            decimals,
        });
    }
    Ok(candidates)
}

fn close_batch_fits(owner: &Pubkey, instructions: &[Instruction], budget: bool) -> Result<bool> {
    let mut with_budget = Vec::with_capacity(instructions.len() + usize::from(budget));
    if budget {
        with_budget.push(set_compute_unit_limit(MAX_COMPUTE_UNITS));
    }
    with_budget.extend_from_slice(instructions);
    let message = v0::Message::try_compile(owner, &with_budget, &[], Hash::default())?;
    let unsigned = VersionedTransaction {
        signatures: vec![Signature::default()],
        message: VersionedMessage::V0(message),
    };
    Ok(wincode::serialize(&unsigned)?.len() <= MAX_TRANSACTION_BYTES)
}

fn send_close_batch(
    app: &mut App,
    rpc: &Rpc,
    signer: &vault::PublicAccount,
    name: &str,
    instructions: Vec<Instruction>,
    candidates: &[CloseCandidate],
) -> Result<bool> {
    let mut details = format!(
        "Close {} associated token account(s); reclaim account lamports\nOwner/destination: {} ({})",
        candidates.len(),
        name,
        signer.pubkey()
    );
    for candidate in candidates {
        if candidate.raw_amount > 0 {
            if is_native_mint(&candidate.mint, &candidate.program) {
                details.push_str(&format!(
                    "\nUnwrap {} native units from mint {}, ATA: {}",
                    candidate.raw_amount, candidate.mint, candidate.address
                ));
            } else {
                details.push_str(&format!(
                    "\nBURN {} token units ({} base units) from mint {}, ATA: {}",
                    format_amount(candidate.raw_amount, candidate.decimals),
                    candidate.raw_amount,
                    candidate.mint,
                    candidate.address
                ));
            }
        } else {
            details.push_str(&format!(
                "\nMint: {}, ATA: {} (empty)",
                candidate.mint, candidate.address
            ));
        }
    }
    if candidates.iter().any(CloseCandidate::requires_burn) {
        details.push_str("\nBurning destroys those tokens; only the ATA lamports are reclaimed.");
    }
    send_transaction(
        app,
        rpc,
        signer,
        instructions,
        &details,
        candidates.iter().any(CloseCandidate::requires_burn),
        None,
    )
}

fn send_close_batches(
    app: &mut App,
    rpc: &Rpc,
    signer: &vault::PublicAccount,
    name: &str,
    candidates: Vec<CloseCandidate>,
) -> Result<()> {
    if candidates.is_empty() {
        println!("No eligible associated token accounts to close.");
        return Ok(());
    }
    let mut instructions = Vec::new();
    let mut batch = Vec::new();
    let mut confirmed = 0;
    let budget =
        app.config.security.simulate_before_send && app.config.security.optimize_compute_units;
    for candidate in candidates {
        let start = instructions.len();
        candidate.append_instructions(&signer.pubkey(), &mut instructions);
        if !close_batch_fits(&signer.pubkey(), &instructions, budget)? {
            let overflow = instructions.split_off(start);
            if batch.is_empty() {
                return fail("one close instruction exceeds the transaction size limit");
            }
            let count = batch.len();
            if !send_close_batch(
                app,
                rpc,
                signer,
                name,
                std::mem::take(&mut instructions),
                &batch,
            )? {
                println!("Stopped after a pending batch; check its signature before retrying.");
                return Ok(());
            }
            confirmed += count;
            batch.clear();
            instructions.extend(overflow);
            if !close_batch_fits(&signer.pubkey(), &instructions, budget)? {
                return fail("one close instruction exceeds the transaction size limit");
            }
        }
        batch.push(candidate);
    }
    if !instructions.is_empty() {
        let count = batch.len();
        if !send_close_batch(app, rpc, signer, name, instructions, &batch)? {
            println!("Stopped after a pending batch; check its signature before retrying.");
            return Ok(());
        }
        confirmed += count;
    }
    println!("Closed {confirmed} associated token account(s).");
    Ok(())
}

fn lock(app: &mut App, args: &[String]) -> Result<()> {
    no_args(args)?;
    app.session = None;
    println!("Wallet locked.");
    Ok(())
}

fn ui(_: &mut App, args: &[String]) -> Result<()> {
    no_args(args)?;
    fail("later")
}

struct Options<'a> {
    values: Vec<(&'a str, &'a str)>,
}
impl<'a> Options<'a> {
    fn parse(args: &'a [String], allowed: &[&str]) -> Result<Self> {
        let mut values = Vec::new();
        let mut words = args.iter();
        while let Some(word) = words.next() {
            let key = word
                .strip_prefix("--")
                .ok_or("expected --option; use 'help'")?;
            if !allowed.contains(&key) {
                return fail("unknown option");
            }
            if values.iter().any(|(existing, _)| *existing == key) {
                return fail("duplicate option");
            }
            let value = words.next().ok_or("missing option value")?;
            if value.starts_with("--") {
                return fail("missing option value");
            }
            values.push((key, value.as_str()));
        }
        Ok(Self { values })
    }
    fn get(&self, name: &str) -> Option<&'a str> {
        self.values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    }
    fn required(&self, name: &str) -> Result<&'a str> {
        self.get(name)
            .ok_or_else(|| format!("missing --{name}").into())
    }
}

fn target_address(data: &vault::PublicVault, value: &str) -> Result<Pubkey> {
    if data.contains(value) {
        Ok(data.account(value)?.pubkey)
    } else {
        Ok(Pubkey::from_str(value)?)
    }
}

fn warn_destination(data: &vault::PublicVault, rpc: &Rpc, target: &Pubkey) -> Result<()> {
    if !data.is_known_recipient(target) {
        eprintln!("Warning: first transfer to {target}");
    }
    if rpc.balance(target)? == 0 {
        eprintln!("Warning: recipient has zero SOL balance");
    }
    Ok(())
}

fn mint_program(rpc: &Rpc, mint: &Pubkey) -> Result<Pubkey> {
    let info = rpc
        .account_info(mint)?
        .ok_or("mint account does not exist")?;
    let owner = Pubkey::from_str(
        info.get("owner")
            .and_then(Value::as_str)
            .ok_or("invalid mint owner")?,
    )?;
    if owner != TOKEN && owner != TOKEN_2022 {
        return fail("mint is not owned by an SPL Token program");
    }
    Ok(owner)
}

fn ensure_transfer_program(program: Pubkey) -> Result<()> {
    if program != TOKEN {
        return fail(
            "Token-2022 transfers are disabled until extension fees and net receipts can be reviewed and enforced; legacy SPL transfers remain supported",
        );
    }
    Ok(())
}

fn ata(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ASSOCIATED_TOKEN,
    )
    .0
}

fn create_ata_idempotent(
    payer: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: ASSOCIATED_TOKEN,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata(owner, mint, token_program), false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(SYSTEM, false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![1],
    }
}

fn transfer_checked(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
    program: Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(12);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

fn burn_checked(
    account: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
    program: Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(10);
    data.push(15);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

fn set_compute_unit_limit(limit: u32) -> Instruction {
    let mut data = Vec::with_capacity(5);
    data.push(2);
    data.extend_from_slice(&limit.to_le_bytes());
    Instruction {
        program_id: COMPUTE_BUDGET,
        accounts: Vec::new(),
        data,
    }
}

fn tuned_compute_limit(used: u64, margin_percent: u8) -> Result<u32> {
    if used == 0 || used > u64::from(MAX_COMPUTE_UNITS) {
        return fail("simulation returned invalid compute usage");
    }
    let margin = used
        .saturating_mul(u64::from(margin_percent))
        .div_ceil(100)
        .max(1_000);
    Ok(u32::try_from(
        (used + margin).min(u64::from(MAX_COMPUTE_UNITS)),
    )?)
}

fn close_token_account(account: &Pubkey, authority: &Pubkey, program: Pubkey) -> Instruction {
    Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new(*authority, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: vec![9],
    }
}

fn send_transaction(
    app: &mut App,
    rpc: &Rpc,
    signer: &vault::PublicAccount,
    mut instructions: Vec<Instruction>,
    details: &str,
    burn_confirmation: bool,
    spend_all: Option<SpendAll>,
) -> Result<bool> {
    if instructions.is_empty() {
        return fail("invalid instruction count");
    }
    let hash = rpc.latest_blockhash()?.hash;
    let optimize =
        app.config.security.simulate_before_send && app.config.security.optimize_compute_units;
    if optimize {
        instructions.insert(0, set_compute_unit_limit(MAX_COMPUTE_UNITS));
        let (_, probe_wire) = compile_unsigned(&signer.pubkey(), &instructions, hash.clone())?;
        let probe = rpc.simulate(&probe_wire)?;
        check_simulation(&probe, false, "CU probe")?;
        let used = probe
            .get("unitsConsumed")
            .and_then(Value::as_u64)
            .ok_or("RPC simulation omitted compute units; cannot tune limit")?;
        let limit = tuned_compute_limit(used, app.config.security.compute_unit_margin_percent)?;
        instructions[0] = set_compute_unit_limit(limit);
    }
    let all_quote = if let Some(spend_all) = spend_all {
        let (provisional, _) = compile_unsigned(&signer.pubkey(), &instructions, hash.clone())?;
        let fee = rpc.fee_for_message(&provisional.message)?;
        let amount = spend_all_lamports(spend_all.balance, fee)?;
        instructions[usize::from(optimize)] =
            system_transfer(&signer.pubkey(), &spend_all.target, amount);
        Some((spend_all.balance, fee, amount))
    } else {
        None
    };
    let (unsigned, simulation_wire) = compile_unsigned(&signer.pubkey(), &instructions, hash)?;
    let approved_fee = rpc.fee_for_message(&unsigned.message)?;
    let approved_rent = ata_rent_quote(rpc, &instructions)?;
    if let Some((_, expected_fee, _)) = all_quote {
        let final_fee = rpc.fee_for_message(&unsigned.message)?;
        if final_fee != expected_fee {
            return fail("transaction fee changed while resolving ALL; retry the transfer");
        }
    }
    println!(
        "\n{OUTPUT_RULE}\nTransaction\n\nGenesis-checked cluster: {}\nRPC host: {}\nFee payer: {}",
        safe_text(&rpc.cluster, 80),
        safe_text(&rpc.endpoint, 150),
        signer.pubkey()
    );
    println!("{details}");
    println!(
        "Network fee: {} SOL\nEstimated ATA rent: {} SOL",
        format_amount(approved_fee, 9),
        format_amount(approved_rent, 9)
    );
    if let Some((balance, fee, amount)) = all_quote {
        println!(
            "Balance: {} SOL\nNetwork fee: {} SOL\nSend: {} SOL\nExpected remaining: 0 SOL",
            format_amount(balance, 9),
            format_amount(fee, 9),
            format_amount(amount, 9)
        );
    }
    if optimize {
        let limit = u32::from_le_bytes(instructions[0].data[1..5].try_into()?);
        println!("Compute-unit limit: {limit}");
    }
    if app.config.security.show_details {
        for (index, instruction) in instructions.iter().enumerate() {
            println!("Instruction {}: {}", index + 1, instruction.program_id);
            for account in &instruction.accounts {
                println!(
                    "  {}{}{}",
                    account.pubkey,
                    if account.is_signer { " signer" } else { "" },
                    if account.is_writable { " writable" } else { "" }
                );
            }
        }
    }
    println!("{OUTPUT_RULE}");
    if app.config.security.simulate_before_send {
        let simulation = rpc.simulate(&simulation_wire)?;
        check_simulation(
            &simulation,
            app.config.security.show_simulation,
            "Simulation",
        )?;
        if !app.config.security.show_simulation {
            println!("Simulation: OK");
        }
        if spend_all.is_some() {
            ensure_all_would_drain(&simulation)?;
        }
    }
    if burn_confirmation {
        print!("Burn tokens and send transaction? Type 'BURN': ");
        io::stdout().flush()?;
        let input = crate::read_bounded_line()?.unwrap_or_default();
        if input.trim() != "BURN" {
            return fail("transaction cancelled");
        }
    } else if app.config.security.confirm_every_transaction {
        print!("Send transaction? Type 'yes': ");
        io::stdout().flush()?;
        let input = crate::read_bounded_line()?.unwrap_or_default();
        if input.trim() != "yes" {
            return fail("transaction cancelled");
        }
    }
    // Password entry must precede the fresh blockhash, and cannot occur in signing.
    app.unlock()?;
    let result = refresh_and_sign(
        app,
        rpc,
        signer,
        &instructions,
        approved_fee,
        approved_rent,
        spend_all,
    );
    app.release_session();
    let transaction = result?;
    let signature = transaction
        .signatures
        .first()
        .ok_or("signed transaction has no signature")?
        .to_string();
    let wire = wincode::serialize(&transaction)?;
    if wire.len() > MAX_TRANSACTION_BYTES {
        return fail("signed transaction exceeds 1232-byte packet limit");
    }
    println!("Local transaction signature: {signature}");
    let outcome = rpc.submit_and_confirm(&wire, transaction.signatures[0]);
    match outcome {
        crate::rpc::SubmissionOutcome::Confirmed(signature) => {
            println!("Confirmed: {signature}");
            Ok(true)
        }
        crate::rpc::SubmissionOutcome::Unknown { signature, reason } => {
            eprintln!(
                "Submission outcome unknown; check signature {signature} before retrying: {reason}"
            );
            Ok(false)
        }
    }
}

fn ata_rent_quote(rpc: &Rpc, instructions: &[Instruction]) -> Result<u64> {
    let mut rent = 0u64;
    for instruction in instructions
        .iter()
        .filter(|ix| ix.program_id == ASSOCIATED_TOKEN)
    {
        let destination = instruction
            .accounts
            .get(1)
            .ok_or("invalid ATA instruction")?
            .pubkey;
        if rpc.account_info(&destination)?.is_none() {
            let quote = rpc
                .call(
                    "getMinimumBalanceForRentExemption",
                    serde_json::json!([165, {"commitment":"confirmed"}]),
                )?
                .as_u64()
                .ok_or("invalid rent quote")?;
            rent = rent.checked_add(quote).ok_or("rent overflow")?;
        }
    }
    Ok(rent)
}

fn refresh_and_sign(
    app: &App,
    rpc: &Rpc,
    identity: &vault::PublicAccount,
    instructions: &[Instruction],
    fee: u64,
    rent: u64,
    spend_all: Option<SpendAll>,
) -> Result<VersionedTransaction> {
    let context = rpc.latest_blockhash()?;
    let (mut transaction, wire) =
        compile_unsigned(&identity.pubkey, instructions, context.hash.clone())?;
    if rpc.fee_for_message(&transaction.message)? != fee
        || ata_rent_quote(rpc, instructions)? != rent
    {
        return fail("fee or rent changed after approval; nothing sent, review the command again");
    }
    if let Some(all) = spend_all
        && rpc.balance(&identity.pubkey)? != all.balance
    {
        return fail("ALL balance changed after approval; nothing sent, review the command again");
    }
    // Final simulation always validates the exact refreshed message, even if the preview was disabled.
    let simulation = rpc.simulate_at(&wire, context.context_slot)?;
    check_simulation(&simulation, false, "Final simulation")?;
    if spend_all.is_some() {
        ensure_all_would_drain(&simulation)?;
    }
    let message = wincode::serialize(&transaction.message)?;
    let vault = app
        .session
        .as_ref()
        .ok_or("signing session is locked")?
        .load()?;
    let key = vault.signer(&identity.name)?;
    if key.pubkey() != identity.pubkey {
        return fail("wallet identity changed after approval");
    }
    drop(vault);
    validate_signer(&transaction.message, &key)?;
    // Disk I/O and derivation must finish before this last expiry check. Only the
    // selected signer remains live across this bounded RPC; errors drop it too.
    if rpc.block_height(&context)? >= context.last_valid_block_height.saturating_sub(5) {
        return fail("fresh transaction is too close to expiry; nothing sent, retry preparation");
    }
    // Critical section: prepared message, preallocated signature slot, no I/O or formatting.
    transaction.signatures[0] = key.sign_message(&message);
    drop(key);
    Ok(transaction)
}

fn compile_unsigned(
    payer: &Pubkey,
    instructions: &[Instruction],
    hash: Hash,
) -> Result<(VersionedTransaction, Vec<u8>)> {
    let message = v0::Message::try_compile(payer, instructions, &[], hash)?;
    let unsigned = VersionedTransaction {
        signatures: vec![Signature::default()],
        message: VersionedMessage::V0(message),
    };
    let wire = wincode::serialize(&unsigned)?;
    if wire.len() > MAX_TRANSACTION_BYTES {
        return fail("transaction exceeds 1232-byte packet limit");
    }
    Ok((unsigned, wire))
}

fn check_simulation(simulation: &Value, show: bool, label: &str) -> Result<()> {
    render_simulation(&mut io::stdout().lock(), simulation, show, label)
}

fn render_simulation(
    output: &mut impl Write,
    simulation: &Value,
    show: bool,
    label: &str,
) -> Result<()> {
    let failure = simulation
        .get("err")
        .ok_or("simulation result is missing err field")?;
    if show {
        writeln!(
            output,
            "\n{OUTPUT_RULE}\n{label}: {}",
            if failure.is_null() { "OK" } else { "FAILED" }
        )?;
        if let Some(units) = simulation.get("unitsConsumed").and_then(Value::as_u64) {
            writeln!(output, "Compute units: {units}")?;
        } else {
            writeln!(output, "Compute units: unavailable")?;
        }
        if !failure.is_null() {
            writeln!(output, "Reason: {}", safe_text(&failure.to_string(), 300))?;
        }
        if let Some(logs) = simulation.get("logs").and_then(Value::as_array)
            && !logs.is_empty()
        {
            writeln!(output, "\nLogs:")?;
            for log in logs.iter().take(20) {
                if let Some(line) = log.as_str() {
                    for line in safe_text(line, 300).lines() {
                        writeln!(output, "  {line}")?;
                    }
                }
            }
            if logs.len() > 20 {
                writeln!(output, "  ... {} more log entries", logs.len() - 20)?;
            }
        }
        writeln!(output, "{OUTPUT_RULE}\n")?;
    }
    if !failure.is_null() {
        if show {
            return Err(format!("{label} failed; transaction not sent").into());
        }
        return Err(format!("{label} failed: {}", safe_text(&failure.to_string(), 300)).into());
    }
    Ok(())
}

fn validate_signer(message: &VersionedMessage, signer: &Keypair) -> Result<()> {
    if !matches!(message, VersionedMessage::V0(_))
        || message.header().num_required_signatures != 1
        || message.static_account_keys().first() != Some(&signer.pubkey())
    {
        return fail("transaction must require only the selected fee payer's signature");
    }
    Ok(())
}

#[cfg(test)]
fn sign_v0(message: VersionedMessage, signer: &Keypair) -> Result<VersionedTransaction> {
    validate_signer(&message, signer)?;
    let bytes = wincode::serialize(&message)?;
    Ok(VersionedTransaction {
        signatures: vec![signer.sign_message(&bytes)],
        message,
    })
}

pub fn parse_amount(input: &str, decimals: u8) -> Result<u64> {
    if decimals > 19 {
        return fail("token precision exceeds u64 decimal range");
    }
    if input.is_empty() || input.starts_with('-') || input.starts_with('+') {
        return fail("invalid amount");
    }
    let (whole, fractional) = input.split_once('.').unwrap_or((input, ""));
    if whole.is_empty()
        || !whole.bytes().all(|c| c.is_ascii_digit())
        || !fractional.bytes().all(|c| c.is_ascii_digit())
        || fractional.len() > usize::from(decimals)
    {
        return fail("invalid amount or too many decimal places");
    }
    let scale = 10u64
        .checked_pow(u32::from(decimals))
        .ok_or("amount precision overflow")?;
    let whole: u64 = whole.parse()?;
    let fraction: u64 = if fractional.is_empty() {
        0
    } else {
        fractional.parse()?
    };
    let padding = u32::from(decimals) - u32::try_from(fractional.len())?;
    whole
        .checked_mul(scale)
        .and_then(|v| {
            fraction
                .checked_mul(10u64.pow(padding))
                .and_then(|f| v.checked_add(f))
        })
        .ok_or_else(|| "amount overflow".into())
}

fn format_amount(amount: u64, decimals: u8) -> String {
    if decimals > 19 {
        return format!("{amount} base units (decimals {decimals})");
    }
    if decimals == 0 {
        return amount.to_string();
    }
    let scale = 10u64.pow(u32::from(decimals));
    let fraction = format!("{:0width$}", amount % scale, width = usize::from(decimals));
    let trimmed = fraction.trim_end_matches('0');
    if trimmed.is_empty() {
        (amount / scale).to_string()
    } else {
        format!("{}.{}", amount / scale, trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;

    #[test]
    fn new_wallet_defaults_to_independent_phrases_and_derives_from_selected_source() {
        let mut wallet = crate::test_support::TestWallet::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        wallet.app.config.rpc.url = Some(format!("http://{}", listener.local_addr().unwrap()));
        wallet.app.config.rpc.show_balances = true;
        wallet.app.config.rpc.timeout_secs = 1;
        let session = Session::test_session(&wallet.app.config.vault);
        for name in ["first", "second"] {
            let mut output = Vec::new();
            new_wallet_with_output(&mut wallet.app, &[name.into()], &mut output).unwrap();
            let saved = session.load().unwrap();
            assert_eq!(saved.derivation_index(name).unwrap(), Some(0));
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains("New recovery phrase (shown once; store it securely):"));
            assert!(text.contains(saved.mnemonic(name).unwrap().as_str()));
            assert!(text.contains(&format!(
                "Created {name}: {}",
                saved.account(name).unwrap().pubkey
            )));
        }
        let saved = session.load().unwrap();
        assert_ne!(
            saved.mnemonic("first").unwrap().as_str(),
            saved.mnemonic("second").unwrap().as_str()
        );
        assert_ne!(
            saved.account("first").unwrap().pubkey,
            saved.account("second").unwrap().pubkey
        );
        drop(saved);

        for (name, source, index) in [
            ("child", "second", 1),
            ("sibling", "child", 2),
            ("other", "first", 1),
        ] {
            let mut output = Vec::new();
            new_wallet_with_output(
                &mut wallet.app,
                &[name.into(), "--wallet".into(), source.into()],
                &mut output,
            )
            .unwrap();
            let saved = session.load().unwrap();
            let shared = saved.mnemonic(source).unwrap();
            assert_eq!(saved.mnemonic(name).unwrap().as_str(), shared.as_str());
            assert_eq!(saved.derivation_index(name).unwrap(), Some(index));
            assert_ne!(
                saved.account(name).unwrap().pubkey,
                saved.account(source).unwrap().pubkey
            );
            assert_eq!(
                saved.signer(name).unwrap().pubkey(),
                saved.account(name).unwrap().pubkey
            );
            assert_eq!(saved.config_audit().edits(), 0);
            let text = String::from_utf8(output).unwrap();
            assert!(text.contains(&format!("Shared recovery phrase with {source}.")));
            assert!(text.contains(&format!("m/44'/501'/{index}'/0'")));
            assert!(!text.contains(shared.as_str()));
            assert!(!text.contains("New recovery phrase"));
        }
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn new_wallet_rejects_removed_options_and_invalid_sources_without_saving() {
        let mut wallet = crate::test_support::TestWallet::new();
        let before = fs::read(&wallet.app.config.vault).unwrap();
        for (args, expected) in [
            (vec![], "usage:"),
            (vec!["--new-master"], "invalid new wallet name"),
            (vec!["child", "--new-master"], "usage:"),
            (vec!["child", "--wallet"], "usage:"),
            (vec!["child", "--wallet", "test", "extra"], "usage:"),
            (
                vec!["child", "--wallet", "--new-master"],
                "invalid source wallet name",
            ),
            (vec!["bad/name"], "invalid new wallet name"),
            (vec!["test"], "wallet name already exists"),
            (vec!["child", "--wallet", "missing"], "unknown wallet"),
            (
                vec!["child", "--wallet", "test"],
                "source wallet has no recovery phrase",
            ),
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
            let mut output = Vec::new();
            let error = new_wallet_with_output(&mut wallet.app, &args, &mut output).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
            assert!(output.is_empty());
            assert_eq!(fs::read(&wallet.app.config.vault).unwrap(), before);
        }
    }

    #[test]
    fn new_wallet_save_failures_do_not_print_success_or_recovery_phrases() {
        use crate::test_support::{Fault, with_fault};
        for shared in [false, true] {
            for fault in [Fault::Write, Fault::Rename, Fault::DirectorySync] {
                let mut wallet = crate::test_support::TestWallet::new();
                let session = Session::test_session(&wallet.app.config.vault);
                let mut initial = session.load().unwrap();
                initial
                    .add_master("source", LockedBytes::from_slice(&[0; 32]).unwrap())
                    .unwrap();
                session.save(&mut initial).unwrap();
                drop(initial);
                let before = fs::read(&wallet.app.config.vault).unwrap();
                let args = if shared {
                    vec!["created".into(), "--wallet".into(), "source".into()]
                } else {
                    vec!["created".into()]
                };
                let mut output = Vec::new();
                let error = with_fault(fault, || {
                    new_wallet_with_output(&mut wallet.app, &args, &mut output)
                })
                .unwrap_err();
                assert!(output.is_empty());
                let saved = session.load().unwrap();
                assert_eq!(saved.config_audit().edits(), 0);
                if fault == Fault::DirectorySync {
                    assert!(error.to_string().contains("vault saved"));
                    assert!(saved.contains("created"));
                    assert_eq!(
                        saved.derivation_index("created").unwrap(),
                        Some(u32::from(shared))
                    );
                } else {
                    assert_eq!(fs::read(&wallet.app.config.vault).unwrap(), before);
                    assert!(!saved.contains("created"));
                    new_wallet_with_output(&mut wallet.app, &args, &mut output).unwrap();
                    assert_eq!(
                        session.load().unwrap().derivation_index("created").unwrap(),
                        Some(u32::from(shared))
                    );
                }
            }
        }
    }

    fn listing_wallet() -> crate::test_support::TestWallet {
        let wallet = crate::test_support::TestWallet::new();
        let session = wallet.app.session.as_ref().unwrap();
        let mut data = session.load().unwrap();
        data.add_imported(
            "other",
            Keypair::new_from_array([8; 32]).to_keypair_bytes().unwrap(),
        )
        .unwrap();
        session.save(&mut data).unwrap();
        wallet
    }

    #[test]
    fn listing_without_balances_never_connects_to_configured_rpc() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        for filtered in [false, true] {
            let mut wallet = listing_wallet();
            wallet.app.config.rpc.url = Some(format!("http://{}", listener.local_addr().unwrap()));
            wallet.app.config.rpc.timeout_secs = 1;
            wallet.app.config.rpc.show_balances = false;
            let args = if filtered {
                vec!["test".into()]
            } else {
                vec![]
            };
            let mut output = Vec::new();
            list_with_output(&mut wallet.app, &args, &mut output).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains(&format!("test  {}\n", wallet.identity.pubkey)));
            assert_eq!(output.contains("other  "), !filtered);
            assert_eq!(output.lines().count(), if filtered { 1 } else { 2 });
            assert!(!output.contains("SOL:"));
            assert!(!output.contains("token "));
            assert!(wallet.app.session.is_none());
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn listing_balances_verifies_cluster_and_queries_only_selected_wallets() {
        use serde_json::json;
        for filtered in [false, true] {
            let mut wallet = listing_wallet();
            let mint = Pubkey::new_from_array([9; 32]);
            let token_address = Pubkey::new_from_array([10; 32]);
            let mut responses = vec![json!(
                crate::rpc::expected_genesis(&wallet.app.config).unwrap()
            )];
            let count = if filtered { 1 } else { 2 };
            for _ in 0..count {
                responses.push(json!({"value":1_250_000_000u64}));
                for program in [TOKEN, TOKEN_2022] {
                    responses.push(json!({"value":[{
                        "pubkey":token_address.to_string(),
                        "account":{"owner":program.to_string(), "data":{"parsed":{"info":{
                            "mint":mint.to_string(),
                            "tokenAmount":{"amount":"250", "decimals":2}
                        }}}}
                    }]}));
                }
            }
            let (config, server) = crate::test_support::mock_rpc_config(responses);
            wallet.app.config.rpc = config.rpc;
            wallet.app.config.rpc.show_balances = true;
            let args = if filtered {
                vec!["test".into()]
            } else {
                vec![]
            };
            let mut output = Vec::new();
            list_with_output(&mut wallet.app, &args, &mut output).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert_eq!(output.contains("other  "), !filtered);
            assert_eq!(output.matches("  SOL: 1.25\n").count(), count);
            assert_eq!(
                output
                    .matches(&format!("  token {mint}  2.5  account {token_address}\n"))
                    .count(),
                count * 2
            );
            let requests = server.join().unwrap();
            assert_eq!(requests.len(), 1 + count * 3);
            assert_eq!(requests[0]["method"], "getGenesisHash");
            let identities = Session::test_session(&wallet.app.config.vault)
                .load()
                .unwrap()
                .public_snapshot();
            let selected = identities
                .accounts
                .iter()
                .filter(|a| !filtered || a.name == "test");
            for (rows, account) in requests[1..].as_chunks::<3>().0.iter().zip(selected) {
                assert_eq!(rows[0]["method"], "getBalance");
                for row in rows {
                    assert_eq!(row["params"][0], account.pubkey.to_string());
                }
                for (row, program) in rows[1..].iter().zip([TOKEN, TOKEN_2022]) {
                    assert_eq!(row["method"], "getTokenAccountsByOwner");
                    assert_eq!(row["params"][1]["programId"], program.to_string());
                }
            }
        }
    }

    #[test]
    fn listing_balances_rejects_wrong_cluster_before_querying_accounts() {
        let mut wallet = listing_wallet();
        let (config, server) =
            crate::test_support::mock_rpc_config(vec![serde_json::json!("wrong")]);
        wallet.app.config.rpc = config.rpc;
        wallet.app.config.rpc.show_balances = true;
        let mut output = Vec::new();
        assert!(
            list_with_output(&mut wallet.app, &[], &mut output)
                .unwrap_err()
                .to_string()
                .contains("genesis hash")
        );
        assert!(output.is_empty());
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], "getGenesisHash");
    }

    #[test]
    fn fixed_keypair_parser_rejects_partial_excess_and_malformed_arrays() {
        let input = serde_json::to_vec(&vec![7u8; 64]).unwrap();
        assert_eq!(*parse_keypair_json(&input).unwrap(), [7; 64]);
        for length in [0, 63, 65] {
            assert!(parse_keypair_json(&serde_json::to_vec(&vec![7u8; length]).unwrap()).is_err());
        }
        for input in [b"[7,7,999]".as_slice(), b"[7,7,", b"null"] {
            assert!(parse_keypair_json(input).is_err());
        }
        let mut trailing = input;
        trailing.extend_from_slice(b" 0");
        assert!(parse_keypair_json(&trailing).is_err());
    }

    #[test]
    fn token_2022_is_rejected_before_any_approval_or_signing() {
        assert!(ensure_transfer_program(TOKEN).is_ok());
        assert!(ensure_transfer_program(TOKEN_2022).is_err());
        assert!(ensure_transfer_program(SYSTEM).is_err());
    }

    fn refresh_responses(fee: u64, height: u64) -> Vec<Value> {
        vec![
            serde_json::json!({"context":{"slot":100}, "value":{"blockhash":Hash::new_from_array([8; 32]).to_string(),"lastValidBlockHeight":200}}),
            serde_json::json!({"value":fee}),
            serde_json::json!({"value":{"err":null}}),
            serde_json::json!(height),
        ]
    }

    #[test]
    fn refresh_signs_exact_fresh_message_and_retains_the_approved_transfer() {
        let wallet = crate::test_support::TestWallet::new();
        let target = Pubkey::new_from_array([9; 32]);
        let instruction = system_transfer(&wallet.identity.pubkey, &target, 123);
        let (rpc, server) = crate::test_support::mock_rpc(refresh_responses(5000, 150));
        let signed = refresh_and_sign(
            &wallet.app,
            &rpc,
            &wallet.identity,
            &[instruction],
            5000,
            0,
            None,
        )
        .unwrap();
        let requests = server.join().unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|r| r["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "getLatestBlockhash",
                "getFeeForMessage",
                "simulateTransaction",
                "getBlockHeight"
            ]
        );
        assert_eq!(requests[2]["params"][1]["minContextSlot"], 100);
        assert_eq!(
            signed.message.recent_blockhash(),
            &Hash::new_from_array([8; 32])
        );
        let VersionedMessage::V0(message) = &signed.message else {
            panic!()
        };
        assert_eq!(&message.instructions[0].data[4..], &123u64.to_le_bytes());
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(wallet.identity.pubkey.as_array()).unwrap();
        key.verify(
            &wincode::serialize(&signed.message).unwrap(),
            &ed25519_dalek::Signature::from_bytes(signed.signatures[0].as_array()),
        )
        .unwrap();
    }

    #[test]
    fn signer_is_prepared_before_the_final_height_request() {
        let wallet = crate::test_support::TestWallet::new();
        let path = wallet.app.config.vault.clone();
        let instruction = system_transfer(
            &wallet.identity.pubkey,
            &Pubkey::new_from_array([9; 32]),
            123,
        );
        let (rpc, server) =
            crate::test_support::mock_rpc_with(refresh_responses(5000, 150), move |request| {
                if request["method"] == "getBlockHeight" {
                    // Once the final check is requested, signing must no longer depend
                    // on disk. The old ordering would fail to load this truncated vault.
                    std::fs::write(&path, []).unwrap();
                }
            });
        let signed = refresh_and_sign(
            &wallet.app,
            &rpc,
            &wallet.identity,
            &[instruction],
            5000,
            0,
            None,
        )
        .unwrap();
        server.join().unwrap();
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(wallet.identity.pubkey.as_array()).unwrap();
        key.verify(
            &wincode::serialize(&signed.message).unwrap(),
            &ed25519_dalek::Signature::from_bytes(signed.signatures[0].as_array()),
        )
        .unwrap();
    }

    #[test]
    fn changed_fees_expiry_and_changed_identity_prevent_signing() {
        let mut wallet = crate::test_support::TestWallet::new();
        let instruction = system_transfer(
            &wallet.identity.pubkey,
            &Pubkey::new_from_array([9; 32]),
            123,
        );
        let mut changed_fee = refresh_responses(6000, 150);
        changed_fee.truncate(2);
        let (rpc, server) = crate::test_support::mock_rpc(changed_fee);
        let error = refresh_and_sign(
            &wallet.app,
            &rpc,
            &wallet.identity,
            std::slice::from_ref(&instruction),
            5000,
            0,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("fee or rent changed"));
        server.join().unwrap();
        let (rpc, server) = crate::test_support::mock_rpc(refresh_responses(5000, 199));
        assert!(
            refresh_and_sign(
                &wallet.app,
                &rpc,
                &wallet.identity,
                std::slice::from_ref(&instruction),
                5000,
                0,
                None
            )
            .unwrap_err()
            .to_string()
            .contains("expiry")
        );
        server.join().unwrap();
        wallet.identity.pubkey = Pubkey::new_from_array([11; 32]);
        let instruction = system_transfer(
            &wallet.identity.pubkey,
            &Pubkey::new_from_array([9; 32]),
            123,
        );
        let mut responses = refresh_responses(5000, 150);
        responses.truncate(3); // Identity validation precedes the final height request.
        let (rpc, server) = crate::test_support::mock_rpc(responses);
        assert!(
            refresh_and_sign(
                &wallet.app,
                &rpc,
                &wallet.identity,
                &[instruction],
                5000,
                0,
                None
            )
            .unwrap_err()
            .to_string()
            .contains("identity changed")
        );
        server.join().unwrap();
    }

    #[test]
    fn export_requires_exactly_one_supported_format() {
        for args in [
            vec![],
            vec!["main"],
            vec!["main", "--base58"],
            vec!["main", "--private-key", "--mnemonic"],
            vec!["main", "--private-key", "--private-key"],
        ] {
            let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
            assert!(parse_export(&args).is_err());
        }
        for flag in ["--private-key", "--mnemonic"] {
            assert_eq!(
                parse_export(&["main".into(), flag.into()]).unwrap().0,
                "main"
            );
        }
    }

    #[test]
    fn private_key_exports_round_trip_for_derived_and_imported_wallets() {
        let mut data = vault::Vault::default();
        data.add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        data.add_derived("child", "main").unwrap();
        let imported = Keypair::new_from_array([7; 32]).to_keypair_bytes().unwrap();
        data.add_imported("imported", imported).unwrap();
        for name in ["main", "child", "imported"] {
            let mut output = Vec::new();
            let mut prompts = 0;
            export_wallet(
                &data,
                name,
                ExportKind::PrivateKey,
                || {
                    prompts += 1;
                    Ok(Some(name.into()))
                },
                &mut output,
            )
            .unwrap();
            assert_eq!(prompts, 1);
            let text = String::from_utf8(output).unwrap();
            let key = text
                .split("Private key (base58):\n")
                .nth(1)
                .unwrap()
                .lines()
                .next()
                .unwrap();
            let bytes = decode_base58_keypair(key).unwrap();
            assert_eq!(
                *bytes,
                *data.signer(name).unwrap().to_keypair_bytes().unwrap()
            );
            assert_eq!(
                Keypair::try_from(&bytes[..]).unwrap().pubkey(),
                data.account(name).unwrap().pubkey
            );
            assert!(!text.contains("Recovery phrase:"));
            if name != "imported" {
                assert!(!text.contains(data.mnemonic(name).unwrap().as_str()));
            }
        }
    }

    #[test]
    fn mnemonic_export_shows_the_selected_wallet_path() {
        let mut data = vault::Vault::default();
        data.add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        data.add_derived("child", "main").unwrap();
        let mut output = Vec::new();
        export_wallet(
            &data,
            "child",
            ExportKind::Mnemonic,
            || Ok(Some("child".into())),
            &mut output,
        )
        .unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Derivation path: m/44'/501'/1'/0'"));
        assert!(text.contains("same master"));
        assert!(text.contains(data.mnemonic("child").unwrap().as_str()));
        assert!(!text.contains("Private key (base58):"));
    }

    #[test]
    fn export_cancellation_and_unavailable_secrets_never_reveal_keys() {
        let mut data = vault::Vault::default();
        data.add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        data.add_imported(
            "imported",
            Keypair::new_from_array([7; 32]).to_keypair_bytes().unwrap(),
        )
        .unwrap();
        let expected_key =
            bs58::encode(&data.signer("main").unwrap().to_keypair_bytes().unwrap()[..])
                .into_string();
        for kind in [ExportKind::PrivateKey, ExportKind::Mnemonic] {
            for answer in [None, Some("wrong".into())] {
                let mut output = Vec::new();
                let result = export_wallet(&data, "main", kind, || Ok(answer.clone()), &mut output);
                assert_eq!(result.unwrap_err().to_string(), "export cancelled");
                let text = String::from_utf8(output).unwrap();
                assert!(!text.contains(&expected_key));
                assert!(!text.contains(data.mnemonic("main").unwrap().as_str()));
                assert!(!text.contains("Recovery phrase:"));
                assert!(!text.contains("Private key (base58):"));
            }
        }
        for (name, kind) in [
            ("imported", ExportKind::Mnemonic),
            ("unknown", ExportKind::PrivateKey),
        ] {
            let mut output = Vec::new();
            assert!(
                export_wallet(
                    &data,
                    name,
                    kind,
                    || panic!("must fail before prompting"),
                    &mut output
                )
                .is_err()
            );
            assert!(output.is_empty());
        }
    }

    #[test]
    fn simulation_output_keeps_logs_bounded_and_failures_visible() {
        let mut output = Vec::new();
        let logs = vec![format!("\u{1b}[31m{}", "x".repeat(400)); 22];
        let simulation = serde_json::json!({"err": null, "unitsConsumed": 5123, "logs": logs});
        render_simulation(&mut output, &simulation, false, "CU probe").unwrap();
        assert!(output.is_empty());
        render_simulation(&mut output, &simulation, true, "Simulation").unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("Simulation: OK"));
        assert!(text.contains("Compute units: 5123"));
        assert!(text.contains("2 more log entries"));
        assert!(!text.contains('\u{1b}'));
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("  [31m"))
                .count(),
            20
        );
        assert!(
            text.lines()
                .filter(|line| line.starts_with("  [31m"))
                .all(|line| line.chars().count() == 302)
        );
        let failed = serde_json::json!({"err": "insufficient funds", "logs": ["Program failed"]});
        let mut output = Vec::new();
        assert!(render_simulation(&mut output, &failed, true, "Simulation").is_err());
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("FAILED"));
        assert!(text.contains("insufficient funds"));
        assert!(text.contains("Program failed"));
        assert!(text.trim_end().ends_with(OUTPUT_RULE));
        let mut output = Vec::new();
        let error = render_simulation(&mut output, &failed, false, "Simulation").unwrap_err();
        assert!(error.to_string().contains("insufficient funds"));
        assert!(output.is_empty());
        assert!(
            render_simulation(&mut output, &serde_json::json!({}), true, "Simulation").is_err()
        );
    }

    #[test]
    fn deletion_confirms_name_and_only_offers_erasure_for_unused_phrases() {
        let mut vault = vault::Vault::default();
        vault
            .add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        assert!(confirm_delete(&vault, "main", || Ok(None)).is_err());
        assert!(confirm_delete(&vault, "main", || Ok(Some("wrong".into()))).is_err());
        let mut keep = [Some("main".into()), Some("".into())].into_iter();
        assert!(!confirm_delete(&vault, "main", || Ok(keep.next().unwrap())).unwrap());
        let mut erase = [Some("main".into()), Some("ERASE".into())].into_iter();
        assert!(confirm_delete(&vault, "main", || Ok(erase.next().unwrap())).unwrap());
        let mut closed = [Some("main".into()), None].into_iter();
        assert!(confirm_delete(&vault, "main", || Ok(closed.next().unwrap())).is_err());
        assert!(vault.contains("main")); // Prompts/cancellation do not mutate the vault.
        vault.add_derived("child", "main").unwrap();
        let mut calls = 0;
        assert!(
            !confirm_delete(&vault, "main", || {
                calls += 1;
                Ok(Some("main".into()))
            })
            .unwrap()
        );
        assert_eq!(calls, 1); // No erasure prompt for a phrase still in use.
    }
    #[test]
    fn amount_exactness() {
        assert_eq!(parse_amount("1.000000001", 9).unwrap(), 1_000_000_001);
        assert_eq!(parse_amount("0.001", 3).unwrap(), 1);
        assert!(parse_amount("0.0001", 3).is_err());
        assert!(parse_amount("-1", 9).is_err());
        assert!(parse_amount("18446744073709551616", 0).is_err());
    }

    #[test]
    fn transfer_all_reserves_quoted_fee_and_requires_zero_remainder() {
        assert_eq!(spend_all_lamports(10_000, 5_000).unwrap(), 5_000);
        assert_eq!(spend_all_lamports(42, 0).unwrap(), 42);
        assert!(spend_all_lamports(5_000, 5_000).is_err());
        assert!(spend_all_lamports(4_999, 5_000).is_err());
        let source = Pubkey::new_from_array([7; 32]);
        let target = Pubkey::new_from_array([8; 32]);
        let instruction = system_transfer(&source, &target, 5_000);
        assert_eq!(instruction.program_id, SYSTEM);
        assert_eq!(instruction.data[..4], 2u32.to_le_bytes());
        assert_eq!(instruction.data[4..], 5_000u64.to_le_bytes());
        let (unsigned, _) = compile_unsigned(&source, &[instruction], Hash::default()).unwrap();
        let VersionedMessage::V0(message) = unsigned.message else {
            panic!("expected v0 message");
        };
        assert_eq!(message.instructions[0].data[4..], 5_000u64.to_le_bytes());
        assert!(ensure_all_would_drain(&serde_json::json!({"postBalances": [0, 5_000]})).is_ok());
        assert!(ensure_all_would_drain(&serde_json::json!({"postBalances": [1]})).is_err());
        assert!(ensure_all_would_drain(&serde_json::json!({"postBalances": null})).is_err());
    }
    #[test]
    fn token_instruction_layout() {
        let owner = Pubkey::new_from_array([7; 32]);
        let mint = Pubkey::new_from_array([8; 32]);
        let source = ata(&owner, &mint, &TOKEN);
        assert_ne!(source, ata(&owner, &mint, &TOKEN_2022));
        let ix = transfer_checked(&source, &mint, &source, &owner, 42, 6, TOKEN);
        assert_eq!(ix.data, [12, 42, 0, 0, 0, 0, 0, 0, 0, 6]);
        assert_eq!(close_token_account(&source, &owner, TOKEN).data, [9]);
    }

    #[test]
    fn close_selection_requires_ata_and_burn_for_nonempty() {
        let owner = Pubkey::new_from_array([7; 32]);
        let mint = Pubkey::new_from_array([8; 32]);
        let address = ata(&owner, &mint, &TOKEN);
        let account = |address, raw_amount| TokenAccount {
            address,
            mint,
            raw_amount,
            decimals: 6,
        };
        assert!(matches!(
            close_eligibility(&owner, TOKEN, account(address, 0), false),
            CloseEligibility::Eligible(_)
        ));
        assert!(matches!(
            close_eligibility(&owner, TOKEN, account(address, 1), false),
            CloseEligibility::NonEmpty
        ));
        assert!(matches!(
            close_eligibility(
                &owner,
                TOKEN,
                account(Pubkey::new_from_array([9; 32]), 0),
                false
            ),
            CloseEligibility::NonAssociated
        ));
        let CloseEligibility::Eligible(candidate) =
            close_eligibility(&owner, TOKEN, account(address, 42), true)
        else {
            panic!("--burn should select non-empty ATA");
        };
        assert_eq!(candidate.raw_amount, 42);
        let mut instructions = Vec::new();
        candidate.append_instructions(&owner, &mut instructions);
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].data, [15, 42, 0, 0, 0, 0, 0, 0, 0, 6]);
        assert_eq!(instructions[1].data, [9]);
        assert_eq!(instructions[0].accounts[1].pubkey, mint);
        assert!(instructions[0].accounts[1].is_writable);
        assert!(instructions[0].accounts[2].is_signer);
    }

    #[test]
    fn close_selection_and_packet_bound() {
        let selection =
            parse_close_selection(&["--wallet".into(), "main".into(), "--all".into()]).unwrap();
        assert_eq!(selection.wallet.as_deref(), Some("main"));
        assert!(selection.all);
        assert!(!selection.burn);
        assert!(
            parse_close_selection(&["--burn".into(), "--all".into()])
                .unwrap()
                .burn
        );
        assert!(
            parse_close_selection(&["--burn".into(), "--burn".into(), "--all".into()]).is_err()
        );
        assert!(parse_close_selection(&[]).is_err());
        assert!(parse_close_selection(&["--all".into(), "mint".into()]).is_err());

        let owner = Pubkey::new_from_array([1; 32]);
        let mut instructions = Vec::new();
        let mut fitting = 0;
        for index in 10..50 {
            let address = Pubkey::new_from_array([index; 32]);
            instructions.push(close_token_account(&address, &owner, TOKEN));
            if !close_batch_fits(&owner, &instructions, true).unwrap() {
                break;
            }
            fitting += 1;
        }
        assert!(fitting > 8);
        assert!(fitting < 40);
    }

    #[test]
    fn wrapped_sol_closes_without_burn_and_cu_limit_is_bounded() {
        let owner = Pubkey::new_from_array([7; 32]);
        for (mint, program) in [(NATIVE_MINT, TOKEN), (NATIVE_MINT_2022, TOKEN_2022)] {
            let candidate = CloseCandidate {
                mint,
                address: ata(&owner, &mint, &program),
                program,
                raw_amount: 1_000_000,
                decimals: 9,
            };
            assert!(!candidate.requires_burn());
            let mut instructions = Vec::new();
            candidate.append_instructions(&owner, &mut instructions);
            assert_eq!(instructions.len(), 1);
            assert_eq!(instructions[0].data, [9]);
        }
        assert_eq!(tuned_compute_limit(10_000, 10).unwrap(), 11_000);
        assert_eq!(tuned_compute_limit(1_000, 0).unwrap(), 2_000);
        assert_eq!(tuned_compute_limit(1_390_000, 10).unwrap(), 1_400_000);
        assert!(tuned_compute_limit(0, 10).is_err());
        assert!(tuned_compute_limit(1_400_001, 10).is_err());
        assert_eq!(set_compute_unit_limit(11_000).data, [2, 248, 42, 0, 0]);
    }

    #[test]
    fn burn_and_close_compile_with_budget_in_order() {
        let owner = Pubkey::new_from_array([7; 32]);
        let mint = Pubkey::new_from_array([8; 32]);
        let candidate = CloseCandidate {
            mint,
            address: ata(&owner, &mint, &TOKEN),
            program: TOKEN,
            raw_amount: 42,
            decimals: 6,
        };
        let mut instructions = vec![set_compute_unit_limit(20_000)];
        candidate.append_instructions(&owner, &mut instructions);
        let (unsigned, wire) = compile_unsigned(&owner, &instructions, Hash::default()).unwrap();
        assert!(wire.len() <= MAX_TRANSACTION_BYTES);
        let decoded: VersionedTransaction = wincode::deserialize(&wire).unwrap();
        assert_eq!(decoded, unsigned);
        let VersionedMessage::V0(message) = decoded.message else {
            panic!("expected v0 message");
        };
        assert_eq!(message.instructions.len(), 3);
        assert_eq!(
            message.instructions[0].data,
            set_compute_unit_limit(20_000).data
        );
        assert_eq!(message.instructions[1].data, instructions[1].data);
        assert_eq!(message.instructions[2].data, [9]);
    }

    #[test]
    fn base58_import_accepts_quoted_seed_and_keypair() {
        let seed = [7u8; 32];
        let expected = Keypair::new_from_array(seed).pubkey();
        let quoted_seed = format!("\"{}\"", bs58::encode(seed).into_string());
        let decoded = decode_base58_keypair(&quoted_seed).unwrap();
        assert_eq!(Keypair::try_from(&decoded[..]).unwrap().pubkey(), expected);

        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(&seed);
        keypair[32..].copy_from_slice(expected.as_ref());
        let quoted_keypair = format!("'{}'", bs58::encode(keypair).into_string());
        assert_eq!(&*decode_base58_keypair(&quoted_keypair).unwrap(), &keypair);

        keypair[32] ^= 1;
        assert!(decode_base58_keypair(&bs58::encode(keypair).into_string()).is_err());
    }

    #[test]
    fn v0_transaction_wincode_round_trip() {
        let signer = Keypair::new_from_array([7; 32]);
        let destination = Pubkey::new_from_array([9; 32]);
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&100u64.to_le_bytes());
        let instruction = Instruction {
            program_id: SYSTEM,
            accounts: vec![
                AccountMeta::new(signer.pubkey(), true),
                AccountMeta::new(destination, false),
            ],
            data,
        };
        let message = v0::Message::try_compile(
            &signer.pubkey(),
            &[instruction],
            &[],
            solana_message::Hash::new_from_array([8; 32]),
        )
        .unwrap();
        assert!(
            sign_v0(
                VersionedMessage::V0(message.clone()),
                &Keypair::new_from_array([8; 32])
            )
            .is_err()
        );
        let transaction = sign_v0(VersionedMessage::V0(message), &signer).unwrap();
        let wire = wincode::serialize(&transaction).unwrap();
        let decoded: VersionedTransaction = wincode::deserialize(&wire).unwrap();
        assert!(matches!(decoded.message, VersionedMessage::V0(_)));
        assert_eq!(decoded.signatures, transaction.signatures);
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(signer.pubkey().as_array()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(decoded.signatures[0].as_array());
        verifying_key
            .verify(&wincode::serialize(&decoded.message).unwrap(), &signature)
            .unwrap();
    }
}
