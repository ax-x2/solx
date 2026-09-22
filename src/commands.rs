use crate::{
    App, Result,
    config::{self, valid_name},
    fail,
    rpc::{Rpc, TokenAccount, safe_text},
    signer::Keypair,
    vault::{self, Session},
};
use bip39::Mnemonic;
use serde_json::Value;
use solana_message::{AccountMeta, Hash, Instruction, VersionedMessage, v0};
use solana_pubkey::Pubkey;
use solana_transaction::{Signature, versioned::VersionedTransaction};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    str::FromStr,
};
use zeroize::Zeroizing;

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
        summary: "derive a wallet or create a new master",
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
        summary: "list wallets and balances",
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
        "Usage: solx [--config PATH] <command> [options]\n       solx shell\n       solx   (opens CLI shell)"
    );
    for plugin in PLUGINS {
        println!("  {:<15} {}", plugin.name, plugin.summary);
    }
    println!(
        "\nCommands:\n  solx init [NAME]\n  solx new NAME [--new-master]\n  solx import NAME (--mnemonic | --base58 [KEY] | --keypair-file PATH)\n  solx export NAME (--private-key | --mnemonic)\n  solx list [--wallet NAME]\n  solx delete NAME\n  solx history [--wallet NAME] [--limit N]\n  solx transfer --wallet NAME --to ADDRESS --amount SOL|ALL\n  solx token-transfer --wallet NAME --mint MINT --to ADDRESS --amount TOKENS\n  solx close-ata [--wallet NAME] [--burn] (--all | MINT [MINT ...])"
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
    let password = Zeroizing::new(rpassword::prompt_password("New vault password: ")?);
    let confirmation = Zeroizing::new(rpassword::prompt_password("Repeat password: ")?);
    if password != confirmation {
        return fail("passwords do not match");
    }
    if password.len() < 12 {
        return fail("password must be at least 12 characters");
    }
    let entropy = vault::fresh_entropy()?;
    let phrase = vault::phrase(&entropy)?;
    let mut data = vault::Vault::default();
    data.add_master(name, entropy)?;
    if !app.config_path.exists() {
        write_example_config(&app.config_path)?;
    }
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

fn write_example_config(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or("config path needs a parent directory")?;
    let existed = parent.exists();
    if !existed {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !existed {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(config::EXAMPLE.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn new_wallet(app: &mut App, args: &[String]) -> Result<()> {
    if args.is_empty() || args.len() > 2 || (args.len() == 2 && args[1] != "--new-master") {
        return fail("usage: solx new NAME [--new-master]");
    }
    let name = &args[0];
    let mut data = app.vault()?;
    if args.len() == 2 {
        let entropy = vault::fresh_entropy()?;
        let phrase = vault::phrase(&entropy)?;
        data.add_master(name, entropy)?;
        app.save_vault(&mut data)?;
        println!("Created {name}: {}", data.account(name)?.pubkey);
        println!(
            "Recovery phrase (shown once; store it securely):\n{}",
            phrase.as_str()
        );
    } else {
        data.add_derived(name)?;
        app.save_vault(&mut data)?;
        println!("Derived {name}: {}", data.account(name)?.pubkey);
    }
    Ok(())
}

fn import(app: &mut App, args: &[String]) -> Result<()> {
    if args.len() < 2 || args.len() > 3 {
        return fail("usage: solx import NAME (--mnemonic | --base58 [KEY] | --keypair-file PATH)");
    }
    if args[1] == "--base58" && args.len() == 3 && !app.shell {
        return fail(
            "inline private keys are only accepted in the CLI shell; omit KEY for a hidden prompt",
        );
    }
    let name = &args[0];
    let mut data = app.vault()?;
    if data.contains(name) {
        return fail("wallet name already exists");
    }
    match args[1].as_str() {
        "--mnemonic" if args.len() == 2 => {
            let phrase = Zeroizing::new(rpassword::prompt_password("Mnemonic (hidden): ")?);
            let mnemonic = Mnemonic::parse(&*phrase)?;
            let entropy = Zeroizing::new(mnemonic.to_entropy());
            data.add_master(name, entropy)?;
        }
        "--base58" if args.len() == 2 || args.len() == 3 => {
            let prompted = if args.len() == 2 {
                Some(Zeroizing::new(rpassword::prompt_password(
                    "Base58 private key (hidden): ",
                )?))
            } else {
                None
            };
            let secret = prompted
                .as_ref()
                .map(|value| value.as_str())
                .unwrap_or_else(|| args[2].as_str());
            data.add_imported(name, decode_base58_keypair(secret)?)?;
        }
        "--keypair-file" if args.len() == 3 => {
            let path = Path::new(&args[2]);
            let file = fs::File::open(path)?;
            if file.metadata()?.len() > 1024 {
                return fail("keypair file is too large");
            }
            let mut contents = Zeroizing::new(Vec::with_capacity(256));
            file.take(1025).read_to_end(&mut contents)?;
            if contents.len() > 1024 {
                return fail("keypair file is too large");
            }
            let numbers: Vec<u8> = serde_json::from_slice(&contents)?;
            let numbers = Zeroizing::new(numbers);
            let bytes = Zeroizing::new(
                <[u8; 64]>::try_from(numbers.as_slice())
                    .map_err(|_| "keypair file must have 64 bytes")?,
            );
            data.add_imported(name, bytes)?;
        }
        _ => {
            return fail(
                "usage: solx import NAME (--mnemonic | --base58 [KEY] | --keypair-file PATH)",
            );
        }
    }
    app.save_vault(&mut data)?;
    println!("Imported {name}: {}", data.account(name)?.pubkey);
    if args[1] == "--keypair-file" {
        eprintln!("Warning: the source keypair file is still on disk.");
    } else if args[1] == "--base58" && args.len() == 3 {
        eprintln!(
            "Warning: the key was visible in your terminal; use --base58 without KEY for a hidden prompt."
        );
    }
    Ok(())
}

fn decode_base58_keypair(input: &str) -> Result<Zeroizing<[u8; 64]>> {
    let input = input
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            input
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(input);
    let mut bytes = Zeroizing::new([0u8; 64]);
    let len = bs58::decode(input).onto(&mut bytes[..])?;
    match len {
        32 => {
            let secret: [u8; 32] = bytes[..32].try_into()?;
            let pubkey = Keypair::new_from_array(secret).pubkey();
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
    // Do not hold a stdout lock while waiting for the user's confirmation.
    export_wallet(
        &data,
        name,
        kind,
        crate::read_bounded_line,
        &mut io::stdout(),
    )
}

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
    match kind {
        ExportKind::PrivateKey => {
            let bytes = data.signer(name)?.to_keypair_bytes();
            let mut encoded = Zeroizing::new([0u8; 88]);
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
    let mut data = app.vault()?;
    let was_default = data.first_name()? == name;
    let erase_phrase = confirm_delete(&data, name, crate::read_bounded_line)?;
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

fn confirm_delete(
    data: &vault::Vault,
    name: &str,
    mut read_line: impl FnMut() -> io::Result<Option<String>>,
) -> Result<bool> {
    let account = data.account(name)?;
    let usage = data.recovery_phrase_use(name)?;
    println!("Delete local wallet: {name}\nAddress: {}", account.pubkey);
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
    let options = Options::parse(args, &["wallet"])?;
    let data = app.vault()?;
    let filter = options.get("wallet");
    if let Some(name) = filter {
        data.account(name)?;
    }
    if data.accounts.is_empty() {
        println!("No saved wallets.");
        return Ok(());
    }
    let rpc = if app.config.rpc.url.is_some() {
        Some(app.rpc()?)
    } else {
        None
    };
    for account in data
        .accounts
        .iter()
        .filter(|a| filter.is_none_or(|name| a.name == name))
    {
        println!("{}  {}", account.name, account.pubkey);
        if let Some(rpc) = &rpc {
            let balance = rpc.balance(&account.pubkey)?;
            println!("  SOL: {}", format_amount(balance, 9));
            if balance == 0 {
                eprintln!("  Warning: {} has zero SOL balance", account.name);
            }
            for program in [TOKEN, TOKEN_2022] {
                for token_account in rpc.token_accounts(&account.pubkey, &program)? {
                    println!(
                        "  token {}  {}  account {}",
                        token_account.mint,
                        safe_text(&token_account.display_amount, 60),
                        token_account.address
                    );
                }
            }
        }
    }
    Ok(())
}

fn history(app: &mut App, args: &[String]) -> Result<()> {
    let options = Options::parse(args, &["wallet", "limit"])?;
    let data = app.vault()?;
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
    let data = app.vault()?;
    let source_name = data.name_or_first(options.get("wallet"))?;
    let source = data.signer(source_name)?;
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
        &source,
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
    let data = app.vault()?;
    let source_name = data.name_or_first(options.get("wallet"))?;
    let source = data.signer(source_name)?;
    let mint = Pubkey::from_str(options.required("mint")?)?;
    let target = target_address(&data, options.required("to")?)?;
    if source.pubkey() == target {
        return fail("cannot transfer to the same wallet");
    }
    let rpc = app.rpc()?;
    let token_program = mint_program(&rpc, &mint)?;
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
    if send_transaction(app, &rpc, &source, instructions, &details, false, None)?
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
    let data = app.vault()?;
    let name = data.name_or_first(selection.wallet.as_deref())?;
    let signer = data.signer(name)?;
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
    send_close_batches(app, &rpc, &signer, name, candidates)
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
    app: &App,
    rpc: &Rpc,
    signer: &Keypair,
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
    app: &App,
    rpc: &Rpc,
    signer: &Keypair,
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

fn target_address(data: &vault::Vault, value: &str) -> Result<Pubkey> {
    if data.contains(value) {
        Ok(data.account(value)?.pubkey)
    } else {
        Ok(Pubkey::from_str(value)?)
    }
}

fn warn_destination(data: &vault::Vault, rpc: &Rpc, target: &Pubkey) -> Result<()> {
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
    app: &App,
    rpc: &Rpc,
    signer: &Keypair,
    mut instructions: Vec<Instruction>,
    details: &str,
    burn_confirmation: bool,
    spend_all: Option<SpendAll>,
) -> Result<bool> {
    if instructions.is_empty() {
        return fail("invalid instruction count");
    }
    let hash = rpc.latest_blockhash()?;
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
    if let Some((_, expected_fee, _)) = all_quote {
        let final_fee = rpc.fee_for_message(&unsigned.message)?;
        if final_fee != expected_fee {
            return fail("transaction fee changed while resolving ALL; retry the transfer");
        }
    }
    println!(
        "\n{OUTPUT_RULE}\nTransaction\n\nConfigured cluster: {}\nRPC host: {}\nFee payer: {}",
        safe_text(&rpc.cluster, 80),
        safe_text(&rpc.endpoint, 150),
        signer.pubkey()
    );
    println!("{details}");
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
    let transaction = sign_v0(unsigned.message, signer)?;
    let signature = transaction
        .signatures
        .first()
        .ok_or("signed transaction has no signature")?
        .to_string();
    let wire = wincode::serialize(&transaction)?;
    if wire.len() > MAX_TRANSACTION_BYTES {
        return fail("signed transaction exceeds 1232-byte packet limit");
    }
    let returned = match rpc.send(&wire) {
        Ok(signature) => signature,
        Err(error) => {
            return Err(format!(
                "send outcome unknown; check signature {signature} before retrying: {error}"
            )
            .into());
        }
    };
    if returned != signature {
        return fail("RPC returned a different transaction signature");
    }
    println!("Submitted: {signature}");
    if rpc.confirm(&signature)? {
        println!("Confirmed: {signature}");
        Ok(true)
    } else {
        println!("Confirmation pending; check signature: {signature}");
        Ok(false)
    }
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

fn sign_v0(message: VersionedMessage, signer: &Keypair) -> Result<VersionedTransaction> {
    if !matches!(message, VersionedMessage::V0(_))
        || message.header().num_required_signatures != 1
        || message.static_account_keys().first() != Some(&signer.pubkey())
    {
        return fail("transaction must require only the selected fee payer's signature");
    }
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
        data.add_master("main", Zeroizing::new(vec![0; 32]))
            .unwrap();
        data.add_derived("child").unwrap();
        let imported = Keypair::new_from_array([7; 32]).to_keypair_bytes();
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
            assert_eq!(*bytes, *data.signer(name).unwrap().to_keypair_bytes());
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
        data.add_master("main", Zeroizing::new(vec![0; 32]))
            .unwrap();
        data.add_derived("child").unwrap();
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
        data.add_master("main", Zeroizing::new(vec![0; 32]))
            .unwrap();
        data.add_imported(
            "imported",
            Keypair::new_from_array([7; 32]).to_keypair_bytes(),
        )
        .unwrap();
        let expected_key =
            bs58::encode(&data.signer("main").unwrap().to_keypair_bytes()[..]).into_string();
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
            .add_master("main", Zeroizing::new(vec![0; 32]))
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
        vault.add_derived("child").unwrap();
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
            display_amount: "0".into(),
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
