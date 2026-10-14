use crate::{
    Result,
    config::{Config, valid_name},
    fail,
    kdf::{self, Argon2idParams},
    secret::{Locked, LockedBytes, LockedKey, LockedKeypair, LockedString},
    signer::Keypair,
};
use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use bip39::Mnemonic;
use ed25519_dalek_bip32::{ChildIndex, ExtendedSigningKey};
use solana_pubkey::Pubkey;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"SOLX";
const VERSION: u8 = 5;
const HEADER_LEN: usize = 48;
const MAX_FILE: u64 = 1024 * 1024;
const MAX_ACCOUNTS: usize = 128;
const MAX_MASTERS: usize = 32;
const MAX_RECIPIENTS: usize = 256;

#[derive(Clone, Copy)]
struct EnvelopeHeader {
    params: Argon2idParams,
    salt: [u8; 16],
    nonce: [u8; 12],
}

impl EnvelopeHeader {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 5 || &bytes[..4] != MAGIC {
            return fail("invalid vault header");
        }
        // Reject all old/unknown formats before allocation or password derivation.
        if bytes[4] != VERSION {
            return fail(
                "unsupported vault format; this build requires a v5 vault with authenticated settings history",
            );
        }
        if bytes.len() < HEADER_LEN + 16 || bytes.len() as u64 > MAX_FILE {
            return fail("truncated or oversized vault");
        }
        if bytes[5] != kdf::KDF_ID || bytes[6] != kdf::ARGON2_VERSION || bytes[7] != 0 {
            return fail("unsupported vault KDF header");
        }
        let params = Argon2idParams::from_costs(
            u32::from_le_bytes(bytes[8..12].try_into()?),
            u32::from_le_bytes(bytes[12..16].try_into()?),
            u32::from_le_bytes(bytes[16..20].try_into()?),
        )?;
        Ok(Self {
            params,
            salt: bytes[20..36].try_into()?,
            nonce: bytes[36..48].try_into()?,
        })
    }

    fn encode(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];
        bytes[..4].copy_from_slice(MAGIC);
        bytes[4] = VERSION;
        bytes[5] = kdf::KDF_ID;
        bytes[6] = kdf::ARGON2_VERSION;
        for (chunk, cost) in bytes[8..20]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(self.params.costs())
        {
            chunk.copy_from_slice(&cost.to_le_bytes());
        }
        bytes[20..36].copy_from_slice(&self.salt);
        bytes[36..48].copy_from_slice(&self.nonce);
        bytes
    }
}

pub struct Master {
    entropy: LockedBytes,
    next_index: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryPhraseUse {
    ImportedKey,
    Shared,
    UnusedAfterDeletion,
}

pub enum AccountKind {
    Derived { master: u8, index: u32 },
    Imported { keypair: LockedKeypair },
}

pub struct Account {
    pub name: String,
    pub pubkey: Pubkey,
    kind: AccountKind,
}

#[derive(Clone)]
pub struct PublicAccount {
    pub name: String,
    pub pubkey: Pubkey,
}
impl PublicAccount {
    pub fn pubkey(&self) -> Pubkey {
        self.pubkey
    }
}

pub struct PublicVault {
    pub accounts: Vec<PublicAccount>,
    recipients: Vec<[u8; 32]>,
}

impl PublicVault {
    pub fn contains(&self, name: &str) -> bool {
        self.accounts.iter().any(|a| a.name == name)
    }
    pub fn account(&self, name: &str) -> Result<&PublicAccount> {
        self.accounts
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| "unknown wallet".into())
    }
    pub fn name_or_first<'a>(&'a self, name: Option<&'a str>) -> Result<&'a str> {
        name.or_else(|| self.accounts.first().map(|a| a.name.as_str()))
            .ok_or_else(|| "vault has no accounts".into())
    }
    pub fn is_known_recipient(&self, key: &Pubkey) -> bool {
        self.recipients.iter().any(|p| p == key.as_ref())
    }
}

/// Authenticated local metadata, not an external audit log or trusted clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigAudit {
    edits: u64,
    last_edit_unix: u64,
}

impl ConfigAudit {
    pub fn edits(self) -> u64 {
        self.edits
    }

    pub fn last_edit(self) -> Option<u64> {
        (self.edits != 0).then_some(self.last_edit_unix)
    }

    fn validate(self) -> Result<()> {
        if (self.edits == 0) != (self.last_edit_unix == 0) || self.last_edit_unix > 253_402_300_799
        {
            return fail("invalid authenticated settings history");
        }
        Ok(())
    }

    fn record_edit(self, now: u64) -> Result<Self> {
        if now == 0 || now < self.last_edit_unix {
            return fail(
                "system clock is earlier than the last settings edit; correct the clock before saving",
            );
        }
        let next = Self {
            edits: self
                .edits
                .checked_add(1)
                .ok_or("settings edit counter exhausted")?,
            last_edit_unix: now,
        };
        next.validate()?;
        Ok(next)
    }
}

#[derive(Default)]
pub struct Vault {
    pub config: Config,
    config_audit: ConfigAudit,
    // Private baseline ensures every settings-changing save is counted.
    saved_config: Option<Config>,
    masters: Vec<Master>,
    pub accounts: Vec<Account>,
    recipients: Vec<[u8; 32]>,
    // Ciphertext loaded from disk, used to reject stale read/modify/write operations.
    source_bytes: Option<Vec<u8>>,
}

pub struct Session {
    path: PathBuf,
    header: EnvelopeHeader,
    key: LockedKey,
}

impl Session {
    #[cfg(test)]
    pub(crate) fn test_session(path: &Path) -> Self {
        let mut key = LockedKey::new().unwrap();
        key.bytes_mut().fill(2);
        Self {
            path: path.to_owned(),
            header: EnvelopeHeader {
                params: Argon2idParams::VAULT,
                salt: [1; 16],
                nonce: [0; 12],
            },
            key,
        }
    }

    pub fn create(path: &Path, password: &str, vault: &mut Vault) -> Result<Self> {
        if path.exists() {
            return fail("vault already exists");
        }
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| "OS randomness unavailable")?;
        let session = Self {
            path: path.to_path_buf(),
            header: EnvelopeHeader {
                params: Argon2idParams::VAULT,
                salt,
                nonce: [0; 12],
            },
            key: Argon2idParams::VAULT.derive(password, &salt)?,
        };
        session.save(vault)?;
        Ok(session)
    }

    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let encrypted = read_private_file(path)?;
        let header = EnvelopeHeader::parse(&encrypted)?;
        let session = Self {
            path: path.to_path_buf(),
            header,
            key: header.params.derive(password, &header.salt)?,
        };
        session.decrypt_bytes(encrypted)?;
        Ok(session)
    }

    pub fn load(&self) -> Result<Vault> {
        self.decrypt_bytes(read_private_file(&self.path)?)
    }

    fn decrypt_bytes(&self, encrypted: Vec<u8>) -> Result<Vault> {
        let header = EnvelopeHeader::parse(&encrypted)?;
        if header.params != self.header.params || header.salt != self.header.salt {
            return fail("vault key parameters changed; lock and unlock again");
        }
        let mut plain = LockedBytes::from_slice(&encrypted[HEADER_LEN..])?;
        let cipher = Aes256GcmSiv::new_from_slice(self.key.bytes())?;
        cipher
            .decrypt_in_place(
                Nonce::from_slice(&header.nonce),
                &encrypted[..HEADER_LEN],
                &mut plain,
            )
            .map_err(|_| "wrong password or vault authentication failed")?;
        let mut vault = Vault::decode(&plain)?;
        vault.source_bytes = Some(encrypted);
        Ok(vault)
    }

    pub fn save(&self, vault: &mut Vault) -> Result<()> {
        let audit = if vault
            .saved_config
            .as_ref()
            .is_some_and(|saved| !vault.config.same_settings(saved))
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system clock is before the Unix epoch")?
                .as_secs();
            vault.config_audit.record_edit(now)?
        } else {
            vault.config_audit
        };
        let committed_config = vault.config.clone();
        #[cfg(test)]
        crate::test_support::fail_at(crate::test_support::Fault::Random)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| "OS randomness unavailable")?;
        let header = EnvelopeHeader {
            nonce,
            ..self.header
        }
        .encode();
        let mut plain = vault.encode_with_audit(audit)?;
        let cipher = Aes256GcmSiv::new_from_slice(self.key.bytes())?;
        cipher
            .encrypt_in_place(Nonce::from_slice(&nonce), &header, &mut plain)
            .map_err(|_| "vault encryption failed")?;
        let mut encrypted = Vec::with_capacity(HEADER_LEN + plain.len());
        encrypted.extend_from_slice(&header);
        encrypted.extend_from_slice(&plain);
        let parent = self
            .path
            .parent()
            .ok_or("vault path needs a parent directory")?;
        create_private_dir(parent)?;
        let directory = crate::secure_file::Directory::open(parent, false)?;
        let filename = self.path.file_name().ok_or("vault filename missing")?;
        let mut lockname = filename.to_owned();
        lockname.push(".lock");
        let _lock = acquire_lock(directory.file(&lockname, libc::O_RDWR | libc::O_CREAT)?)?;
        match &vault.source_bytes {
            Some(original) => {
                if read_file(directory.file(filename, libc::O_RDONLY)?)? != *original {
                    return fail("vault changed; reload and retry the local operation");
                }
            }
            None => match directory.file(filename, libc::O_RDONLY) {
                Ok(_) => return fail("vault already exists"),
                Err(error)
                    if error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => {}
                Err(error) => return Err(error),
            },
        }
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).map_err(|_| "OS randomness unavailable")?;
        let tmp =
            std::ffi::OsString::from(format!(".vault-{:016x}.tmp", u64::from_le_bytes(random)));
        let result = (|| -> Result<()> {
            let mut file = directory.file(&tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
            #[cfg(test)]
            crate::test_support::fail_at(crate::test_support::Fault::Write)?;
            file.write_all(&encrypted)?;
            #[cfg(test)]
            crate::test_support::fail_at(crate::test_support::Fault::FileSync)?;
            file.sync_all()?;
            #[cfg(test)]
            crate::test_support::fail_at(crate::test_support::Fault::Rename)?;
            directory.rename(&tmp, filename)?;
            vault.source_bytes = Some(encrypted);
            vault.config_audit = audit;
            vault.saved_config = Some(committed_config);
            directory
                .sync()
                .map_err(|error| format!("vault saved, but directory sync failed: {error}"))?;
            Ok(())
        })();
        if result.is_err() {
            directory.remove(&tmp);
        }
        result
    }
}

#[cfg(test)]
fn lock_vault(path: &Path) -> Result<File> {
    let directory =
        crate::secure_file::Directory::open(path.parent().ok_or("vault parent missing")?, false)?;
    let mut name = path.file_name().ok_or("vault filename missing")?.to_owned();
    name.push(".lock");
    acquire_lock(directory.file(&name, libc::O_RDWR | libc::O_CREAT)?)
}

fn acquire_lock(file: File) -> Result<File> {
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => fail("vault is busy; retry"),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
    // The file remains on disk: unlinking it could give other writers a different lock.
}

fn read_private_file(path: &Path) -> Result<Vec<u8>> {
    let directory =
        crate::secure_file::Directory::open(path.parent().ok_or("vault parent missing")?, false)?;
    read_file(directory.file(
        path.file_name().ok_or("vault filename missing")?,
        libc::O_RDONLY,
    )?)
}

fn read_file(file: File) -> Result<Vec<u8>> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FILE {
        return fail("vault must be a regular file smaller than 1 MiB");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return fail("vault permissions must be owner-only (chmod 600)");
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE {
        return fail("vault grew beyond 1 MiB");
    }
    Ok(bytes)
}

fn create_private_dir(path: &Path) -> Result<()> {
    crate::secure_file::Directory::open(path, true)?;
    Ok(())
}

impl Vault {
    pub fn config_audit(&self) -> ConfigAudit {
        self.config_audit
    }

    pub fn revision(&self) -> Option<&[u8]> {
        self.source_bytes.as_deref()
    }
    pub fn public_snapshot(&self) -> PublicVault {
        PublicVault {
            accounts: self
                .accounts
                .iter()
                .map(|a| PublicAccount {
                    name: a.name.clone(),
                    pubkey: a.pubkey,
                })
                .collect(),
            recipients: self.recipients.clone(),
        }
    }
    pub fn contains(&self, name: &str) -> bool {
        self.accounts.iter().any(|a| a.name == name)
    }
    pub fn account(&self, name: &str) -> Result<&Account> {
        self.accounts
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| "unknown wallet".into())
    }
    pub fn first_name(&self) -> Result<&str> {
        self.accounts
            .first()
            .map(|a| a.name.as_str())
            .ok_or_else(|| "vault has no accounts".into())
    }

    pub fn recovery_phrase_use(&self, name: &str) -> Result<RecoveryPhraseUse> {
        let account = self.account(name)?;
        let AccountKind::Derived { master, .. } = account.kind else {
            return Ok(RecoveryPhraseUse::ImportedKey);
        };
        let entropy = &self.masters[usize::from(master)].entropy;
        // The same phrase may have been imported into more than one master entry.
        let shared = self.accounts.iter().any(|other| {
            other.name != name
                && matches!(other.kind, AccountKind::Derived { master, .. }
                if self.masters[usize::from(master)].entropy[..] == entropy[..])
        });
        Ok(if shared {
            RecoveryPhraseUse::Shared
        } else {
            RecoveryPhraseUse::UnusedAfterDeletion
        })
    }

    pub fn remove_account(&mut self, name: &str, erase_phrase: bool) -> Result<()> {
        let usage = self.recovery_phrase_use(name)?;
        if erase_phrase && usage != RecoveryPhraseUse::UnusedAfterDeletion {
            return fail("recovery phrase is still used or this wallet has no recovery phrase");
        }
        let index = self
            .accounts
            .iter()
            .position(|a| a.name == name)
            .ok_or("unknown wallet")?;
        let mut erase = [false; MAX_MASTERS];
        if erase_phrase && let AccountKind::Derived { master, .. } = self.accounts[index].kind {
            for (i, candidate) in self.masters.iter().enumerate() {
                erase[i] = candidate.entropy[..] == self.masters[usize::from(master)].entropy[..];
            }
        }
        if let AccountKind::Imported { keypair } = &mut self.accounts[index].kind {
            // Wipe in place before Vec::remove moves the value out of its old slot.
            keypair.zeroize();
        }
        self.accounts.remove(index);
        // Remove all unused copies of that phrase, preserving remaining master references.
        for index in (0..self.masters.len()).rev() {
            if erase[index] {
                self.masters.remove(index);
                for account in &mut self.accounts {
                    if let AccountKind::Derived { master, .. } = &mut account.kind
                        && usize::from(*master) > index
                    {
                        *master -= 1;
                    }
                }
            }
        }
        Ok(())
    }
    pub fn is_known_recipient(&self, pubkey: &Pubkey) -> bool {
        self.recipients.iter().any(|key| key == pubkey.as_ref())
    }
    pub fn remember_recipient(&mut self, pubkey: &Pubkey) {
        if !self.is_known_recipient(pubkey) && self.recipients.len() < MAX_RECIPIENTS {
            self.recipients.push(pubkey.to_bytes());
        }
    }

    pub fn add_master(&mut self, name: &str, entropy: LockedBytes) -> Result<()> {
        self.ensure_new_name(name)?;
        if self.masters.len() >= MAX_MASTERS {
            return fail("master limit reached");
        }
        let mnemonic = Locked::try_new(|| Ok(Mnemonic::from_entropy(&entropy)?))?;
        let master = self.masters.len() as u8;
        let pubkey = derive_signer(&mnemonic, 0)?.pubkey();
        self.masters.push(Master {
            entropy,
            next_index: 1,
        });
        self.accounts.push(Account {
            name: name.into(),
            pubkey,
            kind: AccountKind::Derived { master, index: 0 },
        });
        Ok(())
    }

    pub fn add_derived(&mut self, name: &str, source: &str) -> Result<()> {
        self.ensure_new_name(name)?;
        let AccountKind::Derived { master, .. } = self.account(source)?.kind else {
            return fail(
                "source wallet has no recovery phrase; imported private keys cannot derive wallets",
            );
        };
        let selected = self
            .masters
            .get(usize::from(master))
            .ok_or("invalid master reference")?;
        // Re-imports of one phrase share a sequence, including deleted indices.
        let next = self
            .masters
            .iter()
            .filter(|candidate| candidate.entropy[..] == selected.entropy[..])
            .map(|candidate| candidate.next_index)
            .max()
            .ok_or("invalid master reference")?;
        let mnemonic = Locked::try_new(|| Ok(Mnemonic::from_entropy(&selected.entropy)?))?;
        let pubkey = derive_signer(&mnemonic, next)?.pubkey();
        self.accounts.push(Account {
            name: name.into(),
            pubkey,
            kind: AccountKind::Derived {
                master,
                index: next,
            },
        });
        for index in 0..self.masters.len() {
            if self.masters[index].entropy[..] == self.masters[usize::from(master)].entropy[..] {
                self.masters[index].next_index = next + 1;
            }
        }
        Ok(())
    }

    pub fn add_imported(&mut self, name: &str, bytes: LockedKeypair) -> Result<()> {
        self.ensure_new_name(name)?;
        let keypair = Keypair::try_from(&bytes[..])?;
        self.accounts.push(Account {
            name: name.into(),
            pubkey: keypair.pubkey(),
            kind: AccountKind::Imported { keypair: bytes },
        });
        Ok(())
    }

    fn ensure_new_name(&self, name: &str) -> Result<()> {
        if !valid_name(name) {
            return fail("wallet name must be 1-32 ASCII letters, digits, _ or -");
        }
        if self.contains(name) {
            return fail("wallet name already exists");
        }
        if self.accounts.len() >= MAX_ACCOUNTS {
            return fail("account limit reached");
        }
        Ok(())
    }

    pub fn derivation_index(&self, name: &str) -> Result<Option<u32>> {
        match &self.account(name)?.kind {
            AccountKind::Derived { index, .. } => Ok(Some(*index)),
            AccountKind::Imported { .. } => Ok(None),
        }
    }

    pub fn mnemonic(&self, name: &str) -> Result<LockedString> {
        match &self.account(name)?.kind {
            AccountKind::Derived { master, .. } => {
                let master = self
                    .masters
                    .get(usize::from(*master))
                    .ok_or("invalid master reference")?;
                phrase(&master.entropy)
            }
            AccountKind::Imported { .. } => {
                fail("imported private-key wallets have no stored recovery phrase")
            }
        }
    }

    pub fn signer(&self, name: &str) -> Result<Keypair> {
        let account = self.account(name)?;
        let keypair = match &account.kind {
            AccountKind::Imported { keypair } => Keypair::try_from(&keypair[..])?,
            AccountKind::Derived { master, index } => {
                let entropy = self
                    .masters
                    .get(usize::from(*master))
                    .ok_or("invalid master reference")?;
                let mnemonic = Locked::try_new(|| Ok(Mnemonic::from_entropy(&entropy.entropy)?))?;
                derive_signer(&mnemonic, *index)?
            }
        };
        if keypair.pubkey() != account.pubkey {
            return fail("vault account address mismatch");
        }
        Ok(keypair)
    }

    #[cfg(test)]
    fn encode(&self) -> Result<LockedBytes> {
        self.encode_with_audit(self.config_audit)
    }

    fn encode_with_audit(&self, audit: ConfigAudit) -> Result<LockedBytes> {
        audit.validate()?;
        self.config.validate()?;
        let mut config = LockedBytes::with_capacity(64 * 1024)?;
        serde_json::to_writer(&mut config, &self.config)
            .map_err(|_| "vault config cannot be encoded within 64 KiB")?;
        if self.masters.len() > MAX_MASTERS
            || self.accounts.len() > MAX_ACCOUNTS
            || self.recipients.len() > MAX_RECIPIENTS
        {
            return fail("vault limits exceeded");
        }
        let size = 1
            + self
                .masters
                .iter()
                .map(|m| 1 + m.entropy.len() + 4)
                .sum::<usize>()
            + 2
            + self
                .accounts
                .iter()
                .map(|a| {
                    1 + a.name.len()
                        + 32
                        + 1
                        + match a.kind {
                            AccountKind::Derived { .. } => 5,
                            AccountKind::Imported { .. } => 64,
                        }
                })
                .sum::<usize>()
            + 2
            + self.recipients.len() * 32
            + 4
            + config.len()
            + 16;
        // Reserve the AEAD tag too: growing a plaintext Vec can leave unwiped copies.
        let mut out = LockedBytes::with_capacity(size + 16)?;
        out.push(self.masters.len() as u8)?;
        for master in &self.masters {
            out.push(master.entropy.len() as u8)?;
            out.extend_from_slice(&master.entropy)?;
            out.extend_from_slice(&master.next_index.to_le_bytes())?;
        }
        out.extend_from_slice(&(self.accounts.len() as u16).to_le_bytes())?;
        for account in &self.accounts {
            out.push(account.name.len() as u8)?;
            out.extend_from_slice(account.name.as_bytes())?;
            out.extend_from_slice(account.pubkey.as_ref())?;
            match &account.kind {
                AccountKind::Derived { master, index } => {
                    out.push(0)?;
                    out.push(*master)?;
                    out.extend_from_slice(&index.to_le_bytes())?;
                }
                AccountKind::Imported { keypair } => {
                    out.push(1)?;
                    out.extend_from_slice(&keypair[..])?;
                }
            }
        }
        out.extend_from_slice(&(self.recipients.len() as u16).to_le_bytes())?;
        for recipient in &self.recipients {
            out.extend_from_slice(recipient)?;
        }
        out.extend_from_slice(&(config.len() as u32).to_le_bytes())?;
        out.extend_from_slice(&config)?;
        out.extend_from_slice(&audit.edits.to_le_bytes())?;
        out.extend_from_slice(&audit.last_edit_unix.to_le_bytes())?;
        Ok(out)
    }

    fn decode(data: &[u8]) -> Result<Self> {
        let mut reader = Reader { data, pos: 0 };
        let master_count = reader.u8()? as usize;
        if master_count > MAX_MASTERS {
            return fail("too many masters in vault");
        }
        let mut masters = Vec::with_capacity(master_count);
        for _ in 0..master_count {
            let len = reader.u8()? as usize;
            if !matches!(len, 16 | 20 | 24 | 28 | 32) {
                return fail("invalid master entropy size");
            }
            let entropy = LockedBytes::from_slice(reader.take(len)?)?;
            let next_index = u32::from_le_bytes(reader.take(4)?.try_into()?);
            if next_index == 0 || next_index > (1 << 31) {
                return fail("invalid next derivation index");
            }
            masters.push(Master {
                entropy,
                next_index,
            });
        }
        let count = reader.u16()? as usize;
        if count > MAX_ACCOUNTS {
            return fail("too many accounts in vault");
        }
        let mut accounts = Vec::with_capacity(count);
        for _ in 0..count {
            let len = reader.u8()? as usize;
            let name = std::str::from_utf8(reader.take(len)?)?.to_owned();
            if !valid_name(&name) || accounts.iter().any(|a: &Account| a.name == name) {
                return fail("invalid or duplicate account name");
            }
            let pubkey = Pubkey::new_from_array(reader.take(32)?.try_into()?);
            let kind = match reader.u8()? {
                0 => {
                    let master = reader.u8()?;
                    let index = u32::from_le_bytes(reader.take(4)?.try_into()?);
                    if usize::from(master) >= masters.len() || index >= (1 << 31) {
                        return fail("invalid master reference");
                    }
                    if index >= masters[usize::from(master)].next_index {
                        return fail("derivation counter would reuse an existing index");
                    }
                    AccountKind::Derived { master, index }
                }
                1 => {
                    let bytes = LockedKeypair::from_slice(reader.take(64)?)?;
                    if Keypair::try_from(&bytes[..])?.pubkey() != pubkey {
                        return fail("invalid imported account");
                    }
                    AccountKind::Imported { keypair: bytes }
                }
                _ => return fail("invalid account kind"),
            };
            accounts.push(Account { name, pubkey, kind });
        }
        let recipients_count = reader.u16()? as usize;
        if recipients_count > MAX_RECIPIENTS {
            return fail("too many recipients in vault");
        }
        let mut recipients = Vec::with_capacity(recipients_count);
        for _ in 0..recipients_count {
            recipients.push(reader.take(32)?.try_into()?);
        }
        let len = u32::from_le_bytes(reader.take(4)?.try_into()?) as usize;
        if len == 0 || len > 64 * 1024 {
            return fail("vault requires authenticated config of 1..=65536 bytes");
        }
        let config: Config = serde_json::from_slice(reader.take(len)?)?;
        config.validate()?;
        let config_audit = ConfigAudit {
            edits: u64::from_le_bytes(reader.take(8)?.try_into()?),
            last_edit_unix: u64::from_le_bytes(reader.take(8)?.try_into()?),
        };
        config_audit.validate()?;
        if reader.pos != data.len() {
            return fail("trailing vault data");
        }
        Ok(Self {
            saved_config: Some(config.clone()),
            config,
            config_audit,
            masters,
            accounts,
            recipients,
            source_bytes: None,
        })
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or("vault length overflow")?;
        let slice = self.data.get(self.pos..end).ok_or("truncated vault")?;
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }
}

pub fn fresh_entropy() -> Result<LockedBytes> {
    let mut entropy = LockedBytes::zeroed(32)?;
    getrandom::getrandom(&mut entropy).map_err(|_| "OS randomness unavailable")?;
    Ok(entropy)
}

pub fn phrase(entropy: &[u8]) -> Result<LockedString> {
    let mnemonic = Locked::try_new(|| Ok(Mnemonic::from_entropy(entropy)?))?;
    let words = mnemonic.words();
    let len = words.clone().map(str::len).sum::<usize>() + words.clone().count() - 1;
    let mut text = LockedBytes::with_capacity(len)?;
    for word in words {
        if !text.is_empty() {
            text.push(b' ')?;
        }
        text.extend_from_slice(word.as_bytes())?;
    }
    text.into_text()
}

/// English BIP39 input is parsed by borrowing; avoid a secret normalization String.
pub fn parse_phrase(text: &str) -> Result<LockedBytes> {
    if !text.is_ascii() {
        return fail("recovery phrase must use ASCII English BIP39 words");
    }
    let mnemonic = Locked::try_new(|| {
        Ok(Mnemonic::parse_in_normalized(
            bip39::Language::English,
            text,
        )?)
    })?;
    // Upstream returns an array by value. Erase this explicit temporary; implicit
    // return-value/compiler copies remain outside the owned-buffer guarantee.
    let entropy = Zeroizing::new(mnemonic.to_entropy_array());
    LockedBytes::from_slice(&entropy.0[..entropy.1])
}

fn derive_signer(mnemonic: &Mnemonic, index: u32) -> Result<Keypair> {
    if index >= (1 << 31) {
        return fail("derivation index too large");
    }
    let seed = Locked::<[u8; 64]>::try_new(|| Ok(mnemonic.to_seed_normalized("")))?;
    let mut derived = Locked::try_new(|| Ok(ExtendedSigningKey::from_seed(&seed[..])?))?;
    for i in [44, 501, index, 0] {
        derived = Locked::try_new(|| Ok(derived.derive_child(ChildIndex::Hardened(i))?))?;
    }
    Keypair::from_seed_bytes(derived.signing_key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn settings_and_imported_identity_are_authenticated() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut vault = Vault::default();
        vault
            .add_imported(
                "test",
                Keypair::new_from_array([7; 32]).to_keypair_bytes().unwrap(),
            )
            .unwrap();
        let address = vault.account("test").unwrap().pubkey;
        let mut config = Config::default();
        config.rpc.url = Some("https://api.devnet.solana.com".into());
        config.aliases.insert("ls".into(), vec!["list".into()]);
        vault.config = config;
        session.save(&mut vault).unwrap();
        let reopened = session.load().unwrap();
        assert_eq!(reopened.config.aliases["ls"], ["list"]);
        assert_eq!(reopened.signer("test").unwrap().pubkey(), address);
        let mut encrypted = fs::read(dir.path()).unwrap();
        assert_eq!(encrypted[4], VERSION);
        let offset = encrypted.len() - 20;
        encrypted[offset] ^= 1;
        assert!(session.decrypt_bytes(encrypted).is_err());
    }

    #[test]
    fn settings_history_counts_only_committed_settings_changes() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut vault = Vault::default();
        session.save(&mut vault).unwrap();
        assert_eq!(vault.config_audit(), ConfigAudit::default());
        let initial = fs::read(dir.path()).unwrap();
        vault.config.rpc.timeout_secs = 22;
        session.save(&mut vault).unwrap();
        let first = vault.config_audit();
        assert_eq!(first.edits(), 1);
        assert!(first.last_edit().is_some());
        assert_eq!(session.load().unwrap().config_audit(), first);

        // No-op saves, launch-only paths, and wallet changes do not count.
        session.save(&mut vault).unwrap();
        vault.config.vault = PathBuf::from("/different/launch/path");
        vault
            .add_imported(
                "new",
                Keypair::new_from_array([7; 32]).to_keypair_bytes().unwrap(),
            )
            .unwrap();
        session.save(&mut vault).unwrap();
        assert_eq!(vault.config_audit(), first);
        vault = session.load().unwrap();
        vault.config.history.limit = 30;
        session.save(&mut vault).unwrap();
        assert_eq!(vault.config_audit().edits(), 2);
        assert!(vault.config_audit().last_edit() >= first.last_edit());

        // Explicitly test the documented limit: replay of an old valid vault
        // authenticates, so this local record must never claim rollback detection.
        fs::write(dir.path(), initial).unwrap();
        assert_eq!(
            session.load().unwrap().config_audit(),
            ConfigAudit::default()
        );
    }

    #[test]
    fn settings_history_is_mandatory_authenticated_and_bounded() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut vault = Vault::default();
        session.save(&mut vault).unwrap();
        vault.config.history.limit = 30;
        session.save(&mut vault).unwrap();
        let mut plain = vault.encode().unwrap();
        let offset = plain.len() - 16;
        for len in offset..plain.len() {
            assert!(Vault::decode(&plain[..len]).is_err());
        }
        // Positive count requires a timestamp, and zero count requires none.
        plain[offset..offset + 8].fill(0);
        assert!(Vault::decode(&plain).is_err());
        let bytes = fs::read(dir.path()).unwrap();
        for index in HEADER_LEN + offset..HEADER_LEN + offset + 16 {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            assert!(session.decrypt_bytes(changed).is_err());
        }
        let audit = ConfigAudit::default().record_edit(1_700_000_000).unwrap();
        assert_eq!(audit.record_edit(1_700_000_000).unwrap().edits(), 2);
        assert!(audit.record_edit(1_699_999_999).is_err());
        assert!(audit.record_edit(0).is_err());
        assert!(audit.record_edit(253_402_300_800).is_err());
        assert!(
            ConfigAudit {
                edits: u64::MAX,
                last_edit_unix: 1
            }
            .record_edit(2)
            .is_err()
        );
    }

    #[test]
    fn imported_secrets_stay_at_stable_addresses_when_accounts_move() {
        let mut vault = Vault::default();
        vault
            .add_imported(
                "first",
                Keypair::new_from_array([7; 32]).to_keypair_bytes().unwrap(),
            )
            .unwrap();
        vault
            .add_imported(
                "second",
                Keypair::new_from_array([8; 32]).to_keypair_bytes().unwrap(),
            )
            .unwrap();
        fn pointer(vault: &Vault) -> *const u8 {
            match &vault.account("second").unwrap().kind {
                AccountKind::Imported { keypair } => keypair.as_ptr(),
                _ => unreachable!(),
            }
        }
        let before = pointer(&vault);
        for index in 0..20 {
            vault
                .add_imported(
                    &format!("extra{index}"),
                    Keypair::new_from_array([9; 32]).to_keypair_bytes().unwrap(),
                )
                .unwrap();
        }
        vault.remove_account("first", false).unwrap();
        assert_eq!(before, pointer(&vault)); // Compare addresses; never dereference freed memory.
    }

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            Self(crate::test_support::private_temp_dir("solx-vault-test"))
        }
        fn path(&self) -> PathBuf {
            self.0.join("vault.enc")
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn phrase_round_trips_without_normalization_allocation() {
        for len in [16, 20, 24, 28, 32] {
            let entropy = vec![42; len];
            let text = phrase(&entropy).unwrap();
            assert_eq!(
                text.as_str(),
                Mnemonic::from_entropy(&entropy).unwrap().to_string()
            );
            assert_eq!(&*parse_phrase(&text).unwrap(), &entropy);
        }
    }

    #[test]
    fn selected_wallets_and_reimported_phrases_share_the_highest_derivation_counter() {
        let mut vault = Vault::default();
        vault
            .add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        vault
            .add_master("independent", LockedBytes::from_slice(&[1; 32]).unwrap())
            .unwrap();
        vault.add_derived("first", "independent").unwrap();
        vault.add_derived("second", "first").unwrap();
        assert_eq!(vault.derivation_index("second").unwrap(), Some(2));
        assert_eq!(vault.masters[0].next_index, 1);
        assert_eq!(vault.masters[1].next_index, 3);
        let deleted = vault.account("second").unwrap().pubkey;
        vault.remove_account("second", false).unwrap();
        vault
            .add_master("copy", LockedBytes::from_slice(&[1; 32]).unwrap())
            .unwrap();
        assert_eq!(vault.masters[2].next_index, 1);
        let mut vault = Vault::decode(&vault.encode().unwrap()).unwrap();
        vault.add_derived("third", "copy").unwrap();
        assert_eq!(vault.derivation_index("third").unwrap(), Some(3));
        assert_ne!(vault.account("third").unwrap().pubkey, deleted);
        assert_eq!(vault.masters[1].next_index, 4);
        assert_eq!(vault.masters[2].next_index, 4);
        vault.remove_account("independent", false).unwrap();
        let mut vault = Vault::decode(&vault.encode().unwrap()).unwrap();
        vault.add_derived("fourth", "first").unwrap();
        assert_eq!(vault.derivation_index("fourth").unwrap(), Some(4));
        assert_eq!(vault.masters[0].next_index, 1);
        assert_eq!(
            vault.mnemonic("fourth").unwrap().as_str(),
            vault.mnemonic("copy").unwrap().as_str()
        );

        let before = vault.encode().unwrap();
        assert!(vault.add_derived("missing_source", "independent").is_err());
        assert!(
            crate::test_support::with_fault(crate::test_support::Fault::Lock, || vault
                .add_derived("failed", "copy"))
            .is_err()
        );
        assert_eq!(&*vault.encode().unwrap(), &*before);

        // Exhaustion in either stored copy exhausts the entire phrase.
        vault.masters[2].next_index = 1 << 31;
        let mut vault = Vault::decode(&vault.encode().unwrap()).unwrap();
        let before = vault.encode().unwrap();
        assert!(vault.add_derived("exhausted", "first").is_err());
        assert_eq!(&*vault.encode().unwrap(), &*before);
    }

    #[test]
    fn exported_secrets_match_each_master_without_changing_the_vault() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut data = Vault::default();
        data.add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        data.masters[0].next_index = 7;
        data.add_derived("child", "main").unwrap();
        data.add_master("independent", LockedBytes::from_slice(&[1; 16]).unwrap())
            .unwrap();
        data.add_imported(
            "imported",
            Keypair::new_from_array([7; 32]).to_keypair_bytes().unwrap(),
        )
        .unwrap();
        session.save(&mut data).unwrap();
        let before = fs::read(dir.path()).unwrap();
        let plain_before = data.encode().unwrap();
        for (name, index, entropy) in [
            ("main", 0, vec![0; 32]),
            ("child", 7, vec![0; 32]),
            ("independent", 0, vec![1; 16]),
        ] {
            let text = data.mnemonic(name).unwrap();
            assert_eq!(text.as_str(), phrase(&entropy).unwrap().as_str());
            assert_eq!(data.derivation_index(name).unwrap(), Some(index));
            let mnemonic = Mnemonic::parse(text.as_str()).unwrap();
            let restored = derive_signer(&mnemonic, index).unwrap();
            assert_eq!(restored.pubkey(), data.account(name).unwrap().pubkey);
            assert_eq!(
                *restored.to_keypair_bytes().unwrap(),
                *data.signer(name).unwrap().to_keypair_bytes().unwrap()
            );
        }
        assert_eq!(data.derivation_index("imported").unwrap(), None);
        assert!(data.mnemonic("imported").is_err());
        assert!(data.mnemonic("unknown").is_err());
        assert!(data.derivation_index("unknown").is_err());
        assert_eq!(&*data.encode().unwrap(), &*plain_before);
        assert_eq!(fs::read(dir.path()).unwrap(), before);
        let reopened = session.load().unwrap();
        assert_eq!(reopened.masters[0].next_index, 8);
        assert_eq!(
            reopened.account("child").unwrap().pubkey,
            data.account("child").unwrap().pubkey
        );
    }

    #[test]
    fn stale_saves_and_competing_creates_cannot_overwrite() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut first = Vault::default();
        first
            .add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        session.save(&mut first).unwrap();
        let mut stale = session.load().unwrap();
        first.add_derived("second", "main").unwrap();
        session.save(&mut first).unwrap();
        stale.add_derived("lost", "main").unwrap();
        assert!(
            session
                .save(&mut stale)
                .unwrap_err()
                .to_string()
                .contains("vault changed")
        );
        assert!(session.save(&mut Vault::default()).is_err());
        let saved = session.load().unwrap();
        assert!(saved.contains("second"));
        assert!(!saved.contains("lost"));
        first.add_derived("third", "main").unwrap();
        session.save(&mut first).unwrap();
        assert!(session.load().unwrap().contains("third"));
    }

    #[test]
    fn save_failures_preserve_precommit_bytes_and_report_postcommit_state() {
        use crate::test_support::{Fault, with_fault};
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut vault = Vault::default();
        session.save(&mut vault).unwrap();
        let before = fs::read(dir.path()).unwrap();
        vault.config.rpc.timeout_secs = 21;
        vault
            .add_imported(
                "new",
                Keypair::new_from_array([7; 32]).to_keypair_bytes().unwrap(),
            )
            .unwrap();
        for point in [Fault::Random, Fault::Write, Fault::FileSync, Fault::Rename] {
            assert!(with_fault(point, || session.save(&mut vault)).is_err());
            assert_eq!(fs::read(dir.path()).unwrap(), before, "{point:?}");
            assert_eq!(vault.revision().unwrap(), before);
            assert_eq!(vault.config_audit().edits(), 0);
            assert!(!session.load().unwrap().contains("new"));
            assert!(
                fs::read_dir(&dir.0).unwrap().all(|e| !e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
            );
        }
        let error = with_fault(Fault::DirectorySync, || session.save(&mut vault)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("vault saved, but directory sync failed")
        );
        assert!(session.load().unwrap().contains("new"));
        assert_eq!(session.load().unwrap().config_audit().edits(), 1);
        assert_eq!(vault.revision().unwrap(), fs::read(dir.path()).unwrap());
        // A caller that continues from this committed state must not see a false stale error.
        session.save(&mut vault).unwrap();
        assert_eq!(vault.config_audit().edits(), 1);
        use std::os::unix::fs::PermissionsExt;
        for path in [dir.path(), dir.path().with_file_name("vault.enc.lock")] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn commit_lock_is_nonblocking_and_reusable() {
        let dir = TestDir::new();
        let first = lock_vault(&dir.path()).unwrap();
        assert!(
            lock_vault(&dir.path())
                .unwrap_err()
                .to_string()
                .contains("busy")
        );
        drop(first);
        let lock_path = dir.path().with_file_name("vault.enc.lock");
        assert!(lock_path.exists());
        assert!(lock_vault(&dir.path()).is_ok());
        // A persistent, unlocked file does not prevent the first vault save.
        let session = Session::test_session(&dir.path());
        session.save(&mut Vault::default()).unwrap();
        assert!(lock_path.exists());
    }

    #[test]
    fn deletion_never_erases_a_shared_phrase_and_remaps_remaining_masters() {
        let mut vault = Vault::default();
        vault
            .add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        vault
            .add_master("independent", LockedBytes::from_slice(&[1; 32]).unwrap())
            .unwrap();
        vault
            .add_master("same_phrase", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        let independent = vault.signer("independent").unwrap().pubkey();
        assert_eq!(
            vault.recovery_phrase_use("main").unwrap(),
            RecoveryPhraseUse::Shared
        );
        assert!(vault.remove_account("main", true).is_err());
        assert_eq!(vault.accounts.len(), 3);
        vault.remove_account("same_phrase", false).unwrap();
        assert_eq!(
            vault.recovery_phrase_use("main").unwrap(),
            RecoveryPhraseUse::UnusedAfterDeletion
        );
        vault.remove_account("main", true).unwrap();
        assert_eq!(vault.masters.len(), 1); // Both unused copies of the erased phrase are gone.
        assert_eq!(vault.signer("independent").unwrap().pubkey(), independent);
        let mut reopened = Vault::decode(&vault.encode().unwrap()).unwrap();
        reopened.add_derived("next", "independent").unwrap();
        assert_eq!(
            reopened.signer("independent").unwrap().pubkey(),
            independent
        );
        assert_ne!(reopened.signer("next").unwrap().pubkey(), independent);
    }

    #[test]
    fn deleting_highest_index_does_not_recycle_addresses_after_reopen() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut vault = Vault::default();
        vault
            .add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        vault.add_derived("last", "main").unwrap();
        let removed = vault.signer("last").unwrap().pubkey();
        session.save(&mut vault).unwrap();
        vault.remove_account("last", false).unwrap();
        session.save(&mut vault).unwrap();
        let mut vault = session.load().unwrap();
        assert!(!vault.contains("last"));
        vault.add_derived("new", "main").unwrap();
        let new = vault.signer("new").unwrap().pubkey();
        assert_ne!(new, removed);
        assert!(matches!(
            vault.account("new").unwrap().kind,
            AccountKind::Derived { index: 2, .. }
        ));
        vault.remove_account("main", false).unwrap();
        assert_eq!(vault.signer("new").unwrap().pubkey(), new);
        vault.remove_account("new", false).unwrap();
        session.save(&mut vault).unwrap();
        let mut vault = session.load().unwrap();
        assert!(vault.accounts.is_empty());
        assert!(vault.first_name().is_err());
        assert!(vault.add_derived("after_empty", "main").is_err());
        // An explicit phrase import restores a selectable source while retaining
        // the highest counter from the unused copy still stored in the vault.
        vault
            .add_master("restored", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        vault.add_derived("after_empty", "restored").unwrap();
        assert!(matches!(
            vault.account("after_empty").unwrap().kind,
            AccountKind::Derived { index: 3, .. }
        ));
        vault.remove_account("restored", false).unwrap();
        vault.remove_account("after_empty", true).unwrap();
        session.save(&mut vault).unwrap();
        let mut vault = session.load().unwrap();
        assert!(vault.masters.is_empty());
        assert!(vault.add_derived("no_master", "main").is_err());
        vault
            .add_master("fresh", LockedBytes::from_slice(&[1; 32]).unwrap())
            .unwrap();
    }

    #[test]
    fn erase_decision_cannot_overwrite_a_new_reference() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut vault = Vault::default();
        vault
            .add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        session.save(&mut vault).unwrap();
        let mut stale = session.load().unwrap();
        assert_eq!(
            stale.recovery_phrase_use("main").unwrap(),
            RecoveryPhraseUse::UnusedAfterDeletion
        );
        vault.add_derived("child", "main").unwrap();
        session.save(&mut vault).unwrap();
        stale.remove_account("main", true).unwrap();
        assert!(session.save(&mut stale).is_err());
        let current = session.load().unwrap();
        assert!(current.contains("main"));
        assert!(current.signer("child").is_ok());
    }

    #[test]
    fn imported_key_deletion_and_unknown_name_are_handled() {
        let mut vault = Vault::default();
        let bytes = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).to_keypair_bytes();
        vault
            .add_imported("imported", LockedKeypair::from_slice(&bytes).unwrap())
            .unwrap();
        assert_eq!(
            vault.recovery_phrase_use("imported").unwrap(),
            RecoveryPhraseUse::ImportedKey
        );
        assert!(vault.remove_account("missing", false).is_err());
        assert!(vault.remove_account("imported", true).is_err());
        assert!(vault.contains("imported"));
        vault.remove_account("imported", false).unwrap();
        let decoded = Vault::decode(&vault.encode().unwrap()).unwrap();
        assert!(decoded.accounts.is_empty());
        assert!(decoded.signer("imported").is_err());
    }

    #[test]
    fn old_and_unknown_formats_are_rejected_without_touching_the_file() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        session.save(&mut Vault::default()).unwrap();
        let bytes = fs::read(dir.path()).unwrap();
        for version in [0, 1, 2, 3, 4, 6, 255] {
            let mut old = bytes.clone();
            old[4] = version;
            fs::write(dir.path(), &old).unwrap();
            // Empty password proves format rejection precedes the KDF boundary.
            let error = Session::open(&dir.path(), "").err().unwrap();
            assert!(error.to_string().contains("unsupported vault format"));
            assert!(session.load().is_err());
            assert!(Session::create(&dir.path(), "", &mut Vault::default()).is_err());
            assert!(session.save(&mut Vault::default()).is_err());
            assert_eq!(fs::read(dir.path()).unwrap(), old);
        }
    }

    #[test]
    fn every_envelope_byte_is_checked_and_cached_sessions_reject_new_salts() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        session.save(&mut Vault::default()).unwrap();
        let bytes = fs::read(dir.path()).unwrap();
        assert_eq!(&bytes[..8], b"SOLX\x05\x01\x13\x00");
        for index in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[index] ^= 1;
            assert!(session.decrypt_bytes(tampered).is_err(), "byte {index}");
        }
        for len in 0..HEADER_LEN + 16 {
            assert!(
                EnvelopeHeader::parse(&bytes[..len]).is_err(),
                "length {len}"
            );
        }
        for offset in [8, 12, 16] {
            for cost in [0, u32::MAX] {
                let mut invalid = bytes.clone();
                invalid[offset..offset + 4].copy_from_slice(&cost.to_le_bytes());
                fs::write(dir.path(), &invalid).unwrap();
                assert!(
                    Session::open(&dir.path(), "")
                        .err()
                        .unwrap()
                        .to_string()
                        .contains("unsupported Argon2id profile")
                );
                assert_eq!(fs::read(dir.path()).unwrap(), invalid);
            }
        }
        let mut replacement = Session::test_session(&dir.path());
        replacement.header.salt.fill(9);
        let mut changed = Vault {
            source_bytes: Some(fs::read(dir.path()).unwrap()),
            ..Vault::default()
        };
        replacement.save(&mut changed).unwrap();
        assert!(
            session
                .load()
                .err()
                .unwrap()
                .to_string()
                .contains("parameters changed")
        );
    }

    #[test]
    fn config_is_required_authenticated_and_round_trips() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut vault = Vault::default();
        vault.config.rpc.url = Some("https://api.devnet.solana.com".into());
        vault
            .config
            .aliases
            .insert("mine".into(), vec!["list".into()]);
        session.save(&mut vault).unwrap();
        let reopened = session.load().unwrap();
        assert_eq!(
            serde_json::to_value(&reopened.config).unwrap(),
            serde_json::to_value(&vault.config).unwrap()
        );
        let encoded = vault.encode().unwrap();
        for len in 0..encoded.len() {
            assert!(Vault::decode(&encoded[..len]).is_err());
        }
        // Empty vault: master count, account count, recipient count, config length.
        assert!(Vault::decode(&[0; 9]).is_err());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(Vault::decode(&trailing).is_err());
    }

    #[test]
    fn derivation_counters_reject_reuse_and_do_not_wrap() {
        let mut vault = Vault::default();
        vault
            .add_master("main", LockedBytes::from_slice(&[0; 32]).unwrap())
            .unwrap();
        vault.add_derived("child", "main").unwrap();
        let bytes = vault.encode().unwrap();
        for invalid in [0u32, 1, (1 << 31) + 1] {
            let mut malformed = bytes.to_vec();
            malformed[34..38].copy_from_slice(&invalid.to_le_bytes());
            assert!(Vault::decode(&malformed).is_err());
        }
        vault.masters[0].next_index = 1 << 31;
        let mut reopened = Vault::decode(&vault.encode().unwrap()).unwrap();
        assert!(reopened.add_derived("exhausted", "main").is_err());
        assert_eq!(reopened.accounts.len(), 2);
        assert_eq!(reopened.masters[0].next_index, 1 << 31);
    }

    #[test]
    fn plaintext_has_capacity_for_largest_vault_and_authentication_tag() {
        fn requires_wiping<T: zeroize::ZeroizeOnDrop>() {}
        requires_wiping::<Mnemonic>();
        let mut vault = Vault::default();
        for _ in 0..MAX_MASTERS {
            vault.masters.push(Master {
                entropy: LockedBytes::from_slice(&[0; 32]).unwrap(),
                next_index: 1,
            });
        }
        let bytes = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).to_keypair_bytes();
        for i in 0..MAX_ACCOUNTS {
            vault
                .add_imported(
                    &format!("{i:032}"),
                    LockedKeypair::from_slice(&bytes).unwrap(),
                )
                .unwrap();
        }
        vault.recipients = vec![[3; 32]; MAX_RECIPIENTS];
        let mut plain = vault.encode().unwrap();
        assert!(plain.capacity() >= plain.len() + 16);
        let pointer = plain.as_ptr();
        Aes256GcmSiv::new_from_slice(&[4; 32])
            .unwrap()
            .encrypt_in_place(Nonce::from_slice(&[5; 12]), b"test", &mut plain)
            .unwrap();
        assert_eq!(plain.as_ptr(), pointer);
    }

    #[test]
    fn deterministic_derivation_and_vault_round_trip() {
        let mut vault = Vault::default();
        vault
            .add_master("main", LockedBytes::from_slice(&[0u8; 32]).unwrap())
            .unwrap();
        vault.add_derived("second", "main").unwrap();
        assert_ne!(
            vault.account("main").unwrap().pubkey,
            vault.account("second").unwrap().pubkey
        );
        let bytes = vault.encode().unwrap();
        let decoded = Vault::decode(&bytes).unwrap();
        assert_eq!(
            decoded.signer("main").unwrap().pubkey(),
            vault.account("main").unwrap().pubkey
        );
    }
    #[test]
    #[ignore = "requires >64 MiB memlock allowance; run serially with --ignored"]
    fn wrong_password_and_tamper_rejected() {
        let dir = TestDir::new();
        let path = dir.path();
        let mut vault = Vault::default();
        vault
            .add_master("main", LockedBytes::from_slice(&[0u8; 32]).unwrap())
            .unwrap();
        let session = Session::create(&path, "correct horse battery staple", &mut vault).unwrap();
        assert_eq!(session.load().unwrap().accounts.len(), 1);
        let reopened = Session::open(&path, "correct horse battery staple").unwrap();
        assert_eq!(
            reopened.load().unwrap().signer("main").unwrap().pubkey(),
            vault.signer("main").unwrap().pubkey()
        );
        assert!(Session::open(&path, "wrong").is_err());
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(Session::open(&path, "correct horse battery staple").is_err());
    }
}
