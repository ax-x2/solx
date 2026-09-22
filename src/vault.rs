use crate::{Result, config::valid_name, fail, signer::Keypair};
use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use bip39::Mnemonic;
use ed25519_dalek_bip32::{ChildIndex, ExtendedSigningKey};
use solana_pubkey::Pubkey;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"SOLX";
const VERSION: u8 = 2;
const HEADER_LEN: usize = 33;
const MAX_FILE: u64 = 1024 * 1024;
const MAX_ACCOUNTS: usize = 128;
const MAX_MASTERS: usize = 32;
const MAX_RECIPIENTS: usize = 256;

pub struct Master {
    entropy: Zeroizing<Vec<u8>>,
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
    Imported { keypair: Zeroizing<[u8; 64]> },
}

pub struct Account {
    pub name: String,
    pub pubkey: Pubkey,
    kind: AccountKind,
}

#[derive(Default)]
pub struct Vault {
    masters: Vec<Master>,
    pub accounts: Vec<Account>,
    recipients: Vec<[u8; 32]>,
    // Ciphertext loaded from disk, used to reject stale read/modify/write operations.
    source_bytes: Option<Vec<u8>>,
}

struct LockedKey {
    key: Box<Zeroizing<[u8; 32]>>,
    #[cfg(unix)]
    locked: bool,
}

impl LockedKey {
    fn derive(password: &str, salt: &[u8; 16]) -> Result<Self> {
        if password.is_empty() {
            return fail("password must not be empty");
        }
        let boxed = Box::new(Zeroizing::new([0u8; 32]));
        #[cfg(unix)]
        let locked = unsafe { libc::mlock(boxed.as_ptr().cast(), 32) == 0 };
        let mut locked_key = Self {
            key: boxed,
            #[cfg(unix)]
            locked,
        };
        let params = scrypt::Params::new(15, 8, 1).map_err(|_| "invalid scrypt parameters")?;
        scrypt::scrypt(password.as_bytes(), salt, &params, &mut locked_key.key[..])
            .map_err(|_| "scrypt failed")?;
        Ok(locked_key)
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        self.key.zeroize();
        #[cfg(unix)]
        if self.locked {
            unsafe {
                libc::munlock(self.key.as_ptr().cast(), 32);
            }
        }
    }
}

pub struct Session {
    path: PathBuf,
    salt: [u8; 16],
    key: LockedKey,
}

impl Session {
    #[cfg(test)]
    pub(crate) fn test_session(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            salt: [1; 16],
            key: LockedKey {
                key: Box::new(Zeroizing::new([2; 32])),
                #[cfg(unix)]
                locked: false,
            },
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
            salt,
            key: LockedKey::derive(password, &salt)?,
        };
        session.save(vault)?;
        Ok(session)
    }

    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let encrypted = read_private_file(path)?;
        if encrypted.len() < HEADER_LEN + 16
            || &encrypted[..4] != MAGIC
            || !matches!(encrypted[4], 1 | VERSION)
        {
            return fail("unsupported or corrupt vault");
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&encrypted[5..21]);
        let session = Self {
            path: path.to_path_buf(),
            salt,
            key: LockedKey::derive(password, &salt)?,
        };
        session.decrypt_bytes(encrypted)?;
        Ok(session)
    }

    pub fn load(&self) -> Result<Vault> {
        self.decrypt_bytes(read_private_file(&self.path)?)
    }

    fn decrypt_bytes(&self, encrypted: Vec<u8>) -> Result<Vault> {
        if encrypted.len() < HEADER_LEN + 16
            || &encrypted[..4] != MAGIC
            || !matches!(encrypted[4], 1 | VERSION)
            || encrypted[5..21] != self.salt
        {
            return fail("unsupported or corrupt vault");
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&encrypted[21..33]);
        let mut plain = Zeroizing::new(encrypted[HEADER_LEN..].to_vec());
        let cipher = Aes256GcmSiv::new_from_slice(&self.key.key[..])?;
        cipher
            .decrypt_in_place(
                Nonce::from_slice(&nonce),
                &encrypted[..HEADER_LEN],
                &mut *plain,
            )
            .map_err(|_| "wrong password or vault authentication failed")?;
        let mut vault = Vault::decode(&plain, encrypted[4])?;
        vault.source_bytes = Some(encrypted);
        Ok(vault)
    }

    pub fn save(&self, vault: &mut Vault) -> Result<()> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| "OS randomness unavailable")?;
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(MAGIC);
        header[4] = VERSION;
        header[5..21].copy_from_slice(&self.salt);
        header[21..33].copy_from_slice(&nonce);
        let mut plain = vault.encode()?;
        let cipher = Aes256GcmSiv::new_from_slice(&self.key.key[..])?;
        cipher
            .encrypt_in_place(Nonce::from_slice(&nonce), &header, &mut *plain)
            .map_err(|_| "vault encryption failed")?;
        let mut encrypted = Vec::with_capacity(HEADER_LEN + plain.len());
        encrypted.extend_from_slice(&header);
        encrypted.extend_from_slice(&plain);
        let parent = self
            .path
            .parent()
            .ok_or("vault path needs a parent directory")?;
        create_private_dir(parent)?;
        let _lock = lock_vault(&self.path)?;
        match &vault.source_bytes {
            Some(original) => {
                if read_private_file(&self.path)? != *original {
                    return fail("vault changed; reload and retry the local operation");
                }
            }
            None => match fs::symlink_metadata(&self.path) {
                Ok(_) => return fail("vault already exists"),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            },
        }
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).map_err(|_| "OS randomness unavailable")?;
        let tmp = parent.join(format!(".vault-{:016x}.tmp", u64::from_le_bytes(random)));
        let result = (|| -> Result<()> {
            let mut file = private_file(&tmp)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            vault.source_bytes = Some(encrypted);
            File::open(parent)
                .and_then(|dir| dir.sync_all())
                .map_err(|error| format!("vault saved, but directory sync failed: {error}"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

fn lock_vault(path: &Path) -> Result<File> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(Path::new(&name))?;
    if !file.metadata()?.is_file() {
        return fail("vault lock must be a regular file");
    }
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => fail("vault is busy; retry"),
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
    // The file remains on disk: unlinking it could give other writers a different lock.
}

fn read_private_file(path: &Path) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
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
    let existed = path.exists();
    if !existed {
        fs::create_dir_all(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !existed {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return fail("vault directory must be owner-only (chmod 700)");
        }
    }
    Ok(())
}

fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

impl Vault {
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

    pub fn name_or_first<'a>(&'a self, name: Option<&'a str>) -> Result<&'a str> {
        match name {
            Some(name) => Ok(name),
            None => self.first_name(),
        }
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
                if self.masters[usize::from(master)].entropy == *entropy)
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
                erase[i] = candidate.entropy == self.masters[usize::from(master)].entropy;
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

    pub fn add_master(&mut self, name: &str, entropy: Zeroizing<Vec<u8>>) -> Result<()> {
        self.ensure_new_name(name)?;
        if self.masters.len() >= MAX_MASTERS {
            return fail("master limit reached");
        }
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
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

    pub fn add_derived(&mut self, name: &str) -> Result<()> {
        self.ensure_new_name(name)?;
        if self.masters.is_empty() {
            return fail("no master wallet exists");
        }
        let next = self.masters[0].next_index;
        let mnemonic = Mnemonic::from_entropy(&self.masters[0].entropy)?;
        let pubkey = derive_signer(&mnemonic, next)?.pubkey();
        self.accounts.push(Account {
            name: name.into(),
            pubkey,
            kind: AccountKind::Derived {
                master: 0,
                index: next,
            },
        });
        self.masters[0].next_index = next + 1;
        Ok(())
    }

    pub fn add_imported(&mut self, name: &str, bytes: Zeroizing<[u8; 64]>) -> Result<()> {
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

    pub fn mnemonic(&self, name: &str) -> Result<Zeroizing<String>> {
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
                derive_signer(&Mnemonic::from_entropy(&entropy.entropy)?, *index)?
            }
        };
        if keypair.pubkey() != account.pubkey {
            return fail("vault account address mismatch");
        }
        Ok(keypair)
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
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
            + self.recipients.len() * 32;
        // Reserve the AEAD tag too: growing a plaintext Vec can leave unwiped copies.
        let mut out = Zeroizing::new(Vec::with_capacity(size + 16));
        out.push(self.masters.len() as u8);
        for master in &self.masters {
            out.push(master.entropy.len() as u8);
            out.extend_from_slice(&master.entropy);
            out.extend_from_slice(&master.next_index.to_le_bytes());
        }
        out.extend_from_slice(&(self.accounts.len() as u16).to_le_bytes());
        for account in &self.accounts {
            out.push(account.name.len() as u8);
            out.extend_from_slice(account.name.as_bytes());
            out.extend_from_slice(account.pubkey.as_ref());
            match &account.kind {
                AccountKind::Derived { master, index } => {
                    out.push(0);
                    out.push(*master);
                    out.extend_from_slice(&index.to_le_bytes());
                }
                AccountKind::Imported { keypair } => {
                    out.push(1);
                    out.extend_from_slice(&keypair[..]);
                }
            }
        }
        out.extend_from_slice(&(self.recipients.len() as u16).to_le_bytes());
        for recipient in &self.recipients {
            out.extend_from_slice(recipient);
        }
        Ok(out)
    }

    fn decode(data: &[u8], version: u8) -> Result<Self> {
        if !matches!(version, 1 | VERSION) {
            return fail("unsupported vault version");
        }
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
            let entropy = Zeroizing::new(reader.take(len)?.to_vec());
            Mnemonic::from_entropy(&entropy)?;
            let next_index = if version == 1 {
                1
            } else {
                u32::from_le_bytes(reader.take(4)?.try_into()?)
            };
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
                    let next = &mut masters[usize::from(master)].next_index;
                    if version == 1 {
                        *next = (*next).max(index + 1);
                    } else if index >= *next {
                        return fail("derivation counter would reuse an existing index");
                    }
                    AccountKind::Derived { master, index }
                }
                1 => {
                    let bytes = Zeroizing::new(<[u8; 64]>::try_from(reader.take(64)?)?);
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
        if reader.pos != data.len() {
            return fail("trailing vault data");
        }
        Ok(Self {
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

pub fn fresh_entropy() -> Result<Zeroizing<Vec<u8>>> {
    let mut entropy = Zeroizing::new(vec![0u8; 32]);
    getrandom::getrandom(&mut entropy).map_err(|_| "OS randomness unavailable")?;
    Ok(entropy)
}

pub fn phrase(entropy: &[u8]) -> Result<Zeroizing<String>> {
    let mnemonic = Mnemonic::from_entropy(entropy)?;
    let words = mnemonic.words();
    let len = words.clone().map(str::len).sum::<usize>() + words.clone().count() - 1;
    let mut text = Zeroizing::new(String::with_capacity(len));
    for word in words {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(word);
    }
    Ok(text)
}

fn derive_signer(mnemonic: &Mnemonic, index: u32) -> Result<Keypair> {
    if index >= (1 << 31) {
        return fail("derivation index too large");
    }
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let root = ExtendedSigningKey::from_seed(&seed[..])?;
    let mut derived = root;
    for i in [44, 501, index, 0] {
        derived = derived.derive_child(ChildIndex::Hardened(i))?;
    }
    let secret = Zeroizing::new(derived.signing_key.to_bytes());
    Ok(Keypair::new_from_array(*secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let mut random = [0u8; 8];
            getrandom::getrandom(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "solx-vault-test-{:016x}",
                u64::from_le_bytes(random)
            ));
            create_private_dir(&path).unwrap();
            Self(path)
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
    fn phrase_uses_one_exact_capacity_buffer() {
        for len in [16, 20, 24, 28, 32] {
            let entropy = vec![42; len];
            let text = phrase(&entropy).unwrap();
            assert_eq!(
                text.as_str(),
                Mnemonic::from_entropy(&entropy).unwrap().to_string()
            );
            assert_eq!(text.capacity(), text.len());
        }
    }

    #[test]
    fn exported_secrets_match_each_master_without_changing_the_vault() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut data = Vault::default();
        data.add_master("main", Zeroizing::new(vec![0; 32]))
            .unwrap();
        data.masters[0].next_index = 7;
        data.add_derived("child").unwrap();
        data.add_master("independent", Zeroizing::new(vec![1; 16]))
            .unwrap();
        data.add_imported(
            "imported",
            Keypair::new_from_array([7; 32]).to_keypair_bytes(),
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
                *restored.to_keypair_bytes(),
                *data.signer(name).unwrap().to_keypair_bytes()
            );
        }
        assert_eq!(data.derivation_index("imported").unwrap(), None);
        assert!(data.mnemonic("imported").is_err());
        assert!(data.mnemonic("unknown").is_err());
        assert!(data.derivation_index("unknown").is_err());
        assert_eq!(data.encode().unwrap().as_slice(), plain_before.as_slice());
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
            .add_master("main", Zeroizing::new(vec![0; 32]))
            .unwrap();
        session.save(&mut first).unwrap();
        let mut stale = session.load().unwrap();
        first.add_derived("second").unwrap();
        session.save(&mut first).unwrap();
        stale.add_derived("lost").unwrap();
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
        first.add_derived("third").unwrap();
        session.save(&mut first).unwrap();
        assert!(session.load().unwrap().contains("third"));
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
        assert!(lock_vault(&dir.path()).is_ok());
    }

    #[test]
    fn deletion_never_erases_a_shared_phrase_and_remaps_remaining_masters() {
        let mut vault = Vault::default();
        vault
            .add_master("main", Zeroizing::new(vec![0; 32]))
            .unwrap();
        vault
            .add_master("independent", Zeroizing::new(vec![1; 32]))
            .unwrap();
        vault
            .add_master("same_phrase", Zeroizing::new(vec![0; 32]))
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
        let mut reopened = Vault::decode(&vault.encode().unwrap(), VERSION).unwrap();
        reopened.add_derived("next").unwrap();
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
            .add_master("main", Zeroizing::new(vec![0; 32]))
            .unwrap();
        vault.add_derived("last").unwrap();
        let removed = vault.signer("last").unwrap().pubkey();
        session.save(&mut vault).unwrap();
        vault.remove_account("last", false).unwrap();
        session.save(&mut vault).unwrap();
        let mut vault = session.load().unwrap();
        assert!(!vault.contains("last"));
        vault.add_derived("new").unwrap();
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
        vault.add_derived("after_empty").unwrap();
        assert!(matches!(
            vault.account("after_empty").unwrap().kind,
            AccountKind::Derived { index: 3, .. }
        ));
        vault.remove_account("after_empty", true).unwrap();
        session.save(&mut vault).unwrap();
        let mut vault = session.load().unwrap();
        assert!(vault.masters.is_empty());
        assert!(vault.add_derived("no_master").is_err());
        vault
            .add_master("fresh", Zeroizing::new(vec![1; 32]))
            .unwrap();
    }

    #[test]
    fn erase_decision_cannot_overwrite_a_new_reference() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mut vault = Vault::default();
        vault
            .add_master("main", Zeroizing::new(vec![0; 32]))
            .unwrap();
        session.save(&mut vault).unwrap();
        let mut stale = session.load().unwrap();
        assert_eq!(
            stale.recovery_phrase_use("main").unwrap(),
            RecoveryPhraseUse::UnusedAfterDeletion
        );
        vault.add_derived("child").unwrap();
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
            .add_imported("imported", Zeroizing::new(bytes))
            .unwrap();
        assert_eq!(
            vault.recovery_phrase_use("imported").unwrap(),
            RecoveryPhraseUse::ImportedKey
        );
        assert!(vault.remove_account("missing", false).is_err());
        assert!(vault.remove_account("imported", true).is_err());
        assert!(vault.contains("imported"));
        vault.remove_account("imported", false).unwrap();
        let decoded = Vault::decode(&vault.encode().unwrap(), VERSION).unwrap();
        assert!(decoded.accounts.is_empty());
        assert!(decoded.signer("imported").is_err());
    }

    #[test]
    fn version_one_vault_migrates_without_changing_addresses() {
        let dir = TestDir::new();
        let session = Session::test_session(&dir.path());
        let mnemonic = Mnemonic::from_entropy(&[0; 32]).unwrap();
        let address = derive_signer(&mnemonic, 7).unwrap().pubkey();
        // Original v1 layout: one master, one derived account at index 7, no recipients.
        let mut payload = Zeroizing::new(vec![1, 32]);
        payload.extend_from_slice(&[0; 32]);
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(6);
        payload.extend_from_slice(b"legacy");
        payload.extend_from_slice(address.as_ref());
        payload.extend_from_slice(&[0, 0]);
        payload.extend_from_slice(&7u32.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        let mut header = [0; HEADER_LEN];
        header[..4].copy_from_slice(MAGIC);
        header[4] = 1;
        header[5..21].copy_from_slice(&session.salt);
        header[21..].copy_from_slice(&[3; 12]);
        Aes256GcmSiv::new_from_slice(&session.key.key[..])
            .unwrap()
            .encrypt_in_place(Nonce::from_slice(&[3; 12]), &header, &mut *payload)
            .unwrap();
        let mut file = private_file(&dir.path()).unwrap();
        file.write_all(&header).unwrap();
        file.write_all(&payload).unwrap();
        drop(file);
        let mut vault = session.load().unwrap();
        assert_eq!(vault.signer("legacy").unwrap().pubkey(), address);
        assert_eq!(vault.masters[0].next_index, 8);
        assert_eq!(fs::read(dir.path()).unwrap()[4], 1); // Reading alone does not migrate.
        session.save(&mut vault).unwrap();
        assert_eq!(fs::read(dir.path()).unwrap()[4], VERSION);
        let mut vault = session.load().unwrap();
        assert_eq!(vault.signer("legacy").unwrap().pubkey(), address);
        vault.add_derived("next").unwrap();
        assert_eq!(
            vault.signer("next").unwrap().pubkey(),
            derive_signer(&mnemonic, 8).unwrap().pubkey()
        );
        let bytes = vault.encode().unwrap();
        assert!(Vault::decode(&bytes, 99).is_err());
        assert!(Vault::decode(&bytes[..bytes.len() - 1], VERSION).is_err());
    }

    #[test]
    fn derivation_counters_reject_reuse_and_do_not_wrap() {
        let mut vault = Vault::default();
        vault
            .add_master("main", Zeroizing::new(vec![0; 32]))
            .unwrap();
        vault.add_derived("child").unwrap();
        let bytes = vault.encode().unwrap();
        for invalid in [0u32, 1, (1 << 31) + 1] {
            let mut malformed = bytes.clone();
            malformed[34..38].copy_from_slice(&invalid.to_le_bytes());
            assert!(Vault::decode(&malformed, VERSION).is_err());
        }
        vault.masters[0].next_index = 1 << 31;
        let mut reopened = Vault::decode(&vault.encode().unwrap(), VERSION).unwrap();
        assert!(reopened.add_derived("exhausted").is_err());
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
                entropy: Zeroizing::new(vec![0; 32]),
                next_index: 1,
            });
        }
        let bytes = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).to_keypair_bytes();
        for i in 0..MAX_ACCOUNTS {
            vault
                .add_imported(&format!("{i:032}"), Zeroizing::new(bytes))
                .unwrap();
        }
        vault.recipients = vec![[3; 32]; MAX_RECIPIENTS];
        let mut plain = vault.encode().unwrap();
        assert!(plain.capacity() >= plain.len() + 16);
        let pointer = plain.as_ptr();
        Aes256GcmSiv::new_from_slice(&[4; 32])
            .unwrap()
            .encrypt_in_place(Nonce::from_slice(&[5; 12]), b"test", &mut *plain)
            .unwrap();
        assert_eq!(plain.as_ptr(), pointer);
    }

    #[test]
    fn deterministic_derivation_and_vault_round_trip() {
        let mut vault = Vault::default();
        vault
            .add_master("main", Zeroizing::new(vec![0u8; 32]))
            .unwrap();
        vault.add_derived("second").unwrap();
        assert_ne!(
            vault.account("main").unwrap().pubkey,
            vault.account("second").unwrap().pubkey
        );
        let bytes = vault.encode().unwrap();
        let decoded = Vault::decode(&bytes, VERSION).unwrap();
        assert_eq!(
            decoded.signer("main").unwrap().pubkey(),
            vault.account("main").unwrap().pubkey
        );
    }
    #[test]
    fn wrong_password_and_tamper_rejected() {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let dir =
            std::env::temp_dir().join(format!("solx-vault-test-{}", u64::from_le_bytes(random)));
        fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = dir.join("vault.enc");
        let mut vault = Vault::default();
        vault
            .add_master("main", Zeroizing::new(vec![0u8; 32]))
            .unwrap();
        let session = Session::create(&path, "correct horse battery staple", &mut vault).unwrap();
        assert_eq!(session.load().unwrap().accounts.len(), 1);
        assert!(Session::open(&path, "wrong").is_err());
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(Session::open(&path, "correct horse battery staple").is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
