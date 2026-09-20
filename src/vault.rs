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
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"SOLX";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 33;
const MAX_FILE: u64 = 1024 * 1024;
const MAX_ACCOUNTS: usize = 128;
const MAX_MASTERS: usize = 32;
const MAX_RECIPIENTS: usize = 256;

pub struct Master {
    entropy: Zeroizing<Vec<u8>>,
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
    pub fn create(path: &Path, password: &str, vault: &Vault) -> Result<Self> {
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
        if encrypted.len() < HEADER_LEN + 16 || &encrypted[..4] != MAGIC || encrypted[4] != VERSION
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
            || encrypted[4] != VERSION
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
        Vault::decode(&plain)
    }

    pub fn save(&self, vault: &Vault) -> Result<()> {
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
        let parent = self
            .path
            .parent()
            .ok_or("vault path needs a parent directory")?;
        create_private_dir(parent)?;
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).map_err(|_| "OS randomness unavailable")?;
        let tmp = parent.join(format!(".vault-{:016x}.tmp", u64::from_le_bytes(random)));
        let result = (|| -> Result<()> {
            let mut file = private_file(&tmp)?;
            file.write_all(&header)?;
            file.write_all(&plain)?;
            file.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
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
        self.masters.push(Master { entropy });
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
        let next = self
            .accounts
            .iter()
            .filter_map(|a| match a.kind {
                AccountKind::Derived { master: 0, index } => Some(index),
                _ => None,
            })
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("derivation index exhausted")?;
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
        let mut out = Zeroizing::new(Vec::with_capacity(256 + self.accounts.len() * 120));
        out.push(self.masters.len() as u8);
        for master in &self.masters {
            out.push(master.entropy.len() as u8);
            out.extend_from_slice(&master.entropy);
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
            let entropy = Zeroizing::new(reader.take(len)?.to_vec());
            Mnemonic::from_entropy(&entropy)?;
            masters.push(Master { entropy });
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
                    if usize::from(master) >= masters.len() {
                        return fail("invalid master reference");
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
    Ok(Zeroizing::new(Mnemonic::from_entropy(entropy)?.to_string()))
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
        let decoded = Vault::decode(&bytes).unwrap();
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
        let session = Session::create(&path, "correct horse battery staple", &vault).unwrap();
        assert_eq!(session.load().unwrap().accounts.len(), 1);
        assert!(Session::open(&path, "wrong").is_err());
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(Session::open(&path, "correct horse battery staple").is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
