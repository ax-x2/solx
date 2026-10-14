//! Page-owned secret storage. Lock before use; erase before releasing the mapping.
use crate::{Result, fail};
use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    mem::{MaybeUninit, align_of, size_of},
    ops::{Deref, DerefMut},
    ptr::NonNull,
};
use zeroize::{Zeroize, Zeroizing};

pub fn protect_process() -> Result<()> {
    #[cfg(target_os = "linux")]
    // SAFETY: valid constants; changes only this process's dumpability.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    // Permanent process policy, never restored by a per-operation guard.
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: live rlimit pointer; affects only this process.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Owns complete pages, so releasing it cannot unlock a different owner's page.
/// The mapping is private and never exposed until all required protection succeeds.
struct LockedRegion {
    pointer: NonNull<u8>,
    len: usize,
    locked: bool,
}
impl LockedRegion {
    fn new(size: usize, align: usize) -> Result<Self> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 || size == 0 || align == 0 || !(page as usize).is_multiple_of(align) {
            return fail("invalid secret memory size or alignment");
        }
        let page = page as usize;
        let len = size
            .checked_add(page - 1)
            .map(|n| n / page * page)
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or("secret memory size overflow")?;
        #[cfg(test)]
        crate::test_support::fail_at(crate::test_support::Fault::Map)?;
        // SAFETY: fresh private anonymous mapping; no existing address is replaced.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        let Some(pointer) = NonNull::new(raw.cast()) else {
            unsafe {
                libc::munmap(raw, len);
            }
            return fail("null secret mapping");
        };
        let mut region = Self {
            pointer,
            len,
            locked: false,
        };
        #[cfg(test)]
        LIVE.with(|n| n.set(n.get() + 1));
        #[cfg(test)]
        crate::test_support::fail_at(crate::test_support::Fault::Lock)?;
        // SAFETY: exclusively owned, mapped, complete pages.
        if unsafe { libc::mlock(raw, len) } != 0 {
            let error = io::Error::last_os_error();
            return Err(format!("cannot lock {len} bytes of secret memory (check the OS memlock allowance; Argon2id requires 64 MiB plus other secret buffers): {error}").into());
        }
        region.locked = true;
        #[cfg(test)]
        crate::test_support::fail_at(crate::test_support::Fault::Protect)?;
        #[cfg(target_os = "linux")]
        if unsafe { libc::madvise(raw, len, libc::MADV_DONTDUMP) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(region)
    }

    #[cfg(test)]
    fn watch(&self) {
        WATCH.with(|w| w.set((self.pointer.as_ptr() as usize, None)));
    }
}
impl Drop for LockedRegion {
    fn drop(&mut self) {
        if self.locked {
            // SAFETY: the entire mapping is owned and writable. MaybeUninit covers
            // padding left uninitialized by a typed owner. No typed value is live
            // when its owner releases this region. zeroize uses volatile writes.
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.pointer.as_ptr().cast::<MaybeUninit<u8>>(),
                    self.len,
                )
            }
            .zeroize();
            #[cfg(test)]
            WATCH.with(|w| {
                if w.get().0 == self.pointer.as_ptr() as usize {
                    let erased = (0..self.len)
                        .all(|i| unsafe { self.pointer.as_ptr().add(i).read_volatile() } == 0);
                    w.set((0, Some(erased)));
                }
            });
            // SAFETY: the same exclusively owned mapping, erased while still locked.
            unsafe {
                libc::munlock(self.pointer.as_ptr().cast(), self.len);
            }
        }
        // An unsuccessful constructor has never exposed its zero-filled mapping.
        unsafe {
            libc::munmap(self.pointer.as_ptr().cast(), self.len);
        }
        #[cfg(test)]
        LIVE.with(|n| n.set(n.get() - 1));
    }
}

/// Stable, locked storage for one initialized value. Nested allocations, constructor
/// temporaries, registers, and compiler-generated copies are outside this guarantee.
pub struct Locked<T> {
    region: LockedRegion,
    value: PhantomData<T>,
}
impl<T> Locked<T> {
    pub fn try_new(init: impl FnOnce() -> Result<T>) -> Result<Self> {
        let region = LockedRegion::new(size_of::<T>(), align_of::<T>())?;
        // Initialization runs only after locking. If it fails/unwinds, region drops.
        // Explicitly erase the constructor staging slot after transferring
        // ownership. Upstream return-value/compiler copies remain outside scope.
        let value = Zeroizing::new(MaybeUninit::new(init()?));
        // SAFETY: enough aligned, nonoverlapping storage. Copying transfers the
        // single T owner into the mapping. The MaybeUninit source never drops T;
        // its Zeroizing guard wipes the complete staging slot, including padding.
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr(), region.pointer.as_ptr().cast::<T>(), 1);
        }
        Ok(Self {
            region,
            value: PhantomData,
        })
    }
}
impl<T> Deref for Locked<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: initialized, aligned T owned by self until Drop.
        unsafe { &*self.region.pointer.as_ptr().cast::<T>() }
    }
}
impl<T> DerefMut for Locked<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.region.pointer.as_ptr().cast::<T>() }
    }
}
impl<T> Drop for Locked<T> {
    fn drop(&mut self) {
        // SAFETY: exactly one initialized value. The region then wipes all bytes,
        // including padding, even when the value's destructor unwinds.
        unsafe {
            self.region.pointer.as_ptr().cast::<T>().drop_in_place();
        }
    }
}
impl<const N: usize> Locked<[u8; N]> {
    pub fn new() -> Result<Self> {
        Self::try_new(|| Ok([0; N]))
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != N {
            return fail("incorrect secret length");
        }
        let mut value = Self::new()?;
        value.copy_from_slice(bytes);
        Ok(value)
    }
    pub fn bytes(&self) -> &[u8; N] {
        self
    }
    pub fn bytes_mut(&mut self) -> &mut [u8; N] {
        self
    }
}
pub type LockedKey = Locked<[u8; 32]>;
pub type LockedKeypair = Locked<[u8; 64]>;

/// Bounded, initialized byte storage with no reallocation and no secret Debug/Clone.
pub struct LockedBytes {
    region: LockedRegion,
    len: usize,
    capacity: usize,
}
impl LockedBytes {
    pub fn with_capacity(capacity: usize) -> Result<Self> {
        Ok(Self {
            region: LockedRegion::new(capacity.max(1), 1)?,
            len: 0,
            capacity,
        })
    }
    pub fn zeroed(len: usize) -> Result<Self> {
        let mut value = Self::with_capacity(len)?;
        value.len = len;
        Ok(value)
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let mut value = Self::with_capacity(bytes.len())?;
        value.extend_from_slice(bytes)?;
        Ok(value)
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .len
            .checked_add(bytes.len())
            .filter(|end| *end <= self.capacity)
            .ok_or("secret buffer capacity exceeded")?;
        // SAFETY: exclusive destination inside the initialized mapping. Safe borrows
        // cannot alias the source with this mutable receiver.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.region.pointer.as_ptr().add(self.len),
                bytes.len(),
            );
        }
        self.len = end;
        Ok(())
    }
    pub fn push(&mut self, byte: u8) -> Result<()> {
        self.extend_from_slice(&[byte])
    }
    pub fn truncate(&mut self, len: usize) {
        if len < self.len {
            self[len..].zeroize();
            self.len = len;
        }
    }
    pub fn into_text(self) -> Result<LockedString> {
        std::str::from_utf8(&self).map_err(|_| "secret input is not UTF-8")?;
        Ok(LockedString(self))
    }
}
impl Deref for LockedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.region.pointer.as_ptr(), self.len) }
    }
}
impl DerefMut for LockedBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.region.pointer.as_ptr(), self.len) }
    }
}
impl Write for LockedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.extend_from_slice(bytes).map_err(|_| {
            io::Error::new(io::ErrorKind::WriteZero, "secret buffer capacity exceeded")
        })?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl AsRef<[u8]> for LockedBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl AsMut<[u8]> for LockedBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}
impl aes_gcm_siv::aead::Buffer for LockedBytes {
    fn extend_from_slice(&mut self, bytes: &[u8]) -> aes_gcm_siv::aead::Result<()> {
        self.extend_from_slice(bytes)
            .map_err(|_| aes_gcm_siv::aead::Error)
    }
    fn truncate(&mut self, len: usize) {
        self.truncate(len);
    }
}

/// Validated UTF-8 in a locked owner; text is only exposed by explicit borrowing.
pub struct LockedString(LockedBytes);
impl LockedString {
    pub fn as_str(&self) -> &str {
        self
    }
}
impl Deref for LockedString {
    type Target = str;
    fn deref(&self) -> &str {
        // SAFETY: checked by into_text; no mutable byte access is exposed.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}
impl PartialEq for LockedString {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
impl Eq for LockedString {}

pub struct LockedBlocks {
    region: LockedRegion,
    len: usize,
}
impl LockedBlocks {
    pub fn new(len: usize) -> Result<Self> {
        let size = len
            .checked_mul(size_of::<argon2::Block>())
            .ok_or("Argon2 memory size overflow")?;
        let region = LockedRegion::new(size, align_of::<argon2::Block>())?;
        for i in 0..len {
            // SAFETY: checked array size/alignment, initialized before exposing a slice.
            unsafe {
                region
                    .pointer
                    .as_ptr()
                    .cast::<argon2::Block>()
                    .add(i)
                    .write(argon2::Block::new());
            }
        }
        Ok(Self { region, len })
    }
    #[cfg(test)]
    pub fn watch(&self) {
        self.region.watch();
    }
}
impl Deref for LockedBlocks {
    type Target = [argon2::Block];
    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.region.pointer.as_ptr().cast(), self.len) }
    }
}
impl DerefMut for LockedBlocks {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.region.pointer.as_ptr().cast(), self.len) }
    }
}
// Block is Copy and has no destructor; LockedRegion wipes every block and page tail.

/// Reads bounded secret input from the controlling terminal without echo.
pub fn prompt(label: &str, max: usize) -> Result<LockedString> {
    use std::os::fd::AsRawFd;
    // Lock the input and single-byte read slot before changing terminal settings.
    let bytes = LockedBytes::with_capacity(max)?;
    let byte = Locked::<[u8; 1]>::new()?;
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let fd = tty.as_raw_fd();
    let mut original = MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let original = unsafe { original.assume_init() };
    let mut settings = original;
    settings.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
    settings.c_cc[libc::VMIN] = 1;
    settings.c_cc[libc::VTIME] = 0;
    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.0, libc::TCSAFLUSH, &self.1);
            }
        }
    }
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &settings) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let guard = Restore(fd, original);
    tty.write_all(label.as_bytes())?;
    tty.flush()?;
    let result = read_secret(&mut tty, bytes, byte);
    drop(guard);
    tty.write_all(b"\n")?;
    result
}
fn read_secret(
    reader: &mut impl Read,
    mut bytes: LockedBytes,
    mut byte: Locked<[u8; 1]>,
) -> Result<LockedString> {
    loop {
        if reader.read(&mut byte[..])? == 0 {
            return fail("secret input closed");
        }
        if matches!(byte[0], b'\n' | b'\r') {
            break;
        }
        if matches!(byte[0], 3 | 4) {
            return fail("secret input cancelled");
        }
        if matches!(byte[0], 8 | 127) {
            while let Some(&last) = bytes.last() {
                let continuation = last & 0xc0 == 0x80;
                bytes.truncate(bytes.len() - 1);
                if !continuation {
                    break;
                }
            }
            continue;
        }
        if bytes.len() == bytes.capacity() {
            return fail("secret input exceeds its length limit");
        }
        bytes.extend_from_slice(&byte[..])?;
    }
    bytes.into_text()
}

#[cfg(test)]
thread_local! {
    static WATCH: std::cell::Cell<(usize, Option<bool>)> = const { std::cell::Cell::new((0, None)) };
    static LIVE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub fn was_erased() -> Option<bool> {
    WATCH.with(|w| w.replace((0, None)).1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "isolated subprocess; run with --ignored --test-threads=1"]
    fn process_guards_and_memlock_failure_are_isolated() {
        if let Ok(mode) = std::env::var("SOLX_SECURITY_TEST_CHILD") {
            if mode == "dump" {
                protect_process().unwrap();
                #[cfg(target_os = "linux")]
                assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
                let mut limits = libc::rlimit {
                    rlim_cur: 1,
                    rlim_max: 1,
                };
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limits) },
                    0
                );
                assert_eq!((limits.rlim_cur, limits.rlim_max), (0, 0));
            } else if mode == "budget" {
                let mut limits = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limits) },
                    0
                );
                limits.rlim_cur = limits.rlim_max.min(8 * 1024 * 1024);
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limits) }, 0);
                let before = LIVE.with(|n| n.get());
                let error = crate::kdf::Argon2idParams::VAULT
                    .derive("test password", &[1; 16])
                    .err()
                    .unwrap();
                assert!(error.to_string().contains("cannot lock 67108864 bytes"));
                assert_eq!(LIVE.with(|n| n.get()), before);
                let dir = crate::test_support::private_temp_dir("solx-memlock-budget");
                let path = dir.join("vault.enc");
                let mut vault = crate::vault::Vault::default();
                assert!(crate::vault::Session::create(&path, "test password", &mut vault).is_err());
                assert!(!path.exists());
                crate::vault::Session::test_session(&path)
                    .save(&mut vault)
                    .unwrap();
                let original = std::fs::read(&path).unwrap();
                assert!(crate::vault::Session::open(&path, "test password").is_err());
                assert_eq!(std::fs::read(&path).unwrap(), original);
                std::fs::remove_dir_all(dir).unwrap();
            } else {
                let limits = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limits) }, 0);
                assert!(LockedKey::new().is_err());
                assert!(LockedBytes::zeroed(16).is_err());
                assert!(LockedBlocks::new(32).is_err());
                assert!(crate::signer::Keypair::from_seed_bytes(&[7; 32]).is_err());
            }
            return;
        }
        for mode in ["dump", "lock", "budget"] {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "secret::tests::process_guards_and_memlock_failure_are_isolated",
                    "--test-threads=1",
                ])
                .env("SOLX_SECURITY_TEST_CHILD", mode)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
    #[test]
    fn bounds_stability_and_full_capacity_erasure() {
        assert!(LockedRegion::new(usize::MAX, 1).is_err());
        assert!(LockedRegion::new(1, usize::MAX).is_err());
        let mut bytes = LockedBytes::with_capacity(17).unwrap();
        let pointer = bytes.as_ptr();
        bytes.extend_from_slice(&[42; 17]).unwrap();
        assert!(bytes.push(9).is_err());
        assert_eq!(bytes.len(), 17);
        bytes.truncate(3);
        assert_eq!(bytes.as_ptr(), pointer);
        assert!(
            unsafe { std::slice::from_raw_parts(pointer.add(3), 14) }
                .iter()
                .all(|b| *b == 0)
        );
        // Fill the page tail too; Drop must erase capacity and rounding, not just len.
        unsafe {
            bytes
                .region
                .pointer
                .as_ptr()
                .add(bytes.capacity())
                .write(99);
        }
        bytes.region.watch();
        drop(bytes);
        assert_eq!(was_erased(), Some(true));
    }
    #[test]
    fn failed_construction_and_unwind_release_owned_mappings() {
        let before = LIVE.with(|n| n.get());
        for fault in [
            crate::test_support::Fault::Map,
            crate::test_support::Fault::Lock,
            crate::test_support::Fault::Protect,
        ] {
            assert!(crate::test_support::with_fault(fault, LockedKey::new).is_err());
            assert_eq!(LIVE.with(|n| n.get()), before);
        }
        let entered = std::cell::Cell::new(false);
        assert!(
            crate::test_support::with_fault(crate::test_support::Fault::Lock, || {
                Locked::<u32>::try_new(|| {
                    entered.set(true);
                    Ok(7)
                })
            })
            .is_err()
        );
        assert!(!entered.get());
        assert!(Locked::<u32>::try_new(|| fail("init failure")).is_err());
        let result = std::panic::catch_unwind(|| {
            let mut bytes = LockedBytes::from_slice(&[42; 17]).unwrap();
            bytes[0] = 99;
            bytes.region.watch();
            panic!("synthetic unwind");
        });
        assert!(result.is_err());
        assert_eq!(was_erased(), Some(true));
        assert_eq!(LIVE.with(|n| n.get()), before);
    }
    #[test]
    fn typed_destructor_runs_before_mapping_erasure() {
        struct Value(std::rc::Rc<std::cell::Cell<bool>>, [u8; 32]);
        impl Drop for Value {
            fn drop(&mut self) {
                assert_eq!(self.1, [42; 32]);
                self.0.set(true);
            }
        }
        let dropped = std::rc::Rc::new(std::cell::Cell::new(false));
        let value = Locked::try_new(|| Ok(Value(dropped.clone(), [42; 32]))).unwrap();
        value.region.watch();
        drop(value);
        assert!(dropped.get());
        assert_eq!(was_erased(), Some(true));
    }
    #[test]
    fn independent_regions_remain_locked_until_their_own_release() {
        let a = LockedKey::new().unwrap();
        let b = LockedKey::new().unwrap();
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert_eq!(a.region.len, page);
        assert_eq!(a.region.pointer.as_ptr() as usize % page, 0);
        assert_ne!(a.region.pointer, b.region.pointer);
        drop(a);
        #[cfg(target_os = "linux")]
        {
            let address = b.region.pointer.as_ptr() as usize;
            let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
            let mut selected = false;
            let mut found = false;
            for line in maps.lines() {
                if let Some(range) = line.split_whitespace().next().filter(|s| s.contains('-')) {
                    let (start, end) = range.split_once('-').unwrap();
                    selected = (usize::from_str_radix(start, 16).unwrap()
                        ..usize::from_str_radix(end, 16).unwrap())
                        .contains(&address);
                }
                if selected && line.starts_with("VmFlags:") {
                    assert!(line.split_whitespace().any(|s| s == "lo"));
                    assert!(line.split_whitespace().any(|s| s == "dd"));
                    found = true;
                }
            }
            assert!(found);
        }
    }
    #[test]
    fn input_is_bounded_and_requires_complete_utf8() {
        fn read(mut input: &[u8], max: usize) -> Result<LockedString> {
            read_secret(&mut input, LockedBytes::with_capacity(max)?, Locked::new()?)
        }
        assert_eq!(read(b"abcd\n", 4).unwrap().as_str(), "abcd");
        for input in [&b"abcde\n"[..], b"\xff\n", b"abc", b"abc\x03", b"abc\x04"] {
            assert!(read(input, 4).is_err());
        }
        assert_eq!(read("aé\x7fb\n".as_bytes(), 8).unwrap().as_str(), "ab");
    }
    #[test]
    fn aes_schedules_are_zeroized_on_drop() {
        fn assert_erased<T: zeroize::ZeroizeOnDrop>() {}
        assert_erased::<aes::Aes256>();
    }
}
