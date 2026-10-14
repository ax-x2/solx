//! Descriptor-relative vault access. Never follows path components through symlinks.
use crate::{Result, fail};
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::{ffi::OsStrExt, fs::MetadataExt},
};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    path::{Component, Path},
};

pub struct Directory(File);

fn name(value: &OsStr) -> Result<CString> {
    Ok(CString::new(value.as_bytes())?)
}

impl Directory {
    pub fn open(path: &Path, create: bool) -> Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        if absolute.components().count() > 128 {
            return fail("vault path is too deep");
        }
        let mut current = File::open("/")?;
        for part in absolute.components() {
            let component = match part {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(value) => name(value)?,
                _ => return fail("vault path must not contain parent traversal"),
            };
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            // SAFETY: CString and directory descriptor are live for each syscall.
            let mut fd = unsafe { libc::openat(current.as_raw_fd(), component.as_ptr(), flags) };
            if fd < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                let result =
                    unsafe { libc::mkdirat(current.as_raw_fd(), component.as_ptr(), 0o700) };
                if result != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                {
                    return Err(io::Error::last_os_error().into());
                }
                fd = unsafe { libc::openat(current.as_raw_fd(), component.as_ptr(), flags) };
            }
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            current = unsafe { File::from_raw_fd(fd) };
            let meta = current.metadata()?;
            let uid = unsafe { libc::geteuid() };
            let trusted_sticky = meta.uid() == 0 && meta.mode() & 0o1000 != 0;
            if (meta.uid() != uid && meta.uid() != 0)
                || (meta.mode() & 0o022 != 0 && !trusted_sticky)
            {
                return fail("vault path has an untrusted owner or writable ancestor");
            }
        }
        let meta = current.metadata()?;
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return fail("vault directory must be owned by you with mode 700");
        }
        Ok(Self(current))
    }

    pub fn file(&self, filename: &OsStr, flags: i32) -> Result<File> {
        let filename = name(filename)?;
        // SAFETY: descriptor and CString remain live. Caller supplies access flags only.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                filename.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return fail("vault/lock must be an owner-only regular file owned by you");
        }
        Ok(file)
    }

    pub fn rename(&self, from: &OsStr, to: &OsStr) -> Result<()> {
        let (from, to) = (name(from)?, name(to)?);
        if unsafe {
            libc::renameat(
                self.0.as_raw_fd(),
                from.as_ptr(),
                self.0.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    pub fn remove(&self, filename: &OsStr) {
        if let Ok(filename) = name(filename) {
            unsafe {
                libc::unlinkat(self.0.as_raw_fd(), filename.as_ptr(), 0);
            }
        }
    }
    pub fn sync(&self) -> Result<()> {
        #[cfg(test)]
        crate::test_support::fail_at(crate::test_support::Fault::DirectorySync)?;
        #[cfg(target_os = "macos")]
        loop {
            // File::sync_all uses F_FULLFSYNC on Darwin, which is for files.
            // SAFETY: the owned directory descriptor remains live throughout fsync.
            if unsafe { libc::fsync(self.0.as_raw_fd()) } == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(self.0.sync_all()?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn symlinks_writable_files_and_special_files_are_rejected() {
        let wallet = crate::test_support::TestWallet::new();
        let parent = wallet.app.config.vault.parent().unwrap();
        let directory = Directory::open(parent, false).unwrap();
        symlink("vault.enc", parent.join("link")).unwrap();
        assert!(directory.file(OsStr::new("link"), libc::O_RDONLY).is_err());
        let insecure = parent.join("insecure");
        std::fs::write(&insecure, b"test").unwrap();
        std::fs::set_permissions(&insecure, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            directory
                .file(OsStr::new("insecure"), libc::O_RDONLY)
                .is_err()
        );
        let fifo = CString::new(parent.join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(directory.file(OsStr::new("fifo"), libc::O_RDONLY).is_err());
        symlink(parent, parent.join("directory-link")).unwrap();
        assert!(Directory::open(&parent.join("directory-link"), false).is_err());
        assert!(Directory::open(&parent.join(".."), false).is_err());
    }
    #[test]
    fn anchored_directory_cannot_be_redirected_by_replacing_its_path() {
        let wallet = crate::test_support::TestWallet::new();
        let parent = wallet.app.config.vault.parent().unwrap();
        let path = parent.join("original");
        let anchored = Directory::open(&path, true).unwrap();
        std::fs::rename(&path, parent.join("moved")).unwrap();
        Directory::open(&path, true).unwrap();
        anchored
            .file(
                OsStr::new("data"),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
            .unwrap();
        assert!(parent.join("moved/data").exists());
        assert!(!path.join("data").exists());
    }
}
