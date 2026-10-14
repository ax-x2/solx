//! Native PTY smoke tests with disposable synthetic vaults; never contact RPC.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::DirBuilderExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).unwrap();
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = root.join(format!("solx-cli-test-{:016x}", u64::from_le_bytes(random)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn termios(file: &File) -> libc::termios {
    let mut value = std::mem::MaybeUninit::uninit();
    // SAFETY: tcgetattr initializes the live output on success.
    assert_eq!(
        unsafe { libc::tcgetattr(file.as_raw_fd(), value.as_mut_ptr()) },
        0
    );
    unsafe { value.assume_init() }
}

struct Terminal {
    child: Child,
    master: File,
    slave: File,
    original: libc::termios,
    output: Vec<u8>,
    consumed: usize,
}
impl Terminal {
    fn spawn(vault: &Path, args: &[&str]) -> Self {
        Self::spawn_with_limit(vault, args, None)
    }
    fn spawn_with_low_soft_limit(vault: &Path, args: &[&str]) -> Self {
        let mut limits = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: live output; leave the parent process's limits unchanged.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limits) },
            0
        );
        assert!(
            limits.rlim_max == libc::RLIM_INFINITY || limits.rlim_max >= 128 * 1024 * 1024,
            "provision at least 128 MiB hard memlock for this production CLI test"
        );
        limits.rlim_cur = 0;
        Self::spawn_with_limit(vault, args, Some(limits))
    }

    fn spawn_with_limit(vault: &Path, args: &[&str], memlock: Option<libc::rlimit>) -> Self {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: live output descriptors; null optional name/termios/winsize.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        for file in [&master, &slave] {
            assert_eq!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
        }
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let original = termios(&slave);
        let mut command = Command::new(env!("CARGO_BIN_EXE_solx"));
        command
            .arg("--vault")
            .arg(vault)
            .args(args)
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        // SAFETY: the child performs only async-signal-safe syscalls before exec.
        unsafe {
            command.pre_exec(move || {
                if let Some(limit) = memlock
                    && libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                #[cfg(target_os = "macos")]
                let request = libc::c_ulong::from(libc::TIOCSCTTY);
                #[cfg(target_os = "linux")]
                let request = libc::TIOCSCTTY;
                if libc::setsid() < 0 || libc::ioctl(libc::STDIN_FILENO, request, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Self {
            child: command.spawn().unwrap(),
            master,
            slave,
            original,
            output: Vec::new(),
            consumed: 0,
        }
    }

    fn drain(&mut self) {
        let mut buffer = [0; 4096];
        loop {
            match self.master.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => self.output.extend_from_slice(&buffer[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("PTY read: {e}"),
            }
            assert!(self.output.len() < 128 * 1024);
        }
    }

    fn expect(&mut self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            self.drain();
            if let Some(offset) = self.output[self.consumed..]
                .windows(text.len())
                .position(|w| w == text.as_bytes())
            {
                self.consumed += offset + text.len();
                return;
            }
            assert!(
                Instant::now() < deadline && self.child.try_wait().unwrap().is_none(),
                "missing {text:?}: {}",
                String::from_utf8_lossy(&self.output)
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn send_secret(&mut self, prompt: &str, bytes: &[u8]) {
        self.expect(prompt);
        assert_eq!(
            termios(&self.slave).c_lflag & (libc::ECHO | libc::ICANON | libc::ISIG),
            0
        );
        self.master.write_all(bytes).unwrap();
    }

    fn send_line(&mut self, prompt: &str, bytes: &[u8]) {
        self.expect(prompt);
        self.master.write_all(bytes).unwrap();
    }

    fn finish(mut self) -> (ExitStatus, Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            self.drain();
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "CLI timed out");
            std::thread::sleep(Duration::from_millis(10));
        };
        self.drain();
        let restored = termios(&self.slave);
        assert_eq!(restored.c_lflag, self.original.c_lflag);
        assert_eq!(restored.c_iflag, self.original.c_iflag);
        assert_eq!(restored.c_oflag, self.original.c_oflag);
        assert_eq!(restored.c_cflag, self.original.c_cflag);
        assert_eq!(restored.c_cc, self.original.c_cc);
        (status, std::mem::take(&mut self.output))
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "native PTY and >=128 MiB hard memlock; run separately with --ignored --test-threads=1"]
fn documented_init_and_config_editor_use_hidden_prompts_and_authenticated_settings() {
    let dir = TempDir::new();
    let path = dir.0.join("vault.enc");
    let password = b"test-pass-foo-1234\n";
    let mut terminal = Terminal::spawn_with_low_soft_limit(&path, &["init", "main"]);
    terminal.send_secret(
        "New vault password: ",
        "test-é\x7fpass-foo-1234\n".as_bytes(),
    );
    terminal.send_secret("Repeat password: ", password);
    let (status, output) = terminal.finish();
    assert!(status.success(), "{}", String::from_utf8_lossy(&output));
    assert!(
        !output
            .windows(password.len() - 1)
            .any(|w| w == &password[..password.len() - 1])
    );
    assert!(!dir.0.join("config.toml").exists());
    assert_eq!(&fs::read(&path).unwrap()[..5], b"SOLX\x05");

    let mut terminal = Terminal::spawn_with_low_soft_limit(&path, &["config"]);
    terminal.send_secret("Vault password: ", password);
    terminal.expect("Settings edits: 0");
    terminal.send_line("config> ", b"1\n");
    terminal.send_line("field> ", b"1\n");
    terminal.send_line(
        "RPC URL (Enter keeps; on/off for booleans; clear unsets optional values): ",
        b"https://provider.example/private-token?key=secret\n",
    );
    terminal.send_line("field> ", b"b\n");
    terminal.send_line("config> ", b"4\n");
    terminal.send_line("Alias action (set/remove/back): ", b"set\n");
    terminal.send_line("Alias name: ", b"mine\n");
    terminal.send_line("Command words (space separated): ", b"list main\n");
    terminal.send_line("config> ", b"s\n");
    terminal.send_line("Type SAVE to apply, or Enter to keep editing: ", b"SAVE\n");
    let (status, output) = terminal.finish();
    assert!(status.success(), "{}", String::from_utf8_lossy(&output));
    assert!(
        !output
            .windows(password.len() - 1)
            .any(|w| w == &password[..password.len() - 1])
    );
    let text = String::from_utf8_lossy(&output);
    assert_eq!(text.matches("Vault password:").count(), 1);
    assert!(text.contains("Settings edits: 1"));
    assert!(text.contains("https://provider.example/private-token?key=secret"));

    let mut terminal = Terminal::spawn(&path, &["config", "show"]);
    terminal.send_secret("Vault password: ", password);
    let (status, output) = terminal.finish();
    assert!(status.success());
    assert!(String::from_utf8_lossy(&output).contains("Settings edits: 1"));
    assert!(
        String::from_utf8_lossy(&output)
            .contains("RPC URL: \"https://provider.example/private-token?key=secret\"")
    );
    assert!(String::from_utf8_lossy(&output).contains("Show balances: false"));
    assert!(String::from_utf8_lossy(&output).contains("mine"));

    // Cancel at a group prompt and during visible URL entry.
    let before_cancel = fs::read(&path).unwrap();
    for url_entry in [false, true] {
        let mut terminal = Terminal::spawn(&path, &["config"]);
        terminal.send_secret("Vault password: ", password);
        if url_entry {
            terminal.send_line("config> ", b"1\n");
            terminal.send_line("field> ", b"1\n");
            terminal.send_line(
                "RPC URL (Enter keeps; on/off for booleans; clear unsets optional values): ",
                b"cancel\x03",
            );
        } else {
            terminal.send_line("config> ", b"2\n");
            terminal.send_line("field> ", b"7\n");
            terminal.send_line("Keep vault unlocked in shell (Enter keeps; on/off for booleans; clear unsets optional values): ", b"on\n");
            terminal.send_line("field> ", b"\x03");
        }
        assert!(!terminal.finish().0.success());
        assert_eq!(fs::read(&path).unwrap(), before_cancel);
    }

    // An explicit caching change applies immediately; lock forces one new unlock.
    let mut terminal = Terminal::spawn(&path, &["shell"]);
    terminal.send_secret("Vault password: ", password);
    terminal.send_line("solx> ", b"config\n");
    terminal.send_secret("Vault password: ", password);
    terminal.send_line("config> ", b"2\n");
    terminal.send_line("field> ", b"7\n");
    terminal.send_line("Keep vault unlocked in shell (Enter keeps; on/off for booleans; clear unsets optional values): ", b"on\n");
    terminal.send_line("field> ", b"b\n");
    terminal.send_line("config> ", b"s\n");
    terminal.send_line("Type SAVE to apply, or Enter to keep editing: ", b"SAVE\n");
    terminal.send_line("solx> ", b"config show\n");
    terminal.expect("Settings edits: 2");
    // Exit from a nested config prompt discards edits and leaves the shell usable.
    let before_exit = fs::read(&path).unwrap();
    terminal.send_line("solx> ", b"config\n");
    terminal.send_line("config> ", b"1\n");
    terminal.send_line("field> ", b"4\n");
    terminal.send_line(
        "Timeout seconds (Enter keeps; on/off for booleans; clear unsets optional values): ",
        b"22\n",
    );
    terminal.send_line("field> ", b"exit\n");
    terminal.expect("Settings edit cancelled.");
    terminal.send_line("solx> ", b"config show\n");
    terminal.expect("Settings edits: 2");
    assert_eq!(fs::read(&path).unwrap(), before_exit);
    // Listing must remain local with a configured external URL and balances off.
    terminal.send_line("solx> ", b"list main\n");
    terminal.expect("main  ");
    terminal.send_line("solx> ", b"list\n");
    terminal.expect("main  ");
    // Default creation is independent; any phrase-backed wallet can be a source.
    terminal.send_line("solx> ", b"new independent\n");
    terminal.expect("New recovery phrase (shown once; store it securely):");
    terminal.send_line("solx> ", b"new child --wallet independent\n");
    terminal.expect("Shared recovery phrase with independent.");
    terminal.expect("Derivation path: m/44'/501'/1'/0'");
    terminal.send_line("solx> ", b"new sibling --wallet child\n");
    terminal.expect("Shared recovery phrase with child.");
    terminal.expect("Derivation path: m/44'/501'/2'/0'");
    terminal.send_line("solx> ", b"new rejected --new-master\n");
    terminal.expect("usage: solx new NAME [--wallet SOURCE]");
    terminal.send_line("solx> ", b"lock\n");
    terminal.send_line("solx> ", b"config show\n");
    terminal.send_secret("Vault password: ", password);
    terminal.expect("Settings edits: 2");
    terminal.send_line("solx> ", b"exit\n");
    let (status, output) = terminal.finish();
    assert!(status.success(), "{}", String::from_utf8_lossy(&output));
    assert_eq!(
        String::from_utf8_lossy(&output)
            .matches("Vault password:")
            .count(),
        3
    );

    let before = fs::read(&path).unwrap();
    assert!(
        !Terminal::spawn(&path, &["init", "other"])
            .finish()
            .0
            .success()
    );
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
#[ignore = "native PTY and >=128 MiB hard memlock; run separately with --ignored --test-threads=1"]
fn cancelled_invalid_and_oversized_input_restore_terminal_settings() {
    let dir = TempDir::new();
    let path = dir.0.join("vault.enc");
    for input in [
        b"cancel\x03".to_vec(),
        b"cancel\x04".to_vec(),
        b"\xff\n".to_vec(),
        vec![b'x'; 1025],
    ] {
        let mut terminal = Terminal::spawn(&path, &["init", "main"]);
        terminal.send_secret("New vault password: ", &input);
        let (status, output) = terminal.finish();
        assert!(!status.success());
        assert!(String::from_utf8_lossy(&output).contains("Error:"));
        assert!(!path.exists());
    }
}

#[test]
#[ignore = "native PTY subprocess test; run separately with --ignored --test-threads=1"]
fn insufficient_memlock_never_creates_a_vault_or_exposes_a_secret() {
    let dir = TempDir::new();
    let path = dir.0.join("vault.enc");
    for args in [["init", "main"], ["config", "show"]] {
        let existing = args[0] == "config";
        if existing {
            // Preflight must fail before input or parsing these synthetic bytes.
            fs::write(&path, b"existing vault fixture").unwrap();
        }
        let (status, output) = Terminal::spawn_with_limit(
            &path,
            &args,
            Some(libc::rlimit {
                rlim_cur: 8 * 1024 * 1024,
                rlim_max: 8 * 1024 * 1024,
            }),
        )
        .finish();
        assert!(!status.success());
        if existing {
            assert_eq!(fs::read(&path).unwrap(), b"existing vault fixture");
        } else {
            assert!(!path.exists());
        }
        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("insufficient locked-memory allowance"),
            "{text}"
        );
        assert!(
            text.contains("soft=8388608 bytes, hard=8388608 bytes"),
            "{text}"
        );
        assert!(text.contains("128 MiB"), "{text}");
        assert!(text.contains("Administrator access is required"), "{text}");
        assert!(text.contains("normal user"), "{text}");
        assert!(!text.contains("New vault password:"));
        assert!(!text.contains("Vault password:"));
        assert!(!text.contains("Repeat password:"));
        assert!(!text.contains("Recovery phrase"));
    }
}
