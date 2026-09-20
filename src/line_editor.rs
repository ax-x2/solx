use std::{collections::VecDeque, io};
use zeroize::{Zeroize, Zeroizing};

const MAX_HISTORY: usize = 64;
const MAX_LINE: usize = 4096;

#[derive(Default)]
pub struct CommandHistory {
    entries: VecDeque<Zeroizing<String>>,
    position: Option<usize>,
    draft: Zeroizing<String>,
}

impl CommandHistory {
    pub fn read_line(&mut self, prompt: &str) -> io::Result<Option<String>> {
        #[cfg(unix)]
        if unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
            && unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
        {
            return self.read_tty_line(prompt);
        }
        crate::read_bounded_line()
    }

    pub fn remember(&mut self, line: &str) {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty()
            || line.split_whitespace().next() == Some("import")
            || line.contains("--base58")
            || line.contains("--mnemonic")
        {
            return;
        }
        if self
            .entries
            .back()
            .is_some_and(|last| last.as_str() == line)
        {
            return;
        }
        if self.entries.len() == MAX_HISTORY {
            self.entries.pop_front();
        }
        self.entries.push_back(Zeroizing::new(line.to_owned()));
    }

    fn older(&mut self, current: &str) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        self.position = Some(match self.position {
            Some(index) => index.saturating_sub(1),
            None => {
                self.draft.zeroize();
                self.draft.push_str(current);
                self.entries.len() - 1
            }
        });
        self.position.map(|index| self.entries[index].as_str())
    }

    fn newer(&mut self) -> Option<&str> {
        let index = self.position?;
        if index + 1 < self.entries.len() {
            self.position = Some(index + 1);
            Some(self.entries[index + 1].as_str())
        } else {
            self.position = None;
            Some(self.draft.as_str())
        }
    }
}

#[cfg(unix)]
mod terminal {
    use super::{CommandHistory, MAX_LINE};
    use std::io::{self, Write};
    use zeroize::{Zeroize, Zeroizing};

    struct ModeGuard(libc::termios);

    impl ModeGuard {
        fn enter() -> io::Result<Self> {
            let mut settings = unsafe { std::mem::zeroed::<libc::termios>() };
            if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut settings) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let original = settings;
            settings.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ECHONL | libc::ISIG);
            settings.c_cc[libc::VMIN] = 1;
            settings.c_cc[libc::VTIME] = 0;
            if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &settings) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(original))
        }
    }

    impl Drop for ModeGuard {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
            }
        }
    }

    fn read_byte() -> io::Result<Option<u8>> {
        loop {
            let mut byte = 0u8;
            let count = unsafe { libc::read(libc::STDIN_FILENO, (&mut byte as *mut u8).cast(), 1) };
            if count == 1 {
                return Ok(Some(byte));
            }
            if count == 0 {
                return Ok(None);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn read_byte_soon() -> io::Result<Option<u8>> {
        let mut poll = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 50) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            return Ok(None);
        }
        read_byte()
    }

    fn redraw(prompt: &str, line: &[u8], output: &mut impl Write) -> io::Result<()> {
        output.write_all(b"\r\x1b[2K")?;
        output.write_all(prompt.as_bytes())?;
        output.write_all(line)?;
        output.flush()
    }

    impl CommandHistory {
        pub(super) fn read_tty_line(&mut self, prompt: &str) -> io::Result<Option<String>> {
            let _mode = ModeGuard::enter()?;
            self.position = None;
            self.draft.zeroize();
            let mut line = Zeroizing::new(Vec::with_capacity(128));
            let stdout = io::stdout();
            let mut output = stdout.lock();
            loop {
                match read_byte()? {
                    None | Some(4) if line.is_empty() => {
                        output.write_all(b"\r\n")?;
                        return Ok(None);
                    }
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "terminal closed",
                        ));
                    }
                    Some(b'\r' | b'\n') => {
                        output.write_all(b"\r\n")?;
                        let bytes = std::mem::take(&mut *line);
                        return String::from_utf8(bytes).map(Some).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "command line is not UTF-8")
                        });
                    }
                    Some(3) => {
                        output.write_all(b"^C\r\n")?;
                        return Ok(Some(String::new()));
                    }
                    Some(8 | 127) => {
                        if !line.is_empty() {
                            let mut start = line.len() - 1;
                            while start > 0 && line[start] & 0xc0 == 0x80 {
                                start -= 1;
                            }
                            line[start..].zeroize();
                            line.truncate(start);
                            redraw(prompt, &line, &mut output)?;
                        }
                    }
                    Some(27) => {
                        if matches!(read_byte_soon()?, Some(b'[' | b'O')) {
                            match read_byte_soon()? {
                                Some(b'A') => {
                                    if let Some(previous) =
                                        self.older(std::str::from_utf8(&line).unwrap_or(""))
                                    {
                                        line.zeroize();
                                        line.extend_from_slice(previous.as_bytes());
                                        redraw(prompt, &line, &mut output)?;
                                    }
                                }
                                Some(b'B') => {
                                    if let Some(next) = self.newer() {
                                        line.zeroize();
                                        line.extend_from_slice(next.as_bytes());
                                        redraw(prompt, &line, &mut output)?;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(byte) if byte >= b' ' => {
                        if line.len() < MAX_LINE {
                            line.push(byte);
                            output.write_all(&[byte])?;
                            output.flush()?;
                        } else {
                            output.write_all(b"\x07")?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recalls_recent_commands_and_restores_draft() {
        let mut history = CommandHistory::default();
        history.remember("list --wallet main");
        history.remember("history --wallet main");
        assert_eq!(history.older("unfinished"), Some("history --wallet main"));
        assert_eq!(history.older(""), Some("list --wallet main"));
        assert_eq!(history.newer(), Some("history --wallet main"));
        assert_eq!(history.newer(), Some("unfinished"));
    }

    #[test]
    fn never_recalls_imports_or_inline_secrets() {
        let mut history = CommandHistory::default();
        history.remember("import test --base58 secret");
        history.remember("alias --mnemonic secret");
        assert_eq!(history.older(""), None);
    }
}
