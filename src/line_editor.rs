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

    pub fn remember(&mut self, line: &str, resolved: &[String]) {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty()
            || matches!(line.split_whitespace().next(), Some("import" | "export"))
            || line.contains("--base58")
            || line.contains("--mnemonic")
            || resolved
                .first()
                .is_some_and(|word| matches!(word.as_str(), "import" | "export"))
            || resolved
                .iter()
                .any(|word| matches!(word.as_str(), "--base58" | "--mnemonic"))
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

    struct EditLine {
        bytes: Zeroizing<Vec<u8>>,
        cursor: usize,
    }

    impl EditLine {
        fn new() -> Self {
            Self {
                bytes: Zeroizing::new(Vec::with_capacity(MAX_LINE)),
                cursor: 0,
            }
        }

        fn text(&self) -> &str {
            std::str::from_utf8(&self.bytes).expect("editor keeps valid UTF-8")
        }

        fn replace(&mut self, text: &str) {
            self.bytes.zeroize();
            self.cursor = 0;
            self.insert(text);
        }

        fn insert(&mut self, text: &str) -> bool {
            let len = self.bytes.len();
            if text.len() > MAX_LINE - len {
                return false;
            }
            self.bytes.resize(len + text.len(), 0);
            self.bytes
                .copy_within(self.cursor..len, self.cursor + text.len());
            self.bytes[self.cursor..self.cursor + text.len()].copy_from_slice(text.as_bytes());
            self.cursor += text.len();
            true
        }

        fn left(&mut self) {
            if let Some(ch) = self.text()[..self.cursor].chars().next_back() {
                self.cursor -= ch.len_utf8();
            }
        }

        fn right(&mut self) {
            if let Some(ch) = self.text()[self.cursor..].chars().next() {
                self.cursor += ch.len_utf8();
            }
        }

        fn delete(&mut self) {
            if let Some(ch) = self.text()[self.cursor..].chars().next() {
                let len = self.bytes.len();
                let end = self.cursor + ch.len_utf8();
                self.bytes.copy_within(end..len, self.cursor);
                let new_len = len - (end - self.cursor);
                self.bytes[new_len..].zeroize();
                self.bytes.truncate(new_len);
            }
        }

        fn backspace(&mut self) {
            if self.cursor > 0 {
                self.left();
                self.delete();
            }
        }
    }

    // Read the whole bounded CSI/SS3 sequence, including Delete's trailing '~'.
    fn escape_key(mut read: impl FnMut() -> io::Result<Option<u8>>) -> io::Result<Option<u8>> {
        if !matches!(read()?, Some(b'[' | b'O')) {
            return Ok(None);
        }
        let mut sequence = [0u8; 16];
        for index in 0..sequence.len() {
            let Some(byte) = read()? else { return Ok(None) };
            sequence[index] = byte;
            if (0x40..=0x7e).contains(&byte) {
                return Ok(match &sequence[..=index] {
                    [key @ (b'A' | b'B' | b'C' | b'D')] => Some(*key),
                    b"3~" => Some(b'X'),
                    _ => None,
                });
            }
        }
        Ok(None)
    }

    fn insert_character(
        line: &mut EditLine,
        first: u8,
        pending: &mut Option<u8>,
        mut read: impl FnMut() -> io::Result<Option<u8>>,
    ) -> io::Result<bool> {
        let len = match first {
            0x20..=0x7e => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Ok(false),
        };
        let mut bytes = Zeroizing::new([0u8; 4]);
        bytes[0] = first;
        for slot in &mut bytes[1..len] {
            match read()? {
                Some(byte @ 0x80..=0xbf) => *slot = byte,
                other => {
                    *pending = other;
                    return Ok(false);
                }
            }
        }
        Ok(std::str::from_utf8(&bytes[..len]).is_ok_and(|text| line.insert(text)))
    }

    fn redraw(prompt: &str, line: &EditLine, output: &mut impl Write) -> io::Result<()> {
        output.write_all(b"\r\x1b[2K")?;
        output.write_all(prompt.as_bytes())?;
        output.write_all(&line.bytes[..line.cursor])?;
        if line.cursor < line.bytes.len() {
            output.write_all(b"\x1b7")?;
            output.write_all(&line.bytes[line.cursor..])?;
            output.write_all(b"\x1b8")?;
        }
        output.flush()
    }

    impl CommandHistory {
        pub(super) fn read_tty_line(&mut self, prompt: &str) -> io::Result<Option<String>> {
            let _mode = ModeGuard::enter()?;
            self.position = None;
            self.draft.zeroize();
            let mut line = EditLine::new();
            let mut pending = None;
            let stdout = io::stdout();
            let mut output = stdout.lock();
            loop {
                let byte = match pending.take() {
                    Some(byte) => Some(byte),
                    None => read_byte()?,
                };
                match byte {
                    None | Some(4) if line.bytes.is_empty() => {
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
                        let bytes = std::mem::take(&mut *line.bytes);
                        return String::from_utf8(bytes).map(Some).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidData, "command line is not UTF-8")
                        });
                    }
                    Some(3) => {
                        output.write_all(b"^C\r\n")?;
                        return Ok(Some(String::new()));
                    }
                    Some(8 | 127) => {
                        line.backspace();
                        redraw(prompt, &line, &mut output)?;
                    }
                    Some(27) => {
                        match escape_key(read_byte_soon)? {
                            Some(b'A') => {
                                if let Some(previous) = self.older(line.text()) {
                                    line.replace(previous);
                                }
                            }
                            Some(b'B') => {
                                if let Some(next) = self.newer() {
                                    line.replace(next);
                                }
                            }
                            Some(b'C') => line.right(),
                            Some(b'D') => line.left(),
                            Some(b'X') => line.delete(),
                            _ => {}
                        }
                        redraw(prompt, &line, &mut output)?;
                    }
                    Some(byte) if byte >= b' ' => {
                        if insert_character(&mut line, byte, &mut pending, read_byte_soon)? {
                            redraw(prompt, &line, &mut output)?;
                        } else {
                            output.write_all(b"\x07")?;
                            output.flush()?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn edits_recalled_commands_without_changing_history() {
            let mut history = CommandHistory::default();
            history.remember("help", &["help".into()]);
            let mut line = EditLine::new();
            line.replace("draft");
            line.replace(history.older(line.text()).unwrap());
            assert_eq!(line.cursor, 4);
            line.left();
            line.left();
            assert!(line.insert("X"));
            assert_eq!(line.text(), "heXlp");
            line.backspace();
            assert_eq!(line.text(), "help");
            line.delete();
            assert_eq!(line.text(), "hep");
            assert!(line.insert("l"));
            line.right();
            assert_eq!(line.text(), "help");
            assert_eq!(line.cursor, 4);
            assert_eq!(history.entries[0].as_str(), "help");
            line.replace(history.newer().unwrap());
            assert_eq!(line.text(), "draft");
            assert_eq!(line.cursor, 5);
        }

        #[test]
        fn editing_at_boundaries_is_a_noop() {
            let mut line = EditLine::new();
            line.left();
            line.right();
            line.backspace();
            line.delete();
            assert_eq!(line.cursor, 0);
            assert_eq!(line.text(), "");
            line.insert("ab");
            line.right();
            line.delete();
            assert_eq!(line.text(), "ab");
            assert_eq!(line.cursor, 2);
            line.left();
            line.left();
            line.left();
            line.backspace();
            assert_eq!(line.text(), "ab");
            assert_eq!(line.cursor, 0);
            line.delete();
            assert_eq!(line.text(), "b");
        }

        #[test]
        fn edits_utf8_on_character_boundaries() {
            let mut line = EditLine::new();
            line.insert("aé界🦀z");
            line.left();
            line.left();
            assert_eq!(line.cursor, "aé界".len());
            line.delete();
            assert_eq!(line.text(), "aé界z");
            line.backspace();
            assert_eq!(line.text(), "aéz");
            line.left();
            assert_eq!(line.cursor, 1);
            line.insert("ö");
            line.right();
            assert_eq!(line.text(), "aöéz");
            assert_eq!(line.cursor, "aöé".len());
        }

        #[test]
        fn editing_never_grows_beyond_the_line_limit() {
            let mut line = EditLine::new();
            let capacity = line.bytes.capacity();
            line.insert(&"x".repeat(MAX_LINE));
            line.left();
            assert!(!line.insert("y"));
            assert_eq!(line.cursor, MAX_LINE - 1);
            assert_eq!(line.bytes.len(), MAX_LINE);
            line.delete();
            assert!(!line.insert("é"));
            assert!(line.insert("y"));
            assert_eq!(line.bytes.capacity(), capacity);
            assert!(line.text().ends_with('y'));
        }

        #[test]
        fn escape_decoder_consumes_delete_and_ignores_unknown_sequences() {
            for (sequence, expected) in [
                (&b"[A"[..], Some(b'A')),
                (&b"[B"[..], Some(b'B')),
                (&b"[C"[..], Some(b'C')),
                (&b"[D"[..], Some(b'D')),
                (&b"OC"[..], Some(b'C')),
                (&b"OD"[..], Some(b'D')),
                (&b"[3~"[..], Some(b'X')),
                (&b"[1;5D"[..], None),
                (&b"[200~"[..], None),
                (&b"[3"[..], None),
            ] {
                let mut bytes = sequence.iter().copied();
                assert_eq!(escape_key(|| Ok(bytes.next())).unwrap(), expected);
                assert!(bytes.next().is_none());
            }
            let mut calls = 0;
            assert_eq!(
                escape_key(|| {
                    calls += 1;
                    Ok(Some(if calls == 1 { b'[' } else { b'1' }))
                })
                .unwrap(),
                None
            );
            assert_eq!(calls, 17);
        }

        #[test]
        fn character_decoder_rejects_invalid_input_and_preserves_controls() {
            let mut line = EditLine::new();
            let mut pending = None;
            let mut rest = [0xa9].into_iter();
            assert!(insert_character(&mut line, 0xc3, &mut pending, || Ok(rest.next())).unwrap());
            assert_eq!(line.text(), "é");
            assert!(!insert_character(&mut line, 0xe0, &mut pending, || Ok(Some(0x80))).unwrap());
            assert!(
                !insert_character(&mut line, 0xff, &mut pending, || panic!(
                    "invalid lead byte"
                ))
                .unwrap()
            );
            assert!(!insert_character(&mut line, 0xc3, &mut pending, || Ok(None)).unwrap());
            for byte in [b'\n', 3, b'x'] {
                assert!(
                    !insert_character(&mut line, 0xc3, &mut pending, || Ok(Some(byte))).unwrap()
                );
                assert_eq!(pending.take(), Some(byte));
            }
            assert_eq!(line.text(), "é");
        }

        #[test]
        fn redraw_restores_cursor_between_prefix_and_suffix() {
            let mut line = EditLine::new();
            line.insert("héllo");
            line.left();
            line.left();
            let mut output = Vec::new();
            redraw("solx> ", &line, &mut output).unwrap();
            assert_eq!(output, "\r\x1b[2Ksolx> hél\x1b7lo\x1b8".as_bytes());
            line.right();
            line.right();
            output.clear();
            redraw("solx> ", &line, &mut output).unwrap();
            assert_eq!(output, "\r\x1b[2Ksolx> héllo".as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recalls_recent_commands_and_restores_draft() {
        let mut history = CommandHistory::default();
        history.remember("list --wallet main", &[]);
        history.remember("history --wallet main", &[]);
        assert_eq!(history.older("unfinished"), Some("history --wallet main"));
        assert_eq!(history.older(""), Some("list --wallet main"));
        assert_eq!(history.newer(), Some("history --wallet main"));
        assert_eq!(history.newer(), Some("unfinished"));
    }

    #[test]
    fn never_recalls_imports_or_inline_secrets() {
        let mut history = CommandHistory::default();
        history.remember("import test --base58 secret", &[]);
        history.remember("alias --mnemonic secret", &[]);
        history.remember("export main --private-key", &[]);
        assert_eq!(history.older(""), None);
    }

    #[test]
    fn aliases_cannot_hide_exports_from_history() {
        let mut config = crate::config::Config::default();
        config.aliases.insert(
            "reveal".into(),
            vec!["export".into(), "main".into(), "--private-key".into()],
        );
        let mut history = CommandHistory::default();
        history.remember("reveal", &config.expand_alias(&["reveal".into()]).unwrap());
        assert!(history.older("").is_none());
        history.remember("list", &["list".into()]);
        assert_eq!(history.older(""), Some("list"));
    }

    #[test]
    fn aliases_cannot_hide_imports_from_history() {
        let mut config = crate::config::Config::default();
        config.aliases.insert(
            "imp".into(),
            vec!["import".into(), "old".into(), "--base58".into()],
        );
        config.aliases.insert("ls".into(), vec!["list".into()]);
        let mut history = CommandHistory::default();
        let resolved = config
            .expand_alias(&["imp".into(), "secret".into()])
            .unwrap();
        history.remember("imp secret", &resolved);
        assert!(history.older("").is_none());
        history.remember("ls", &config.expand_alias(&["ls".into()]).unwrap());
        assert_eq!(history.older(""), Some("ls"));
        assert_eq!(history.older(""), Some("ls"));
    }
}
