//! Local-only synthetic fixtures; never accesses the user's home or wallet.
use crate::{
    App,
    config::Config,
    rpc::Rpc,
    signer::Keypair,
    vault::{PublicAccount, Session, Vault},
};
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    Allocate,
    Map,
    Lock,
    Protect,
    AfterHash,
    Random,
    Write,
    FileSync,
    Rename,
    DirectorySync,
}
thread_local! { static FAULT: std::cell::Cell<Option<Fault>> = const { std::cell::Cell::new(None) }; }

pub fn fail_at(point: Fault) -> crate::Result<()> {
    if FAULT.with(|f| f.get() == Some(point)) {
        return crate::fail("injected failure");
    }
    Ok(())
}

pub fn with_fault<T>(point: Fault, operation: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|f| f.set(None));
        }
    }
    FAULT.with(|f| f.set(Some(point)));
    let _reset = Reset;
    operation()
}

pub fn mock_rpc(responses: Vec<Value>) -> (Rpc, thread::JoinHandle<Vec<Value>>) {
    mock_rpc_with(responses, |_| {})
}

pub fn mock_rpc_with(
    responses: Vec<Value>,
    on_request: impl FnMut(&Value) + Send + 'static,
) -> (Rpc, thread::JoinHandle<Vec<Value>>) {
    let (config, server) = mock_rpc_config_with(responses, on_request);
    (Rpc::new(&config).unwrap(), server)
}

pub fn mock_rpc_config(responses: Vec<Value>) -> (Config, thread::JoinHandle<Vec<Value>>) {
    mock_rpc_config_with(responses, |_| {})
}

fn mock_rpc_config_with(
    responses: Vec<Value>,
    mut on_request: impl FnMut(&Value) + Send + 'static,
) -> (Config, thread::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut config = Config::default();
    config.rpc.url = Some(format!("http://{}", listener.local_addr().unwrap()));
    config.rpc.timeout_secs = 2;
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let deadline = Instant::now() + Duration::from_secs(4);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(stream) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(error) => panic!("mock RPC did not receive expected request: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            let request = loop {
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = std::str::from_utf8(&bytes[..end]).unwrap();
                    let length: usize = header
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap();
                    }
                }
                assert!(bytes.len() < 16384);
            };
            on_request(&request);
            requests.push(request);
            let body = serde_json::json!({"jsonrpc":"2.0", "id":1, "result":response}).to_string();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        }
        requests
    });
    (config, server)
}

pub struct TestWallet {
    pub app: App,
    pub identity: PublicAccount,
    dir: PathBuf,
}

pub fn private_temp_dir(prefix: &str) -> PathBuf {
    let mut random = [0; 8];
    getrandom::getrandom(&mut random).unwrap();
    // Only resolve the OS test root: macOS /var and /tmp are system symlinks.
    // Production vault paths still reject every symlink component.
    let root = std::env::temp_dir().canonicalize().unwrap();
    let dir = root.join(format!("{prefix}-{:016x}", u64::from_le_bytes(random)));
    crate::secure_file::Directory::open(&dir, true).unwrap();
    dir
}

impl TestWallet {
    pub fn new() -> Self {
        let dir = private_temp_dir("solx-security-test");
        let path = dir.join("vault.enc");
        let session = Session::test_session(&path);
        let mut vault = Vault::default();
        vault
            .add_imported(
                "test",
                Keypair::new_from_array([7; 32]).to_keypair_bytes().unwrap(),
            )
            .unwrap();
        session.save(&mut vault).unwrap();
        let identity = vault.public_snapshot().accounts.remove(0);
        let config = Config {
            vault: path,
            ..Config::default()
        };
        let app = App {
            config,
            session: Some(session),
            shell: false,
            last_history: None,
        };
        Self { app, identity, dir }
    }
}
impl Drop for TestWallet {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}
