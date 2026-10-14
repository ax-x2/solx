use crate::{Result, config::Config, fail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use solana_message::{Hash, VersionedMessage};
use solana_pubkey::Pubkey;
use std::{
    io::Read,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

const MAX_BODY: u64 = 2 * 1024 * 1024;

pub struct Rpc {
    client: Client,
    url: String,
    pub cluster: String,
    pub endpoint: String,
    timeout: Duration,
    expected_genesis: String,
}

pub struct BlockhashContext {
    pub hash: Hash,
    pub last_valid_block_height: u64,
    pub context_slot: u64,
}

pub enum SubmissionOutcome {
    Confirmed(solana_transaction::Signature),
    Unknown {
        signature: solana_transaction::Signature,
        reason: String,
    },
}

pub fn expected_genesis(config: &Config) -> Result<&str> {
    // Pinned network identities from Solana SDK genesis_config.rs.
    let known = match config.rpc.cluster.as_str() {
        "mainnet" => "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
        "devnet" => "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
        "testnet" => "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
        "custom" => {
            return config
                .rpc
                .expected_genesis_hash
                .as_deref()
                .ok_or_else(|| "custom cluster requires expected_genesis_hash".into());
        }
        _ => return fail("unknown cluster"),
    };
    if config
        .rpc
        .expected_genesis_hash
        .as_deref()
        .is_some_and(|hash| hash != known)
    {
        return fail("expected_genesis_hash disagrees with the selected cluster");
    }
    Ok(known)
}

pub struct TokenAccount {
    pub address: Pubkey,
    pub mint: Pubkey,
    pub raw_amount: u64,
    pub decimals: u8,
}

impl Rpc {
    pub fn new(config: &Config) -> Result<Self> {
        let url = config
            .rpc
            .url
            .as_ref()
            .ok_or("RPC is not configured; use config to set the RPC URL and cluster")?;
        let endpoint = reqwest::Url::parse(url)?
            .host_str()
            .ok_or("RPC URL has no host")?
            .to_owned();
        let client = Client::builder()
            .timeout(config.rpc_timeout())
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            url: url.clone(),
            cluster: config.rpc.cluster.clone(),
            endpoint,
            timeout: config.rpc_timeout(),
            expected_genesis: expected_genesis(config)?.to_owned(),
        })
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        self.call_with_timeout(method, params, self.timeout)
    }

    pub fn verify_cluster(&self) -> Result<()> {
        let result = self.call("getGenesisHash", json!([]))?;
        if result.as_str() != Some(&self.expected_genesis) {
            return fail(
                "RPC genesis hash does not match the configured cluster; refusing operation",
            );
        }
        Ok(())
    }

    fn call_with_timeout(&self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let request = json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params});
        let mut response = self
            .client
            .post(&self.url)
            .timeout(timeout)
            .json(&request)
            .send()
            .map_err(reqwest::Error::without_url)?;
        if !response.status().is_success() {
            return Err(format!("RPC {method}: HTTP {}", response.status()).into());
        }
        let mut body = Vec::new();
        response
            .by_ref()
            .take(MAX_BODY + 1)
            .read_to_end(&mut body)?;
        if body.len() as u64 > MAX_BODY {
            return fail("RPC response exceeds 2 MiB");
        }
        let mut parsed: Value = serde_json::from_slice(&body)?;
        if parsed.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || parsed.get("id").and_then(Value::as_u64) != Some(1)
        {
            return fail("invalid JSON-RPC envelope");
        }
        if let Some(error) = parsed.get("error") {
            return Err(format!("RPC {method}: {}", safe_text(&error.to_string(), 500)).into());
        }
        parsed
            .get_mut("result")
            .map(Value::take)
            .ok_or_else(|| "RPC result missing".into())
    }

    pub fn balance(&self, address: &Pubkey) -> Result<u64> {
        self.call(
            "getBalance",
            json!([address.to_string(), {"commitment":"confirmed"}]),
        )?
        .get("value")
        .and_then(Value::as_u64)
        .ok_or_else(|| "invalid getBalance response".into())
    }

    pub fn account_info(&self, address: &Pubkey) -> Result<Option<Value>> {
        let result = self.call(
            "getAccountInfo",
            json!([address.to_string(), {"encoding":"base64", "commitment":"confirmed"}]),
        )?;
        match result.get("value") {
            Some(Value::Null) => Ok(None),
            Some(value) if value.is_object() => Ok(Some(value.clone())),
            _ => fail("invalid getAccountInfo response"),
        }
    }

    pub fn token_balance(&self, address: &Pubkey) -> Result<Option<u64>> {
        if self.account_info(address)?.is_none() {
            return Ok(None);
        }
        let value = self.call(
            "getTokenAccountBalance",
            json!([address.to_string(), {"commitment":"confirmed"}]),
        )?;
        let amount = value
            .pointer("/value/amount")
            .and_then(Value::as_str)
            .ok_or("invalid token balance response")?
            .parse()?;
        Ok(Some(amount))
    }

    pub fn token_decimals(&self, mint: &Pubkey) -> Result<u8> {
        let result = self.call(
            "getTokenSupply",
            json!([mint.to_string(), {"commitment":"confirmed"}]),
        )?;
        let decimals = result
            .pointer("/value/decimals")
            .and_then(Value::as_u64)
            .ok_or("invalid token supply response")?;
        Ok(u8::try_from(decimals)?)
    }

    pub fn latest_blockhash(&self) -> Result<BlockhashContext> {
        let result = self.call("getLatestBlockhash", json!([{"commitment":"confirmed"}]))?;
        let hash = result
            .pointer("/value/blockhash")
            .and_then(Value::as_str)
            .ok_or("invalid getLatestBlockhash response")?;
        Ok(BlockhashContext {
            hash: Hash::from_str(hash)?,
            last_valid_block_height: result
                .pointer("/value/lastValidBlockHeight")
                .and_then(Value::as_u64)
                .ok_or("missing blockhash expiry")?,
            context_slot: result
                .pointer("/context/slot")
                .and_then(Value::as_u64)
                .ok_or("missing blockhash context")?,
        })
    }

    pub fn block_height(&self, context: &BlockhashContext) -> Result<u64> {
        self.call(
            "getBlockHeight",
            json!([{"commitment":"confirmed", "minContextSlot":context.context_slot}]),
        )?
        .as_u64()
        .ok_or_else(|| "invalid block height".into())
    }

    pub fn fee_for_message(&self, message: &VersionedMessage) -> Result<u64> {
        let wire = wincode::serialize(message)?;
        let result = self.call(
            "getFeeForMessage",
            json!([STANDARD.encode(wire), {"commitment":"confirmed"}]),
        )?;
        fee_from_response(&result)
    }

    pub fn token_accounts(
        &self,
        owner: &Pubkey,
        token_program: &Pubkey,
    ) -> Result<Vec<TokenAccount>> {
        let result = self.call(
            "getTokenAccountsByOwner",
            json!([
                owner.to_string(), {"programId":token_program.to_string()},
                {"encoding":"jsonParsed", "commitment":"confirmed"}
            ]),
        )?;
        parse_token_accounts(&result, token_program)
    }

    pub fn signatures(&self, address: &Pubkey, limit: usize) -> Result<Vec<Value>> {
        let result = self.call(
            "getSignaturesForAddress",
            json!([
                address.to_string(), {"limit":limit, "commitment":"confirmed"}
            ]),
        )?;
        let list = result
            .as_array()
            .ok_or("invalid signature history response")?;
        if list.len() > limit {
            return fail("RPC returned too many signatures");
        }
        Ok(list.clone())
    }

    pub fn simulate(&self, wire: &[u8]) -> Result<Value> {
        self.simulate_at(wire, 0)
    }
    pub fn simulate_at(&self, wire: &[u8], min_context_slot: u64) -> Result<Value> {
        let result = self.call("simulateTransaction", json!([
            STANDARD.encode(wire), {"encoding":"base64", "sigVerify":false, "commitment":"confirmed", "minContextSlot": min_context_slot}
        ]))?;
        let value = result.get("value").ok_or("invalid simulation response")?;
        if value.get("err").is_none() {
            return fail("simulation result is missing err field");
        }
        Ok(value.clone())
    }

    pub fn submit_and_confirm(
        &self,
        wire: &[u8],
        signature: solana_transaction::Signature,
    ) -> SubmissionOutcome {
        let expected = signature.to_string();
        let result = (|| -> Result<bool> {
            if self.send(wire)? != expected {
                return fail("RPC returned a different transaction signature");
            }
            self.confirm(&expected)
        })();
        match result {
            Ok(true) => SubmissionOutcome::Confirmed(signature),
            Ok(false) => SubmissionOutcome::Unknown {
                signature,
                reason: "confirmation deadline or poll budget reached".into(),
            },
            Err(error) => SubmissionOutcome::Unknown {
                signature,
                reason: safe_text(&error.to_string(), 500),
            },
        }
    }

    pub fn send(&self, wire: &[u8]) -> Result<String> {
        let result = self.call("sendTransaction", json!([
            STANDARD.encode(wire), {"encoding":"base64", "skipPreflight":false, "preflightCommitment":"confirmed", "maxRetries":0}
        ]))?;
        let signature = result.as_str().ok_or("invalid sendTransaction response")?;
        if signature.len() > 100 {
            return fail("invalid transaction signature");
        }
        Ok(signature.into())
    }

    pub fn confirm(&self, signature: &str) -> Result<bool> {
        let deadline = Instant::now() + Duration::from_secs(60);
        for _ in 0..20 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let result = self.call_with_timeout(
                "getSignatureStatuses",
                json!([[signature], {"searchTransactionHistory":false}]),
                self.timeout.min(remaining),
            )?;
            let status = result
                .pointer("/value/0")
                .ok_or("invalid signature status response")?;
            if status.is_object() {
                if !status.get("err").is_some_and(Value::is_null) {
                    return Err(format!(
                        "transaction failed: {}",
                        safe_text(&status["err"].to_string(), 300)
                    )
                    .into());
                }
                if matches!(
                    status.get("confirmationStatus").and_then(Value::as_str),
                    Some("confirmed" | "finalized")
                ) {
                    return Ok(true);
                }
            }
            thread::sleep(
                Duration::from_secs(2).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        Ok(false)
    }
}

fn fee_from_response(result: &Value) -> Result<u64> {
    result
        .get("value")
        .and_then(Value::as_u64)
        .ok_or_else(|| "RPC fee unavailable for transaction message".into())
}

fn parse_token_accounts(result: &Value, token_program: &Pubkey) -> Result<Vec<TokenAccount>> {
    let array = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or("invalid token account response")?;
    if array.len() > 512 {
        return fail("too many token accounts in RPC response");
    }
    let mut accounts = Vec::with_capacity(array.len());
    let expected_owner = token_program.to_string();
    for item in array {
        let address = item
            .get("pubkey")
            .and_then(Value::as_str)
            .ok_or("invalid token account address")?;
        if item.pointer("/account/owner").and_then(Value::as_str) != Some(expected_owner.as_str()) {
            return fail("token account has unexpected owner program");
        }
        let info = item
            .pointer("/account/data/parsed/info")
            .ok_or("invalid parsed token account")?;
        let mint = info
            .get("mint")
            .and_then(Value::as_str)
            .ok_or("invalid token mint")?;
        let raw_amount = info
            .pointer("/tokenAmount/amount")
            .and_then(Value::as_str)
            .ok_or("invalid raw token amount")?
            .parse()?;
        let decimals = info
            .pointer("/tokenAmount/decimals")
            .and_then(Value::as_u64)
            .ok_or("invalid token decimals")?;
        accounts.push(TokenAccount {
            address: Pubkey::from_str(address)?,
            mint: Pubkey::from_str(mint)?,
            raw_amount,
            decimals: u8::try_from(decimals)?,
        });
    }
    Ok(accounts)
}

pub fn safe_text(input: &str, max: usize) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(max)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatched_genesis_is_rejected_and_correct_genesis_passes() {
        let (rpc, server) = crate::test_support::mock_rpc(vec![json!("wrong")]);
        assert!(rpc.verify_cluster().is_err());
        assert_eq!(server.join().unwrap()[0]["method"], "getGenesisHash");
        let (rpc, server) = crate::test_support::mock_rpc(vec![json!(
            expected_genesis(&Config::default()).unwrap()
        )]);
        rpc.verify_cluster().unwrap();
        server.join().unwrap();
    }

    #[test]
    fn mismatched_and_malformed_send_responses_keep_the_local_signature() {
        let signature = solana_transaction::Signature::from([7; 64]);
        for response in [json!("different"), json!(42)] {
            let (rpc, server) = crate::test_support::mock_rpc(vec![response]);
            let SubmissionOutcome::Unknown {
                signature: actual, ..
            } = rpc.submit_and_confirm(&[0; 5], signature)
            else {
                panic!("expected unknown outcome")
            };
            assert_eq!(actual, signature);
            let requests = server.join().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0]["method"], "sendTransaction");
        }
    }

    #[test]
    fn successful_submission_confirms_only_the_local_signature() {
        let signature = solana_transaction::Signature::from([7; 64]);
        let (rpc, server) = crate::test_support::mock_rpc(vec![
            json!(signature.to_string()),
            json!({"value":[{"err":null,"confirmationStatus":"confirmed"}]}),
        ]);
        assert!(
            matches!(rpc.submit_and_confirm(&[0; 5], signature), SubmissionOutcome::Confirmed(actual) if actual == signature)
        );
        let requests = server.join().unwrap();
        assert_eq!(requests[1]["params"][0][0], signature.to_string());
    }

    #[test]
    fn confirmation_error_still_retains_signature() {
        let signature = solana_transaction::Signature::from([7; 64]);
        let (rpc, server) = crate::test_support::mock_rpc(vec![
            json!(signature.to_string()),
            json!({"value":[{"err":{"InstructionError":[0,"error"]}}]}),
        ]);
        assert!(
            matches!(rpc.submit_and_confirm(&[0; 5], signature), SubmissionOutcome::Unknown { signature: actual, .. } if actual == signature)
        );
        assert_eq!(server.join().unwrap().len(), 2);
    }

    #[test]
    fn rpc_rejects_redirects_without_contacting_the_target() {
        use std::{io::Write, net::TcpListener};
        for status in [301, 302, 307, 308, 500] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let target = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut config = Config::default();
            config.rpc.url = Some(format!("http://{}", listener.local_addr().unwrap()));
            config.rpc.timeout_secs = 2;
            let location = format!("http://{}", target.local_addr().unwrap());
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buffer = [0; 4096];
                assert!(stream.read(&mut buffer).unwrap() > 0);
                write!(stream, "HTTP/1.1 {status} Test\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            });
            let error = Rpc::new(&config)
                .unwrap()
                .call("test", json!([]))
                .unwrap_err();
            server.join().unwrap();
            assert!(
                error.to_string().contains(&format!("HTTP {status}")),
                "{error}"
            );
            target.set_nonblocking(true).unwrap();
            assert_eq!(
                target.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn parsed_token_balance_uses_raw_amount_and_checks_program() {
        let program = Pubkey::new_from_array([3; 32]);
        let mint = Pubkey::new_from_array([4; 32]);
        let address = Pubkey::new_from_array([5; 32]);
        let mut response = json!({"value": [{
            "pubkey": address.to_string(),
            "account": {
                "owner": program.to_string(),
                "data": {"parsed": {"info": {
                    "mint": mint.to_string(),
                    "tokenAmount": {"amount": "0", "decimals": 2, "uiAmountString": "0.00"}
                }}}
            }
        }]});
        let accounts = parse_token_accounts(&response, &program).unwrap();
        assert_eq!(accounts[0].raw_amount, 0);
        assert_eq!(accounts[0].decimals, 2);
        response["value"][0]["account"]["owner"] = Value::String(mint.to_string());
        assert!(parse_token_accounts(&response, &program).is_err());
    }

    #[test]
    fn fee_response_requires_a_usable_quote() {
        assert_eq!(fee_from_response(&json!({"value": 5_000})).unwrap(), 5_000);
        assert!(fee_from_response(&json!({"value": null})).is_err());
        assert!(fee_from_response(&json!({"value": "5000"})).is_err());
    }
}
