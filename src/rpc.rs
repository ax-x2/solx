use crate::{Result, config::Config, fail};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use solana_message::{Hash, VersionedMessage};
use solana_pubkey::Pubkey;
use std::{io::Read, str::FromStr, thread, time::Duration};

const MAX_BODY: u64 = 2 * 1024 * 1024;

pub struct Rpc {
    client: Client,
    url: String,
    pub cluster: String,
    pub endpoint: String,
}

pub struct TokenAccount {
    pub address: Pubkey,
    pub mint: Pubkey,
    pub raw_amount: u64,
    pub decimals: u8,
    pub display_amount: String,
}

impl Rpc {
    pub fn new(config: &Config) -> Result<Self> {
        let url = config
            .rpc
            .url
            .as_ref()
            .ok_or("RPC is not configured in config.toml")?;
        let endpoint = reqwest::Url::parse(url)?
            .host_str()
            .ok_or("RPC URL has no host")?
            .to_owned();
        let client = Client::builder().timeout(config.rpc_timeout()).build()?;
        Ok(Self {
            client,
            url: url.clone(),
            cluster: config.rpc.cluster.clone(),
            endpoint,
        })
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let request = json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params});
        let mut response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()?
            .error_for_status()?;
        let mut body = Vec::new();
        response
            .by_ref()
            .take(MAX_BODY + 1)
            .read_to_end(&mut body)?;
        if body.len() as u64 > MAX_BODY {
            return fail("RPC response exceeds 2 MiB");
        }
        let parsed: Value = serde_json::from_slice(&body)?;
        if let Some(error) = parsed.get("error") {
            return Err(format!("RPC {method}: {}", safe_text(&error.to_string(), 500)).into());
        }
        parsed
            .get("result")
            .cloned()
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

    pub fn latest_blockhash(&self) -> Result<Hash> {
        let result = self.call("getLatestBlockhash", json!([{"commitment":"confirmed"}]))?;
        let hash = result
            .pointer("/value/blockhash")
            .and_then(Value::as_str)
            .ok_or("invalid getLatestBlockhash response")?;
        Ok(Hash::from_str(hash)?)
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
        let result = self.call("simulateTransaction", json!([
            STANDARD.encode(wire), {"encoding":"base64", "sigVerify":false, "commitment":"confirmed"}
        ]))?;
        let value = result.get("value").ok_or("invalid simulation response")?;
        if value.get("err").is_none() {
            return fail("simulation result is missing err field");
        }
        Ok(value.clone())
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
        for _ in 0..20 {
            let result = self.call(
                "getSignatureStatuses",
                json!([[signature], {"searchTransactionHistory":false}]),
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
            thread::sleep(Duration::from_secs(2));
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
        let display_amount = info
            .pointer("/tokenAmount/uiAmountString")
            .and_then(Value::as_str)
            .or_else(|| info.pointer("/tokenAmount/amount").and_then(Value::as_str))
            .ok_or("invalid token amount")?;
        accounts.push(TokenAccount {
            address: Pubkey::from_str(address)?,
            mint: Pubkey::from_str(mint)?,
            raw_amount,
            decimals: u8::try_from(decimals)?,
            display_amount: display_amount.into(),
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
        assert_eq!(accounts[0].display_amount, "0.00");
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
