use std::{ops::RangeInclusive, time::Duration};

use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use solana_account::Account;
use solana_account_decoder_client_types::UiAccount;
use solana_address::Address;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client_api::{
    client_error::{reqwest, Error as ClientError, ErrorKind},
    request::{RpcError as RequestError, RpcRequest},
    response::Response,
};
use solana_transaction_status_client_types::{TransactionDetails, UiConfirmedBlock};
use thiserror::Error;

const TIMEOUT: Duration = Duration::from_secs(90);
/// Both codes name a slot without a block, in recent and in long term storage.
const SLOT_SKIPPED: i64 = -32007;
const LONG_TERM_STORAGE_SLOT_SKIPPED: i64 = -32009;

pub struct SolanaRpc {
    client: RpcClient,
    block_headers: BlockHeaders,
}

#[derive(Clone, Copy, Debug, Default)]
pub enum BlockHeaders {
    #[default]
    Chain,
    /// Surfpool's synthetic parent link is replaced by the fetched parent's hash.
    #[cfg(feature = "surfpool-fixture")]
    SurfpoolFixture,
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("RPC transport failed")]
    Transport(#[source] reqwest::Error),
    #[error("RPC request failed ({0})")]
    Request(String),
    #[error("RPC answered code {code} ({message})")]
    Response { code: i64, message: String },
    #[error("invalid account ({0})")]
    InvalidAccount(String),
    #[cfg(feature = "surfpool-fixture")]
    #[error("only Surfpool synthetic block headers are supported")]
    ForeignBlockHeader,
}

impl RpcError {
    pub fn is_slot_skipped(&self) -> bool {
        matches!(
            self,
            Self::Response {
                code: SLOT_SKIPPED | LONG_TERM_STORAGE_SLOT_SKIPPED,
                ..
            }
        )
    }
}

impl From<ClientError> for RpcError {
    fn from(error: ClientError) -> Self {
        match *error.kind {
            ErrorKind::RpcError(RequestError::RpcResponseError { code, message, .. }) => {
                Self::Response { code, message }
            }
            // The URL can carry an API key.
            ErrorKind::Reqwest(error) => Self::Transport(error.without_url()),
            kind => Self::Request(kind.to_string()),
        }
    }
}

impl SolanaRpc {
    pub fn new(url: String) -> Self {
        Self {
            client: RpcClient::new_with_timeout(url, TIMEOUT),
            block_headers: BlockHeaders::Chain,
        }
    }

    #[must_use]
    pub fn with_block_headers(mut self, block_headers: BlockHeaders) -> Self {
        self.block_headers = block_headers;
        self
    }

    pub async fn get_slot(&self) -> Result<u64, RpcError> {
        self.call(RpcRequest::GetSlot, json!([{ "commitment": "confirmed" }]))
            .await
    }

    pub async fn get_blocks(&self, slots: RangeInclusive<u64>) -> Result<Vec<u64>, RpcError> {
        self.call(
            RpcRequest::GetBlocks,
            json!([slots.start(), slots.end(), { "commitment": "confirmed" }]),
        )
        .await
    }

    pub async fn get_block(
        &self,
        slot: u64,
        transaction_details: TransactionDetails,
    ) -> Result<UiConfirmedBlock, RpcError> {
        let block: UiConfirmedBlock = self
            .call(
                RpcRequest::GetBlock,
                block_params(slot, transaction_details),
            )
            .await?;
        match self.block_headers {
            BlockHeaders::Chain => Ok(block),
            #[cfg(feature = "surfpool-fixture")]
            BlockHeaders::SurfpoolFixture => {
                let parent: UiConfirmedBlock = self
                    .call(
                        RpcRequest::GetBlock,
                        block_params(block.parent_slot, TransactionDetails::None),
                    )
                    .await?;
                normalize_fixture_header(block, &parent)
            }
        }
    }

    /// The node refuses to answer from a bank older than `min_context_slot`.
    pub async fn get_multiple_accounts_from_slot(
        &self,
        addresses: &[Address],
        min_context_slot: u64,
    ) -> Result<Vec<Option<Account>>, RpcError> {
        let mut config = account_config();
        config["minContextSlot"] = min_context_slot.into();
        self.multiple_accounts(addresses, config).await
    }

    async fn multiple_accounts(
        &self,
        addresses: &[Address],
        config: Value,
    ) -> Result<Vec<Option<Account>>, RpcError> {
        let addresses = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let response: Response<Vec<Option<UiAccount>>> = self
            .call(RpcRequest::GetMultipleAccounts, json!([addresses, config]))
            .await?;
        response
            .value
            .into_iter()
            .map(|account| account.map(decode_account).transpose())
            .collect()
    }

    async fn call<T: DeserializeOwned>(
        &self,
        request: RpcRequest,
        params: Value,
    ) -> Result<T, RpcError> {
        Ok(self.client.send(request, params).await?)
    }
}

fn decode_account(account: UiAccount) -> Result<Account, RpcError> {
    account
        .to_account()
        .ok_or_else(|| RpcError::InvalidAccount("account data is not base64".into()))
}

fn account_config() -> Value {
    json!({ "commitment": "confirmed", "encoding": "base64" })
}

fn block_params(slot: u64, transaction_details: TransactionDetails) -> Value {
    json!([slot, {
        "commitment": "confirmed",
        "encoding": "base64",
        // A block holding a newer version is refused whole, not skipped.
        "maxSupportedTransactionVersion": 1,
        "rewards": false,
        "transactionDetails": transaction_details,
    }])
}

#[cfg(feature = "surfpool-fixture")]
fn normalize_fixture_header(
    mut block: UiConfirmedBlock,
    parent: &UiConfirmedBlock,
) -> Result<UiConfirmedBlock, RpcError> {
    if [
        &block.blockhash,
        &block.previous_blockhash,
        &parent.blockhash,
    ]
    .into_iter()
    .any(|hash| !hash.starts_with("SURFNETxSAFEHASH"))
    {
        return Err(RpcError::ForeignBlockHeader);
    }
    block.previous_blockhash = parent.blockhash.clone();
    Ok(block)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    use super::*;

    fn serve_once(status: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).unwrap();
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{address}")
    }

    #[cfg(feature = "surfpool-fixture")]
    fn surfpool_block(hash: &str, parent_slot: u64) -> UiConfirmedBlock {
        serde_json::from_value(json!({
            "blockhash": hash,
            "previousBlockhash": "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "parentSlot": parent_slot,
            "blockTime": 1,
            "blockHeight": parent_slot + 1,
        }))
        .unwrap()
    }

    #[cfg(feature = "surfpool-fixture")]
    #[test]
    fn fixture_only_normalizes_surfpool_parent_links() {
        let block = surfpool_block("SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxxxxxx28", 39);
        let mut parent = surfpool_block("SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxxxxxxxx27", 38);
        let normalized = normalize_fixture_header(block.clone(), &parent).unwrap();
        assert_eq!(normalized.previous_blockhash, parent.blockhash);
        assert_eq!(normalized.blockhash, block.blockhash);
        parent.blockhash = "11111111111111111111111111111111".into();
        assert!(matches!(
            normalize_fixture_header(block, &parent),
            Err(RpcError::ForeignBlockHeader)
        ));
    }

    #[tokio::test]
    async fn skipped_slots_keep_their_response_code() {
        let url = serve_once(
            "200 OK",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32007,"message":"skipped"}}"#,
        );
        let error = SolanaRpc::new(url)
            .get_block(42, TransactionDetails::Full)
            .await
            .unwrap_err();
        assert!(error.is_slot_skipped(), "{error}");
    }

    #[tokio::test]
    async fn transport_errors_do_not_expose_the_rpc_url_query() {
        let url = serve_once("502 Bad Gateway", "not JSON");
        let error = SolanaRpc::new(format!("{url}/?api-key=super-secret"))
            .get_slot()
            .await
            .unwrap_err();
        let message = format!("{:#}", anyhow::Error::from(error));
        assert!(!message.contains("api-key"), "{message}");
        assert!(!message.contains("super-secret"), "{message}");
    }

    #[test]
    fn block_request_matches_solana_rpc_wire_format() {
        assert_eq!(
            block_params(42, TransactionDetails::Full),
            json!([42, {
                "commitment": "confirmed",
                "encoding": "base64",
                "maxSupportedTransactionVersion": 1,
                "rewards": false,
                "transactionDetails": "full",
            }])
        );
    }
}
