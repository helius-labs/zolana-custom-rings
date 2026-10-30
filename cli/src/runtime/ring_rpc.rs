use anyhow::{bail, ensure, Context as _, Result};
use custom_ring_sdk::{CustomRing, InitializeStorage};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use solana_address::Address;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_indexer_api::{Base64String, Hash};
use spr_keypair::X25519Pubkey;
use zolana_ring_client::{
    auditor_view_tag,
    rpc::{
        AuditorKeyStatement, CreateAuditorKeyRequest, CreateAuditorKeyResponse,
        CreateRecordsRegistryRequest, CreateRecordsRegistryResponse, DecryptedTransaction,
        DecryptedTransactionsPage, GetDecryptedTransactionsRequest,
        GetDecryptedTransactionsResponse, GetPendingEnrolmentsRequest,
        GetPendingEnrolmentsResponse, GetRecordUpdateStatusRequest, HealthResponse,
        PendingEnrolment, ReadTarget, RecordUpdateStatus, RingState, RingStatusRequest,
        RingStatusResponse, SubmitRecordUpdateRequest, SubmitRecordUpdateResponse,
        CREATE_AUDITOR_KEY, CREATE_RECORDS_REGISTRY, GET_DECRYPTED_TRANSACTIONS,
        GET_PENDING_ENROLMENTS, GET_RECORD_UPDATE_STATUS, HEALTH, RING_STATUS,
        SUBMIT_RECORD_UPDATE,
    },
};

use crate::{config::redact_url, line, probe, wait_for, Context, Probe};

/// More pages than a ring rpc returns for one transaction search.
const MAX_PAGES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Pinned(Address),
    Unpinned,
    Refuse,
}

pub struct AttestedAuditorKey {
    pub auditor_pk: X25519Pubkey,
    pub service_pubkey: Address,
}

pub struct RingRpcClient {
    url: String,
    http: reqwest::blocking::Client,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

/// Answers before the ring has a config, so a pipeline stops before `init` pins an
/// auditor the service does not hold.
pub fn run_check(ctx: &Context) -> Result<()> {
    let client = ctx.ring_rpc();
    let held = match client.state(ctx.ring.program_id())? {
        RingState::Served => "serves this ring",
        _ => "holds a key for the ring, `init` pins it",
    };
    line(
        "ring rpc",
        format_args!("{} {held}", redact_url(&client.url)),
    );
    Ok(())
}

impl AttestedAuditorKey {
    pub fn require(self, trust: Trust) -> Result<X25519Pubkey> {
        let actual = self.service_pubkey;
        match trust {
            Trust::Pinned(pinned) => ensure!(
                pinned == actual,
                "the ring rpc signs with {actual} but ring.toml pins {pinned}"
            ),
            Trust::Unpinned => {}
            Trust::Refuse => bail!(
                "ring.toml pins no ring rpc service key, the rpc signs with {actual}. Put it in ring_rpc_pubkey after confirming it out of band, or pass --trust-ring-rpc for a local instance"
            ),
        }
        Ok(self.auditor_pk)
    }
}

impl RingRpcClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            http: probe::http(probe::CONNECT_TIMEOUT, probe::TOTAL_TIMEOUT),
        }
    }

    /// Verified against the service key the response names, the caller decides whether to trust it.
    pub fn release_auditor_key(
        &self,
        ring: Address,
        genesis_hash: [u8; 32],
        authority: &dyn Signer,
    ) -> Result<AttestedAuditorKey> {
        let request = CreateAuditorKeyRequest::for_ring(ring, genesis_hash).sign(authority)?;
        let nonce: [u8; 32] = request
            .auth
            .nonce
            .0
            .as_slice()
            .try_into()
            .context("the signed request carries no 32-byte nonce")?;
        let created: CreateAuditorKeyResponse = self.call(CREATE_AUDITOR_KEY, request)?;
        let service_pubkey = created.service_pubkey.0;
        let auditor_pk = *created.auditor_pubkey.as_key();
        let statement = AuditorKeyStatement {
            cluster: &genesis_hash,
            ring: &ring,
            auditor_pubkey: &auditor_pk,
            nonce: &nonce,
        };
        let url = redact_url(&self.url);
        ensure!(
            created.signature.0.verify(service_pubkey.as_ref(), &statement.message()),
            "the ring rpc at {url} returned an auditor key its service key {service_pubkey} did not sign"
        );
        Ok(AttestedAuditorKey {
            auditor_pk,
            service_pubkey,
        })
    }

    /// The ring's records PDA under the storage authority the service names, created on first call.
    pub fn create_records_registry(
        &self,
        target: ReadTarget,
        authority: &dyn Signer,
    ) -> Result<Address> {
        let ring = target.ring;
        let request =
            CreateRecordsRegistryRequest::create(target, authority.pubkey()).sign(authority)?;
        let created: CreateRecordsRegistryResponse = self.call(CREATE_RECORDS_REGISTRY, request)?;
        let records = created.registry.0;
        let storage_authority = created.storage_authority.0;
        let expected =
            InitializeStorage::records(CustomRing::new(ring), storage_authority).registry();
        ensure!(
            records == expected,
            "the ring rpc at {} named registry {} that is not the ring records under storage authority {}",
            redact_url(&self.url),
            records,
            storage_authority
        );
        Ok(records)
    }

    /// Unsigned, `release_auditor_key` is the attested path `init` pins from.
    pub fn ring_status(&self, ring: Address) -> Result<RingStatusResponse> {
        let ring_program_id = ring.to_bytes().into();
        self.call(RING_STATUS, RingStatusRequest { ring_program_id })
    }

    /// The key a signed read binds.
    pub fn service_pubkey(&self) -> Result<Address> {
        let health: HealthResponse = self.call(HEALTH, json!([]))?;
        Ok(health.service_pubkey.0)
    }

    pub fn check_serves(&self, ring: Address) -> Result<()> {
        ensure!(
            self.state(ring)? == RingState::Served,
            "the ring has no config yet, run `zolana-ring init` before `transact`"
        );
        Ok(())
    }

    /// A failed read is retried, a transaction the service skipped is final.
    pub fn wait_for_decrypted(
        &self,
        target: ReadTarget,
        reader: &dyn Signer,
        signature: Signature,
        event_index: u16,
    ) -> Result<DecryptedTransaction> {
        wait_for("ring rpc to open the transaction", || {
            find_decrypted(signature, event_index, |cursor| {
                let mut request = GetDecryptedTransactionsRequest::read(target);
                if let Some(cursor) = cursor {
                    request = request.with_cursor(cursor)?;
                }
                let request = request.sign(reader)?;
                let page: GetDecryptedTransactionsResponse =
                    self.call(GET_DECRYPTED_TRANSACTIONS, request)?;
                Ok(page.value)
            })
        })
    }

    /// Blocks until the writer applies the update, a refusal fails.
    pub fn apply_record_update(&self, request: SubmitRecordUpdateRequest) -> Result<u64> {
        let update_id = request.verify()?;
        let submitted: SubmitRecordUpdateResponse = self.call(SUBMIT_RECORD_UPDATE, request)?;
        ensure!(
            submitted.update_id == update_id,
            "the ring rpc at {} answered another update id",
            redact_url(&self.url)
        );
        wait_for("ring rpc to apply the record update", || {
            let status: RecordUpdateStatus = self.call(
                GET_RECORD_UPDATE_STATUS,
                GetRecordUpdateStatusRequest {
                    update_id: update_id.clone(),
                },
            )?;
            match status {
                RecordUpdateStatus::Applied { revision, .. } => Ok(Probe::Ready(revision)),
                RecordUpdateStatus::Refused { reason } => {
                    bail!("the writer refused the record update, {reason}")
                }
                RecordUpdateStatus::AwaitingAuthority
                | RecordUpdateStatus::Queued
                | RecordUpdateStatus::Submitted { .. } => Ok(Probe::NotYet),
            }
        })
    }

    /// Every page signed by the config authority, oldest first.
    pub fn pending_enrolments(
        &self,
        target: ReadTarget,
        authority: &dyn Signer,
    ) -> Result<Vec<PendingEnrolment>> {
        let mut enrolments = Vec::new();
        let mut cursor = None;
        for _ in 0..MAX_PAGES {
            let read = GetPendingEnrolmentsRequest::read(target, authority.pubkey());
            let read = match cursor.clone() {
                Some(cursor) => read.with_cursor(cursor),
                None => read,
            };
            let page: GetPendingEnrolmentsResponse =
                self.call(GET_PENDING_ENROLMENTS, read.sign(authority)?)?;
            let Some(next) = page.next_cursor else {
                enrolments.extend(page.enrolments);
                return Ok(enrolments);
            };
            ensure!(
                page.enrolments.last().map(|row| &row.update_id) == Some(&next),
                "the ring rpc named a cursor outside its page"
            );
            enrolments.extend(page.enrolments);
            cursor = Some(next);
        }
        bail!("the ring rpc returned more than {MAX_PAGES} pending enrolment pages")
    }

    /// A service that holds another key for this ring can open nothing here.
    fn state(&self, ring: Address) -> Result<RingState> {
        let status = self.ring_status(ring)?;
        let expected_tag = status
            .config_auditor_pubkey
            .map(|key| Hash(auditor_view_tag(key.as_key())))
            .unwrap_or_default();
        let url = redact_url(&self.url);
        ensure!(status.state != RingState::ForeignAuditor, "the ring rpc at {url} holds another auditor key for this ring than the one its config names ({expected_tag}). A config fixes its auditor when it is created, so this service can never open the ring. Serve the ring from a ring rpc holding its key, or deploy a new ring");
        Ok(status.state)
    }

    fn call<T: DeserializeOwned>(&self, method: &str, params: impl Serialize) -> Result<T> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response: JsonRpcResponse<T> = self
            .http
            .post(probe::service_url(&self.url, method))
            .json(&body)
            .send()
            .map_err(reqwest::Error::without_url)
            .with_context(|| format!("no ring rpc answers at {}", redact_url(&self.url)))?
            .error_for_status()
            .map_err(reqwest::Error::without_url)?
            .json()
            .map_err(reqwest::Error::without_url)?;
        if let Some(error) = response.error {
            bail!("ring rpc {method} failed, {error}");
        }
        response
            .result
            .with_context(|| format!("ring rpc {method} returned no result"))
    }
}

fn find_decrypted(
    signature: Signature,
    event_index: u16,
    mut page: impl FnMut(Option<Base64String>) -> Result<DecryptedTransactionsPage>,
) -> Result<Probe<DecryptedTransaction>> {
    let mut cursor = None;
    for _ in 0..MAX_PAGES {
        let read = match page(cursor.clone()) {
            Ok(read) => read,
            Err(error) => return Ok(Probe::Retry(error)),
        };
        if let Some(item) = read
            .items
            .into_iter()
            .find(|item| item.tx_signature.0 == signature && item.event_index == event_index)
        {
            return Ok(Probe::Ready(item));
        }
        for skipped in read.skipped {
            let reason = skipped.reason;
            ensure!(
                skipped.tx_signature.0 != signature || skipped.event_index != event_index,
                "ring rpc could not open {signature} event {event_index}, {reason:?}"
            );
        }
        let Some(next) = read.cursor else {
            return Ok(Probe::NotYet);
        };
        ensure!(
            cursor.as_ref() != Some(&next),
            "the ring rpc repeated its cursor"
        );
        cursor = Some(next);
    }
    bail!("the ring rpc returned more than {MAX_PAGES} pages")
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    use spr_keypair::X25519Keypair;
    use zolana_ring_client::rpc::{SkippedReason, SkippedTransaction};

    use super::*;

    const SERVICE: Address = Address::new_from_array([7u8; 32]);

    fn gateway(status: u16) -> (String, thread::JoinHandle<(String, serde_json::Value)>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let url = format!(
            "http://{}/v1/zolana/ring/?api-key=secret&tenant=a%20b",
            listener.local_addr().expect("address")
        );
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let mut reader = BufReader::new(&stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).expect("request line");
            let mut content_length = None;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("header");
                if line == "\r\n" {
                    break;
                }
                assert!(!line.is_empty(), "incomplete request");
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = Some(value.trim().parse::<usize>().expect("length"));
                    }
                }
            }
            let mut body = vec![0; content_length.expect("content length")];
            reader.read_exact(&mut body).expect("request body");
            let body = serde_json::from_slice(&body).expect("JSON request");
            let response = r#"{"jsonrpc":"2.0","id":1,"result":true}"#;
            write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).expect("response");
            (request_line, body)
        });
        (url, handle)
    }

    #[test]
    fn gateway_calls_keep_the_method_path_and_query() {
        for method in [CREATE_AUDITOR_KEY, RING_STATUS, GET_DECRYPTED_TRANSACTIONS] {
            let (url, server) = gateway(200);
            let result: bool = RingRpcClient::new(&url)
                .call(method, json!({}))
                .expect("call");
            let (line, body) = server.join().expect("server");
            assert!(result);
            assert_eq!(
                line,
                format!("POST /v1/zolana/ring/{method}?api-key=secret&tenant=a%20b HTTP/1.1\r\n")
            );
            assert_eq!(body["method"], method);
        }
    }

    #[test]
    fn gateway_http_failures_do_not_expose_the_key() {
        let (url, server) = gateway(401);
        let error = RingRpcClient::new(&url)
            .call::<bool>(RING_STATUS, json!({}))
            .expect_err("unauthorized");
        server.join().expect("server");
        assert!(!error.to_string().contains("secret"));
        assert!(!format!("{error:?}").contains("secret"));
    }

    #[test]
    fn gateway_connection_failures_do_not_expose_the_key() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let url = format!(
            "http://{}/v1/zolana/ring?api-key=secret",
            listener.local_addr().expect("address")
        );
        drop(listener);
        let error = RingRpcClient::new(&url)
            .call::<bool>(RING_STATUS, json!({}))
            .expect_err("unreachable");
        assert!(!error.to_string().contains("secret"));
        assert!(!format!("{error:?}").contains("secret"));
    }

    fn attested(auditor_pk: X25519Pubkey) -> AttestedAuditorKey {
        AttestedAuditorKey {
            auditor_pk,
            service_pubkey: SERVICE,
        }
    }

    #[test]
    fn trust_accepts_the_pinned_key_or_an_explicit_waiver() {
        let auditor_pk = X25519Keypair::new().pubkey();
        let required = |trust| attested(auditor_pk).require(trust);
        assert_eq!(
            required(Trust::Pinned(SERVICE)).expect("pinned"),
            auditor_pk
        );
        assert_eq!(required(Trust::Unpinned).expect("unpinned"), auditor_pk);
        let mismatch = required(Trust::Pinned(Address::new_from_array([8u8; 32])));
        assert!(mismatch
            .expect_err("other")
            .to_string()
            .contains("but ring.toml pins"));
        let refused = required(Trust::Refuse).expect_err("refused").to_string();
        assert!(refused.contains("--trust-ring-rpc"), "{refused}");
    }

    fn page(cursor: Option<u8>, items: Vec<DecryptedTransaction>) -> DecryptedTransactionsPage {
        DecryptedTransactionsPage {
            items,
            skipped: Vec::new(),
            cursor: cursor.map(|cursor| vec![cursor].into()),
        }
    }

    fn opened(signature: Signature) -> DecryptedTransaction {
        DecryptedTransaction {
            slot: 1,
            tx_signature: signature.into(),
            event_index: 0,
            tx_viewing_pk: Vec::new().into(),
            outputs: Vec::new(),
            payload_errors: Vec::new(),
            sender: None,
            inputs: Vec::new(),
            nullifiers: Vec::new(),
            spenders: Vec::new(),
            signers: Vec::new(),
            withdrawals: Vec::new(),
        }
    }

    #[test]
    fn the_page_walk_follows_cursors_to_the_transaction() {
        let wanted = Signature::from([3; 64]);
        let pages = Cell::new(0u8);
        let found = find_decrypted(wanted, 0, |cursor| {
            let index = pages.get();
            pages.set(index + 1);
            assert_eq!(cursor, (index > 0).then(|| vec![index].into()));
            Ok(match index {
                0 => page(Some(1), vec![opened(Signature::default())]),
                _ => page(None, vec![opened(wanted)]),
            })
        })
        .expect("walk");
        assert!(matches!(found, Probe::Ready(item) if item.tx_signature.0 == wanted));
        let absent = find_decrypted(wanted, 0, |_| Ok(page(None, Vec::new()))).expect("walk");
        assert!(matches!(absent, Probe::NotYet));
    }

    #[test]
    fn the_page_walk_matches_the_event_within_a_signature() {
        let wanted = Signature::from([3; 64]);
        let mut other = opened(wanted);
        other.event_index = 1;
        let mut pages = 0;
        let found = find_decrypted(wanted, 0, |_| {
            pages += 1;
            Ok(if pages == 1 {
                DecryptedTransactionsPage {
                    skipped: vec![SkippedTransaction {
                        slot: 1,
                        tx_signature: wanted.into(),
                        event_index: 1,
                        reason: SkippedReason::InvalidAuditData,
                    }],
                    ..page(Some(1), vec![other.clone()])
                }
            } else {
                page(None, vec![opened(wanted)])
            })
        })
        .expect("walk");
        assert!(matches!(found, Probe::Ready(item) if item.event_index == 0));
        assert_eq!(pages, 2);
    }

    #[test]
    fn a_repeated_cursor_or_an_endless_walk_is_refused() {
        let wanted = Signature::from([3; 64]);
        let repeated = find_decrypted(wanted, 0, |_| Ok(page(Some(9), Vec::new())));
        let error = repeated.err().expect("repeated cursor").to_string();
        assert_eq!(error, "the ring rpc repeated its cursor");
        let next = Cell::new(0u8);
        let endless = find_decrypted(wanted, 0, |_| {
            next.set(next.get().wrapping_add(1));
            Ok(page(Some(next.get()), Vec::new()))
        });
        let error = endless.err().expect("endless walk").to_string();
        assert!(error.contains("more than 64 pages"), "{error}");
        assert_eq!(usize::from(next.get()), MAX_PAGES);
    }

    #[test]
    fn a_skipped_transaction_is_final_and_a_failed_page_is_retried() {
        let wanted = Signature::from([3; 64]);
        let skipped = find_decrypted(wanted, 0, |_| {
            Ok(DecryptedTransactionsPage {
                skipped: vec![SkippedTransaction {
                    slot: 1,
                    tx_signature: wanted.into(),
                    event_index: 0,
                    reason: SkippedReason::InvalidAuditData,
                }],
                ..page(None, Vec::new())
            })
        });
        assert!(skipped
            .err()
            .expect("skipped")
            .to_string()
            .contains("could not open"));
        let failed = find_decrypted(wanted, 0, |_| bail!("down")).expect("retry");
        assert!(matches!(failed, Probe::Retry(error) if error.to_string() == "down"));
    }
}
