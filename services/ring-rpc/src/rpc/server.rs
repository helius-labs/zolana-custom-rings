use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use hyper::{header::CONTENT_TYPE, Method, StatusCode};
use jsonrpsee::{
    core::{BoxError, RegisterMethodError},
    server::{
        middleware::{
            http::{ProxyGetRequestError, ProxyGetRequestLayer},
            rpc::RpcServiceBuilder,
        },
        BatchRequestConfig, HttpBody, HttpRequest, HttpResponse, ServerBuilder, ServerConfig,
        ServerHandle,
    },
    types::ErrorObjectOwned,
    RpcModule,
};
use serde::{de::DeserializeOwned, Serialize};
use spr_rpc_http::MethodPathLayer;
use thiserror::Error;
use tower::Service;
use tower_http::cors::{AllowOrigin, CorsLayer};

use zolana_ring_client::rpc::{
    CreateAuditorKeyRequest, CreateAuditorKeyResponse, GetAuditedUtxosRequest,
    GetDecryptedTransactionsRequest, GetRecordUpdateStatusRequest, GetRelayQuoteRequest,
    GetRelayStatusRequest, HealthResponse, PagedRead, PrepareRelayRequest, RingDepositsRequest,
    RingDepositsResponse, RingState, RingStatusRequest, RingStatusResponse,
    SetMergeSettingsRequest, SetReaderGrantRequest, SubmitRecordUpdateRequest, SubmitRelayRequest,
    CREATE_AUDITOR_KEY, GET_AUDITED_MERGES, GET_AUDITED_UTXOS, GET_DECRYPTED_TRANSACTIONS,
    GET_RECORD_UPDATE_STATUS, GET_RELAY_QUOTE, GET_RELAY_STATUS, HEALTH, PREPARE_RELAY,
    RING_DEPOSITS, RING_STATUS, SET_MERGE_SETTINGS, SET_READER_GRANT, SUBMIT_RECORD_UPDATE,
    SUBMIT_RELAY,
};

use crate::{
    audit::{AuditRead, Page},
    error::RingRpcError,
    hub::{Hub, Lane, ReadinessStatus},
    metering::{Metering, MeteringHeaderLayer},
    origins::{OriginError, Origins},
    relay::Relay,
    upstream::{DepositPage, TransactionSource},
};

const MAX_REQUEST_BODY_SIZE: u32 = 64 * 1024;
const MAX_RESPONSE_BODY_SIZE: u32 = 16 * 1024 * 1024;

/// Only a loopback bind keeps the decrypted audit data behind a TLS proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindPolicy {
    LoopbackOnly,
    InsecurePublic,
}

pub struct ServerOptions {
    pub bind: IpAddr,
    pub bind_policy: BindPolicy,
    pub port: u16,
    pub max_connections: u32,
    pub request_timeout: Duration,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("ring RPC must bind to a loopback address")]
    PublicBind,
    #[error(transparent)]
    Origin(#[from] OriginError),
    #[error("health proxy setup failed")]
    Proxy(#[from] ProxyGetRequestError),
    #[error("RPC listener setup failed")]
    Listener(#[from] std::io::Error),
    #[error("RPC method setup failed")]
    Method(#[from] RegisterMethodError),
}

pub async fn run_server<S: TransactionSource + 'static>(
    hub: Arc<Hub<S>>,
    options: ServerOptions,
) -> Result<ServerHandle, ServerError> {
    if options.bind_policy == BindPolicy::LoopbackOnly && !options.bind.is_loopback() {
        return Err(ServerError::PublicBind);
    }
    let addr = SocketAddr::from((options.bind, options.port));
    let middleware = tower::ServiceBuilder::new()
        .layer(cors(hub.origins())?)
        .layer(tower::timeout::TimeoutLayer::new(options.request_timeout))
        .layer(tower::layer::layer_fn({
            let hub = hub.clone();
            move |inner| ReadyService {
                inner,
                hub: hub.clone(),
            }
        }))
        .layer(MeteringHeaderLayer)
        .layer(ProxyGetRequestLayer::new([("/health", HEALTH)])?)
        .layer(MethodPathLayer {
            max_body_size: MAX_REQUEST_BODY_SIZE as usize,
        });
    let server = ServerBuilder::default()
        .set_config(
            ServerConfig::builder()
                // A WebSocket call runs outside the timeout layer and the CORS check.
                .http_only()
                .max_connections(options.max_connections)
                .max_request_body_size(MAX_REQUEST_BODY_SIZE)
                .max_response_body_size(MAX_RESPONSE_BODY_SIZE)
                .set_batch_request_config(BatchRequestConfig::Disabled)
                .build(),
        )
        .set_http_middleware(middleware)
        .set_rpc_middleware(RpcServiceBuilder::new().layer_fn(Metering))
        .build(addr)
        .await?;
    Ok(server.start(rpc_module(hub)?))
}

fn cors(origins: &Origins) -> Result<CorsLayer, OriginError> {
    if origins.is_empty() {
        return Ok(CorsLayer::new());
    }
    let allow = if origins.allows_any() {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(origins.header_values()?)
    };
    Ok(CorsLayer::new()
        .allow_origin(allow)
        .allow_methods([Method::POST, Method::GET])
        .allow_headers([CONTENT_TYPE]))
}

pub fn rpc_module<S: TransactionSource + 'static>(
    hub: Arc<Hub<S>>,
) -> Result<RpcModule<Arc<Hub<S>>>, RegisterMethodError> {
    let relay = hub.relay().cloned();
    let mut module = RpcModule::new(hub);
    module.register_async_method(HEALTH, |_, hub, _| async move {
        Ok::<_, ErrorObjectOwned>(HealthResponse {
            mode: hub.mode(),
            service_pubkey: hub.service_pubkey().into(),
        })
    })?;
    method(
        &mut module,
        CREATE_AUDITOR_KEY,
        |hub, request: CreateAuditorKeyRequest| async move {
            let _slot = hub.admit(Lane::Authentication)?;
            let service = hub.service(Some(request.ring_program_id.0))?;
            let statement = service.auditor_key_statement(&request.auth).await?;
            let signature = hub.sign_attestation(&statement);
            let (ring, auditor_pubkey) = (service.ring(), service.auditor_pubkey());
            Ok(CreateAuditorKeyResponse {
                ring_program_id: ring.into(),
                auditor_pubkey: auditor_pubkey.into(),
                auditor_view_tag: service.auditor_view_tag().into(),
                service_pubkey: hub.service_pubkey().into(),
                signature: signature.into(),
            })
        },
    )?;
    method(
        &mut module,
        RING_DEPOSITS,
        |hub, request: RingDepositsRequest| async move {
            let (limit, before) = (
                request.page_limit(),
                request.before().map_err(|_| RingRpcError::InvalidPage)?,
            );
            let ring = request.ring_program_id.0;
            hub.validate_ring(ring)?;
            let _scan = hub.admit(Lane::Deposits(limit))?;
            let page = DepositPage {
                ring,
                limit,
                before,
            };
            Ok(RingDepositsResponse::from(hub.ring_deposits(page).await?))
        },
    )?;
    method(
        &mut module,
        RING_STATUS,
        |hub, request: RingStatusRequest| async move {
            hub.admit(Lane::Public)?;
            let service = hub.service(Some(request.ring_program_id.0))?;
            let configured = service.configured_auditor().await?;
            let chain = service.chain_status().await?;
            let state = match configured {
                None => RingState::Uninitialized,
                Some(key) if key == service.auditor_pubkey() => RingState::Served,
                Some(_) => RingState::ForeignAuditor,
            };
            Ok(RingStatusResponse {
                ring_program_id: service.ring().into(),
                state,
                config_auditor_pubkey: configured.map(Into::into),
                service_pubkey: hub.service_pubkey().into(),
                activation: chain.activation,
                registry: chain.registry,
            })
        },
    )?;
    method(
        &mut module,
        GET_DECRYPTED_TRANSACTIONS,
        |hub, request: GetDecryptedTransactionsRequest| async move {
            let authentication = hub.admit(Lane::Authentication)?;
            let service = hub.service(request.ring_program_id.map(|ring| ring.0))?;
            let page = Page::new(request.cursor, request.limit)?;
            let auth = &request.auth;
            let read = service
                .authorize(AuditRead {
                    read: PagedRead::DecryptedTransactions,
                    auth,
                    page: &page,
                    wallet: request.wallet.map(|wallet| wallet.0),
                })
                .await?;
            // Decrypting holds a read slot, the authentication slot is free again.
            drop(authentication);
            let _slot = hub.admit(Lane::Read)?;
            read.execute().await
        },
    )?;
    method(
        &mut module,
        GET_AUDITED_MERGES,
        |hub, request: GetDecryptedTransactionsRequest| async move {
            let authentication = hub.admit(Lane::Authentication)?;
            let service = hub.service(request.ring_program_id.map(|ring| ring.0))?;
            let page = Page::new(request.cursor, request.limit)?;
            let read = service
                .authorize(AuditRead {
                    read: PagedRead::AuditedMerges,
                    auth: &request.auth,
                    page: &page,
                    wallet: request.wallet.map(|wallet| wallet.0),
                })
                .await?;
            drop(authentication);
            let _slot = hub.admit(Lane::Read)?;
            read.execute_merges().await
        },
    )?;
    method(
        &mut module,
        GET_AUDITED_UTXOS,
        |hub, request: GetAuditedUtxosRequest| async move {
            let _authentication = hub.admit(Lane::Authentication)?;
            let service = hub.service(request.ring_program_id.map(|ring| ring.0))?;
            service.audited_utxos(&request).await
        },
    )?;
    method(
        &mut module,
        SUBMIT_RECORD_UPDATE,
        |hub, request: SubmitRecordUpdateRequest| async move {
            let _slot = hub.admit(Lane::Authentication)?;
            hub.record_writer()?.submit(request).await
        },
    )?;
    method(
        &mut module,
        GET_RECORD_UPDATE_STATUS,
        |hub, request: GetRecordUpdateStatusRequest| async move {
            hub.admit(Lane::Public)?;
            hub.record_writer()?.status(request).await
        },
    )?;
    method(
        &mut module,
        SET_READER_GRANT,
        |hub, request: SetReaderGrantRequest| async move {
            let _authentication = hub.admit(Lane::Authentication)?;
            let service = hub.service(Some(request.ring.0))?;
            service.set_reader_grant(&request).await
        },
    )?;
    method(
        &mut module,
        SET_MERGE_SETTINGS,
        |hub, request: SetMergeSettingsRequest| async move {
            let _authentication = hub.admit(Lane::Authentication)?;
            hub.set_merge_settings(&request).await
        },
    )?;
    if let Some(relay) = relay {
        module.merge(relay_module(relay)?)?;
    }
    Ok(module)
}

pub fn relay_module(relay: Arc<Relay>) -> Result<RpcModule<Arc<Relay>>, RegisterMethodError> {
    let mut module = RpcModule::new(relay);
    method(
        &mut module,
        GET_RELAY_QUOTE,
        |relay, request: GetRelayQuoteRequest| async move { relay.quote(&request).await },
    )?;
    method(
        &mut module,
        PREPARE_RELAY,
        |relay, request: PrepareRelayRequest| async move { relay.prepare(&request).await },
    )?;
    method(
        &mut module,
        SUBMIT_RELAY,
        |relay, request: SubmitRelayRequest| async move { relay.submit(&request).await },
    )?;
    method(
        &mut module,
        GET_RELAY_STATUS,
        |relay, request: GetRelayStatusRequest| async move { relay.status(&request).await },
    )?;
    Ok(module)
}

/// Every handler error becomes a JSON-RPC error through one conversion.
fn method<C, P, T, F, Fut>(
    module: &mut RpcModule<Arc<C>>,
    name: &'static str,
    handler: F,
) -> Result<(), RegisterMethodError>
where
    C: Send + Sync + 'static,
    P: DeserializeOwned + Send + 'static,
    T: Serialize + Clone + Send + 'static,
    F: Fn(Arc<C>, P) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<T, RingRpcError>> + Send,
{
    module.register_async_method(name, move |params, context, _| {
        let handler = handler.clone();
        async move {
            let request = params.parse::<P>()?;
            handler(Arc::clone(&*context), request)
                .await
                .map_err(ErrorObjectOwned::from)
        }
    })?;
    Ok(())
}

struct ReadyService<S, Inner> {
    inner: Inner,
    hub: Arc<Hub<S>>,
}

impl<S, Inner: Clone> Clone for ReadyService<S, Inner> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            hub: self.hub.clone(),
        }
    }
}

impl<S, Inner, B> Service<HttpRequest<B>> for ReadyService<S, Inner>
where
    S: TransactionSource + 'static,
    Inner: Service<HttpRequest<B>, Response = HttpResponse>,
    Inner::Error: Into<BoxError> + 'static,
    Inner::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: HttpRequest<B>) -> Self::Future {
        if request.method() == Method::GET && request.uri().path() == "/ready" {
            let hub = self.hub.clone();
            return Box::pin(async move {
                let (status, body) = match hub.readiness().await {
                    ReadinessStatus::Ready => (StatusCode::OK, "ready"),
                    ReadinessStatus::Unavailable(check) => (StatusCode::SERVICE_UNAVAILABLE, check),
                };
                let mut response = hyper::Response::new(HttpBody::from(body));
                *response.status_mut() = status;
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                Ok(response)
            });
        }
        let future = self.inner.call(request);
        Box::pin(async move { future.await.map_err(Into::into) })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        net::Ipv4Addr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use solana_address::Address;
    use solana_signature::Signature;
    use spr_client::{ClientError, GetShieldedTransactionsByTagsResponse};
    use spr_keypair::X25519Keypair;
    use zolana_ring_client::RingIndexerError;
    use zolana_ring_client::{
        rpc::{KeyMode, RingChainStatus, DEPOSITS_PAGE_LIMIT},
        AuditError, RingOrigin,
    };
    use zolana_ring_transaction::RingAssets;

    use crate::{
        config::RootSecret,
        error::RingRpcError,
        limits::{
            MAX_CONCURRENT_AUTHENTICATIONS, MAX_CONCURRENT_DEPOSIT_SCANS, MAX_CONCURRENT_READS,
            MAX_REQUEST_UNITS_PER_SECOND,
        },
        origins::OriginPolicy,
        upstream::{
            DepositHistory, MergeAuditRequest, RecordsRoot, RingConfiguration, RingHistoryPage,
            TransactionPage,
        },
    };

    use super::*;

    const SERVED_RING: Address = Address::new_from_array([8; 32]);
    const TEST_GENESIS: [u8; 32] = [3; 32];

    struct TestSource {
        healthy: bool,
        delay: Duration,
        config: Option<RingConfiguration>,
        health_calls: Arc<AtomicUsize>,
    }

    impl TransactionSource for TestSource {
        async fn transactions_by_tag(
            &self,
            _request: TransactionPage<'_>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Err(ClientError::Rpc("unused source".to_owned()))
        }

        async fn ring_history(
            &self,
            _request: RingHistoryPage<'_>,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            Err(ClientError::Rpc("unused source".to_owned()))
        }

        async fn merge_audit_page(
            &self,
            _request: MergeAuditRequest<'_>,
        ) -> Result<zolana_ring_client::MergeAuditPage, AuditError> {
            Err(AuditError::InvalidMemberRegistry)
        }

        async fn transaction_origin(
            &self,
            _signature: Signature,
            _event_index: u16,
            _ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            Err(AuditError::Unavailable {
                signature: _signature,
                message: "unused source".to_owned(),
            })
        }

        async fn ring_deposits(&self, _page: DepositPage) -> Result<DepositHistory, ClientError> {
            Ok(DepositHistory {
                deposits: Vec::new(),
                cursor: None,
                oldest_slot: None,
            })
        }

        async fn ring_config(
            &self,
            _ring: Address,
        ) -> Result<Option<RingConfiguration>, ClientError> {
            Ok(self.config)
        }

        async fn ring_chain_status(&self, _ring: Address) -> Result<RingChainStatus, ClientError> {
            Ok(RingChainStatus::default())
        }

        async fn ring_member_records(
            &self,
            _request: zolana_ring_indexer::rpc::GetRingMemberRecordsRequest,
        ) -> Result<zolana_ring_indexer::rpc::GetRingMemberRecordsResponse, RingIndexerError>
        {
            Err(ClientError::Rpc("unused source".to_owned()).into())
        }

        async fn ring_member_openings(
            &self,
            _request: zolana_ring_indexer::rpc::GetRingMemberOpeningsRequest,
        ) -> Result<zolana_ring_indexer::rpc::GetRingMemberOpeningsResponse, RingIndexerError>
        {
            Err(ClientError::Rpc("unused source".to_owned()).into())
        }

        async fn ring_record_queue(
            &self,
            _ring: Address,
        ) -> Result<zolana_ring_indexer::rpc::GetRingRecordQueueResponse, RingIndexerError>
        {
            Err(ClientError::Rpc("unused source".to_owned()).into())
        }

        async fn slot(&self) -> Result<u64, ClientError> {
            Err(ClientError::Rpc("unused source".to_owned()))
        }

        async fn records_root(&self, _ring: Address) -> Result<Option<RecordsRoot>, ClientError> {
            Ok(None)
        }

        async fn storage_member_openings(
            &self,
            _request: zolana_ring_indexer::rpc::GetStorageMemberOpeningsRequest,
        ) -> Result<zolana_ring_indexer::rpc::GetStorageMemberOpeningsResponse, RingIndexerError>
        {
            Err(ClientError::Rpc("unused source".to_owned()).into())
        }

        async fn upgrade_authority(
            &self,
            _program: Address,
        ) -> Result<Option<Address>, ClientError> {
            Ok(None)
        }

        fn health(&self) -> impl Future<Output = Result<(), ClientError>> + Send {
            let healthy = self.healthy;
            let delay = self.delay;
            let calls = self.health_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(delay).await;
                healthy
                    .then_some(())
                    .ok_or_else(|| ClientError::Rpc("unavailable".to_owned()))
            }
        }

        async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
            Ok(TEST_GENESIS)
        }

        async fn ring_assets(&self) -> Result<RingAssets, ClientError> {
            Ok(RingAssets::new([]).unwrap())
        }
    }

    fn port() -> u16 {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        listener.local_addr().expect("address").port()
    }

    fn hub(mut source: TestSource, origins: Origins) -> Arc<Hub<TestSource>> {
        let auditor = X25519Keypair::new();
        source.config = Some(RingConfiguration {
            auditor_pubkey: auditor.pubkey(),
            authority: Address::new_from_array([2; 32]),
            mode: custom_ring_interface::RingMode::Confidential,
        });
        Arc::new(
            Hub::builder(source, TEST_GENESIS)
                .with_origins(origins)
                .local(SERVED_RING, auditor)
                .expect("hub"),
        )
    }

    fn derived_hub(source: TestSource, genesis: [u8; 32]) -> Arc<Hub<TestSource>> {
        Arc::new(
            Hub::builder(source, genesis)
                .derived(RootSecret::from_bytes([5; 32]).expect("root"))
                .expect("hub"),
        )
    }

    fn source() -> TestSource {
        TestSource {
            healthy: true,
            delay: Duration::ZERO,
            config: None,
            health_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn params<T: serde::Serialize>(value: T) -> serde_json::Map<String, serde_json::Value> {
        let serde_json::Value::Object(map) = serde_json::to_value(value).expect("JSON object")
        else {
            panic!("expected JSON object");
        };
        map
    }

    fn deposits(ring: Address) -> RingDepositsRequest {
        RingDepositsRequest {
            ring_program_id: ring.to_bytes().into(),
            limit: None,
            cursor: None,
        }
    }

    fn options(port: u16, timeout: Duration) -> ServerOptions {
        ServerOptions {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            bind_policy: BindPolicy::LoopbackOnly,
            port,
            max_connections: 8,
            request_timeout: timeout,
        }
    }

    #[tokio::test]
    async fn server_enforces_transport_boundaries() {
        let origins = OriginPolicy::new(vec!["http://localhost:3000".to_owned()])
            .with_relying_party_id("localhost".to_owned())
            .build()
            .expect("origins");
        let server_port = port();
        let handle = run_server(
            hub(source(), origins),
            options(server_port, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let url = format!("http://127.0.0.1:{server_port}");
        let client = reqwest::Client::new();

        let allowed = client
            .post(&url)
            .header("origin", "http://localhost:3000")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": HEALTH,
            }))
            .send()
            .await
            .expect("allowed request");
        assert_eq!(
            allowed
                .headers()
                .get("access-control-allow-origin")
                .expect("CORS"),
            "http://localhost:3000"
        );

        let denied = client
            .post(&url)
            .header("origin", "https://evil.example")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": HEALTH,
            }))
            .send()
            .await
            .expect("denied request");
        assert!(denied
            .headers()
            .get("access-control-allow-origin")
            .is_none());

        let batch = client
            .post(&url)
            .json(&serde_json::json!([{
                "jsonrpc": "2.0",
                "id": 1,
                "method": HEALTH,
            }]))
            .send()
            .await
            .expect("batch");
        let batch_body: serde_json::Value = batch.json().await.expect("batch body");
        assert_eq!(batch_body["error"]["code"], -32005);

        let oversized = client
            .post(&url)
            .body("a".repeat(MAX_REQUEST_BODY_SIZE as usize + 1))
            .send()
            .await
            .expect("oversized request");
        assert!(!oversized.status().is_success());

        let ready = client
            .get(format!("{url}/ready"))
            .send()
            .await
            .expect("ready");
        assert_eq!(ready.status(), StatusCode::OK);
        handle.stop().expect("stop");
        handle.stopped().await;
    }

    /// A gateway bills a deposits page by the signatures it asks to examine,
    /// and only for a successful answer.
    #[tokio::test]
    async fn a_deposits_page_reports_its_metering_units() {
        let server_port = port();
        let handle = run_server(
            hub(source(), Origins::default()),
            options(server_port, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let url = format!("http://127.0.0.1:{server_port}/v1/zolana/ring");
        let client = reqwest::Client::new();
        let units = |method: &str, params: serde_json::Value| {
            let request = client
                .post(format!("{url}/{method}"))
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": method,
                    "params": params,
                }));
            async move {
                let response = request.send().await.expect("call");
                let units = response
                    .headers()
                    .get("x-helius-metering-units")
                    .map(|units| units.to_str().expect("ascii").to_owned());
                let body: serde_json::Value = response.json().await.expect("JSON-RPC answer");
                (units, body)
            }
        };

        let mut wide = deposits(SERVED_RING);
        wide.limit = Some(200);
        let (wide_units, body) =
            units(RING_DEPOSITS, serde_json::to_value(wide).expect("params")).await;
        assert!(body["result"].is_object(), "{body}");
        assert_eq!(wide_units.as_deref(), Some("4"));

        let (default_units, _) = units(
            RING_DEPOSITS,
            serde_json::to_value(deposits(SERVED_RING)).expect("params"),
        )
        .await;
        assert_eq!(default_units.as_deref(), Some("1"));

        let (failed_units, body) = units(
            RING_DEPOSITS,
            serde_json::to_value(deposits(Address::new_from_array([9; 32]))).expect("params"),
        )
        .await;
        assert!(body["error"].is_object(), "{body}");
        assert_eq!(failed_units, None);

        let (health_units, _) = units(HEALTH, serde_json::Value::Null).await;
        assert_eq!(health_units, None);
        handle.stop().expect("stop");
        handle.stopped().await;
    }

    #[tokio::test]
    async fn a_path_runs_only_the_method_it_names() {
        let server_port = port();
        let handle = run_server(
            hub(source(), Origins::default()),
            options(server_port, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let url = format!("http://127.0.0.1:{server_port}");
        let client = reqwest::Client::new();
        let call = |path: &str, body: serde_json::Value| {
            let request = client.post(format!("{url}{path}")).json(&body);
            async move {
                request
                    .send()
                    .await
                    .expect("call")
                    .json::<serde_json::Value>()
                    .await
                    .expect("JSON-RPC answer")
            }
        };
        let named =
            |method: &str| serde_json::json!({ "jsonrpc": "2.0", "id": 7, "method": method });

        for path in ["/", "/health", "/health/", "/v1/zolana/ring/health"] {
            let answer = call(path, named(HEALTH)).await;
            assert_eq!(answer["result"]["mode"], "local", "{path}: {answer}");
            assert!(
                answer["result"]["servicePubkey"].is_string(),
                "{path}: {answer}"
            );
        }
        for (path, method) in [
            ("/health", GET_DECRYPTED_TRANSACTIONS),
            ("/v1/zolana/ring/health", GET_DECRYPTED_TRANSACTIONS),
            ("/v1/zolana/ring/ringStatus", RING_DEPOSITS),
        ] {
            let answer = call(path, named(method)).await;
            assert_eq!(answer["error"]["code"], -32601, "{path} {method}");
            assert_eq!(answer["id"], 7, "{path} {method}");
        }
        // Not one call naming the path's method: a batch, an unnamed call,
        // or a body that is not JSON.
        for body in [
            serde_json::json!([named(HEALTH)]),
            serde_json::json!({ "jsonrpc": "2.0", "id": 1 }),
            serde_json::json!("health"),
        ] {
            let answer = call("/health", body.clone()).await;
            assert_eq!(answer["error"]["code"], -32601, "{body}");
        }
        let unparsed = client
            .post(format!("{url}/health"))
            .body("not json")
            .send()
            .await
            .expect("unparsed");
        let unparsed: serde_json::Value = unparsed.json().await.expect("refusal");
        assert_eq!(unparsed["error"]["code"], -32601);

        let probe = client
            .get(format!("{url}/health"))
            .send()
            .await
            .expect("health probe");
        assert_eq!(probe.status(), StatusCode::OK);
        handle.stop().expect("stop");
        handle.stopped().await;
    }

    #[tokio::test]
    async fn server_refuses_a_websocket_upgrade() {
        let server_port = port();
        let handle = run_server(
            hub(source(), Origins::default()),
            options(server_port, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let upgrade = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{server_port}/"))
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .expect("upgrade response");
        assert_ne!(upgrade.status(), StatusCode::SWITCHING_PROTOCOLS);
        handle.stop().expect("stop");
        handle.stopped().await;
    }

    #[tokio::test]
    async fn server_rejects_public_bind_and_failed_readiness() {
        let public = run_server(
            hub(source(), Origins::default()),
            ServerOptions {
                bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                bind_policy: BindPolicy::LoopbackOnly,
                port: 0,
                max_connections: 1,
                request_timeout: Duration::from_secs(1),
            },
        )
        .await;
        assert!(matches!(public, Err(ServerError::PublicBind)));
        let insecure = run_server(
            hub(source(), Origins::default()),
            ServerOptions {
                bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                bind_policy: BindPolicy::InsecurePublic,
                port: 0,
                max_connections: 1,
                request_timeout: Duration::from_secs(1),
            },
        )
        .await
        .expect("public bind under the insecure policy");
        insecure.stop().expect("stop");

        let failed_port = port();
        let handle = run_server(
            hub(
                TestSource {
                    healthy: false,
                    ..source()
                },
                Origins::default(),
            ),
            options(failed_port, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let response = reqwest::get(format!("http://127.0.0.1:{failed_port}/ready"))
            .await
            .expect("ready response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        handle.stop().expect("stop");
        handle.stopped().await;

        let timeout_port = port();
        let handle = run_server(
            hub(
                TestSource {
                    delay: Duration::from_millis(50),
                    ..source()
                },
                Origins::default(),
            ),
            options(timeout_port, Duration::from_millis(5)),
        )
        .await
        .expect("server");
        assert!(
            reqwest::get(format!("http://127.0.0.1:{timeout_port}/ready"))
                .await
                .is_err()
        );
        handle.stop().expect("stop");
        handle.stopped().await;
    }

    #[tokio::test]
    async fn deposit_pages_are_metered_and_serve_one_ring() {
        let module = rpc_module(hub(source(), Origins::default())).expect("module");

        let foreign = module
            .call::<_, RingDepositsResponse>(
                RING_DEPOSITS,
                params(deposits(Address::new_from_array([1; 32]))),
            )
            .await
            .expect_err("another ring");
        assert!(foreign.to_string().contains("not served"), "{foreign}");

        for _ in 0..MAX_REQUEST_UNITS_PER_SECOND / DEPOSITS_PAGE_LIMIT as usize {
            module
                .call::<_, RingDepositsResponse>(RING_DEPOSITS, params(deposits(SERVED_RING)))
                .await
                .expect("page");
        }
        let busy = module
            .call::<_, RingDepositsResponse>(RING_DEPOSITS, params(deposits(SERVED_RING)))
            .await
            .expect_err("exhausted window");
        assert!(busy.to_string().contains("busy"), "{busy}");

        let health: HealthResponse = module.call(HEALTH, [(); 0]).await.expect("health");
        assert_eq!(health.mode, KeyMode::Local);
        let status: RingStatusResponse = module
            .call(
                RING_STATUS,
                params(RingStatusRequest {
                    ring_program_id: SERVED_RING.to_bytes().into(),
                }),
            )
            .await
            .expect("status");
        assert_eq!(status.state, RingState::Served);
    }

    #[tokio::test]
    async fn readiness_probes_share_a_cached_result() {
        let source = source();
        let calls = source.health_calls.clone();
        let hub = hub(source, Origins::default());

        assert_eq!(hub.readiness().await, ReadinessStatus::Ready);
        assert_eq!(hub.readiness().await, ReadinessStatus::Ready);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cancelled_readiness_waiters_leave_one_probe() {
        let source = TestSource {
            delay: Duration::from_millis(10),
            ..source()
        };
        let calls = source.health_calls.clone();
        let hub = hub(source, Origins::default());
        let waiter = tokio::spawn({
            let hub = hub.clone();
            async move { hub.readiness().await }
        });
        while calls.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
        waiter.abort();

        assert_eq!(hub.readiness().await, ReadinessStatus::Ready);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    /// A decrypting page holds its slot for the whole page, and the gate
    /// refuses the next reader rather than queueing it behind them.
    #[test]
    fn concurrent_reads_are_capped_and_refused_rather_than_queued() {
        let hub = hub(source(), Origins::default());
        let held = (0..MAX_CONCURRENT_READS)
            .map(|_| hub.admit(Lane::Read).expect("read slot"))
            .collect::<Vec<_>>();

        assert!(matches!(hub.admit(Lane::Read), Err(RingRpcError::Busy)));
        drop(held);
        let _reopened = hub.admit(Lane::Read).expect("released slot");
    }

    #[test]
    fn concurrent_deposit_scans_are_capped() {
        let hub = hub(source(), Origins::default());
        let held = (0..MAX_CONCURRENT_DEPOSIT_SCANS)
            .map(|_| hub.admit(Lane::Deposits(1)).expect("deposit slot"))
            .collect::<Vec<_>>();

        assert!(matches!(
            hub.admit(Lane::Deposits(1)),
            Err(RingRpcError::Busy)
        ));
        drop(held);
        let _reopened = hub.admit(Lane::Deposits(1)).expect("released slot");
    }

    #[test]
    fn authentication_attempts_do_not_consume_audit_capacity() {
        let hub = hub(source(), Origins::default());
        for _ in 0..MAX_REQUEST_UNITS_PER_SECOND {
            hub.admit(Lane::Authentication).expect("authentication");
        }
        assert!(matches!(
            hub.admit(Lane::Authentication),
            Err(RingRpcError::Busy)
        ));
        hub.admit(Lane::Read).expect("audit capacity");
    }

    #[test]
    fn concurrent_authentication_attempts_are_capped() {
        let hub = hub(source(), Origins::default());
        let held = (0..MAX_CONCURRENT_AUTHENTICATIONS)
            .map(|_| {
                hub.admit(Lane::Authentication)
                    .expect("authentication slot")
            })
            .collect::<Vec<_>>();

        assert!(matches!(
            hub.admit(Lane::Authentication),
            Err(RingRpcError::Busy)
        ));
        drop(held);
        let _reopened = hub.admit(Lane::Authentication).expect("released slot");
    }

    /// Every derived key is bound to the genesis hash captured at boot, so
    /// another cluster orphans every ring already registered.
    #[tokio::test]
    async fn derived_readiness_checks_the_cluster() {
        let matching = port();
        let handle = run_server(
            derived_hub(source(), TEST_GENESIS),
            options(matching, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let ready = reqwest::get(format!("http://127.0.0.1:{matching}/ready"))
            .await
            .expect("ready");
        assert_eq!(ready.status(), StatusCode::OK);
        handle.stop().expect("stop");
        handle.stopped().await;

        let repointed = port();
        let handle = run_server(
            derived_hub(source(), [1; 32]),
            options(repointed, Duration::from_secs(1)),
        )
        .await
        .expect("server");
        let response = reqwest::get(format!("http://127.0.0.1:{repointed}/ready"))
            .await
            .expect("ready");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.text().await.expect("body"), "unavailable cluster");
        handle.stop().expect("stop");
        handle.stopped().await;
    }
}
