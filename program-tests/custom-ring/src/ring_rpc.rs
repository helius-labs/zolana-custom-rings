//! The ring rpc a test serves in process for the operator cli and the relay wallet.

use std::{
    net::{Ipv4Addr, TcpListener},
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use custom_ring_cli::{wait_for, Probe};
use custom_ring_sdk::{RingError, RingRelay};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::ClientError;
use spr_keypair::X25519Keypair;
use spr_test_utils::localnet::isolated_temp_path;
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareAuthorityTransferRequest,
    PrepareRelayRequest, ReadTarget, RelayId, RelayOperation, RelayQuote, RelayStatus, RelayStep,
    SetMergeSettingsRequest, SetMergeSettingsResponse, SubmitRelayRequest, GET_RELAY_QUOTE,
    GET_RELAY_STATUS, PREPARE_AUTHORITY_TRANSFER, PREPARE_RELAY, SET_MERGE_SETTINGS, SUBMIT_RELAY,
};
use zolana_ring_rpc::{
    run_server, BindPolicy, ChainSource, ClientLimits, Hub, LiveStorageChain, ManagedMerge,
    RelayServices, RelayServicesInit, ServerOptions, ServiceIdentity, Store, TransactionSource,
    Upstreams, STORE_CONNECTIONS,
};

use crate::shared::{prover_url, TestEnv, ACTOR_AIRDROP};

pub struct RingRpcSpec<'a> {
    pub env: &'a TestEnv,
    pub ring: Address,
    pub auditor: X25519Keypair,
}

pub struct LocalRingRpc {
    pub url: String,
    runtime: tokio::runtime::Runtime,
}

pub struct RelayedRingRpc {
    served: LocalRingRpc,
    pub fee_payer: Address,
    pub target: ReadTarget,
    pub relay: RingRpcRelay,
    merge: ManagedMerge<ChainSource>,
}

pub struct RingRpcRelay {
    url: String,
    http: reqwest::Client,
}

struct Served {
    rpc: LocalRingRpc,
    hub: Arc<Hub<ChainSource>>,
    genesis_hash: [u8; 32],
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

impl RingRpcSpec<'_> {
    pub fn serve(self) -> Result<LocalRingRpc> {
        let runtime = tokio::runtime::Runtime::new()?;
        let store = open_store(&runtime)?;
        Ok(self.start(runtime, store, None)?.rpc)
    }

    pub fn serve_relayed(self) -> Result<RelayedRingRpc> {
        // The relay and managed merge log every refusal they swallow.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
            .try_init();
        let runtime = tokio::runtime::Runtime::new()?;
        let fee_payer = Keypair::new();
        let fee_payer_address = fee_payer.pubkey();
        self.env.fund(fee_payer_address, ACTOR_AIRDROP)?;
        let store = open_store(&runtime)?;
        let services = RelayServicesInit {
            fee_payer,
            store: store.clone(),
            rpc_url: &self.env.rpc_url,
            indexer_url: &self.env.indexer_url,
            prover_url: &prover_url(),
        }
        .build();
        let ring = self.ring;
        let Served {
            rpc,
            hub,
            genesis_hash,
        } = self.start(runtime, store, Some(services))?;
        let merge = hub
            .managed_merge()
            .context("relay services run the managed merge")?;
        Ok(RelayedRingRpc {
            relay: RingRpcRelay::new(&rpc.url),
            served: rpc,
            fee_payer: fee_payer_address,
            target: ReadTarget {
                cluster: genesis_hash,
                service: hub.service_pubkey(),
                ring,
            },
            merge,
        })
    }

    fn start(
        self,
        runtime: tokio::runtime::Runtime,
        store: Store,
        relay: Option<RelayServices>,
    ) -> Result<Served> {
        let upstreams = Upstreams {
            indexer_url: &self.env.indexer_url,
            rpc_url: &self.env.rpc_url,
            timeout: Duration::from_secs(30),
        };
        let source =
            ChainSource::connect(upstreams).map_err(|e| anyhow!("ring rpc upstreams {e:?}"))?;
        let genesis_hash = runtime
            .block_on(source.genesis_hash())
            .map_err(|e| anyhow!("genesis hash {e:?}"))?;
        let storage_chain = LiveStorageChain::connect(upstreams, &prover_url())
            .map_err(|e| anyhow!("storage chain {e:?}"))?;
        let identity = ServiceIdentity {
            genesis_hash,
            service: Keypair::new(),
        };
        let mut builder = Hub::builder(source, identity)
            .with_store(store)
            .with_storage_chain(Arc::new(storage_chain), Keypair::new())
            .with_co_signer(Keypair::new());
        if let Some(services) = relay {
            builder = builder.with_relay_services(services);
        }
        let hub = Arc::new(
            builder
                .local(self.ring, self.auditor)
                .map_err(|e| anyhow!("hub {e:?}"))?,
        );
        let writer = hub.record_writer().map_err(|e| anyhow!("writer {e:?}"))?;
        self.env.fund(writer.authority(), ACTOR_AIRDROP)?;
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
            .local_addr()?
            .port();
        let server = runtime
            .block_on(run_server(
                hub.clone(),
                ServerOptions {
                    bind: Ipv4Addr::LOCALHOST.into(),
                    bind_policy: BindPolicy::LoopbackOnly,
                    port,
                    max_connections: 16,
                    request_timeout: Duration::from_secs(30),
                    client_limits: ClientLimits::default(),
                },
            ))
            .map_err(|e| anyhow!("ring rpc server {e:?}"))?;
        // The server stops with its last handle, the task holds one until the
        // runtime goes.
        runtime.spawn(async move {
            let _server = server;
            std::future::pending::<()>().await;
        });
        {
            let _entered = runtime.enter();
            hub.spawn_workers();
        }
        Ok(Served {
            rpc: LocalRingRpc {
                url: format!("http://127.0.0.1:{port}"),
                runtime,
            },
            hub,
            genesis_hash,
        })
    }
}

impl RelayedRingRpc {
    pub fn quote(&self, env: &TestEnv, operation: RelayOperation) -> Result<RelayQuote> {
        Ok(env.run(self.relay.get_relay_quote(GetRelayQuoteRequest {
            ring: self.target.ring.into(),
            operation,
        }))?)
    }

    pub fn confirmed(&self, env: &TestEnv, relay_id: &RelayId) -> Result<Signature> {
        wait_for("the relay to confirm", || {
            let status = env.run(self.relay.get_relay_status(GetRelayStatusRequest {
                relay_id: relay_id.clone(),
            }))?;
            Ok(match status {
                RelayStatus::Confirmed { signature, .. } => Probe::Ready(signature.0),
                RelayStatus::Failed { reason } => bail!("the relay failed, {reason}"),
                RelayStatus::AwaitingSignature | RelayStatus::Sent { .. } => Probe::NotYet,
            })
        })
    }

    pub fn managed_merge_pass(&self) -> Result<Vec<RelayId>> {
        self.served
            .runtime
            .block_on(self.merge.merge_due())
            .map_err(|e| anyhow!("managed merge pass {e:?}"))
    }
}

impl RingRpcRelay {
    fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn set_merge_settings(
        &self,
        request: SetMergeSettingsRequest,
    ) -> Result<SetMergeSettingsResponse, RingError> {
        self.call(SET_MERGE_SETTINGS, request).await
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: impl Serialize,
    ) -> Result<T, RingError> {
        let failed = |reason: String| RingError::Client(ClientError::Rpc(reason));
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response: JsonRpcResponse<T> = self
            .http
            .post(format!("{}/{method}", self.url))
            .json(&body)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| failed(format!("ring rpc {method} {e}")))?
            .json()
            .await
            .map_err(|e| failed(format!("ring rpc {method} answer {e}")))?;
        if let Some(error) = response.error {
            return Err(failed(format!("ring rpc {method} failed, {error}")));
        }
        response
            .result
            .ok_or_else(|| failed(format!("ring rpc {method} returned no result")))
    }
}

#[async_trait]
impl RingRelay for RingRpcRelay {
    async fn get_relay_quote(
        &self,
        request: GetRelayQuoteRequest,
    ) -> Result<RelayQuote, RingError> {
        self.call(GET_RELAY_QUOTE, request).await
    }

    async fn prepare_relay(&self, request: PrepareRelayRequest) -> Result<RelayStep, RingError> {
        self.call(PREPARE_RELAY, request).await
    }

    async fn prepare_authority_transfer(
        &self,
        request: PrepareAuthorityTransferRequest,
    ) -> Result<RelayStep, RingError> {
        self.call(PREPARE_AUTHORITY_TRANSFER, request).await
    }

    async fn submit_relay(&self, request: SubmitRelayRequest) -> Result<RelayStatus, RingError> {
        self.call(SUBMIT_RELAY, request).await
    }

    async fn get_relay_status(
        &self,
        request: GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingError> {
        self.call(GET_RELAY_STATUS, request).await
    }
}

fn open_store(runtime: &tokio::runtime::Runtime) -> Result<Store> {
    let store_dir = isolated_temp_path("zolana-ring-rpc-store");
    std::fs::create_dir_all(&store_dir)?;
    runtime
        .block_on(Store::open(
            &format!("sqlite://{store_dir}/store.sqlite?mode=rwc"),
            STORE_CONNECTIONS,
        ))
        .map_err(|e| anyhow!("ring rpc store {e:?}"))
}
