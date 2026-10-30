//! Token buckets per client and method class, and per signing key over accepted writes.

use std::{
    collections::{BTreeSet, HashMap},
    future::Future,
    net::{IpAddr, Ipv6Addr},
    num::NonZeroU32,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use clap::Args;
use hyper::{
    header::{HeaderValue, CONTENT_TYPE, RETRY_AFTER},
    StatusCode,
};
use jsonrpsee::{
    core::{
        middleware::{Batch, Notification, RpcServiceT},
        BoxError,
    },
    server::{HttpBody, HttpRequest, HttpResponse, MethodResponse},
    types::{ErrorObjectOwned, Id, Request},
};
use solana_address::Address;
use thiserror::Error;
use tower::{Layer, Service};

use zolana_ring_client::rpc::{
    CreateRecordsRegistryRequest, PrepareAuthorityTransferRequest, RefuseEnrolmentRequest,
    SetMergeSettingsRequest, SetReaderGrantRequest, SubmitRecordUpdateRequest, SubmitRelayRequest,
    CREATE_AUDITOR_KEY, CREATE_RECORDS_REGISTRY, GET_AUDITED_MERGES, GET_AUDITED_UTXOS,
    GET_DECRYPTED_TRANSACTIONS, GET_PENDING_ENROLMENTS, GET_RECORD_UPDATE_STATUS, GET_RELAY_QUOTE,
    GET_RELAY_STATUS, GET_WALLET_ACTIVITY, HEALTH, PREPARE_AUTHORITY_TRANSFER, REFUSE_ENROLMENT,
    RING_DEPOSITS, RING_STATUS, SET_MERGE_SETTINGS, SET_READER_GRANT, SUBMIT_RECORD_UPDATE,
    SUBMIT_RELAY,
};

use crate::{
    client_identity::{
        ApiKeyDigest, ClientIdentity, ClientIdentityPolicy, PeerAddress, UnknownApiKey,
    },
    error::RingRpcError,
    metering::call_units,
};

/// Past it the bucket nearest to full is dropped.
const MAX_BUCKETS: usize = 65_536;
/// An IPv6 /48 spends the rates of this many /64 clients.
pub(crate) const NETWORK_CLIENTS: NonZeroU32 = NonZeroU32::new(16).unwrap();
const UNKNOWN_API_KEY: i32 = -32254;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BucketRate {
    pub per_minute: NonZeroU32,
    pub burst: NonZeroU32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientRates {
    pub public_reads: BucketRate,
    pub signed_reads: BucketRate,
    /// Also the rate of each signing key.
    pub signed_writes: BucketRate,
}

#[derive(Clone, Debug, Default)]
pub struct ClientLimits {
    pub rates: ClientRates,
    pub identity: ClientIdentityPolicy,
}

#[derive(Debug, Args)]
pub struct ClientLimitArgs {
    #[arg(
        long,
        env = "RING_RPC_PUBLIC_READS_PER_MINUTE",
        default_value_t = DEFAULT_RATES.public_reads.per_minute
    )]
    pub public_reads_per_minute: NonZeroU32,
    #[arg(
        long,
        env = "RING_RPC_PUBLIC_READ_BURST",
        default_value_t = DEFAULT_RATES.public_reads.burst
    )]
    pub public_read_burst: NonZeroU32,
    #[arg(
        long,
        env = "RING_RPC_SIGNED_READS_PER_MINUTE",
        default_value_t = DEFAULT_RATES.signed_reads.per_minute
    )]
    pub signed_reads_per_minute: NonZeroU32,
    #[arg(
        long,
        env = "RING_RPC_SIGNED_READ_BURST",
        default_value_t = DEFAULT_RATES.signed_reads.burst
    )]
    pub signed_read_burst: NonZeroU32,
    #[arg(
        long,
        env = "RING_RPC_SIGNED_WRITES_PER_MINUTE",
        default_value_t = DEFAULT_RATES.signed_writes.per_minute
    )]
    pub signed_writes_per_minute: NonZeroU32,
    #[arg(
        long,
        env = "RING_RPC_SIGNED_WRITE_BURST",
        default_value_t = DEFAULT_RATES.signed_writes.burst
    )]
    pub signed_write_burst: NonZeroU32,
    /// A peer whose `x-forwarded-for` names the client, repeatable.
    #[arg(
        long = "trusted-proxy",
        env = "RING_RPC_TRUSTED_PROXIES",
        value_delimiter = ','
    )]
    pub trusted_proxies: Vec<IpAddr>,
    /// Lowercase hex SHA-256 of an `x-api-key` or `api-key` query value, repeatable.
    #[arg(
        long = "api-key-sha256",
        env = "RING_RPC_API_KEY_SHA256S",
        value_delimiter = ','
    )]
    pub api_key_sha256s: Vec<ApiKeyDigest>,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum RateLimit {
    #[error("client exceeds its public read rate")]
    PublicReads = -32250,
    #[error("client exceeds its signed read rate")]
    SignedReads = -32251,
    #[error("client exceeds its signed write rate")]
    SignedWrites = -32252,
    #[error("signing key exceeds its signed write rate")]
    SigningKey = -32253,
}

/// Rides a refused answer to the HTTP layer for its 429.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RateLimited {
    limit: RateLimit,
    retry_after: Duration,
}

enum Admission {
    Limited(RateLimited),
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum MethodClass {
    PublicRead,
    SignedRead,
    SignedWrite,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RatedCall {
    PublicRead {
        units: u32,
    },
    SignedRead,
    /// Claimed by the request, unverified until the answer succeeds.
    SignedWrite {
        signer: Option<Address>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum BucketKey {
    Client(MethodClass, ClientIdentity),
    Network(MethodClass, Ipv6Addr),
    Signer(Address),
}

#[derive(Clone, Copy, Debug)]
struct Charge {
    key: BucketKey,
    rate: BucketRate,
    units: u32,
}

/// GCRA buckets, a bucket whose arrival is not past now is full and equals an absent one.
#[derive(Default)]
struct Buckets {
    arrivals: HashMap<BucketKey, Instant>,
    by_arrival: BTreeSet<(Instant, BucketKey)>,
}

pub(crate) struct ClientRateLimiter {
    rates: ClientRates,
    buckets: Mutex<Buckets>,
}

#[derive(Clone)]
pub(crate) struct ClientRate<S> {
    pub(crate) service: S,
    pub(crate) limiter: Arc<ClientRateLimiter>,
}

#[derive(Clone)]
pub(crate) struct ClientLayer(Arc<ClientIdentityPolicy>);

#[derive(Clone)]
pub(crate) struct ClientService<Inner> {
    inner: Inner,
    policy: Arc<ClientIdentityPolicy>,
}

const DEFAULT_RATES: ClientRates = ClientRates {
    public_reads: BucketRate::new(600, 60),
    signed_reads: BucketRate::new(120, 20),
    signed_writes: BucketRate::new(30, 10),
};

impl BucketRate {
    /// Panics on zero, for constants only.
    pub const fn new(per_minute: u32, burst: u32) -> Self {
        let Some(per_minute) = NonZeroU32::new(per_minute) else {
            panic!("bucket rate is zero");
        };
        let Some(burst) = NonZeroU32::new(burst) else {
            panic!("bucket burst is zero");
        };
        Self { per_minute, burst }
    }

    fn interval(self) -> Duration {
        Duration::from_secs(60) / self.per_minute.get()
    }

    fn capacity(self) -> Duration {
        self.interval().saturating_mul(self.burst.get())
    }

    fn shared_by(self, clients: NonZeroU32) -> Self {
        Self {
            per_minute: self.per_minute.saturating_mul(clients),
            burst: self.burst.saturating_mul(clients),
        }
    }
}

impl Default for ClientRates {
    fn default() -> Self {
        DEFAULT_RATES
    }
}

impl ClientLimitArgs {
    pub fn client_limits(&self) -> ClientLimits {
        ClientLimits {
            rates: ClientRates {
                public_reads: BucketRate {
                    per_minute: self.public_reads_per_minute,
                    burst: self.public_read_burst,
                },
                signed_reads: BucketRate {
                    per_minute: self.signed_reads_per_minute,
                    burst: self.signed_read_burst,
                },
                signed_writes: BucketRate {
                    per_minute: self.signed_writes_per_minute,
                    burst: self.signed_write_burst,
                },
            },
            identity: ClientIdentityPolicy::default()
                .with_trusted_proxies(self.trusted_proxies.iter().copied())
                .with_api_keys(self.api_key_sha256s.iter().copied()),
        }
    }
}

impl RateLimit {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl RateLimited {
    fn retry_after_secs(self) -> u64 {
        self.retry_after.as_secs() + u64::from(self.retry_after.subsec_nanos() > 0)
    }
}

impl From<RateLimited> for ErrorObjectOwned {
    fn from(limited: RateLimited) -> Self {
        let retry_after_ms = u64::try_from(limited.retry_after.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        ErrorObjectOwned::owned(
            limited.limit.code(),
            limited.limit.to_string(),
            Some(serde_json::json!({ "retryAfterMs": retry_after_ms })),
        )
    }
}

impl ClientRateLimiter {
    pub(crate) fn new(rates: ClientRates) -> Self {
        Self {
            rates,
            buckets: Mutex::default(),
        }
    }

    /// Charges the client at once, the signing key only through `record_accepted`.
    fn admit(
        &self,
        client: ClientIdentity,
        call: RatedCall,
        now: Instant,
    ) -> Result<(), Admission> {
        let mut buckets = self.buckets.lock().map_err(|_| Admission::Unavailable)?;
        let class = call.class();
        let rate = self.rates.of(class);
        let units = call.units();
        let client_charge = Charge {
            key: BucketKey::Client(class, client),
            rate,
            units,
        };
        let network_charge = client.network().map(|network| Charge {
            key: BucketKey::Network(class, network),
            rate: rate.shared_by(NETWORK_CLIENTS),
            units,
        });
        let (arrivals, waits): (Vec<_>, Vec<_>) = std::iter::once(client_charge)
            .chain(network_charge)
            .map(|charge| {
                buckets
                    .within_burst(charge, now)
                    .map(|arrival| (charge.key, arrival))
            })
            .partition(Result::is_ok);
        // The longest wait, a shorter one leaves the other bucket refusing.
        if let Some(retry_after) = waits.into_iter().filter_map(Result::err).max() {
            return Err(Admission::limited(class.limit(), retry_after));
        }
        for (key, arrival) in arrivals.into_iter().flatten() {
            buckets.record(key, arrival, now);
        }
        if let Some(signer) = call.signer() {
            buckets
                .within_burst(self.signer_charge(signer), now)
                .map_err(|retry_after| Admission::limited(RateLimit::SigningKey, retry_after))?;
        }
        Ok(())
    }

    /// Runs on success only, after the service verified the signer.
    fn record_accepted(&self, call: RatedCall, now: Instant) {
        let Some(signer) = call.signer() else {
            return;
        };
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.spend(self.signer_charge(signer), now);
        }
    }

    fn signer_charge(&self, signer: Address) -> Charge {
        Charge {
            key: BucketKey::Signer(signer),
            rate: self.rates.signed_writes,
            units: 1,
        }
    }
}

impl Buckets {
    /// The arrival a charge moves its bucket to, or the wait past the burst.
    fn within_burst(&self, charge: Charge, now: Instant) -> Result<Instant, Duration> {
        let debt = self.debt_after(charge, now);
        let capacity = charge.rate.capacity();
        if debt > capacity {
            return Err(debt - capacity);
        }
        now.checked_add(debt).ok_or(capacity)
    }

    /// Spends past the burst too, the debt stops at a full burst.
    fn spend(&mut self, charge: Charge, now: Instant) {
        let debt = self.debt_after(charge, now).min(charge.rate.capacity());
        if let Some(arrival) = now.checked_add(debt) {
            self.record(charge.key, arrival, now);
        }
    }

    fn debt_after(&self, charge: Charge, now: Instant) -> Duration {
        let owed = self
            .arrivals
            .get(&charge.key)
            .map_or(Duration::ZERO, |arrival| {
                arrival.saturating_duration_since(now)
            });
        let units = charge.units.clamp(1, charge.rate.burst.get());
        owed.saturating_add(charge.rate.interval().saturating_mul(units))
    }

    fn record(&mut self, key: BucketKey, arrival: Instant, now: Instant) {
        if let Some(previous) = self.arrivals.insert(key, arrival) {
            self.by_arrival.remove(&(previous, key));
        }
        self.by_arrival.insert((arrival, key));
        while let Some(&(oldest, evicted)) = self.by_arrival.first() {
            if oldest > now && self.arrivals.len() <= MAX_BUCKETS {
                break;
            }
            self.by_arrival.pop_first();
            self.arrivals.remove(&evicted);
        }
    }
}

impl Admission {
    fn limited(limit: RateLimit, retry_after: Duration) -> Self {
        Self::Limited(RateLimited { limit, retry_after })
    }

    fn response(self, id: Id<'_>) -> MethodResponse {
        match self {
            Self::Limited(limited) => {
                let mut refused = MethodResponse::error(id, limited);
                refused.extensions_mut().insert(limited);
                refused
            }
            Self::Unavailable => {
                MethodResponse::error(id, ErrorObjectOwned::from(RingRpcError::StateUnavailable))
            }
        }
    }
}

impl ClientRates {
    fn of(&self, class: MethodClass) -> BucketRate {
        match class {
            MethodClass::PublicRead => self.public_reads,
            MethodClass::SignedRead => self.signed_reads,
            MethodClass::SignedWrite => self.signed_writes,
        }
    }
}

impl MethodClass {
    fn limit(self) -> RateLimit {
        match self {
            Self::PublicRead => RateLimit::PublicReads,
            Self::SignedRead => RateLimit::SignedReads,
            Self::SignedWrite => RateLimit::SignedWrites,
        }
    }
}

impl<S> RpcServiceT for ClientRate<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse> + Send + Sync + Clone + 'static,
{
    type MethodResponse = S::MethodResponse;
    type NotificationResponse = S::NotificationResponse;
    type BatchResponse = S::BatchResponse;

    fn call<'a>(
        &self,
        request: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let now = Instant::now();
        let call = RatedCall::of(&request);
        let admission = match request.extensions().get::<ClientIdentity>() {
            Some(client) => self.limiter.admit(*client, call, now),
            None => Err(Admission::Unavailable),
        };
        let service = self.service.clone();
        let limiter = self.limiter.clone();
        async move {
            if let Err(refusal) = admission {
                return refusal.response(request.id);
            }
            let response = service.call(request).await;
            if response.is_success() {
                limiter.record_accepted(call, Instant::now());
            }
            response
        }
    }

    fn batch<'a>(
        &self,
        requests: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        self.service.batch(requests)
    }

    fn notification<'a>(
        &self,
        notification: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        self.service.notification(notification)
    }
}

impl RatedCall {
    fn class(self) -> MethodClass {
        match self {
            Self::PublicRead { .. } => MethodClass::PublicRead,
            Self::SignedRead => MethodClass::SignedRead,
            Self::SignedWrite { .. } => MethodClass::SignedWrite,
        }
    }

    fn units(self) -> u32 {
        match self {
            Self::PublicRead { units } => units,
            Self::SignedRead | Self::SignedWrite { .. } => 1,
        }
    }

    fn signer(self) -> Option<Address> {
        match self {
            Self::SignedWrite { signer } => signer,
            Self::PublicRead { .. } | Self::SignedRead => None,
        }
    }

    fn of(request: &Request<'_>) -> Self {
        let params = request.params();
        let write = |signer: Option<Address>| Self::SignedWrite { signer };
        match request.method_name() {
            HEALTH
            | RING_STATUS
            | RING_DEPOSITS
            | GET_RECORD_UPDATE_STATUS
            | GET_RELAY_QUOTE
            | GET_RELAY_STATUS => Self::PublicRead {
                units: call_units(request).unwrap_or(1),
            },
            CREATE_AUDITOR_KEY
            | GET_DECRYPTED_TRANSACTIONS
            | GET_WALLET_ACTIVITY
            | GET_AUDITED_MERGES
            | GET_AUDITED_UTXOS
            | GET_PENDING_ENROLMENTS => Self::SignedRead,
            SUBMIT_RECORD_UPDATE => write(
                params
                    .parse::<SubmitRecordUpdateRequest>()
                    .ok()
                    .map(|request| request.signer.0),
            ),
            REFUSE_ENROLMENT => write(
                params
                    .parse::<RefuseEnrolmentRequest>()
                    .ok()
                    .map(|request| request.auth.authority.0),
            ),
            CREATE_RECORDS_REGISTRY => write(
                params
                    .parse::<CreateRecordsRegistryRequest>()
                    .ok()
                    .map(|request| request.auth.authority.0),
            ),
            SET_READER_GRANT => write(
                params
                    .parse::<SetReaderGrantRequest>()
                    .ok()
                    .and_then(|request| request.wallet)
                    .map(|wallet| wallet.0),
            ),
            SET_MERGE_SETTINGS => write(
                params
                    .parse::<SetMergeSettingsRequest>()
                    .ok()
                    .map(|request| request.owner.0),
            ),
            PREPARE_AUTHORITY_TRANSFER => write(
                params
                    .parse::<PrepareAuthorityTransferRequest>()
                    .ok()
                    .map(|request| request.delegate.0),
            ),
            SUBMIT_RELAY => write(
                params
                    .parse::<SubmitRelayRequest>()
                    .ok()
                    .map(|request| request.signer.0),
            ),
            // `prepareRelay` and every unlisted method charge only the client.
            _ => write(None),
        }
    }
}

impl ClientLayer {
    pub(crate) fn new(policy: ClientIdentityPolicy) -> Self {
        Self(Arc::new(policy))
    }
}

impl<Inner> Layer<Inner> for ClientLayer {
    type Service = ClientService<Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        ClientService {
            inner,
            policy: self.0.clone(),
        }
    }
}

impl<Inner, B> Service<HttpRequest<B>> for ClientService<Inner>
where
    Inner: Service<HttpRequest<B>, Response = HttpResponse>,
    Inner::Error: Into<BoxError> + 'static,
    Inner::Future: Send + 'static,
{
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut request: HttpRequest<B>) -> Self::Future {
        let identity = request
            .extensions()
            .get::<PeerAddress>()
            .map(|peer| self.policy.identify(peer.0.ip(), &request));
        match identity {
            Some(Ok(client)) => {
                request.extensions_mut().insert(client);
            }
            Some(Err(UnknownApiKey)) => {
                return Box::pin(async { Ok(unknown_api_key()) });
            }
            // The RPC layer refuses a call with no client.
            None => {}
        }
        let future = self.inner.call(request);
        Box::pin(async move {
            let mut response = future.await.map_err(Into::into)?;
            if let Some(limited) = response.extensions().get::<RateLimited>().copied() {
                *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                response
                    .headers_mut()
                    .insert(RETRY_AFTER, HeaderValue::from(limited.retry_after_secs()));
            }
            Ok(response)
        })
    }
}

/// The body names no call id, the request body is never read.
fn unknown_api_key() -> HttpResponse {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": UNKNOWN_API_KEY, "message": "api key is unknown" },
        "id": null,
    });
    let mut response = HttpResponse::new(HttpBody::from(body.to_string()));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}
