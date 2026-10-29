use std::{
    borrow::Cow,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Result;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::Bytes,
    header::{HeaderValue, CONTENT_TYPE},
    Method, StatusCode, Uri,
};
use jsonrpsee::{
    core::{BoxError, TEN_MB_SIZE_BYTES},
    server::{HttpBody, HttpRequest, HttpResponse, ServerBuilder, ServerConfig, ServerHandle},
    types::{error::ErrorCode, ErrorObjectOwned},
    RpcModule,
};
use sea_orm::DatabaseConnection;
use serde::Deserialize;
use spr_indexer_api::RpcMethod;
use spr_rpc_http::MethodPathLayer;
use tower::{Layer, Service};
use tower_http::cors::{Any, CorsLayer};
use zolana_ring_indexer::rpc::method::{
    GetRingApplyProofInputs, GetRingMemberOpenings, GetRingMemberRecord, GetRingMemberRecords,
    GetRingMemberRegistryRoot, GetRingRecordPool, GetRingRecordQueue, GetStorageApplyProofInputs,
    GetStorageMemberOpenings, GetStorageMemberRecords, GetStorageRecordPool,
};

use crate::{
    api::{self, CachedChain},
    indexer::Readiness,
    rpc::SolanaRpc,
};

/// Served here, every other call goes to Photon untouched.
pub const RING_METHODS: [&str; 11] = [
    GetRingMemberRecord::NAME,
    GetRingMemberRecords::NAME,
    GetRingMemberOpenings::NAME,
    GetRingRecordPool::NAME,
    GetRingMemberRegistryRoot::NAME,
    GetRingRecordQueue::NAME,
    GetRingApplyProofInputs::NAME,
    GetStorageMemberOpenings::NAME,
    GetStorageMemberRecords::NAME,
    GetStorageRecordPool::NAME,
    GetStorageApplyProofInputs::NAME,
];

const MAX_BODY_BYTES: u32 = TEN_MB_SIZE_BYTES;
const PHOTON_TIMEOUT: Duration = Duration::from_secs(90);

/// A Photon base URL without query or fragment, request paths append to it.
#[derive(Clone, Debug)]
pub struct PhotonUrl(String);

impl FromStr for PhotonUrl {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let url = reqwest::Url::parse(value).map_err(|error| error.to_string())?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err("the Photon URL must be http or https".into());
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err("the Photon URL takes no query or fragment".into());
        }
        Ok(Self(url.as_str().trim_end_matches('/').to_owned()))
    }
}

pub(crate) struct Server {
    pub db: Arc<DatabaseConnection>,
    pub rpc: Arc<SolanaRpc>,
    pub photon: PhotonUrl,
    pub readiness: Readiness,
    pub max_connections: u32,
}

impl Server {
    pub async fn start(self, address: SocketAddr) -> Result<(SocketAddr, ServerHandle)> {
        let Self {
            db,
            rpc,
            photon,
            readiness,
            max_connections,
        } = self;
        let cors = CorsLayer::new()
            .allow_methods([Method::POST, Method::GET])
            .allow_origin(Any)
            .allow_headers([CONTENT_TYPE]);
        // Below the route, forwarded calls keep Photon's own path check.
        let middleware = tower::ServiceBuilder::new()
            .layer(cors)
            .layer(RouteLayer {
                photon: Arc::new(Photon::new(photon)?),
                readiness,
            })
            .layer(MethodPathLayer {
                max_body_size: MAX_BODY_BYTES as usize,
            });
        let server = ServerBuilder::default()
            .set_config(
                ServerConfig::builder()
                    .max_connections(max_connections)
                    .max_request_body_size(MAX_BODY_BYTES)
                    .build(),
            )
            .set_http_middleware(middleware)
            .build(address)
            .await?;
        Ok((
            server.local_addr()?,
            server.start(ring_methods(Lookups {
                db,
                chain: CachedChain::new(rpc),
            })?),
        ))
    }
}

struct Lookups {
    db: Arc<DatabaseConnection>,
    chain: CachedChain,
}

macro_rules! register {
    ($module:ident, $($method:ty => $read:path,)+) => {
        $($module.register_async_method(<$method>::NAME, |params, lookups, _| async move {
            $read(&lookups.db, &lookups.chain, params.parse()?)
                .await
                .map_err(ErrorObjectOwned::from)
        })?;)+
    };
}

fn ring_methods(lookups: Lookups) -> Result<RpcModule<Lookups>> {
    let mut module = RpcModule::new(lookups);
    register!(
        module,
        GetRingMemberRecord => api::member_record,
        GetRingMemberRecords => api::member_records,
        GetRingMemberOpenings => api::member_openings,
        GetRingRecordPool => api::record_pool,
        GetRingMemberRegistryRoot => api::registry_root,
        GetRingRecordQueue => api::record_queue,
        GetRingApplyProofInputs => api::apply_proof_inputs,
        GetStorageMemberOpenings => api::storage_member_openings,
        GetStorageMemberRecords => api::storage_member_records,
        GetStorageRecordPool => api::storage_record_pool,
        GetStorageApplyProofInputs => api::storage_apply_proof_inputs,
    );
    Ok(module)
}

#[derive(Clone)]
struct RouteLayer {
    photon: Arc<Photon>,
    readiness: Readiness,
}

impl<Inner> Layer<Inner> for RouteLayer {
    type Service = Route<Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        Route {
            inner,
            photon: self.photon.clone(),
            readiness: self.readiness.clone(),
        }
    }
}

#[derive(Clone)]
struct Route<Inner> {
    inner: Inner,
    photon: Arc<Photon>,
    readiness: Readiness,
}

/// Any other body shape goes to Photon.
#[derive(Deserialize)]
struct Call<'a> {
    #[serde(borrow)]
    method: Cow<'a, str>,
}

impl<Inner> Service<HttpRequest> for Route<Inner>
where
    Inner: Service<HttpRequest, Response = HttpResponse> + Clone + Send + 'static,
    Inner::Error: Into<BoxError> + 'static,
    Inner::Future: Send + 'static,
{
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: HttpRequest) -> Self::Future {
        // The service polled ready serves the current call, its clone serves the next.
        let ready = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, ready);
        let photon = self.photon.clone();
        let readiness = self.readiness.clone();
        Box::pin(async move {
            if request.method() == Method::GET {
                match request.uri().path() {
                    "/health" => return Ok(plain(StatusCode::OK, "ok")),
                    "/ready" if readiness.is_ready() => return Ok(plain(StatusCode::OK, "ready")),
                    "/ready" => return Ok(plain(StatusCode::SERVICE_UNAVAILABLE, "catching up")),
                    _ => {}
                }
            }
            let (parts, body) = request.into_parts();
            let Ok(collected) = Limited::new(body, MAX_BODY_BYTES as usize).collect().await else {
                return Ok(refusal(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::InvalidRequest,
                    "unreadable request body",
                ));
            };
            let body = collected.to_bytes();
            let ring_call = parts.method == Method::POST
                && serde_json::from_slice::<Call<'_>>(&body)
                    .is_ok_and(|call| RING_METHODS.contains(&call.method.as_ref()));
            if ring_call {
                let request = HttpRequest::from_parts(parts, HttpBody::new(Full::new(body)));
                return inner.call(request).await.map_err(Into::into);
            }
            Ok(photon
                .forward(Forwarded {
                    method: parts.method,
                    uri: parts.uri,
                    content_type: parts.headers.get(CONTENT_TYPE).cloned(),
                    body,
                })
                .await)
        })
    }
}

struct Photon {
    http: reqwest::Client,
    base: PhotonUrl,
}

struct Forwarded {
    method: Method,
    uri: Uri,
    content_type: Option<HeaderValue>,
    body: Bytes,
}

impl Photon {
    fn new(base: PhotonUrl) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .timeout(PHOTON_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            base,
        })
    }

    async fn forward(&self, request: Forwarded) -> HttpResponse {
        match self.send(request).await {
            Ok(response) => response,
            Err(error) => {
                log::warn!(
                    "photon did not answer ({:#})",
                    anyhow::Error::from(error.without_url())
                );
                refusal(
                    StatusCode::BAD_GATEWAY,
                    ErrorCode::InternalError,
                    "photon did not answer",
                )
            }
        }
    }

    async fn send(&self, request: Forwarded) -> Result<HttpResponse, reqwest::Error> {
        let Forwarded {
            method,
            uri,
            content_type,
            body,
        } = request;
        let path = uri.path_and_query().map_or("/", |path| path.as_str());
        let mut upstream = self
            .http
            .request(method, format!("{}{path}", self.base.0))
            .body(body);
        if let Some(content_type) = content_type {
            upstream = upstream.header(CONTENT_TYPE, content_type);
        }
        let upstream = upstream.send().await?;
        let status = upstream.status();
        let content_type = upstream.headers().get(CONTENT_TYPE).cloned();
        let mut response = HttpResponse::new(HttpBody::new(Full::new(upstream.bytes().await?)));
        *response.status_mut() = status;
        if let Some(content_type) = content_type {
            response.headers_mut().insert(CONTENT_TYPE, content_type);
        }
        Ok(response)
    }
}

fn plain(status: StatusCode, body: &'static str) -> HttpResponse {
    let mut response = HttpResponse::new(HttpBody::from(body));
    *response.status_mut() = status;
    response
}

fn refusal(status: StatusCode, code: ErrorCode, message: &str) -> HttpResponse {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": code.code(), "message": message },
        "id": null,
    });
    let mut response = HttpResponse::new(HttpBody::from(body.to_string()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

#[cfg(test)]
mod tests;
