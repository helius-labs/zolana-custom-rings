use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

use http_body_util::BodyExt;
use hyper::{body::Incoming, service::service_fn, Request, Response};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::net::TcpListener;

use super::*;
use crate::tests::database;

const UPSTREAM_STATUS: StatusCode = StatusCode::MULTI_STATUS;
const UPSTREAM_TYPE: &str = "application/json; charset=photon";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    method: Method,
    path: String,
    content_type: Option<String>,
    body: Bytes,
}

/// Answers every request with a body naming what it saw.
async fn upstream() -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let log = log.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let log = log.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        let path = parts.uri.path_and_query().unwrap().to_string();
                        let seen = Seen {
                            method: parts.method,
                            path: path.clone(),
                            content_type: parts
                                .headers
                                .get(CONTENT_TYPE)
                                .map(|value| value.to_str().unwrap().to_owned()),
                            body: body.collect().await.unwrap().to_bytes(),
                        };
                        log.lock().unwrap().push(seen);
                        let mut response =
                            Response::new(Full::new(Bytes::from(format!("upstream {path}"))));
                        *response.status_mut() = UPSTREAM_STATUS;
                        response
                            .headers_mut()
                            .insert(CONTENT_TYPE, HeaderValue::from_static(UPSTREAM_TYPE));
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{address}"), seen)
}

async fn indexer(photon: &str) -> (String, ServerHandle) {
    let (address, handle) = Server {
        db: Arc::new(database().await),
        rpc: Arc::new(SolanaRpc::new("http://127.0.0.1:1".into())),
        photon: photon.parse().unwrap(),
        readiness: Readiness::default(),
        max_connections: 16,
    }
    .start("127.0.0.1:0".parse().unwrap())
    .await
    .unwrap();
    (format!("http://{address}"), handle)
}

/// Photon's JSON-RPC contract, one path per method.
fn photon_methods() -> Vec<String> {
    let spec = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../zolana/services/photon/src/openapi/specs/rings.yaml"
    ))
    .unwrap();
    spec.lines()
        .filter_map(|line| line.strip_prefix("  /")?.strip_suffix(':'))
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn every_photon_method_passes_through_unchanged() {
    let (photon, seen) = upstream().await;
    let (url, handle) = indexer(&photon).await;
    let client = reqwest::Client::new();
    let methods = photon_methods();
    assert_eq!(methods.len(), 8, "{methods:?}");
    for method in &methods {
        let body = format!(
            r#"{{ "jsonrpc": "2.0", "id": 7, "method": "{method}", "params": {{ "tags": ["a"] }} }}"#
        );
        for path in [
            format!("/v1/zolana/{method}?api-key=secret"),
            "/?api-key=secret".to_owned(),
        ] {
            let response = client
                .post(format!("{url}{path}"))
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), UPSTREAM_STATUS, "{path}");
            assert_eq!(response.headers()[CONTENT_TYPE], UPSTREAM_TYPE);
            assert_eq!(response.text().await.unwrap(), format!("upstream {path}"));
            assert_eq!(
                seen.lock().unwrap().pop(),
                Some(Seen {
                    method: Method::POST,
                    path,
                    content_type: Some("application/json".into()),
                    body: Bytes::from(body.clone()),
                })
            );
        }
    }
    let batch = r#"[{"jsonrpc":"2.0","id":1,"method":"getSlot"}]"#;
    let response = client.post(&url).body(batch).send().await.unwrap();
    assert_eq!(response.status(), UPSTREAM_STATUS);
    assert_eq!(seen.lock().unwrap().pop().unwrap().body, batch);
    let response = client.get(format!("{url}/readiness")).send().await.unwrap();
    assert_eq!(response.status(), UPSTREAM_STATUS);
    assert_eq!(seen.lock().unwrap().pop().unwrap().method, Method::GET);
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn ring_methods_and_refused_paths_never_reach_photon() {
    let (photon, seen) = upstream().await;
    let (url, handle) = indexer(&photon).await;
    let client = reqwest::Client::new();
    for method in RING_METHODS {
        let body = format!(r#"{{"jsonrpc":"2.0","id":7,"method":"{method}","params":{{}}}}"#);
        for path in [format!("/v1/zolana/{method}"), "/".to_owned()] {
            let answer: serde_json::Value = client
                .post(format!("{url}{path}"))
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone())
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(answer["error"]["code"], -32602, "{method} {path} {answer}");
        }
    }
    let response = client
        .post(format!("{url}/v1/zolana/getMerkleProofs"))
        .body(r#"{"jsonrpc":"2.0","id":7,"method":"getStorageMemberRecords"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        client
            .get(format!("{url}/health"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(format!("{url}/ready"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(seen.lock().unwrap().is_empty());
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn an_unreachable_photon_is_a_bad_gateway() {
    let (url, handle) = indexer("http://127.0.0.1:1").await;
    let response = reqwest::Client::new()
        .post(&url)
        .body(r#"{"jsonrpc":"2.0","id":7,"method":"getUserRecords"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    handle.stop().unwrap();
    handle.stopped().await;
}

#[test]
fn photon_urls_are_bases_without_query() {
    assert_eq!(
        "https://photon.example/v1/".parse::<PhotonUrl>().unwrap().0,
        "https://photon.example/v1"
    );
    assert!("https://photon.example/?api-key=1"
        .parse::<PhotonUrl>()
        .is_err());
    assert!("ftp://photon.example".parse::<PhotonUrl>().is_err());
}
