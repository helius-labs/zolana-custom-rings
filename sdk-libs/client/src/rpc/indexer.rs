use async_trait::async_trait;
use spr_api::{ApiError, BlockingInsideRuntime, ZolanaApi};
use spr_client::{
    indexer::{indexer_error, AsyncZolanaIndexer, ZolanaIndexer},
    AsyncZolanaClient, Blocking, ClientError, ZolanaClient,
};
use spr_indexer_api::RpcMethod;
use thiserror::Error;
use zolana_ring_indexer::rpc::{
    method::{
        GetRingApplyProofInputs, GetRingMemberOpenings, GetRingMemberRecord, GetRingMemberRecords,
        GetRingMemberRegistryRoot, GetRingRecordPool, GetRingRecordQueue,
        GetStorageApplyProofInputs,
    },
    RingRpcError,
};

#[derive(Debug, Error)]
pub enum RingIndexerError {
    #[error(transparent)]
    Refused(#[from] RingRpcError),
    #[error(transparent)]
    Client(#[from] ClientError),
}

impl From<BlockingInsideRuntime> for RingIndexerError {
    fn from(error: BlockingInsideRuntime) -> Self {
        Self::Client(error.into())
    }
}

macro_rules! ring_indexer {
    ($($name:ident => $method:ty),+ $(,)?) => {
        pub trait RingIndexer {
            $(fn $name(
                &self,
                _request: <$method as RpcMethod>::Request,
            ) -> Result<<$method as RpcMethod>::Response, RingIndexerError> {
                Err(unsupported::<$method>())
            })+
        }

        #[async_trait]
        pub trait AsyncRingIndexer: Send + Sync {
            $(async fn $name(
                &self,
                _request: <$method as RpcMethod>::Request,
            ) -> Result<<$method as RpcMethod>::Response, RingIndexerError> {
                Err(unsupported::<$method>())
            })+
        }

        impl RingIndexer for ZolanaIndexer {
            $(fn $name(
                &self,
                request: <$method as RpcMethod>::Request,
            ) -> Result<<$method as RpcMethod>::Response, RingIndexerError> {
                self.runtime().block_on(call::<$method>(self.api(), request))
            })+
        }

        #[async_trait]
        impl AsyncRingIndexer for AsyncZolanaIndexer {
            $(async fn $name(
                &self,
                request: <$method as RpcMethod>::Request,
            ) -> Result<<$method as RpcMethod>::Response, RingIndexerError> {
                call::<$method>(self.api(), request).await
            })+
        }

        impl<R, I: RingIndexer> RingIndexer for ZolanaClient<R, I> {
            $(fn $name(
                &self,
                request: <$method as RpcMethod>::Request,
            ) -> Result<<$method as RpcMethod>::Response, RingIndexerError> {
                self.indexer().$name(request)
            })+
        }

        #[async_trait]
        impl<I: RingIndexer + Send + Sync + 'static> AsyncRingIndexer for Blocking<I> {
            $(async fn $name(
                &self,
                request: <$method as RpcMethod>::Request,
            ) -> Result<<$method as RpcMethod>::Response, RingIndexerError> {
                let indexer = self.clone();
                tokio::task::spawn_blocking(move || indexer.inner().$name(request))
                    .await
                    .map_err(|error| {
                        ClientError::Rpc(format!("blocking call failed: {error}"))
                    })?
            })+
        }

        #[async_trait]
        impl<R: Send + Sync, I: AsyncRingIndexer> AsyncRingIndexer for AsyncZolanaClient<R, I> {
            $(async fn $name(
                &self,
                request: <$method as RpcMethod>::Request,
            ) -> Result<<$method as RpcMethod>::Response, RingIndexerError> {
                self.indexer().$name(request).await
            })+
        }
    };
}

ring_indexer! {
    get_ring_member_record => GetRingMemberRecord,
    get_ring_member_records => GetRingMemberRecords,
    get_ring_member_openings => GetRingMemberOpenings,
    get_ring_record_pool => GetRingRecordPool,
    get_ring_member_registry_root => GetRingMemberRegistryRoot,
    get_ring_record_queue => GetRingRecordQueue,
    get_ring_apply_proof_inputs => GetRingApplyProofInputs,
    get_storage_apply_proof_inputs => GetStorageApplyProofInputs,
}

async fn call<M: RpcMethod>(
    api: &ZolanaApi,
    request: M::Request,
) -> Result<M::Response, RingIndexerError> {
    api.call::<M>(request).await.map_err(ring_error)
}

fn ring_error(error: ApiError) -> RingIndexerError {
    if let ApiError::JsonRpc {
        code: Some(code), ..
    } = &error
    {
        if let Some(refusal) = RingRpcError::from_code(*code) {
            return refusal.into();
        }
    }
    indexer_error(error).into()
}

fn unsupported<M: RpcMethod>() -> RingIndexerError {
    ClientError::UnsupportedRpcMethod(M::NAME).into()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use http::{HeaderMap, StatusCode};
    use serde_json::{json, Value};
    use spr_api::{
        BlockingHttpClient, BlockingZolanaApi, HttpClient, HttpFuture, HttpRequest, HttpResponse,
    };
    use spr_indexer_api::{Hash, SerializablePubkey};
    use zolana_ring_indexer::rpc::GetRingRecordQueueRequest;

    use super::*;

    #[derive(Clone, Debug)]
    struct Canned {
        response: Value,
        sent: Arc<Mutex<Option<(String, Value)>>>,
    }

    impl Canned {
        fn new(response: Value) -> Self {
            Self {
                response,
                sent: Arc::default(),
            }
        }

        fn answer(&self, request: HttpRequest) -> Result<HttpResponse, ApiError> {
            let body = serde_json::from_slice(&request.body).unwrap();
            *self.sent.lock().unwrap() = Some((request.url.clone(), body));
            Ok(HttpResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: serde_json::to_vec(&self.response).unwrap(),
            })
        }

        fn sent(&self) -> (String, Value) {
            self.sent.lock().unwrap().clone().unwrap()
        }
    }

    impl HttpClient for Canned {
        fn send<'a>(&'a self, request: HttpRequest) -> HttpFuture<'a> {
            let answer = self.answer(request);
            Box::pin(async move { answer })
        }
    }

    impl BlockingHttpClient for Canned {
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, ApiError> {
            self.answer(request)
        }
    }

    fn rpc_result(result: Value) -> Value {
        json!({"id": "test-account", "jsonrpc": "2.0", "result": result})
    }

    fn query() -> GetRingRecordQueueRequest {
        GetRingRecordQueueRequest {
            ring_program_id: SerializablePubkey::from([1; 32]),
        }
    }

    fn queue_result(slot: u64) -> Value {
        rpc_result(json!({
            "context": {"blockTime": 90, "slot": slot},
            "head": 3,
            "tail": 4,
            "chainHead": Hash([5; 32]),
            "entries": [{
                "position": 3,
                "member": Hash([2; 32]),
                "mask": 1,
                "value": 1,
                "escrowKey": Hash([0; 32]),
                "slot": slot - 1,
            }],
        }))
    }

    #[test]
    fn record_queue_transport_returns_the_pending_writes() {
        let http = Canned::new(queue_result(20));
        let indexer = ZolanaIndexer::with_api(BlockingZolanaApi::with_client(
            "http://indexer",
            http.clone(),
        ));
        let response = indexer.get_ring_record_queue(query()).unwrap();
        let (url, body) = http.sent();
        assert_eq!(url, "http://indexer/getRingRecordQueue");
        assert_eq!(body["method"], "getRingRecordQueue");
        assert_eq!(body["params"], serde_json::to_value(query()).unwrap());
        assert_eq!(response.context.slot, 20);
        assert_eq!((response.head, response.tail), (3, 4));
        assert_eq!(response.entries[0].member, Hash([2; 32]));
    }

    #[tokio::test]
    async fn async_record_queue_transport_returns_the_pending_writes() {
        let http = Canned::new(queue_result(21));
        let indexer =
            AsyncZolanaIndexer::with_api(ZolanaApi::with_client("http://indexer", http.clone()));
        let response = indexer.get_ring_record_queue(query()).await.unwrap();
        assert_eq!(http.sent().1["method"], "getRingRecordQueue");
        assert_eq!(response.context.slot, 21);
        assert_eq!(response.entries.len(), 1);
    }

    #[test]
    fn preserves_ring_error_codes() {
        for expected in RingRpcError::ALL {
            let error = ring_error(ApiError::JsonRpc {
                method: GetRingRecordQueue::NAME,
                code: Some(i64::from(expected.code())),
                message: Some("projection error".into()),
            });
            assert!(
                matches!(error, RingIndexerError::Refused(refused) if refused == expected),
                "{expected:?}"
            );
        }
        let other = ring_error(ApiError::JsonRpc {
            method: GetRingRecordQueue::NAME,
            code: Some(-32603),
            message: Some("internal".into()),
        });
        assert!(matches!(
            other,
            RingIndexerError::Client(ClientError::IndexerUnavailable(_))
        ));
    }
}
