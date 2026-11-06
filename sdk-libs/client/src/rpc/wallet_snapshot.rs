use std::ops::ControlFlow;

use solana_address::Address;
use solana_signer::Signer;
use spr_api::{ApiError, SprApi};
use spr_indexer_api::{Base64String, RpcMethod};
use thiserror::Error;

use super::{
    DelegateNotesAttestation, DelegateNotesRequest, DelegateSnapshotReleaseAttestation,
    DelegateSnapshotReleaseRequest, GetDelegateNotesRequest, GetDelegateNotesResponse,
    GetWalletStatusRequest, GetWalletStatusResponse, ReadBuildError, ReadSigner, ReadTarget,
    RequestBuildError, WalletSnapshotReleaseAttestation, WalletSnapshotReleaseRequest,
    WalletStatusRequest, GET_DELEGATE_NOTES, GET_WALLET_STATUS, RELEASE_DELEGATE_SNAPSHOT,
    RELEASE_WALLET_SNAPSHOT, WALLET_SNAPSHOT_CURSOR_LEN, WALLET_SNAPSHOT_CURSOR_VERSION,
};

pub struct WalletSnapshotScope<'a> {
    pub target: ReadTarget,
    pub wallet: Address,
    pub signer: &'a dyn ReadSigner,
}

pub struct DelegateSnapshotScope<'a> {
    pub target: ReadTarget,
    pub owner: Address,
    pub delegate: &'a dyn Signer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletSnapshotPage {
    Wallet(GetWalletStatusResponse),
    Delegate(GetDelegateNotesResponse),
}

#[derive(Debug, Error)]
pub enum WalletSnapshotError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Read(#[from] ReadBuildError),
    #[error(transparent)]
    Request(#[from] RequestBuildError),
    #[error("wallet snapshot page is inconsistent")]
    InvalidPage,
    #[error("wallet snapshot release was not accepted")]
    ReleaseRefused,
    #[error("wallet snapshot read and release failed")]
    ReadAndRelease { read: Box<Self>, release: Box<Self> },
}

#[must_use]
pub struct WalletSnapshot<'a> {
    reader: SnapshotReader<'a>,
    state: SnapshotState,
}

enum SnapshotReader<'a> {
    Wallet(WalletSnapshotScope<'a>),
    Delegate(DelegateSnapshotScope<'a>),
}

#[derive(Default)]
struct SnapshotState {
    cursor: Option<Base64String>,
    release_cursor: Option<Base64String>,
    capture: Option<SnapshotCapture>,
    finished: bool,
}

struct SnapshotCapture {
    history_through: u64,
    expires_at: Option<u64>,
    enrollment: super::WalletEnrollment,
}

struct ReadWallet;
struct ReadDelegate;
struct ReleaseWallet;
struct ReleaseDelegate;

impl<'a> WalletSnapshot<'a> {
    pub fn new_wallet(scope: WalletSnapshotScope<'a>) -> Self {
        WalletSnapshot {
            reader: SnapshotReader::Wallet(scope),
            state: SnapshotState::default(),
        }
    }

    pub fn new_delegate(scope: DelegateSnapshotScope<'a>) -> Self {
        WalletSnapshot {
            reader: SnapshotReader::Delegate(scope),
            state: SnapshotState::default(),
        }
    }

    pub async fn next_page(
        &mut self,
        api: &SprApi,
    ) -> Result<Option<WalletSnapshotPage>, WalletSnapshotError> {
        if self.state.finished {
            self.close(api).await?;
            return Ok(None);
        }
        let result = self.read_page(api).await;
        match result {
            Ok(page) => {
                if let Err(error) = self.state.accept(page.status()) {
                    return Err(self.close_after_error(api, error).await);
                }
                // The terminal page reaches the caller first, its release runs and fails at the next call.
                Ok(Some(page))
            }
            Err(error) => Err(self.close_after_error(api, error).await),
        }
    }

    pub async fn close(&mut self, api: &SprApi) -> Result<(), WalletSnapshotError> {
        self.state.finished = true;
        let Some(cursor) = self.state.release_cursor.clone() else {
            return Ok(());
        };
        let accepted = match &self.reader {
            SnapshotReader::Wallet(scope) => {
                let request =
                    WalletSnapshotReleaseRequest::new(WalletSnapshotReleaseAttestation {
                        target: scope.target,
                        wallet: scope.wallet,
                        cursor,
                    })?
                    .sign(scope.signer)?;
                api.call::<ReleaseWallet>(request).await?
            }
            SnapshotReader::Delegate(scope) => {
                let request =
                    DelegateSnapshotReleaseRequest::new(DelegateSnapshotReleaseAttestation {
                        target: scope.target,
                        delegate: scope.delegate.pubkey(),
                        owner: scope.owner,
                        cursor,
                    })?
                    .sign(scope.delegate)?;
                api.call::<ReleaseDelegate>(request).await?
            }
        };
        if !accepted {
            return Err(WalletSnapshotError::ReleaseRefused);
        }
        self.state.release_cursor = None;
        Ok(())
    }

    pub async fn visit(
        &mut self,
        api: &SprApi,
        mut visitor: impl FnMut(WalletSnapshotPage) -> Result<ControlFlow<()>, WalletSnapshotError>,
    ) -> Result<(), WalletSnapshotError> {
        while let Some(page) = self.next_page(api).await? {
            match visitor(page) {
                Ok(ControlFlow::Continue(())) => {}
                Ok(ControlFlow::Break(())) => return self.close(api).await,
                Err(error) => return Err(self.close_after_error(api, error).await),
            }
        }
        Ok(())
    }

    async fn read_page(&self, api: &SprApi) -> Result<WalletSnapshotPage, WalletSnapshotError> {
        Ok(match &self.reader {
            SnapshotReader::Wallet(scope) => {
                let mut request = WalletStatusRequest::new(scope.target, scope.wallet);
                if let Some(cursor) = &self.state.cursor {
                    request = request.with_cursor(cursor.clone())?;
                }
                WalletSnapshotPage::Wallet(
                    api.call::<ReadWallet>(request.sign(scope.signer)?).await?,
                )
            }
            SnapshotReader::Delegate(scope) => {
                let request = DelegateNotesRequest::new(DelegateNotesAttestation {
                    target: scope.target,
                    delegate: scope.delegate.pubkey(),
                    owner: scope.owner,
                    cursor: self.state.cursor.clone(),
                })
                .sign(scope.delegate)?;
                WalletSnapshotPage::Delegate(api.call::<ReadDelegate>(request).await?)
            }
        })
    }

    async fn close_after_error(
        &mut self,
        api: &SprApi,
        error: WalletSnapshotError,
    ) -> WalletSnapshotError {
        match self.close(api).await {
            Ok(()) => error,
            Err(release) => WalletSnapshotError::ReadAndRelease {
                read: Box::new(error),
                release: Box::new(release),
            },
        }
    }
}

impl WalletSnapshotPage {
    pub fn status(&self) -> &GetWalletStatusResponse {
        match self {
            Self::Wallet(status) => status,
            Self::Delegate(page) => &page.status,
        }
    }
}

impl SnapshotState {
    fn accept(&mut self, page: &GetWalletStatusResponse) -> Result<(), WalletSnapshotError> {
        if let Some(cursor) = &page.cursor {
            validate_snapshot_cursor(cursor)?;
            if page.snapshot_expires_at.is_none() {
                return Err(WalletSnapshotError::InvalidPage);
            }
            if let Some(previous) = &self.release_cursor {
                let position = WALLET_SNAPSHOT_CURSOR_LEN - 32;
                if previous.0[..position] != cursor.0[..position]
                    || previous.0[position..] >= cursor.0[position..]
                {
                    return Err(WalletSnapshotError::InvalidPage);
                }
            }
        }
        if let Some(capture) = &self.capture {
            if capture.history_through != page.history_through
                || capture.expires_at != page.snapshot_expires_at
                || capture.enrollment != page.enrollment
                || !page.balances.is_empty()
            {
                return Err(WalletSnapshotError::InvalidPage);
            }
        } else {
            if page.snapshot_expires_at.is_some() && page.cursor.is_none() {
                return Err(WalletSnapshotError::InvalidPage);
            }
            self.capture = Some(SnapshotCapture {
                history_through: page.history_through,
                expires_at: page.snapshot_expires_at,
                enrollment: page.enrollment,
            });
        }
        if let Some(cursor) = &page.cursor {
            self.release_cursor = Some(cursor.clone());
        }
        self.cursor = page.cursor.clone();
        self.finished = self.cursor.is_none();
        Ok(())
    }
}

pub(crate) fn validate_snapshot_cursor(cursor: &Base64String) -> Result<(), ReadBuildError> {
    if cursor.0.len() != WALLET_SNAPSHOT_CURSOR_LEN || cursor.0[0] != WALLET_SNAPSHOT_CURSOR_VERSION
    {
        return Err(ReadBuildError::Cursor);
    }
    Ok(())
}

impl RpcMethod for ReadWallet {
    const NAME: &'static str = GET_WALLET_STATUS;
    type Request = GetWalletStatusRequest;
    type Response = GetWalletStatusResponse;
}

impl RpcMethod for ReadDelegate {
    const NAME: &'static str = GET_DELEGATE_NOTES;
    type Request = GetDelegateNotesRequest;
    type Response = GetDelegateNotesResponse;
}

impl RpcMethod for ReleaseWallet {
    const NAME: &'static str = RELEASE_WALLET_SNAPSHOT;
    type Request = GetWalletStatusRequest;
    type Response = bool;
}

impl RpcMethod for ReleaseDelegate {
    const NAME: &'static str = RELEASE_DELEGATE_SNAPSHOT;
    type Request = GetDelegateNotesRequest;
    type Response = bool;
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use http::{HeaderMap, StatusCode};
    use serde_json::{json, Value};
    use solana_keypair::Keypair;
    use solana_signature::Signature;
    use spr_api::{HttpClient, HttpFuture, HttpRequest, HttpResponse};

    use super::*;
    use crate::rpc::{Attestation, WalletEnrollment, WalletStatusAttestation};

    #[derive(Clone, Debug)]
    struct Canned {
        responses: Arc<Mutex<VecDeque<Value>>>,
        methods: Arc<Mutex<Vec<String>>>,
    }

    impl Canned {
        fn new(responses: Vec<Value>) -> Self {
            Self {
                responses: Arc::new(Mutex::new(responses.into())),
                methods: Arc::default(),
            }
        }
    }

    impl HttpClient for Canned {
        fn send<'a>(&'a self, request: HttpRequest) -> HttpFuture<'a> {
            let sent: Value = serde_json::from_slice(&request.body).unwrap();
            self.methods
                .lock()
                .unwrap()
                .push(sent["method"].as_str().unwrap().to_owned());
            let result = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("expected request");
            Box::pin(async move {
                Ok(HttpResponse {
                    status: StatusCode::OK,
                    headers: HeaderMap::new(),
                    body: serde_json::to_vec(
                        &json!({"jsonrpc": "2.0", "id": sent["id"], "result": result}),
                    )
                    .unwrap(),
                })
            })
        }
    }

    fn target() -> ReadTarget {
        ReadTarget {
            cluster: [1; 32],
            service: Address::new_from_array([2; 32]),
            ring: Address::new_from_array([3; 32]),
        }
    }

    fn cursor(position: u8) -> Base64String {
        let mut value = vec![2; 129];
        value[97..].fill(position);
        value.into()
    }

    fn page(cursor: Option<Base64String>) -> GetWalletStatusResponse {
        GetWalletStatusResponse {
            history_through: 10,
            enrollment: WalletEnrollment::Applied,
            snapshot_expires_at: Some(300),
            balances: vec![],
            notes: vec![],
            cursor,
        }
    }

    #[test]
    fn release_signature_binds_its_domain_and_cursor() {
        let signer = Keypair::new();
        let wallet = signer.pubkey();
        let release = WalletSnapshotReleaseAttestation {
            target: target(),
            wallet,
            cursor: cursor(1),
        };
        let request = WalletSnapshotReleaseRequest::new(release.clone())
            .unwrap()
            .at(1)
            .sign(&signer)
            .unwrap();
        let nonce: [u8; 32] = request.auth.nonce.0.try_into().unwrap();
        let signature = Signature::try_from(request.auth.signature.0.as_slice()).unwrap();
        assert!(signature.verify(wallet.as_ref(), &release.message(1, &nonce)));
        let read = WalletStatusAttestation {
            target: target(),
            wallet,
            cursor: Some(cursor(1)),
        };
        assert!(!signature.verify(wallet.as_ref(), &read.message(1, &nonce)));
        let changed = WalletSnapshotReleaseAttestation {
            cursor: cursor(2),
            ..release
        };
        assert!(!signature.verify(wallet.as_ref(), &changed.message(1, &nonce)));
    }

    #[test]
    fn release_refuses_legacy_and_empty_cursors() {
        let mut legacy = cursor(1);
        legacy.0[0] = 1;
        for cursor in [legacy, vec![].into()] {
            assert!(
                WalletSnapshotReleaseRequest::new(WalletSnapshotReleaseAttestation {
                    target: target(),
                    wallet: Address::new_from_array([4; 32]),
                    cursor,
                })
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn terminal_page_releases_the_captured_snapshot() {
        let http = Canned::new(vec![
            json!(page(Some(cursor(1)))),
            json!(page(None)),
            json!(true),
        ]);
        let api = SprApi::with_client("http://ring", http.clone());
        let signer = Keypair::new();
        let mut snapshot = WalletSnapshot::new_wallet(WalletSnapshotScope {
            target: target(),
            wallet: signer.pubkey(),
            signer: &signer,
        });
        assert!(snapshot.next_page(&api).await.unwrap().is_some());
        assert!(snapshot.next_page(&api).await.unwrap().is_some());
        assert!(snapshot.next_page(&api).await.unwrap().is_none());
        snapshot.close(&api).await.unwrap();
        assert_eq!(
            *http.methods.lock().unwrap(),
            [
                GET_WALLET_STATUS,
                GET_WALLET_STATUS,
                RELEASE_WALLET_SNAPSHOT
            ]
        );
    }

    #[tokio::test]
    async fn visitor_stop_releases_without_reading_another_page() {
        let http = Canned::new(vec![json!(page(Some(cursor(1)))), json!(true)]);
        let api = SprApi::with_client("http://ring", http.clone());
        let signer = Keypair::new();
        let mut snapshot = WalletSnapshot::new_delegate(DelegateSnapshotScope {
            target: target(),
            owner: signer.pubkey(),
            delegate: &signer,
        });
        http.responses.lock().unwrap()[0] = json!(GetDelegateNotesResponse {
            nullifier_secret: None,
            status: page(Some(cursor(1))),
        });
        snapshot
            .visit(&api, |_| Ok(ControlFlow::Break(())))
            .await
            .unwrap();
        assert_eq!(
            *http.methods.lock().unwrap(),
            [GET_DELEGATE_NOTES, RELEASE_DELEGATE_SNAPSHOT]
        );
    }

    #[tokio::test]
    async fn changed_capture_releases_and_refuses_the_page() {
        let mut changed = page(None);
        changed.history_through = 11;
        let http = Canned::new(vec![
            json!(page(Some(cursor(1)))),
            json!(changed),
            json!(true),
        ]);
        let api = SprApi::with_client("http://ring", http.clone());
        let signer = Keypair::new();
        let mut snapshot = WalletSnapshot::new_wallet(WalletSnapshotScope {
            target: target(),
            wallet: signer.pubkey(),
            signer: &signer,
        });
        snapshot.next_page(&api).await.unwrap();
        assert!(matches!(
            snapshot.next_page(&api).await,
            Err(WalletSnapshotError::InvalidPage)
        ));
        assert_eq!(
            http.methods.lock().unwrap().last().map(String::as_str),
            Some(RELEASE_WALLET_SNAPSHOT)
        );
    }

    #[tokio::test]
    async fn single_page_needs_no_release() {
        let single = GetWalletStatusResponse {
            snapshot_expires_at: None,
            ..page(None)
        };
        let http = Canned::new(vec![json!(single)]);
        let api = SprApi::with_client("http://ring", http.clone());
        let signer = Keypair::new();
        let mut snapshot = WalletSnapshot::new_wallet(WalletSnapshotScope {
            target: target(),
            wallet: signer.pubkey(),
            signer: &signer,
        });
        snapshot.next_page(&api).await.unwrap();
        assert!(snapshot.next_page(&api).await.unwrap().is_none());
        assert_eq!(*http.methods.lock().unwrap(), [GET_WALLET_STATUS]);
    }
}
