use solana_address::Address;
use zolana_ring_client::rpc::{
    ConfigAuthorityAuth, CreateRecords, CreateRecordsRegistryRequest,
    CreateRecordsRegistryResponse, EnrolmentAction, EnrolmentAttestation,
    GetPendingEnrolmentsRequest, GetPendingEnrolmentsResponse, ListEnrolments, ReadTarget,
    RecordUpdateStatus, RefuseEnrolment, RefuseEnrolmentRequest,
};

use crate::{
    authorize::WalletCheck, error::RingRpcError, hub::Hub, replay::ReplayCheck,
    upstream::TransactionSource,
};

impl<S: TransactionSource> Hub<S> {
    pub async fn pending_enrolments(
        &self,
        request: &GetPendingEnrolmentsRequest,
    ) -> Result<GetPendingEnrolmentsResponse, RingRpcError> {
        let ring = request.ring.0;
        let action = ListEnrolments {
            cursor: request.cursor.clone(),
        };
        let authority = self.authorize_enrolment(ring, &request.auth, action)?;
        self.record_writer()?
            .pending_enrolments(authority, request)
            .await
    }

    pub async fn refuse_enrolment(
        &self,
        request: &RefuseEnrolmentRequest,
    ) -> Result<RecordUpdateStatus, RingRpcError> {
        let ring = request.ring.0;
        let action = RefuseEnrolment(request.update_id.clone());
        let authority = self.authorize_enrolment(ring, &request.auth, action)?;
        self.record_writer()?
            .refuse_enrolment(ring, authority, &request.update_id)
            .await
    }

    /// The upgrade authority signs before the config exists, the config authority after.
    pub async fn create_records_registry(
        &self,
        request: &CreateRecordsRegistryRequest,
    ) -> Result<CreateRecordsRegistryResponse, RingRpcError> {
        let ring = request.ring.0;
        let writer = self.record_writer()?;
        let authority = self.authorize_enrolment(ring, &request.auth, CreateRecords)?;
        self.shared()
            .require_ring_authority(ring, authority)
            .await?;
        Ok(CreateRecordsRegistryResponse {
            registry: writer.create_records(ring).await?.into(),
            storage_authority: writer.authority().into(),
        })
    }

    /// Signature and nonce only, the writer checks the config authority.
    fn authorize_enrolment<A: EnrolmentAction>(
        &self,
        ring: Address,
        auth: &ConfigAuthorityAuth,
        action: A,
    ) -> Result<Address, RingRpcError> {
        let shared = self.shared();
        let authority = auth.authority.0;
        let now = shared.clock.now()?;
        let nonce = WalletCheck {
            wallet: authority,
            timestamp: auth.timestamp,
            nonce: &auth.nonce,
            signature: &auth.signature,
            attestation: &EnrolmentAttestation {
                target: ReadTarget {
                    cluster: shared.genesis_hash,
                    service: shared.service,
                    ring,
                },
                authority,
                action,
            },
            now,
        }
        .decide()?;
        shared.replay.accept(ReplayCheck {
            ring,
            nonce,
            timestamp: auth.timestamp,
            now,
        })?;
        Ok(authority)
    }
}
