//! The Ring RPC methods the ring policy authority signs.
//! Read `record_update` after for the pending state, and `record_writer` for how an approval lands.

use solana_address::Address;
use zolana_ring_client::rpc::{
    CreateRecords, CreateRecordsRegistryRequest, CreateRecordsRegistryResponse,
    GetPendingListApprovalsRequest, GetPendingListApprovalsResponse, ListPendingApprovals,
    PolicyAuthorityAction, PolicyAuthorityAttestation, PolicyAuthorityAuth, ReadTarget,
    RecordUpdateStatus, RefuseListApproval, RefuseListApprovalRequest,
};

use crate::{
    authorize::WalletCheck, error::RingRpcError, hub::Hub, replay::ReplayCheck,
    upstream::TransactionSource,
};

impl<S: TransactionSource> Hub<S> {
    pub async fn pending_list_approvals(
        &self,
        request: &GetPendingListApprovalsRequest,
    ) -> Result<GetPendingListApprovalsResponse, RingRpcError> {
        let ring = request.ring.0;
        let action = ListPendingApprovals {
            registry: request.registry.0,
            cursor: request.cursor.clone(),
        };
        let authority = self
            .authorize_policy_action(ring, &request.auth, action)
            .await?;
        self.record_writer()?
            .pending_list_approvals(authority, request)
            .await
    }

    pub async fn refuse_list_approval(
        &self,
        request: &RefuseListApprovalRequest,
    ) -> Result<RecordUpdateStatus, RingRpcError> {
        let ring = request.ring.0;
        let action = RefuseListApproval {
            registry: request.registry.0,
            update_id: request.update_id.clone(),
        };
        let authority = self
            .authorize_policy_action(ring, &request.auth, action)
            .await?;
        self.record_writer()?
            .refuse_list_approval(authority, request)
            .await
    }

    /// The upgrade authority signs before `Initialize`, the policy authority after.
    pub async fn create_records_registry(
        &self,
        request: &CreateRecordsRegistryRequest,
    ) -> Result<CreateRecordsRegistryResponse, RingRpcError> {
        let ring = request.ring.0;
        let writer = self.record_writer()?;
        let authority = self
            .authorize_policy_action(ring, &request.auth, CreateRecords)
            .await?;
        self.shared()
            .require_ring_authority(ring, authority)
            .await?;
        Ok(CreateRecordsRegistryResponse {
            registry: writer.create_records(ring).await?.into(),
            storage_authority: writer.authority().into(),
        })
    }

    /// Signature and nonce only, the writer checks the policy authority.
    async fn authorize_policy_action<A: PolicyAuthorityAction>(
        &self,
        ring: Address,
        auth: &PolicyAuthorityAuth,
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
            attestation: &PolicyAuthorityAttestation {
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
        shared
            .replay
            .accept(ReplayCheck {
                ring,
                nonce,
                timestamp: auth.timestamp,
                now,
            })
            .await?;
        Ok(authority)
    }
}
