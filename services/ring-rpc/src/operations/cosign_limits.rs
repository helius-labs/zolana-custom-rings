use std::{
    collections::{BTreeSet, HashMap},
    future::Future,
    sync::Arc,
};

use async_trait::async_trait;
use custom_ring_interface::CoSignScope;
use sea_orm::{ConnectionTrait, DbErr, TransactionTrait};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_ring_policy::{
    ApprovalInputs, ApprovalMask, Member, MintPolicy, OwnerDebit, PublicGross,
};

use crate::{
    cosign::{
        AssetFlow, CoSignDecision, CoSignError, CoSignFlows, CoSignPolicy, CoSignRefusal,
        CoSignRequest, CoSignSettlement, CoSignerApproval, OwnerFlow,
    },
    cosign_usage::{
        AdmissionSlot, AssetScope, Measure, ReservationState, Reserve, UsageLedger, WindowSum,
        MAX_USAGE_FLOWS,
    },
    database::Store,
    error::RingRpcError,
    hub::Shared,
    record_update::MAX_LIMIT_WINDOW_SLOTS,
    transfer_debits::TransferDebits,
    upstream::{RecordsTip, TransactionSource, VerifiedOpenings},
};

pub trait AssetLimitSource: Send + Sync {
    fn current_slot(&self) -> impl Future<Output = Result<u64, RingRpcError>> + Send;

    /// In `assets` order, `None` for an asset without a record.
    fn asset_policies(
        &self,
        ring: Address,
        assets: &[Address],
    ) -> impl Future<Output = Result<Vec<Option<MintPolicy>>, RingRpcError>> + Send;

    /// The classes the ring's record of `signer` holds, none without a record.
    fn co_signer_scope(
        &self,
        ring: Address,
        signer: Address,
    ) -> impl Future<Output = Result<CoSignScope, RingRpcError>> + Send;

    /// One flow per owner and asset of the transfer `message` carries, refused on an unknown input.
    fn transfer_flows(
        &self,
        ring: Address,
        message: &VersionedMessage,
    ) -> impl Future<Output = Result<FrameRead, RingRpcError>> + Send;
}

/// What the frame a co-signer signs moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameRead {
    /// The delegate rail demands no class and no limit reads it.
    Delegate,
    Transfer(TransferRead),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRead {
    pub flows: Vec<OwnerFlow>,
    /// Clear on a frame of public legs alone.
    pub spends_note: bool,
    /// The frame's proven mask, `None` on a frame that carries none.
    pub approval_bits: Option<u8>,
    /// In run order, each covers the classes the earlier ones left.
    pub co_signers: Vec<Address>,
}

/// Reads each asset record under the newest root of the ring's records registry.
pub(crate) struct RecordLimits<S>(pub(crate) Arc<Shared<S>>);

pub struct LimitedCoSignerInit<L> {
    pub signer: Keypair,
    pub limits: L,
    pub store: Arc<Store>,
    pub approval: CoSignerApproval,
}

/// Window limits bind only the transactions that need its signature.
pub struct LimitedCoSigner<L> {
    signer: Keypair,
    limits: L,
    store: Arc<Store>,
    approval: CoSignerApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AssetCheck {
    pub asset: Address,
    pub policy: MintPolicy,
}

/// Each non-zero cap's window total before the transfer, the sender cap per owner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WindowTotals(HashMap<TotalKey, u128>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TotalKey {
    asset: Address,
    measure: Measure,
    /// `None` on a ring cap.
    owner: Option<[u8; 32]>,
}

/// The ledger reads a window per non-zero cap, ending at `slot`.
#[must_use]
struct TotalsRead<'a> {
    ring: &'a Address,
    slot: u64,
    flows: &'a [OwnerFlow],
    checks: &'a [AssetCheck],
}

#[must_use]
pub(crate) struct LimitDecision<'a> {
    pub flows: &'a [OwnerFlow],
    pub assets: &'a [AssetCheck],
    pub held: &'a WindowTotals,
}

#[derive(Clone, Copy)]
enum Scope {
    Owner,
    Ring,
}

struct WindowCap {
    cap: u64,
    window_slots: u64,
    measure: Measure,
    scope: Scope,
}

impl<L> LimitedCoSignerInit<L> {
    pub fn build(self) -> LimitedCoSigner<L> {
        LimitedCoSigner {
            signer: self.signer,
            limits: self.limits,
            store: self.store,
            approval: self.approval,
        }
    }
}

#[async_trait]
impl<L: AssetLimitSource> CoSignPolicy for LimitedCoSigner<L> {
    fn signer(&self) -> Option<Address> {
        Some(self.signer.pubkey())
    }

    async fn decide(&self, request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError> {
        // 1. The frame names every transfer outflow, an owner and asset appears once.
        let (flows, operation, run) = match &request.flows {
            CoSignFlows::Frame => {
                match self
                    .limits
                    .transfer_flows(request.ring, &request.message)
                    .await?
                {
                    // A delegate transfer demands no class, no limit reads it and nothing reserves.
                    FrameRead::Delegate => {
                        return Ok(CoSignDecision::Signed(
                            self.signer.sign_message(&request.message.serialize()),
                        ))
                    }
                    FrameRead::Transfer(read) => (
                        read.flows,
                        Operation::Transfer {
                            spends_note: read.spends_note,
                            approval_bits: read.approval_bits,
                        },
                        read.co_signers,
                    ),
                }
            }
            CoSignFlows::Published(flows) => (flows.clone(), Operation::Published, Vec::new()),
        };
        if flows.len() > MAX_USAGE_FLOWS {
            return Err(CoSignError::MessageScope.into());
        }
        let rows: BTreeSet<_> = flows
            .iter()
            .map(|flow| (*flow.owner.as_bytes(), flow.flow.asset))
            .collect();
        if rows.len() != flows.len() {
            return Err(CoSignError::RepeatedAsset.into());
        }
        // 2. Each asset has a record in the ring's registry.
        let assets: Vec<Address> = flows
            .iter()
            .map(|flow| flow.flow.asset)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let policies = self.limits.asset_policies(request.ring, &assets).await?;
        if policies.len() != assets.len() {
            return Err(CoSignError::LimitsUnavailable.into());
        }
        let checks: Vec<AssetCheck> = assets
            .iter()
            .zip(policies)
            .map(|(asset, recorded)| {
                recorded.map(|policy| AssetCheck {
                    asset: *asset,
                    policy,
                })
            })
            .collect::<Option<_>>()
            .ok_or(CoSignError::UnrecordedAsset)?;
        if checks
            .iter()
            .flat_map(|check| window_caps(&check.policy.limits))
            .any(|cap| cap.window_slots > MAX_LIMIT_WINDOW_SLOTS)
        {
            return Err(CoSignError::LimitsUnavailable.into());
        }
        // 3. Demanded classes its record holds and the earlier run left, each explicitly approved.
        let mask = approval_mask(&flows, &checks);
        let signer = self.signer.pubkey();
        let mut share = operation
            .demand(&flows, mask)
            .intersection(self.limits.co_signer_scope(request.ring, signer).await?);
        for earlier in run.iter().take_while(|approver| **approver != signer) {
            share = share.without(self.limits.co_signer_scope(request.ring, *earlier).await?);
        }
        if !operation.frame_holds(mask)
            || share.is_empty()
            || !self.approval.scope().contains(share)
        {
            return Ok(CoSignDecision::Refused(CoSignRefusal::NotApproved));
        }
        let signature = self.signer.sign_message(&request.message.serialize());

        let transaction = self.store.connection().begin().await?;
        let ledger = UsageLedger { conn: &transaction };
        let scope = AssetScope {
            ring: &request.ring,
            assets: &assets,
        };
        ledger.admit(scope).await?;
        match ledger.reservation_state(&signature).await? {
            Some(ReservationState::Held | ReservationState::Confirmed) => {
                return Ok(CoSignDecision::Signed(signature));
            }
            Some(ReservationState::Released) => return Err(CoSignError::ReleasedReservation.into()),
            None => {}
        }
        let slot = self.limits.current_slot().await?;
        if !ledger.slot_allowed(AdmissionSlot { scope, slot }).await? {
            transaction.rollback().await?;
            return Err(CoSignError::LimitsUnavailable.into());
        }
        let held = TotalsRead {
            ring: &request.ring,
            slot,
            flows: &flows,
            checks: &checks,
        }
        .read(&ledger)
        .await?;
        let decision = LimitDecision {
            flows: &flows,
            assets: &checks,
            held: &held,
        }
        .decide(signature);
        if let CoSignDecision::Signed(_) = decision {
            ledger
                .reserve(Reserve {
                    signature: &signature,
                    ring: &request.ring,
                    slot,
                    flows: &flows,
                })
                .await?;
        }
        if self.limits.current_slot().await? != slot {
            transaction.rollback().await?;
            return Err(CoSignError::LimitsUnavailable.into());
        }
        transaction.commit().await?;
        Ok(decision)
    }

    async fn settle(&self, settlement: CoSignSettlement) -> Result<(), RingRpcError> {
        let ledger = UsageLedger {
            conn: self.store.connection(),
        };
        let signature = match settlement {
            CoSignSettlement::Confirmed(signature) | CoSignSettlement::Failed(signature) => {
                signature
            }
        };
        let Some(scope) = ledger.settlement_scope(&signature).await? else {
            return Ok(());
        };
        let transaction = self.store.connection().begin().await?;
        let ledger = UsageLedger { conn: &transaction };
        ledger.admit(scope.as_scope()).await?;
        ledger.settle(settlement).await?;
        transaction.commit().await?;
        Ok(())
    }
}

impl<S: TransactionSource + 'static> AssetLimitSource for RecordLimits<S> {
    async fn current_slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.0.source.slot().await?)
    }

    /// No record without a ring policy, refused without a records registry.
    async fn asset_policies(
        &self,
        ring: Address,
        assets: &[Address],
    ) -> Result<Vec<Option<MintPolicy>>, RingRpcError> {
        if assets.is_empty() {
            return Ok(Vec::new());
        }
        let source = &self.0.source;
        let tip = match source.records_root(ring).await? {
            RecordsTip::NoPolicy => return Ok(vec![None; assets.len()]),
            RecordsTip::NoRegistry => return Err(CoSignError::LimitsUnavailable.into()),
            RecordsTip::Newest(tip) => tip,
        };
        let members = assets
            .iter()
            .map(|asset| Member::asset(asset).map(|member| *member.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CoSignError::LimitsUnavailable)?;
        Ok(source
            .verified_openings(&tip, &members)
            .await?
            .iter()
            .map(|opening| opening.record().map(|record| record.mint_policy))
            .collect())
    }

    async fn co_signer_scope(
        &self,
        ring: Address,
        signer: Address,
    ) -> Result<CoSignScope, RingRpcError> {
        Ok(self
            .0
            .source
            .co_signer_scope(ring, signer)
            .await?
            .unwrap_or(CoSignScope::NONE))
    }

    async fn transfer_flows(
        &self,
        ring: Address,
        message: &VersionedMessage,
    ) -> Result<FrameRead, RingRpcError> {
        TransferDebits {
            shared: &self.0,
            ring,
            message,
        }
        .flows()
        .await
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Transfer {
        spends_note: bool,
        approval_bits: Option<u8>,
    },
    /// A deposit's public leg, or nothing on a merge.
    Published,
}

/// The shared formula over the flows a reservation holds, the mint stands for its asset.
fn approval_mask(flows: &[OwnerFlow], checks: &[AssetCheck]) -> ApprovalMask {
    let debits: Vec<OwnerDebit> = flows
        .iter()
        .map(|flow| OwnerDebit {
            owner: *flow.owner.as_bytes(),
            asset: flow.flow.asset.to_bytes(),
            debit: flow.flow.debit,
            kept: 0,
            charge: 0,
            charged_outflow: flow.flow.charged_outflow,
        })
        .collect();
    let public_gross: Vec<PublicGross> = flows
        .iter()
        .map(|flow| PublicGross {
            asset: flow.flow.asset.to_bytes(),
            gross: flow.flow.withdrawn,
        })
        .collect();
    ApprovalInputs {
        flows: &debits,
        public_gross: &public_gross,
    }
    .mask(|asset| {
        checks
            .iter()
            .find(|check| check.asset.as_array() == asset)
            .map_or(MintPolicy::EMPTY, |check| check.policy)
    })
}

impl Operation {
    /// A frame's proven bits meet the thresholds the service reads, or it signs nothing.
    fn frame_holds(self, mask: ApprovalMask) -> bool {
        match self {
            Self::Transfer {
                approval_bits: Some(bits),
                ..
            } => bits == mask.bits(),
            Self::Transfer { .. } | Self::Published => true,
        }
    }

    /// The classes the ring's rule demands of the operation.
    fn demand(self, flows: &[OwnerFlow], mask: ApprovalMask) -> CoSignScope {
        let moved = |legs: fn(&AssetFlow) -> u128| flows.iter().any(|flow| legs(&flow.flow) != 0);
        let when = |held: bool, scope| if held { scope } else { CoSignScope::NONE };
        let deposits = moved(|flow| flow.deposited);
        let spends_note = match self {
            Self::Transfer { spends_note, .. } => spends_note,
            Self::Published => !deposits,
        };
        when(deposits, CoSignScope::DEPOSITS)
            | when(moved(|flow| flow.withdrawn), CoSignScope::WITHDRAWALS)
            | when(
                mask.contains(ApprovalMask::OUTFLOW),
                CoSignScope::APPROVE_OUTFLOW,
            )
            | when(
                mask.contains(ApprovalMask::WITHDRAWAL),
                CoSignScope::APPROVE_WITHDRAWAL,
            )
            | when(spends_note, CoSignScope::TRANSFERS)
    }
}

impl TotalsRead<'_> {
    async fn read<C: ConnectionTrait>(
        self,
        ledger: &UsageLedger<'_, C>,
    ) -> Result<WindowTotals, DbErr> {
        let mut totals = HashMap::new();
        for check in self.checks {
            for cap in window_caps(&check.policy.limits) {
                // A zero cap reads nothing, a zero window counts the checked transaction alone.
                if cap.cap == 0 || cap.window_slots == 0 {
                    continue;
                }
                let sum = WindowSum {
                    ring: self.ring,
                    asset: &check.asset,
                    measure: cap.measure,
                    slot: self.slot,
                    window_slots: cap.window_slots,
                };
                let key = |owner| TotalKey {
                    asset: check.asset,
                    measure: cap.measure,
                    owner,
                };
                match cap.scope {
                    Scope::Owner => {
                        let owners: Vec<[u8; 32]> = self
                            .flows
                            .iter()
                            .filter(|flow| flow.flow.asset == check.asset)
                            .map(|flow| *flow.owner.as_bytes())
                            .collect();
                        for (owner, total) in ledger.owner_totals(sum, &owners).await? {
                            totals.insert(key(Some(owner)), total);
                        }
                    }
                    Scope::Ring => {
                        totals.insert(key(None), ledger.ring_total(sum).await?);
                    }
                }
            }
        }
        Ok(WindowTotals(totals))
    }
}

impl WindowTotals {
    /// Zero under a zero window, `None` for a window the read skipped.
    fn held(&self, asset: Address, cap: &WindowCap, owner: Option<[u8; 32]>) -> Option<u128> {
        if cap.window_slots == 0 {
            return Some(0);
        }
        self.0
            .get(&TotalKey {
                asset,
                measure: cap.measure,
                owner,
            })
            .copied()
    }
}

impl LimitDecision<'_> {
    /// `signature` is the co-signature over the request message.
    pub fn decide(self, signature: Signature) -> CoSignDecision {
        let within = self.assets.iter().all(|check| {
            window_caps(&check.policy.limits)
                .iter()
                .all(|cap| self.within(check.asset, cap))
        });
        match within {
            true => CoSignDecision::Signed(signature),
            false => CoSignDecision::Refused(CoSignRefusal::OverLimit),
        }
    }

    fn within(&self, asset: Address, cap: &WindowCap) -> bool {
        // A zero cap sets no window limit, the approval decided the signature.
        if cap.cap == 0 {
            return true;
        }
        let of_asset = || self.flows.iter().filter(|flow| flow.flow.asset == asset);
        // An overflowing total lies past every u64 cap and refuses.
        let fits = |total: Option<u128>| total.is_some_and(|total| total <= u128::from(cap.cap));
        match cap.scope {
            // Credits never move between owners, each answers for its own debit.
            Scope::Owner => of_asset().all(|flow| {
                fits(
                    self.held
                        .held(asset, cap, Some(*flow.owner.as_bytes()))
                        .zip(cap.measure.of(&flow.flow))
                        .and_then(|(held, moved)| held.checked_add(moved)),
                )
            }),
            Scope::Ring => fits(self.held.held(asset, cap, None).and_then(|held| {
                of_asset()
                    .map(|flow| cap.measure.of(&flow.flow))
                    .try_fold(held, |total, moved| total.checked_add(moved?))
            })),
        }
    }
}

/// A zero window counts the checked transaction alone.
fn window_caps(limits: &zolana_ring_policy::AssetLimits) -> [WindowCap; 4] {
    let ring = |cap, window_slots, measure| WindowCap {
        cap,
        window_slots,
        measure,
        scope: Scope::Ring,
    };
    [
        WindowCap {
            cap: limits.sender_cap,
            window_slots: limits.sender_window_slots,
            measure: Measure::Outflow,
            scope: Scope::Owner,
        },
        ring(
            limits.volume_cap,
            limits.volume_window_slots,
            Measure::Volume,
        ),
        ring(
            limits.deposit_cap,
            limits.deposit_window_slots,
            Measure::Deposited,
        ),
        ring(
            limits.withdrawal_cap,
            limits.withdrawal_window_slots,
            Measure::Withdrawn,
        ),
    ]
}

#[cfg(test)]
#[path = "cosign_window_tests.rs"]
mod cosign_window_tests;

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        },
    };

    use sea_orm::ConnectionTrait;
    use solana_message::Message;
    use zolana_ring_policy::AssetLimits;

    use super::cosign_window_tests::clear_usage;
    use super::*;
    use crate::cosign::ApproveClass;

    const ASSET: Address = Address::new_from_array([3; 32]);
    const SENDER_LIMITS: AssetLimits = AssetLimits {
        sender_cap: 100,
        sender_window_slots: 50,
        ..AssetLimits::EMPTY
    };

    fn member(byte: u8) -> Member {
        Member::from_bytes([byte; 32]).expect("member")
    }

    fn debit(owner: u8, amount: u64) -> OwnerFlow {
        OwnerFlow {
            owner: member(owner),
            flow: AssetFlow {
                asset: ASSET,
                debit: amount.into(),
                charged_outflow: amount.into(),
                deposited: 0,
                withdrawn: 0,
            },
        }
    }

    /// One window total of `measure`, an owner's or the ring's.
    fn held(measure: Measure, owner: Option<u8>, total: u128) -> WindowTotals {
        WindowTotals(HashMap::from([(
            TotalKey {
                asset: ASSET,
                measure,
                owner: owner.map(|owner| [owner; 32]),
            },
            total,
        )]))
    }

    fn policy(limits: AssetLimits) -> MintPolicy {
        MintPolicy {
            limits,
            ..MintPolicy::EMPTY
        }
    }

    fn sender_check() -> [AssetCheck; 1] {
        [AssetCheck {
            asset: ASSET,
            policy: policy(SENDER_LIMITS),
        }]
    }

    /// A gross past `u64::MAX` signs under a zero cap and refuses under any cap, a held total past it refuses.
    #[test]
    fn a_gross_past_u64_signs_uncapped_and_an_overflowing_total_refuses() {
        let signature = Signature::from([1; 64]);
        let withdrawal = |withdrawn| OwnerFlow {
            owner: member(7),
            flow: AssetFlow {
                withdrawn,
                ..debit(7, 0).flow
            },
        };
        let limits = |withdrawal_cap| {
            [AssetCheck {
                asset: ASSET,
                policy: policy(AssetLimits {
                    withdrawal_cap,
                    withdrawal_window_slots: 50,
                    ..AssetLimits::EMPTY
                }),
            }]
        };
        let decide = |flows: &[OwnerFlow], cap: u64, held: &WindowTotals| {
            LimitDecision {
                flows,
                assets: &limits(cap),
                held,
            }
            .decide(signature)
        };
        let past_u64 = u128::from(u64::MAX) + 1;
        let idle = held(Measure::Withdrawn, None, 0);
        assert_eq!(
            decide(&[withdrawal(past_u64)], 0, &idle),
            CoSignDecision::Signed(signature)
        );
        assert_eq!(
            decide(&[withdrawal(past_u64)], u64::MAX, &idle),
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );
        let full = held(Measure::Withdrawn, None, past_u64);
        assert_eq!(
            decide(&[withdrawal(0)], u64::MAX, &full),
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );
    }

    #[test]
    fn each_owner_of_a_mixed_transfer_answers_for_its_own_window() {
        let signature = Signature::from([1; 64]);
        let mut usage = held(Measure::Outflow, Some(7), 60);
        usage.0.extend(held(Measure::Outflow, Some(8), 0).0);
        let decide = |flows: &[OwnerFlow]| {
            LimitDecision {
                flows,
                assets: &sender_check(),
                held: &usage,
            }
            .decide(signature)
        };
        assert_eq!(
            decide(&[debit(7, 40), debit(8, 100)]),
            CoSignDecision::Signed(signature),
            "each owner stays at its own cap"
        );
        assert_eq!(
            decide(&[debit(7, 41), debit(8, 1)]),
            CoSignDecision::Refused(CoSignRefusal::OverLimit),
            "a credit of one owner never pays for another"
        );
    }

    #[test]
    fn a_ring_cap_sums_every_owner_of_the_transfer() {
        let signature = Signature::from([1; 64]);
        let check = [AssetCheck {
            asset: ASSET,
            policy: policy(AssetLimits {
                volume_cap: 100,
                volume_window_slots: 50,
                ..AssetLimits::EMPTY
            }),
        }];
        let usage = held(Measure::Volume, None, 0);
        let decide = |flows: &[OwnerFlow]| {
            LimitDecision {
                flows,
                assets: &check,
                held: &usage,
            }
            .decide(signature)
        };
        assert_eq!(
            decide(&[debit(7, 60), debit(8, 40)]),
            CoSignDecision::Signed(signature)
        );
        assert_eq!(
            decide(&[debit(7, 60), debit(8, 41)]),
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );
    }

    struct FixedLimits {
        limits: Option<MintPolicy>,
        flows: Result<FrameRead, CoSignError>,
        /// A signer outside it holds every class.
        scopes: HashMap<Address, CoSignScope>,
    }

    impl AssetLimitSource for FixedLimits {
        async fn current_slot(&self) -> Result<u64, RingRpcError> {
            Ok(1_000)
        }

        async fn asset_policies(
            &self,
            _ring: Address,
            assets: &[Address],
        ) -> Result<Vec<Option<MintPolicy>>, RingRpcError> {
            Ok(vec![self.limits; assets.len()])
        }

        async fn co_signer_scope(
            &self,
            _ring: Address,
            signer: Address,
        ) -> Result<CoSignScope, RingRpcError> {
            Ok(self
                .scopes
                .get(&signer)
                .copied()
                .unwrap_or(CoSignScope::ALL))
        }

        async fn transfer_flows(
            &self,
            _ring: Address,
            _message: &VersionedMessage,
        ) -> Result<FrameRead, RingRpcError> {
            self.flows.clone().map_err(Into::into)
        }
    }

    struct TimedLimits {
        limits: FixedLimits,
        slots: Mutex<VecDeque<u64>>,
        policies_ready: AtomicBool,
    }

    impl AssetLimitSource for TimedLimits {
        async fn current_slot(&self) -> Result<u64, RingRpcError> {
            if !self.policies_ready.load(Ordering::SeqCst) {
                return Ok(1_000);
            }
            let mut slots = self.slots.lock().expect("slots");
            if slots.len() > 1 {
                Ok(slots.pop_front().expect("slot"))
            } else {
                Ok(*slots.front().expect("slot"))
            }
        }

        async fn asset_policies(
            &self,
            ring: Address,
            assets: &[Address],
        ) -> Result<Vec<Option<MintPolicy>>, RingRpcError> {
            let policies = self.limits.asset_policies(ring, assets).await?;
            self.policies_ready.store(true, Ordering::SeqCst);
            Ok(policies)
        }

        async fn co_signer_scope(
            &self,
            ring: Address,
            signer: Address,
        ) -> Result<CoSignScope, RingRpcError> {
            self.limits.co_signer_scope(ring, signer).await
        }

        async fn transfer_flows(
            &self,
            ring: Address,
            message: &VersionedMessage,
        ) -> Result<FrameRead, RingRpcError> {
            self.limits.transfer_flows(ring, message).await
        }
    }

    fn message(nonce: u8) -> VersionedMessage {
        VersionedMessage::Legacy(Message {
            account_keys: vec![Address::new_from_array([nonce; 32])],
            ..Message::default()
        })
    }

    fn request(nonce: u8, amount: u64) -> CoSignRequest {
        CoSignRequest {
            ring: Address::new_from_array([9; 32]),
            message: message(nonce),
            flows: CoSignFlows::Published(vec![debit(7, amount)]),
        }
    }

    async fn store_rows(store: &Store) -> usize {
        store
            .connection()
            .query_all(sea_orm::Statement::from_string(
                store.connection().get_database_backend(),
                "SELECT owner FROM cosign_usage WHERE state<>'released'",
            ))
            .await
            .expect("rows")
            .len()
    }

    fn all_classes() -> CoSignerApproval {
        CoSignerApproval::new([
            ApproveClass::Outflow,
            ApproveClass::Withdrawal,
            ApproveClass::Transfers,
            ApproveClass::Deposits,
            ApproveClass::Withdrawals,
        ])
    }

    fn service_key() -> Address {
        Keypair::new_from_array([5; 32]).pubkey()
    }

    fn signer_over(store: Store, limits: FixedLimits) -> LimitedCoSigner<FixedLimits> {
        approving(store, limits, all_classes())
    }

    fn approving(
        store: Store,
        limits: FixedLimits,
        approval: CoSignerApproval,
    ) -> LimitedCoSigner<FixedLimits> {
        LimitedCoSignerInit {
            signer: Keypair::new_from_array([5; 32]),
            limits,
            store: Arc::new(store),
            approval,
        }
        .build()
    }

    fn frame(flows: Vec<OwnerFlow>) -> FrameRead {
        FrameRead::Transfer(TransferRead {
            flows,
            spends_note: true,
            approval_bits: None,
            co_signers: Vec::new(),
        })
    }

    fn frame_request() -> CoSignRequest {
        CoSignRequest {
            ring: Address::new_from_array([9; 32]),
            message: message(1),
            flows: CoSignFlows::Frame,
        }
    }

    async fn decided(
        limits: MintPolicy,
        read: FrameRead,
        approval: CoSignerApproval,
    ) -> CoSignDecision {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        approving(
            store,
            FixedLimits {
                limits: Some(limits),
                flows: Ok(read),
                scopes: HashMap::from([(service_key(), approval.scope())]),
            },
            approval,
        )
        .decide(&frame_request())
        .await
        .expect("decision")
    }

    #[tokio::test]
    async fn zero_caps_with_no_approval_refuse() {
        assert_eq!(
            decided(
                MintPolicy::EMPTY,
                frame(vec![debit(7, 1_000_000)]),
                CoSignerApproval::default()
            )
            .await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved)
        );
    }

    #[tokio::test]
    async fn an_approved_class_signs_and_an_undemanded_one_does_not() {
        let transfer = frame(vec![debit(7, 10)]);
        assert!(matches!(
            decided(
                MintPolicy::EMPTY,
                transfer.clone(),
                CoSignerApproval::new([ApproveClass::Transfers])
            )
            .await,
            CoSignDecision::Signed(_)
        ));
        assert_eq!(
            decided(
                MintPolicy::EMPTY,
                transfer,
                CoSignerApproval::new([ApproveClass::Deposits])
            )
            .await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved)
        );
    }

    /// The owner spends 100 and takes 100 back while a public leg withdraws 100, its debit is zero and
    /// its charged outflow 100.
    #[tokio::test]
    async fn a_returned_spend_beside_a_withdrawal_demands_approval_by_its_charged_outflow() {
        use zolana_ring_policy::{DebitInput, DebitOutput};

        use crate::transfer_debits::{OwnerFlows, PublicFlow};

        let (owner, asset) = ([7; 32], [3; 32]);
        let flows = OwnerFlows {
            inputs: &[DebitInput {
                owner,
                asset,
                amount: 100,
            }],
            outputs: &[DebitOutput {
                ring: true,
                owner,
                asset,
                amount: 100,
            }],
            owner_signers: &[owner],
            public: &[PublicFlow {
                mint: ASSET,
                asset,
                deposited: 100,
                withdrawn: 100,
            }],
            no_spend_owner: member(0xee),
        }
        .rows(|_| Ok(ASSET))
        .expect("rows");
        assert_eq!(
            (flows[0].flow.debit, flows[0].flow.charged_outflow),
            (0, 100)
        );
        let read = || {
            FrameRead::Transfer(TransferRead {
                flows: flows.clone(),
                spends_note: true,
                approval_bits: None,
                co_signers: Vec::new(),
            })
        };
        let over = MintPolicy {
            cosign_above: 99,
            ..MintPolicy::EMPTY
        };
        assert_eq!(
            decided(over, read(), CoSignerApproval::new([])).await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved),
            "a zero debit demands no approval, the charged outflow does"
        );
        assert!(matches!(
            decided(over, read(), CoSignerApproval::new([ApproveClass::Outflow])).await,
            CoSignDecision::Signed(_)
        ));
    }

    #[tokio::test]
    async fn a_threshold_passes_demand_its_approval_class() {
        let over = MintPolicy {
            cosign_above: 100,
            withdrawal_threshold: 100,
            ..MintPolicy::EMPTY
        };
        let moved = |outflow, withdrawn| {
            FrameRead::Transfer(TransferRead {
                flows: vec![OwnerFlow {
                    owner: member(7),
                    flow: AssetFlow {
                        asset: ASSET,
                        debit: outflow,
                        charged_outflow: outflow,
                        deposited: 0,
                        withdrawn,
                    },
                }],
                spends_note: false,
                approval_bits: None,
                co_signers: Vec::new(),
            })
        };
        let outflow = CoSignerApproval::new([ApproveClass::Outflow]);
        let withdrawal = CoSignerApproval::new([ApproveClass::Withdrawal]);
        assert!(matches!(
            decided(over, moved(101, 0), outflow.clone()).await,
            CoSignDecision::Signed(_)
        ));
        assert_eq!(
            decided(over, moved(100, 0), outflow.clone()).await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved),
            "at the threshold no approval is demanded"
        );
        assert_eq!(
            decided(over, moved(101, 0), withdrawal.clone()).await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved),
            "an approver of the other class does not count"
        );
        assert!(matches!(
            decided(over, moved(0, 101), withdrawal).await,
            CoSignDecision::Signed(_)
        ));
    }

    #[tokio::test]
    async fn an_approver_signs_only_for_the_classes_the_earlier_run_left() {
        let other = Address::new_from_array([6; 32]);
        let over = MintPolicy {
            cosign_above: 100,
            withdrawal_threshold: 100,
            ..MintPolicy::EMPTY
        };
        let run = |co_signers| {
            FrameRead::Transfer(TransferRead {
                flows: vec![OwnerFlow {
                    owner: member(7),
                    flow: AssetFlow {
                        asset: ASSET,
                        debit: 101,
                        charged_outflow: 101,
                        deposited: 0,
                        withdrawn: 101,
                    },
                }],
                spends_note: false,
                approval_bits: None,
                co_signers,
            })
        };
        let decide = |co_signers| async {
            let store = Store::open("sqlite::memory:", 1).await.expect("store");
            approving(
                store,
                FixedLimits {
                    limits: Some(over),
                    flows: Ok(run(co_signers)),
                    scopes: HashMap::from([(
                        other,
                        CoSignScope::APPROVE_WITHDRAWAL | CoSignScope::WITHDRAWALS,
                    )]),
                },
                CoSignerApproval::new([ApproveClass::Outflow]),
            )
            .decide(&frame_request())
            .await
            .expect("decision")
        };
        assert!(matches!(
            decide(vec![other, service_key()]).await,
            CoSignDecision::Signed(_)
        ));
        assert_eq!(
            decide(vec![service_key()]).await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved),
            "alone its signature would cover the withdrawal it does not approve"
        );
    }

    #[tokio::test]
    async fn a_delegate_frame_reads_no_limit_and_reserves_nothing() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let reader = store.clone();
        let co_signer = approving(
            store,
            FixedLimits {
                limits: None,
                flows: Ok(FrameRead::Delegate),
                scopes: HashMap::new(),
            },
            CoSignerApproval::default(),
        );
        assert!(matches!(
            co_signer.decide(&frame_request()).await.expect("decision"),
            CoSignDecision::Signed(_)
        ));
        assert_eq!(store_rows(&reader).await, 0);
    }

    fn within_limits() -> FixedLimits {
        FixedLimits {
            limits: Some(policy(SENDER_LIMITS)),
            flows: Ok(frame(Vec::new())),
            scopes: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn a_failed_transfer_frees_its_usage() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(store, within_limits());
        let CoSignDecision::Signed(first) = co_signer.decide(&request(1, 60)).await.expect("first")
        else {
            panic!("the first transfer is within the cap");
        };
        assert_eq!(
            co_signer.decide(&request(2, 60)).await.expect("second"),
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );

        for _ in 0..2 {
            co_signer
                .settle(CoSignSettlement::Failed(first))
                .await
                .expect("settle");
        }
        assert!(matches!(
            co_signer.decide(&request(2, 60)).await.expect("retry"),
            CoSignDecision::Signed(_)
        ));
    }

    #[tokio::test]
    async fn a_transfer_of_an_unrecorded_asset_is_refused() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(
            store,
            FixedLimits {
                limits: None,
                flows: Ok(frame(Vec::new())),
                scopes: HashMap::new(),
            },
        );

        assert!(matches!(
            co_signer.decide(&request(1, 1)).await,
            Err(RingRpcError::CoSign(CoSignError::UnrecordedAsset))
        ));
    }

    #[tokio::test]
    async fn a_transfer_reserves_what_its_frame_names_and_never_a_caller_total() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(
            store,
            FixedLimits {
                limits: Some(policy(SENDER_LIMITS)),
                flows: Ok(frame(vec![debit(7, 101)])),
                scopes: HashMap::new(),
            },
        );
        let decision = co_signer
            .decide(&CoSignRequest {
                ring: Address::new_from_array([9; 32]),
                message: message(1),
                flows: CoSignFlows::Frame,
            })
            .await
            .expect("decision");
        assert_eq!(decision, CoSignDecision::Refused(CoSignRefusal::OverLimit));
    }

    #[tokio::test]
    async fn an_unknown_input_refuses_until_the_wallet_retries_after_ingestion() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(
            store,
            FixedLimits {
                limits: Some(policy(SENDER_LIMITS)),
                flows: Err(CoSignError::LimitsUnavailable),
                scopes: HashMap::new(),
            },
        );
        assert!(matches!(
            co_signer
                .decide(&CoSignRequest {
                    ring: Address::new_from_array([9; 32]),
                    message: message(1),
                    flows: CoSignFlows::Frame,
                })
                .await,
            Err(RingRpcError::CoSign(CoSignError::LimitsUnavailable))
        ));
    }

    fn timed_approver(
        store: &Store,
        slots: impl IntoIterator<Item = u64>,
    ) -> LimitedCoSigner<TimedLimits> {
        LimitedCoSignerInit {
            signer: Keypair::new_from_array([5; 32]),
            limits: TimedLimits {
                limits: within_limits(),
                slots: Mutex::new(slots.into_iter().collect()),
                policies_ready: AtomicBool::new(false),
            },
            store: Arc::new(store.clone()),
            approval: all_classes(),
        }
        .build()
    }

    #[tokio::test]
    async fn policy_reads_precede_admission_time() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = timed_approver(&store, [1_102, 1_102]);
        assert!(matches!(
            co_signer.decide(&request(1, 60)).await.expect("decision"),
            CoSignDecision::Signed(_)
        ));
        let rows = store
            .connection()
            .query_all(sea_orm::Statement::from_string(
                store.connection().get_database_backend(),
                "SELECT slot FROM cosign_usage",
            ))
            .await
            .expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].try_get::<i64>("", "slot").expect("slot"), 1_102);
        assert_eq!(
            co_signer.decide(&request(2, 41)).await.expect("decision"),
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );
    }

    #[tokio::test]
    async fn a_changed_admission_slot_releases_the_reservation() {
        for slots in [[1_051, 1_052], [1_051, 1_050]] {
            let store = Store::open("sqlite::memory:", 1).await.expect("store");
            let co_signer = timed_approver(&store, slots);
            assert!(matches!(
                co_signer.decide(&request(1, 60)).await,
                Err(RingRpcError::CoSign(CoSignError::LimitsUnavailable))
            ));
            assert_eq!(store_rows(&store).await, 0);
            assert!(matches!(
                co_signer
                    .decide(&request(2, 100))
                    .await
                    .expect("fresh retry"),
                CoSignDecision::Signed(_)
            ));
        }
    }

    #[tokio::test]
    async fn a_slot_change_never_returns_an_expired_over_limit_decision() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let first = signer_over(store.clone(), within_limits());
        assert!(matches!(
            first.decide(&request(1, 100)).await.expect("first"),
            CoSignDecision::Signed(_)
        ));
        let co_signer = timed_approver(&store, [1_049, 1_051]);
        assert!(matches!(
            co_signer.decide(&request(2, 1)).await,
            Err(RingRpcError::CoSign(CoSignError::LimitsUnavailable))
        ));
        assert!(matches!(
            co_signer.decide(&request(2, 1)).await.expect("fresh retry"),
            CoSignDecision::Signed(_)
        ));
    }

    #[tokio::test]
    async fn a_repeated_message_keeps_its_rows_and_settles_each_at_once() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let reader = store.clone();
        let co_signer = signer_over(store, within_limits());
        let mixed = || CoSignRequest {
            ring: Address::new_from_array([9; 32]),
            message: message(1),
            flows: CoSignFlows::Published(vec![debit(7, 10), debit(8, 20)]),
        };
        let CoSignDecision::Signed(signature) = co_signer.decide(&mixed()).await.expect("first")
        else {
            panic!("within the cap");
        };
        assert_eq!(store_rows(&reader).await, 2);
        assert_eq!(
            co_signer.decide(&mixed()).await.expect("retry"),
            CoSignDecision::Signed(signature)
        );
        assert_eq!(store_rows(&reader).await, 2, "a retry adds no row");
        co_signer
            .settle(CoSignSettlement::Failed(signature))
            .await
            .expect("settle");
        assert_eq!(store_rows(&reader).await, 0, "every row releases together");
    }

    #[tokio::test]
    async fn a_confirmed_message_keeps_every_row_through_a_late_failure() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let reader = store.clone();
        let co_signer = signer_over(store, within_limits());
        let CoSignDecision::Signed(signature) = co_signer
            .decide(&CoSignRequest {
                ring: Address::new_from_array([9; 32]),
                message: message(1),
                flows: CoSignFlows::Published(vec![debit(7, 10), debit(8, 20)]),
            })
            .await
            .expect("decision")
        else {
            panic!("within the cap");
        };
        co_signer
            .settle(CoSignSettlement::Confirmed(signature))
            .await
            .expect("confirm");
        co_signer
            .settle(CoSignSettlement::Failed(signature))
            .await
            .expect("late failure");
        assert_eq!(store_rows(&reader).await, 2);
    }

    #[tokio::test]
    async fn an_owner_and_asset_named_twice_is_refused() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(store, within_limits());
        assert!(matches!(
            co_signer
                .decide(&CoSignRequest {
                    ring: Address::new_from_array([9; 32]),
                    message: message(1),
                    flows: CoSignFlows::Published(vec![debit(7, 10), debit(7, 20)]),
                })
                .await,
            Err(RingRpcError::CoSign(CoSignError::RepeatedAsset))
        ));
    }

    async fn co_signer(url: &str) -> Arc<LimitedCoSigner<FixedLimits>> {
        let store = Store::open(url, crate::database::STORE_CONNECTIONS)
            .await
            .expect("store");
        Arc::new(signer_over(store, within_limits()))
    }

    async fn assert_two_co_signers_share_one_allowance(url: &str) {
        let co_signers = [co_signer(url).await, co_signer(url).await];
        let mut decisions = tokio::task::JoinSet::new();
        for nonce in 0..24u8 {
            let co_signer = co_signers[usize::from(nonce % 2)].clone();
            decisions.spawn(async move { co_signer.decide(&request(nonce, 20)).await });
        }
        let mut signed = 0;
        while let Some(decision) = decisions.join_next().await {
            if let CoSignDecision::Signed(_) = decision.expect("task").expect("decision") {
                signed += 1;
            }
        }
        assert_eq!(signed, 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_co_signers_over_one_sqlite_file_grant_the_allowance_once() {
        let path = std::env::temp_dir().join(format!("cosign-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_two_co_signers_share_one_allowance(&format!("sqlite://{}?mode=rwc", path.display()))
            .await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs RING_RPC_TEST_POSTGRES_URL"]
    async fn two_co_signers_over_one_postgres_store_grant_the_allowance_once() {
        let url = std::env::var("RING_RPC_TEST_POSTGRES_URL").expect("postgres url");
        let store = Store::open(&url, 1).await.expect("store");
        clear_usage(&store).await;
        assert_two_co_signers_share_one_allowance(&url).await;
    }
}
