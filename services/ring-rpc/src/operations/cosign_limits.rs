use std::{collections::HashSet, future::Future, sync::Arc};

use async_trait::async_trait;
use sea_orm::TransactionTrait;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_ring_policy::{AssetLimits, Member};

use crate::{
    cosign::CoSignPolicy,
    cosign::{
        AssetFlow, CoSignDecision, CoSignError, CoSignRefusal, CoSignRequest, CoSignSettlement,
    },
    cosign_usage::{Reservation, Reserve, UsageLedger, UsageWindow},
    database::Store,
    error::RingRpcError,
    hub::Shared,
    upstream::{RecordsTip, TransactionSource, VerifiedOpenings},
};

pub trait AssetLimitSource: Send + Sync {
    fn current_slot(&self) -> impl Future<Output = Result<u64, RingRpcError>> + Send;

    /// In `assets` order, `None` for an asset without a record.
    fn asset_limits(
        &self,
        ring: Address,
        assets: &[Address],
    ) -> impl Future<Output = Result<Vec<Option<AssetLimits>>, RingRpcError>> + Send;
}

/// Reads each asset record under the newest root of the ring's records registry.
pub(crate) struct RecordLimits<S>(pub(crate) Arc<Shared<S>>);

pub struct LimitedCoSignerInit<L> {
    pub signer: Keypair,
    pub limits: L,
    pub store: Arc<Store>,
}

pub struct LimitedCoSigner<L> {
    signer: Keypair,
    limits: L,
    store: Arc<Store>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetCheck {
    pub flow: AssetFlow,
    pub limits: AssetLimits,
}

/// Windows end at the current `slot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowUsage {
    pub slot: u64,
    pub reservations: Vec<Reservation>,
}

#[must_use]
pub struct LimitDecision<'a> {
    pub sender: &'a Member,
    pub assets: &'a [AssetCheck],
    pub usage: &'a WindowUsage,
}

#[derive(Clone, Copy)]
enum Measure {
    Outflow,
    Volume,
    Deposited,
    Withdrawn,
}

#[derive(Clone, Copy)]
enum Scope {
    Sender,
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
        }
    }
}

#[async_trait]
impl<L: AssetLimitSource> CoSignPolicy for LimitedCoSigner<L> {
    fn signer(&self) -> Option<Address> {
        Some(self.signer.pubkey())
    }

    async fn decide(&self, request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError> {
        // 1. Each asset is named once and has a record in the ring's registry.
        let assets: Vec<Address> = request.flows.iter().map(|flow| flow.asset).collect();
        if assets.iter().collect::<HashSet<_>>().len() != assets.len() {
            return Err(CoSignError::RepeatedAsset.into());
        }
        let slot = self.limits.current_slot().await?;
        let limits = self.limits.asset_limits(request.ring, &assets).await?;
        if limits.len() != assets.len() {
            return Err(CoSignError::LimitsUnavailable.into());
        }
        let checks: Vec<AssetCheck> = request
            .flows
            .iter()
            .zip(limits)
            .map(|(flow, recorded)| {
                recorded.map(|limits| AssetCheck {
                    flow: *flow,
                    limits,
                })
            })
            .collect::<Option<_>>()
            .ok_or(CoSignError::UnrecordedAsset)?;
        let signature = self.signer.sign_message(&request.message.serialize());

        // 2. Co-signers sharing the store decide one at a time for each asset.
        let transaction = self.store.connection().begin().await?;
        let ledger = UsageLedger { conn: &transaction };
        ledger.admit(&request.ring, &assets).await?;

        // 3. A repeated message keeps its one reservation.
        if ledger.reserved(&signature).await? {
            return Ok(CoSignDecision::Signed(signature));
        }

        // 4. The window read and the reservation commit in one database transaction.
        let usage = WindowUsage {
            slot,
            reservations: ledger
                .window(UsageWindow {
                    ring: &request.ring,
                    assets: &assets,
                    since_slot: slot.saturating_sub(longest_window(&checks)),
                })
                .await?,
        };
        let decision = LimitDecision {
            sender: &request.sender,
            assets: &checks,
            usage: &usage,
        }
        .decide(signature);
        if let CoSignDecision::Signed(_) = decision {
            ledger
                .reserve(Reserve {
                    signature: &signature,
                    ring: &request.ring,
                    sender: &request.sender,
                    slot,
                    flows: &request.flows,
                })
                .await?;
        }
        transaction.commit().await?;
        Ok(decision)
    }

    async fn settle(&self, settlement: CoSignSettlement) -> Result<(), RingRpcError> {
        let ledger = UsageLedger {
            conn: self.store.connection(),
        };
        match settlement {
            CoSignSettlement::Confirmed(signature) => ledger.confirm(&signature).await?,
            CoSignSettlement::Failed(signature) => ledger.free(&signature).await?,
        }
        Ok(())
    }
}

impl<S: TransactionSource> AssetLimitSource for RecordLimits<S> {
    async fn current_slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.0.source.slot().await?)
    }

    /// No record without a ring policy, refused without a records registry.
    async fn asset_limits(
        &self,
        ring: Address,
        assets: &[Address],
    ) -> Result<Vec<Option<AssetLimits>>, RingRpcError> {
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
            .map(|opening| opening.record().map(|record| record.mint_policy.limits))
            .collect())
    }
}

impl LimitDecision<'_> {
    /// `signature` is the co-signature over the request message.
    pub fn decide(self, signature: Signature) -> CoSignDecision {
        let within = self.assets.iter().all(|check| {
            window_caps(&check.limits)
                .iter()
                .all(|cap| self.within(check.flow, cap))
        });
        match within {
            true => CoSignDecision::Signed(signature),
            false => CoSignDecision::Refused(CoSignRefusal::OverLimit),
        }
    }

    fn within(&self, flow: AssetFlow, cap: &WindowCap) -> bool {
        if cap.cap == 0 {
            return true;
        }
        let earlier: u128 = self
            .usage
            .reservations
            .iter()
            .filter(|reservation| {
                reservation.flow.asset == flow.asset
                    && self.usage.slot.saturating_sub(reservation.slot) < cap.window_slots
                    && match cap.scope {
                        Scope::Sender => reservation.sender == *self.sender.as_bytes(),
                        Scope::Ring => true,
                    }
            })
            .map(|reservation| cap.measure.of(&reservation.flow))
            .sum();
        earlier + cap.measure.of(&flow) <= u128::from(cap.cap)
    }
}

impl Measure {
    fn of(self, flow: &AssetFlow) -> u128 {
        let [transferred, deposited, withdrawn] =
            [flow.transferred, flow.deposited, flow.withdrawn].map(u128::from);
        match self {
            Self::Outflow => transferred + withdrawn,
            Self::Volume => transferred + deposited + withdrawn,
            Self::Deposited => deposited,
            Self::Withdrawn => withdrawn,
        }
    }
}

/// A zero window counts the checked transaction alone.
fn window_caps(limits: &AssetLimits) -> [WindowCap; 4] {
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
            scope: Scope::Sender,
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

fn longest_window(checks: &[AssetCheck]) -> u64 {
    checks
        .iter()
        .flat_map(|check| window_caps(&check.limits))
        .map(|cap| cap.window_slots)
        .max()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use sea_orm::ConnectionTrait;
    use solana_message::{Message, VersionedMessage};

    use super::*;

    const ASSET: Address = Address::new_from_array([3; 32]);
    const SENDER_LIMITS: AssetLimits = AssetLimits {
        sender_cap: 100,
        sender_window_slots: 50,
        ..AssetLimits::EMPTY
    };

    fn member(byte: u8) -> Member {
        Member::from_bytes([byte; 32]).expect("member")
    }

    fn transfer(amount: u64) -> AssetFlow {
        AssetFlow {
            asset: ASSET,
            transferred: amount,
            deposited: 0,
            withdrawn: 0,
        }
    }

    #[test]
    fn a_second_transfer_over_the_sender_window_cap_is_refused() {
        let sender = member(7);
        let signature = Signature::from([1; 64]);
        let usage = |slot| WindowUsage {
            slot,
            reservations: vec![Reservation {
                sender: *sender.as_bytes(),
                slot: 1_000,
                flow: transfer(60),
            }],
        };
        let decide = |sender: &Member, usage: &WindowUsage| {
            LimitDecision {
                sender,
                assets: &[AssetCheck {
                    flow: transfer(60),
                    limits: SENDER_LIMITS,
                }],
                usage,
            }
            .decide(signature)
        };

        assert_eq!(
            decide(&sender, &usage(1_049)),
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );
        assert_eq!(
            decide(&sender, &usage(1_050)),
            CoSignDecision::Signed(signature)
        );
        assert_eq!(
            decide(&member(8), &usage(1_049)),
            CoSignDecision::Signed(signature)
        );
    }

    #[test]
    fn a_deposit_never_offsets_the_sender_outflow() {
        let sender = member(7);
        let signature = Signature::from([1; 64]);
        let decision = LimitDecision {
            sender: &sender,
            assets: &[AssetCheck {
                flow: AssetFlow {
                    asset: ASSET,
                    transferred: 80,
                    deposited: 60,
                    withdrawn: 30,
                },
                limits: SENDER_LIMITS,
            }],
            usage: &WindowUsage {
                slot: 1_000,
                reservations: Vec::new(),
            },
        }
        .decide(signature);

        assert_eq!(decision, CoSignDecision::Refused(CoSignRefusal::OverLimit));
    }

    struct FixedLimits(Option<AssetLimits>);

    impl AssetLimitSource for FixedLimits {
        async fn current_slot(&self) -> Result<u64, RingRpcError> {
            Ok(1_000)
        }

        async fn asset_limits(
            &self,
            _ring: Address,
            assets: &[Address],
        ) -> Result<Vec<Option<AssetLimits>>, RingRpcError> {
            Ok(vec![self.0; assets.len()])
        }
    }

    fn request(nonce: u8, amount: u64) -> CoSignRequest {
        CoSignRequest {
            ring: Address::new_from_array([9; 32]),
            message: VersionedMessage::Legacy(Message {
                account_keys: vec![Address::new_from_array([nonce; 32])],
                ..Message::default()
            }),
            sender: member(7),
            flows: vec![transfer(amount)],
        }
    }

    #[tokio::test]
    async fn a_failed_transfer_frees_its_usage() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = LimitedCoSignerInit {
            signer: Keypair::new_from_array([5; 32]),
            limits: FixedLimits(Some(SENDER_LIMITS)),
            store: Arc::new(store),
        }
        .build();
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
        let co_signer = LimitedCoSignerInit {
            signer: Keypair::new_from_array([5; 32]),
            limits: FixedLimits(None),
            store: Arc::new(store),
        }
        .build();

        assert!(matches!(
            co_signer.decide(&request(1, 1)).await,
            Err(RingRpcError::CoSign(CoSignError::UnrecordedAsset))
        ));
    }

    async fn co_signer(url: &str) -> Arc<LimitedCoSigner<FixedLimits>> {
        let store = Store::open(url, crate::database::STORE_CONNECTIONS)
            .await
            .expect("store");
        Arc::new(
            LimitedCoSignerInit {
                signer: Keypair::new_from_array([5; 32]),
                limits: FixedLimits(Some(SENDER_LIMITS)),
                store: Arc::new(store),
            }
            .build(),
        )
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
        store
            .connection()
            .execute_unprepared("DELETE FROM cosign_usage")
            .await
            .expect("empty usage");
        assert_two_co_signers_share_one_allowance(&url).await;
    }
}
