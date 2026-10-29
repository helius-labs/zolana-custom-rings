use std::{collections::HashSet, future::Future, sync::Arc};

use async_trait::async_trait;
use sea_orm::TransactionTrait;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use tokio::sync::Mutex;
use zolana_ring_policy::{AssetLimits, Member};

use crate::{
    cosign::CoSigner as CoSignerTrait,
    cosign::{
        AssetFlow, CoSignDecision, CoSignError, CoSignRefusal, CoSignRequest, CoSignSettlement,
    },
    cosign_usage::{Reservation, Reserve, UsageLedger, UsageWindow},
    database::Store,
    error::RingRpcError,
};

pub trait AssetLimitSource: Send + Sync {
    fn current_slot(&self) -> impl Future<Output = Result<u64, RingRpcError>> + Send;

    /// In `assets` order, zero for an asset without a record.
    fn asset_limits(
        &self,
        ring: Address,
        assets: &[Address],
    ) -> impl Future<Output = Result<Vec<AssetLimits>, RingRpcError>> + Send;
}

pub struct LimitedCoSignerInit<L> {
    pub signer: Keypair,
    pub limits: L,
    pub store: Arc<Store>,
}

pub struct LimitedCoSigner<L> {
    signer: Keypair,
    limits: L,
    store: Arc<Store>,
    /// Held from the usage read until the reservation commits.
    reserving: Mutex<()>,
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
            reserving: Mutex::new(()),
        }
    }
}

#[async_trait]
impl<L: AssetLimitSource> CoSignerTrait for LimitedCoSigner<L> {
    async fn decide(&self, request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError> {
        // 1. Each asset is named once and has its limits from the ring's registry.
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
            .map(|(flow, limits)| AssetCheck {
                flow: *flow,
                limits,
            })
            .collect();
        let signature = self.signer.sign_message(&request.message.serialize());

        // 2. A repeated message keeps its one reservation.
        let _reserving = self.reserving.lock().await;
        let transaction = self.store.connection().begin().await?;
        let ledger = UsageLedger { conn: &transaction };
        if ledger.reserved(&signature).await? {
            return Ok(CoSignDecision::Signed(signature));
        }

        // 3. The window read and the reservation commit in one database transaction.
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
    let ring = |cap, measure| WindowCap {
        cap,
        window_slots: limits.volume_window_slots,
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
        ring(limits.volume_cap, Measure::Volume),
        ring(limits.deposit_cap, Measure::Deposited),
        ring(limits.withdrawal_cap, Measure::Withdrawn),
    ]
}

fn longest_window(checks: &[AssetCheck]) -> u64 {
    checks
        .iter()
        .flat_map(|check| {
            [
                check.limits.sender_window_slots,
                check.limits.volume_window_slots,
            ]
        })
        .max()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::{cosign::CoSignDemand, CoSignScope};
    use solana_message::{Message, VersionedMessage};

    use super::*;

    const ASSET: Address = Address::new_from_array([3; 32]);
    const SENDER_LIMITS: AssetLimits = AssetLimits {
        sender_cap: 100,
        sender_window_slots: 50,
        volume_cap: 0,
        volume_window_slots: 0,
        deposit_cap: 0,
        withdrawal_cap: 0,
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

    struct FixedLimits;

    impl AssetLimitSource for FixedLimits {
        async fn current_slot(&self) -> Result<u64, RingRpcError> {
            Ok(1_000)
        }

        async fn asset_limits(
            &self,
            _ring: Address,
            assets: &[Address],
        ) -> Result<Vec<AssetLimits>, RingRpcError> {
            Ok(vec![SENDER_LIMITS; assets.len()])
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
            demand: CoSignDemand {
                approval_required: true,
                classes: CoSignScope::TRANSFERS,
                withdrawals: Vec::new(),
            },
            flows: vec![transfer(amount)],
        }
    }

    #[tokio::test]
    async fn a_failed_transfer_frees_its_usage() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = LimitedCoSignerInit {
            signer: Keypair::new_from_array([5; 32]),
            limits: FixedLimits,
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
}
