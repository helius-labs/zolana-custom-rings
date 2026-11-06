//! Stored relays, every change passes `RelayState::apply` and lands only over the revision its writer
//! read.

use sea_orm::{ConnectionTrait, DbErr, QueryResult, Statement, Value};
use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use spr_indexer_api::{Base64String, Hash, SerializablePubkey, SerializableSignature};
use thiserror::Error;
use zolana_ring_client::rpc::RelayId;
use zolana_ring_policy::Member;

use crate::{
    cosign::{AssetFlow, CoSignFlows, OwnerFlow},
    relay_submit::CollectedSignature,
};

/// Holds no proof input.
#[derive(Clone)]
pub(crate) struct RelayRecord {
    pub message: VersionedMessage,
    pub last_valid_block_height: u64,
    pub state: RelayState,
}

#[derive(Clone)]
pub(crate) struct RelayRow {
    pub revision: RelayRevision,
    pub record: RelayRecord,
}

/// Raised by every committed write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelayRevision(u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelayState {
    AwaitingSignature(Awaiting),
    /// Stored before its first send, a restart resends the same transaction.
    Sent(SentAttempt),
    Confirmed {
        signature: Signature,
        slot: u64,
        co_signature: Option<Signature>,
    },
    Failed {
        reason: String,
        co_signature: Option<Signature>,
    },
}

/// A stored one awaits at least one wallet signer and reserves no co-sign allowance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Awaiting {
    pub signatures: Vec<CollectedSignature>,
    pub awaiting: Vec<Address>,
    /// Decided once no wallet signer is awaited.
    pub co_sign: Option<PendingCoSign>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SentAttempt {
    /// The fee payer's, the transaction's identity on chain.
    pub signature: Signature,
    pub signatures: Vec<CollectedSignature>,
    /// Settled with the co-signer when the relay ends.
    pub co_signature: Option<Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingCoSign {
    pub signer: Address,
    pub ring: Address,
    pub flows: CoSignFlows,
}

/// Made only once every wallet signer signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Closing {
    pub co_signature: Option<CollectedSignature>,
    pub fee_payer: CollectedSignature,
}

pub(crate) enum RelayEvent {
    /// The last awaited one carries the closing signatures.
    Signed {
        signature: CollectedSignature,
        closing: Option<Box<Closing>>,
    },
    Landed {
        slot: u64,
    },
    /// Landed and failed, the chain kept its fee.
    Reverted {
        reason: String,
    },
    /// Expired unlanded, the chain took nothing.
    Dropped {
        reason: String,
    },
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignerAdmission {
    /// The signer signed already, the same submission changes nothing.
    Collected,
    /// `last` once no other wallet signer is awaited, the signature then closes the relay.
    Awaited { last: bool },
}

#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Transition {
    Next(RelayState),
    /// The state already holds the event.
    Unchanged,
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum TransitionError {
    #[error("the relay awaits no signature from the signer")]
    UnexpectedSigner,
    #[error("the closing signatures do not match the awaited signers")]
    Closing,
    #[error("the relay was never sent")]
    Unsent,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Committed {
    Written(RelayRevision),
    /// Another writer moved the relay past the expected revision.
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayPhase {
    Pending,
    Confirmed,
    Failed,
}

pub(crate) struct RelayStore<'a, C> {
    db: &'a C,
}

const PENDING: [&str; 2] = ["awaitingSignature", "sent"];
const CONFIRMED: &str = "confirmed";
const FAILED: &str = "failed";

impl RelayRevision {
    pub const FIRST: Self = Self(0);

    fn next(self) -> Result<Self, DbErr> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| corrupt("revision"))
    }

    fn value(self) -> Result<Value, DbErr> {
        i64::try_from(self.0)
            .map(Value::from)
            .map_err(|_| corrupt("revision"))
    }
}

impl RelayState {
    /// A relay awaiting no wallet signer goes to `Sent`, only with the closing signatures.
    pub fn open(awaiting: Awaiting, closing: Option<Closing>) -> Result<Self, TransitionError> {
        match (awaiting.awaiting.is_empty(), closing) {
            (true, Some(closing)) => Ok(Self::Sent(awaiting.close(closing))),
            (false, None) => Ok(Self::AwaitingSignature(awaiting)),
            _ => Err(TransitionError::Closing),
        }
    }

    /// A terminal state holds every later event.
    pub fn apply(&self, event: RelayEvent) -> Result<Transition, TransitionError> {
        let next = match (self, event) {
            (Self::Confirmed { .. } | Self::Failed { .. }, _) => return Ok(Transition::Unchanged),
            (Self::AwaitingSignature(awaiting), RelayEvent::Signed { signature, closing }) => {
                if awaiting.admit(signature.signer)? == SignerAdmission::Collected {
                    return Ok(Transition::Unchanged);
                }
                let mut signed = awaiting.clone();
                signed
                    .awaiting
                    .retain(|awaited| *awaited != signature.signer);
                signed.signatures.push(signature);
                Self::open(signed, closing.map(|closing| *closing))?
            }
            (Self::Sent(_), RelayEvent::Signed { .. }) => return Ok(Transition::Unchanged),
            (Self::Sent(sent), RelayEvent::Landed { slot }) => Self::Confirmed {
                signature: sent.signature,
                slot,
                co_signature: sent.co_signature,
            },
            (
                Self::Sent(sent),
                RelayEvent::Reverted { reason } | RelayEvent::Dropped { reason },
            ) => Self::Failed {
                reason,
                co_signature: sent.co_signature,
            },
            // An expired message never reached the co-signer, it holds no allowance.
            (Self::AwaitingSignature(_), RelayEvent::Dropped { reason }) => Self::Failed {
                reason,
                co_signature: None,
            },
            (
                Self::AwaitingSignature(_),
                RelayEvent::Landed { .. } | RelayEvent::Reverted { .. },
            ) => return Err(TransitionError::Unsent),
        };
        Ok(Transition::Next(next))
    }

    pub fn co_signature(&self) -> Option<Signature> {
        match self {
            Self::AwaitingSignature(_) => None,
            Self::Sent(SentAttempt { co_signature, .. })
            | Self::Confirmed { co_signature, .. }
            | Self::Failed { co_signature, .. } => *co_signature,
        }
    }

    fn status(&self) -> &'static str {
        match self {
            Self::AwaitingSignature(_) => PENDING[0],
            Self::Sent(_) => PENDING[1],
            Self::Confirmed { .. } => CONFIRMED,
            Self::Failed { .. } => FAILED,
        }
    }
}

impl Awaiting {
    pub fn admit(&self, signer: Address) -> Result<SignerAdmission, TransitionError> {
        if self
            .signatures
            .iter()
            .any(|collected| collected.signer == signer)
        {
            return Ok(SignerAdmission::Collected);
        }
        match self.awaiting.contains(&signer) {
            true => Ok(SignerAdmission::Awaited {
                last: self.awaiting.len() == 1,
            }),
            false => Err(TransitionError::UnexpectedSigner),
        }
    }

    fn close(self, closing: Closing) -> SentAttempt {
        let Closing {
            co_signature,
            fee_payer,
        } = closing;
        SentAttempt {
            signature: fee_payer.signature,
            signatures: self
                .signatures
                .into_iter()
                .chain(co_signature)
                .chain([fee_payer])
                .collect(),
            co_signature: co_signature.map(|collected| collected.signature),
        }
    }
}

impl RelayPhase {
    pub(crate) fn of_status(status: &str) -> Result<Self, DbErr> {
        match status {
            CONFIRMED => Ok(Self::Confirmed),
            FAILED => Ok(Self::Failed),
            pending if PENDING.contains(&pending) => Ok(Self::Pending),
            _ => Err(corrupt("status")),
        }
    }
}

impl<'a, C: ConnectionTrait> RelayStore<'a, C> {
    pub fn new(db: &'a C) -> Self {
        Self { db }
    }

    pub async fn get(&self, id: &RelayId) -> Result<Option<RelayRow>, DbErr> {
        let sql = "SELECT state, revision FROM relay_relays WHERE relay_id=$1";
        let statement = self.statement(sql, vec![key(id)]);
        self.db
            .query_one(statement)
            .await?
            .map(|row| relay_row(&row))
            .transpose()
    }

    /// `false` when the relay is stored already, the first record stays.
    pub async fn insert(&self, id: &RelayId, record: &RelayRecord) -> Result<bool, DbErr> {
        let sql = "INSERT INTO relay_relays(relay_id,status,state,revision) VALUES($1,$2,$3,$4) \
                   ON CONFLICT(relay_id) DO NOTHING";
        let values = vec![
            key(id),
            record.state.status().into(),
            state(record)?,
            RelayRevision::FIRST.value()?,
        ];
        let result = self.db.execute(self.statement(sql, values)).await?;
        Ok(result.rows_affected() == 1)
    }

    /// A stale `expected` writes nothing, the caller then acts on the stored relay.
    pub async fn commit(
        &self,
        id: &RelayId,
        expected: RelayRevision,
        record: &RelayRecord,
    ) -> Result<Committed, DbErr> {
        let next = expected.next()?;
        let sql = "UPDATE relay_relays SET status=$2, state=$3, revision=$4 \
                   WHERE relay_id=$1 AND revision=$5";
        let values = vec![
            key(id),
            record.state.status().into(),
            state(record)?,
            next.value()?,
            expected.value()?,
        ];
        let result = self.db.execute(self.statement(sql, values)).await?;
        Ok(match result.rows_affected() {
            1 => Committed::Written(next),
            _ => Committed::Stale,
        })
    }

    pub async fn pending(&self) -> Result<Vec<RelayId>, DbErr> {
        let sql = "SELECT relay_id FROM relay_relays WHERE status IN ($1,$2)";
        let values = PENDING.map(Value::from).to_vec();
        self.db
            .query_all(self.statement(sql, values))
            .await?
            .iter()
            .map(|row| {
                let id: Vec<u8> = row.try_get("", "relay_id")?;
                let id: [u8; 32] = id.try_into().map_err(|_| corrupt("relay_id"))?;
                Ok(RelayId(id.into()))
            })
            .collect()
    }

    fn statement(&self, sql: &str, values: Vec<Value>) -> Statement {
        Statement::from_sql_and_values(self.db.get_database_backend(), sql, values)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredRelay {
    message: Base64String,
    last_valid_block_height: u64,
    state: StoredState,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum StoredState {
    AwaitingSignature {
        signatures: Vec<StoredSignature>,
        awaiting: Vec<SerializablePubkey>,
        co_sign: Option<StoredCoSign>,
    },
    Sent {
        signature: SerializableSignature,
        signatures: Vec<StoredSignature>,
        co_signature: Option<SerializableSignature>,
    },
    Confirmed {
        signature: SerializableSignature,
        slot: u64,
        co_signature: Option<SerializableSignature>,
    },
    Failed {
        reason: String,
        co_signature: Option<SerializableSignature>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredCoSign {
    signer: SerializablePubkey,
    ring: SerializablePubkey,
    /// `None` reads the debits from the signed frame.
    flows: Option<Vec<StoredFlow>>,
}

/// Amounts as decimal strings, the internally tagged state buffers numbers and refuses a `u128`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredFlow {
    owner: Hash,
    asset: SerializablePubkey,
    #[serde(with = "decimal")]
    debit: u128,
    #[serde(with = "decimal")]
    charged_outflow: u128,
    #[serde(with = "decimal")]
    deposited: u128,
    #[serde(with = "decimal")]
    withdrawn: u128,
}

mod decimal {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(amount: &u128, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(amount)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
struct StoredSignature {
    signer: SerializablePubkey,
    signature: SerializableSignature,
}

fn key(id: &RelayId) -> Value {
    id.0 .0.to_vec().into()
}

fn state(record: &RelayRecord) -> Result<Value, DbErr> {
    let stored = StoredRelay {
        message: record.message.serialize().into(),
        last_valid_block_height: record.last_valid_block_height,
        state: match &record.state {
            RelayState::AwaitingSignature(awaiting) => StoredState::AwaitingSignature {
                signatures: stored_signatures(&awaiting.signatures),
                awaiting: awaiting.awaiting.iter().copied().map(Into::into).collect(),
                co_sign: awaiting.co_sign.as_ref().map(stored_co_sign),
            },
            RelayState::Sent(sent) => StoredState::Sent {
                signature: sent.signature.into(),
                signatures: stored_signatures(&sent.signatures),
                co_signature: sent.co_signature.map(Into::into),
            },
            RelayState::Confirmed {
                signature,
                slot,
                co_signature,
            } => StoredState::Confirmed {
                signature: (*signature).into(),
                slot: *slot,
                co_signature: co_signature.map(Into::into),
            },
            RelayState::Failed {
                reason,
                co_signature,
            } => StoredState::Failed {
                reason: reason.clone(),
                co_signature: co_signature.map(Into::into),
            },
        },
    };
    serde_json::to_string(&stored)
        .map(Value::from)
        .map_err(|error| DbErr::Custom(error.to_string()))
}

fn stored_signatures(signatures: &[CollectedSignature]) -> Vec<StoredSignature> {
    signatures
        .iter()
        .map(|collected| StoredSignature {
            signer: collected.signer.into(),
            signature: collected.signature.into(),
        })
        .collect()
}

fn stored_co_sign(pending: &PendingCoSign) -> StoredCoSign {
    StoredCoSign {
        signer: pending.signer.into(),
        ring: pending.ring.into(),
        flows: match &pending.flows {
            CoSignFlows::Frame => None,
            CoSignFlows::Published(flows) => Some(
                flows
                    .iter()
                    .map(|OwnerFlow { owner, flow }| StoredFlow {
                        owner: Hash(*owner.as_bytes()),
                        asset: flow.asset.into(),
                        debit: flow.debit,
                        charged_outflow: flow.charged_outflow,
                        deposited: flow.deposited,
                        withdrawn: flow.withdrawn,
                    })
                    .collect(),
            ),
        },
    }
}

fn relay_row(row: &QueryResult) -> Result<RelayRow, DbErr> {
    let revision: i64 = row.try_get("", "revision")?;
    let state: String = row.try_get("", "state")?;
    let stored: StoredRelay = serde_json::from_str(&state).map_err(|_| corrupt("state"))?;
    Ok(RelayRow {
        revision: RelayRevision(u64::try_from(revision).map_err(|_| corrupt("revision"))?),
        record: RelayRecord {
            message: wincode::deserialize(&stored.message.0).map_err(|_| corrupt("message"))?,
            last_valid_block_height: stored.last_valid_block_height,
            state: relay_state(stored.state)?,
        },
    })
}

fn relay_state(stored: StoredState) -> Result<RelayState, DbErr> {
    Ok(match stored {
        // A relay awaiting nobody is sent before it is stored.
        StoredState::AwaitingSignature { awaiting, .. } if awaiting.is_empty() => {
            return Err(corrupt("state"))
        }
        StoredState::AwaitingSignature {
            signatures,
            awaiting,
            co_sign,
        } => RelayState::AwaitingSignature(Awaiting {
            signatures: collected_signatures(signatures),
            awaiting: awaiting.into_iter().map(|signer| signer.0).collect(),
            co_sign: co_sign.map(pending_co_sign).transpose()?,
        }),
        StoredState::Sent {
            signature,
            signatures,
            co_signature,
        } => RelayState::Sent(SentAttempt {
            signature: signature.0,
            signatures: collected_signatures(signatures),
            co_signature: co_signature.map(|signature| signature.0),
        }),
        StoredState::Confirmed {
            signature,
            slot,
            co_signature,
        } => RelayState::Confirmed {
            signature: signature.0,
            slot,
            co_signature: co_signature.map(|signature| signature.0),
        },
        StoredState::Failed {
            reason,
            co_signature,
        } => RelayState::Failed {
            reason,
            co_signature: co_signature.map(|signature| signature.0),
        },
    })
}

fn collected_signatures(stored: Vec<StoredSignature>) -> Vec<CollectedSignature> {
    stored
        .into_iter()
        .map(|stored| CollectedSignature {
            signer: stored.signer.0,
            signature: stored.signature.0,
        })
        .collect()
}

fn pending_co_sign(stored: StoredCoSign) -> Result<PendingCoSign, DbErr> {
    Ok(PendingCoSign {
        signer: stored.signer.0,
        ring: stored.ring.0,
        flows: match stored.flows {
            None => CoSignFlows::Frame,
            Some(flows) => CoSignFlows::Published(
                flows
                    .into_iter()
                    .map(|flow| {
                        Ok(OwnerFlow {
                            owner: Member::from_bytes(flow.owner.0)
                                .map_err(|_| corrupt("co_sign"))?,
                            flow: AssetFlow {
                                asset: flow.asset.0,
                                debit: flow.debit,
                                charged_outflow: flow.charged_outflow,
                                deposited: flow.deposited,
                                withdrawn: flow.withdrawn,
                            },
                        })
                    })
                    .collect::<Result<_, DbErr>>()?,
            ),
        },
    })
}

fn corrupt(column: &str) -> DbErr {
    DbErr::Custom(format!("relay_relays {column} is corrupt"))
}

#[cfg(test)]
mod tests {
    use spr_client::{compile_message, ComputeBudgetConfig};

    use super::*;
    use crate::database::Store;

    const SIGNER: Address = Address::new_from_array([2; 32]);
    const FEE_PAYER: Address = Address::new_from_array([3; 32]);

    fn collected(signer: Address, byte: u8) -> CollectedSignature {
        CollectedSignature {
            signer,
            signature: Signature::from([byte; 64]),
        }
    }

    fn closing() -> Closing {
        Closing {
            co_signature: None,
            fee_payer: collected(FEE_PAYER, 9),
        }
    }

    fn awaiting(signers: &[Address]) -> RelayState {
        RelayState::AwaitingSignature(Awaiting {
            signatures: Vec::new(),
            awaiting: signers.to_vec(),
            co_sign: None,
        })
    }

    fn signed(signer: Address, closing: Option<Closing>) -> RelayEvent {
        RelayEvent::Signed {
            signature: collected(signer, 1),
            closing: closing.map(Box::new),
        }
    }

    #[test]
    fn the_last_awaited_signature_sends_only_with_the_closing_signatures() {
        let state = awaiting(&[SIGNER]);

        let sent = state.apply(signed(SIGNER, Some(closing())));
        let unclosed = state.apply(signed(SIGNER, None));
        let stranger = state.apply(signed(FEE_PAYER, Some(closing())));

        let Ok(Transition::Next(RelayState::Sent(sent))) = sent else {
            panic!("the last signature sends the relay, got {sent:?}");
        };
        assert_eq!(sent.signature, closing().fee_payer.signature);
        assert_eq!(sent.signatures, [collected(SIGNER, 1), closing().fee_payer]);
        assert_eq!(unclosed, Err(TransitionError::Closing));
        assert_eq!(stranger, Err(TransitionError::UnexpectedSigner));
    }

    #[test]
    fn a_repeated_signature_and_any_event_after_the_end_change_nothing() {
        let other = Address::new_from_array([4; 32]);
        let RelayState::AwaitingSignature(mut half) = awaiting(&[other]) else {
            unreachable!();
        };
        half.signatures.push(collected(SIGNER, 1));
        let ended = RelayState::Failed {
            reason: "expired".to_owned(),
            co_signature: None,
        };

        assert_eq!(
            RelayState::AwaitingSignature(half).apply(signed(SIGNER, None)),
            Ok(Transition::Unchanged)
        );
        assert_eq!(
            ended.apply(RelayEvent::Landed { slot: 1 }),
            Ok(Transition::Unchanged)
        );
        assert_eq!(
            awaiting(&[SIGNER]).apply(RelayEvent::Landed { slot: 1 }),
            Err(TransitionError::Unsent)
        );
    }

    #[tokio::test]
    async fn a_commit_over_a_stale_revision_writes_nothing() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let relays = RelayStore::new(store.connection());
        let id = RelayId([5; 32].into());
        let budget = ComputeBudgetConfig::new(1);
        let message =
            compile_message(&FEE_PAYER, &[], Default::default(), budget).expect("message");
        let record = |state| RelayRecord {
            message: message.clone(),
            last_valid_block_height: 1,
            state,
        };
        assert!(relays
            .insert(&id, &record(awaiting(&[SIGNER])))
            .await
            .expect("insert"));
        let expired = RelayState::Failed {
            reason: "expired".to_owned(),
            co_signature: None,
        };

        let first = relays
            .commit(&id, RelayRevision::FIRST, &record(expired.clone()))
            .await
            .expect("first");
        let stale = relays
            .commit(&id, RelayRevision::FIRST, &record(awaiting(&[SIGNER])))
            .await
            .expect("stale");

        assert_eq!(first, Committed::Written(RelayRevision(1)));
        assert_eq!(stale, Committed::Stale);
        let stored = relays.get(&id).await.expect("read").expect("row");
        assert_eq!(stored.revision, RelayRevision(1));
        assert_eq!(stored.record.state, expired);
    }

    /// Deposit legs sum past `u64::MAX`, the stored amounts read back exact.
    #[tokio::test]
    async fn a_deposit_relay_with_co_sign_amounts_past_u64_round_trips() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let relays = RelayStore::new(store.connection());
        let id = RelayId([6; 32].into());
        let message = compile_message(
            &FEE_PAYER,
            &[],
            Default::default(),
            ComputeBudgetConfig::new(1),
        )
        .expect("message");
        let past_u64 = u128::from(u64::MAX) + 2;
        let state = RelayState::AwaitingSignature(Awaiting {
            signatures: Vec::new(),
            awaiting: vec![SIGNER],
            co_sign: Some(PendingCoSign {
                signer: SIGNER,
                ring: FEE_PAYER,
                flows: CoSignFlows::Published(vec![OwnerFlow {
                    owner: Member::from_bytes([7; 32]).expect("member"),
                    flow: AssetFlow {
                        asset: FEE_PAYER,
                        debit: u128::MAX,
                        charged_outflow: u128::MAX,
                        deposited: past_u64,
                        withdrawn: 0,
                    },
                }]),
            }),
        });
        let record = RelayRecord {
            message,
            last_valid_block_height: 1,
            state: state.clone(),
        };

        assert!(relays.insert(&id, &record).await.expect("insert"));

        let stored = relays.get(&id).await.expect("read").expect("row");
        assert_eq!(stored.record.state, state);
    }
}
